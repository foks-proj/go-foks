// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type rotateMgr struct {
	// input parameters
	uc              *UserContext
	targetEid       proto.EntityID
	forceRotateRole map[core.RoleKey]bool

	// state parameters
	uw         *UserWrapper
	target     core.PublicSuiter
	targetRole core.RoleKey
	allRoles   map[core.RoleKey]proto.Generation
	allPuks    map[core.RoleKey]PUKSet
	selfRevoke bool
	nextPuks   map[core.RoleKey]core.SharedPrivateSuiter
	puksToPost []core.SharedPrivateSuiter
	seedChain  []proto.SeedChainBox
	boxes      *proto.SharedKeyBoxSet
	anx        *rem.SetPassphraseAnnex
	devkey     core.PrivateSuiter
	ppm        *PassphraseManager
	hepks      *core.HEPKSet
	newSeqno   proto.Seqno
}

func (r *rotateMgr) checkInputParams() error {
	if r.uc == nil {
		return core.InternalError("rotateMgr::checkInputParams: uc is nil")
	}

	switch {
	case r.targetEid != nil:
		// OK, we're going to be revoking
	case len(r.forceRotateRole) > 0:
		// OK, we're going to be rotating
	default:
		return core.InternalError("rotateMgr::checkInputParams: no target or forceRotateRole")
	}

	return nil
}

func (r *rotateMgr) runOnce(m MetaContext) error {

	r.resetState()

	err := r.checkInputParams()
	if err != nil {
		return err
	}
	err = r.loadUser(m)
	if err != nil {
		return err
	}
	err = r.checkRevokeOrRotate(m)
	if err != nil {
		return err
	}
	err = r.collectAllRoles(m)
	if err != nil {
		return err
	}
	err = r.loadAllPUKs(m)
	if err != nil {
		return err
	}
	err = r.makeSeeds(m)
	if err != nil {
		return err
	}
	err = r.makeBoxes(m)
	if err != nil {
		return err
	}
	err = r.updatePPE(m)
	if err != nil {
		return err
	}
	err = r.post(m)
	if err != nil {
		return err
	}

	// past this point, we can't retry, so wrap all errors in non-retriable errors
	err = r.postscript(m)
	if err != nil {
		m.Warnw("revokeMgr::runOnce", "stage", "postscript", "err", err)
		return core.NonRetriableError{Err: err}
	}

	return nil
}

func (r *rotateMgr) postscript(m MetaContext) error {
	err := r.updateState(m)
	if err != nil {
		m.Warnw("revokeMgr::runOnce", "stage", "updateState", "err", err)
		return err
	}
	err = r.reencryptSecretKeys(m)
	if err != nil {
		return err
	}
	return nil
}

func (r *rotateMgr) resetState() {
	r.uw = nil
	r.allRoles = nil
	r.allPuks = nil
	r.selfRevoke = false
	r.puksToPost = nil
	r.seedChain = nil
	r.anx = nil
	r.hepks = core.NewHEPKSet()
}

type RaceError interface {
	error
	IsRace() bool
}

func (r *rotateMgr) reloadMe(m MetaContext) error {

	return MerkleRaceRetry(m,
		func() error {
			uw, err := LoadMe(m, r.uc)
			if err != nil {
				return err
			}

			if uw.Prot().Tail.Base.Seqno != r.newSeqno {
				return core.RevokeRaceError{}
			}

			// If just a rotate, no reason to check the device is revoked.
			if r.target == nil {
				r.uw = uw
				return nil
			}

			dev, err := uw.FindDevice(r.target.GetEntityID())
			if err != nil {
				return err
			}
			if dev == nil {
				return core.InternalError("revokeMgr::updateState: revoked device not found")
			}
			if dev.Revoked == nil {
				return core.RevokeRaceError{}
			}
			r.uw = uw
			return nil
		},
		nil,
		"revokeMgr::reloadMe",
	)
}

func (r *rotateMgr) updateState(m MetaContext) error {

	err := r.reloadMe(m)
	if err != nil {
		return err
	}

	// This will reload Me *again* but that's fine for now.
	err = r.uc.PopulateWithDevkey(m)
	if err != nil {
		return err
	}

	err = r.clearUser(m)
	if err != nil {
		return err
	}
	return nil
}

func (r *rotateMgr) clearUser(m MetaContext) error {

	if r.target == nil {
		return nil
	}
	return clearUserFromLocalStores(m, r.uw.fqu, r.target)
}

func cleanKeyDeleteError(err error) error {
	if err == nil {
		return nil
	}
	switch err.(type) {
	case core.NotFoundError, core.KeyMismatchError, core.RowNotFoundError:
		return nil
	}
	return err
}

func clearUserFromLocalStores(m MetaContext, fqu proto.FQUser, target core.PublicSuiter) error {

	targetKeyID := target.GetEntityID()
	kg, err := targetKeyID.Type().KeyGenus()
	if err != nil {
		return err
	}

	lui, err := core.NewLocalUserIndex(fqu, targetKeyID)
	if err != nil {
		return err
	}

	err = cleanKeyDeleteError(
		m.DeleteUserWithLocalUserIndex(*lui, targetKeyID),
	)
	if err != nil {
		return err
	}

	if kg != proto.KeyGenus_Device {
		return nil
	}

	err = cleanKeyDeleteError(
		DeleteUserDevkey(
			m,
			fqu,
			target.GetRole(),
			targetKeyID,
		),
	)
	if err != nil {
		return err
	}

	err = cleanKeyDeleteError(
		DeleteUserFromDB(m, lui.Export(), targetKeyID),
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *rotateMgr) post(m MetaContext) error {
	usrv, err := r.uc.UserClient(m)
	if err != nil {
		return err
	}
	fqu := r.uc.FQU()
	ma, err := r.uc.MerkleAgent(m)
	if err != nil {
		return err
	}
	mroot, err := ma.GetLatestRootAndValidate(m.Ctx())
	if err != nil {
		return err
	}
	root, err := merkle.ToTreeRoot(mroot)
	if err != nil {
		return err
	}

	r.newSeqno = r.uw.Prot().Tail.Base.Seqno + 1

	mlr, err := core.MakeRevokeLink(
		fqu.Uid,
		fqu.HostID,
		r.devkey,
		r.target, // might be null if just doing a rotate after a self-revoke
		r.puksToPost,
		r.newSeqno,
		r.uw.Prot().LastHash,
		*root,
	)
	if err != nil {
		return err
	}

	arg := rem.RevokeDeviceArg{
		Link:             *mlr.Link,
		SeedChain:        r.seedChain,
		NextTreeLocation: *mlr.NextTreeLocation,
		Ppa:              r.anx,
		Hepks:            r.hepks.Export(),
	}
	if r.boxes != nil {
		arg.PukBoxes = *r.boxes
	}

	err = usrv.RevokeDevice(m.Ctx(), arg)
	return err
}

// updatePPE updates the passphrase encryption system for the new PUK. Only encrypts
// if the target role is the owner.
func (r *rotateMgr) updatePPE(m MetaContext) error {
	if r.selfRevoke {
		return nil
	}
	if !r.targetRole.IsOwner() {
		return nil
	}
	pme, err := NewPMELoggedIn(m, r.uc)
	if err != nil {
		return err
	}
	ppm := NewPassphraseManager(r.uc.FQU())

	// Careful. Previously we were references r.uc.PUKs(),
	// but that set isn't loaded here. We already have the full puks
	// in memory in the rotate Mgr itself.
	puks, ok := r.allPuks[r.targetRole]
	var allPuks []core.SharedPrivateSuiter
	if ok {
		allPuks = append(allPuks, puks.All()...)
	}
	oPuk, found := r.nextPuks[r.targetRole]
	if !found {
		return core.InternalError("new owner PUK wasn't found")
	}
	allPuks = append(allPuks, oPuk)

	anx, err := ppm.RotateWithPUK(m.Ctx(), pme, allPuks)
	// It's ok to not have a passphrase here
	if err != nil && errors.Is(err, core.PassphraseNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	r.anx = anx
	r.ppm = ppm
	return nil
}

func (r *rotateMgr) reencryptSecretKeys(m MetaContext) error {
	if r.ppm == nil {
		return nil
	}
	return ReencryptIfPassphraseLocked(m, r.uc, r.ppm)
}

func (r *rotateMgr) makeBoxes(m MetaContext) error {
	if r.selfRevoke {
		return nil
	}

	dk, err := r.uc.Devkey(m.Ctx())
	if err != nil {
		return err
	}
	skb, err := core.NewSharedKeyBoxer(r.uc.FQU().HostID, dk)
	if err != nil {
		return err
	}

	for _, dev := range r.uw.ActiveDevices() {

		// don't encrypt for the device being revoked
		if r.target != nil && core.PublicSuiterEq(dev, r.target) {
			continue
		}
		drk, err := core.ImportRole(dev.GetRole())
		if err != nil {
			return err
		}
		for rk, puk := range r.nextPuks {

			// if r.targetRole is less than rk, the target role (the key being revoekd)
			// never had access to rk, the key being boxed.
			// If drk is less than the new PUK, then this device doesn't need the new PUK.
			if drk.LessThan(rk) || (r.target != nil && r.targetRole.LessThan(rk)) {
				continue
			}
			err = skb.Box(puk, dev)
			if err != nil {
				return err
			}
		}
	}
	tmp, err := skb.Finish()
	if err != nil {
		return err
	}
	r.boxes = tmp
	return nil
}

func (r *rotateMgr) sortedRoleList() []core.RoleKey {
	keys := make([]core.RoleKey, 0, len(r.allPuks))
	for rk := range r.allPuks {
		keys = append(keys, rk)
	}
	slices.SortFunc(keys, func(a, b core.RoleKey) int { return a.Cmp(b) })
	return keys
}

// Make new seeds for all roles that are less than or equal to the target role,
// assuming it is not a self-revoke.
func (r *rotateMgr) makeSeeds(m MetaContext) error {

	fqu := r.uc.FQU()
	host := fqu.HostID
	r.nextPuks = make(map[core.RoleKey]core.SharedPrivateSuiter)
	roles := r.sortedRoleList()

	for _, rk := range roles {
		puk := r.allPuks[rk]

		curr := puk.Current()

		if (r.forceRotateRole != nil && !r.forceRotateRole[rk]) ||
			(r.target != nil && r.targetRole.LessThan(rk)) ||
			r.selfRevoke {
			r.nextPuks[rk] = curr
			continue
		}

		// First make a new PUK with a new secret seed.
		ss := core.RandomSecretSeed32()
		newPuk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_PUKVerify,
			curr.GetRole(),
			ss,
			curr.Metadata().Gen+1,
			host,
		)
		if err != nil {
			return err
		}
		r.nextPuks[rk] = newPuk
		r.puksToPost = append(r.puksToPost, newPuk)
		hpek, err := newPuk.ExportHEPK()
		if err != nil {
			return err
		}
		err = r.hepks.Add(*hpek)
		if err != nil {
			return err
		}

		// Next box the old seed for the new PUK, to assist in historical
		// recovery.
		sboxKey := newPuk.SecretBoxKey()
		fqe := fqu.ToFQEntity()
		cleartext := curr.ExportToBoxCleartext(fqe)
		box, err := core.SealIntoSecretBox(&cleartext, &sboxKey)
		if err != nil {
			return err
		}
		r.seedChain = append(r.seedChain, proto.SeedChainBox{
			Box:  *box,
			Gen:  curr.Metadata().Gen,
			Role: rk.Export(),
		})
	}
	return nil
}

func (r *rotateMgr) run(m MetaContext) error {
	return MerkleRaceRetry(m,
		func() error { return r.runOnce(m) },
		nil,
		"revokeMgr::run",
	)
}

func (r *rotateMgr) loadAllPUKs(m MetaContext) error {
	pm := NewPUKMinder(r.uc)
	pm.SetUser(r.uw)
	res := make(map[core.RoleKey]PUKSet)
	for rk := range r.allRoles {
		puk, err := pm.GetPUKSetForRole(m, rk.Export())
		if err != nil {
			return err
		}
		res[rk] = *puk
	}
	r.allPuks = res
	return nil
}

func (r *rotateMgr) collectAllRoles(m MetaContext) error {
	res := make(map[core.RoleKey]proto.Generation)
	for _, puk := range r.uw.Prot().Puks {
		rk, err := core.ImportRole(puk.Role)
		if err != nil {
			return err
		}
		if gen, ok := res[*rk]; !ok || gen < puk.Gen {
			res[*rk] = puk.Gen
		}
	}
	r.allRoles = res
	return nil
}

func (r *rotateMgr) checkRotate(m MetaContext) error {
	rk, err := core.ImportRole(r.devkey.GetRole())
	if err != nil {
		return err
	}
	var maxRole *core.RoleKey
	var found bool
	for frk := range r.forceRotateRole {
		if maxRole == nil || maxRole.LessThan(frk) {
			frk := frk
			maxRole = &frk
		}
		// if we can rotate at least one of the force-rotate roles with the current devkey,
		// then we are good to go.
		if !rk.LessThan(frk) {
			found = true
		}
	}
	if !found {
		return core.CannotRotateError{}
	}
	if maxRole != nil {
		r.targetRole = *maxRole
	}
	return nil
}

func (r *rotateMgr) checkRevokeOrRotate(m MetaContext) error {
	if r.target == nil {
		return r.checkRotate(m)
	}
	return r.checkRevoke(m)
}

func (r *rotateMgr) checkRevoke(m MetaContext) error {

	dev, err := r.uw.FindDevice(r.target.GetEntityID())
	if err != nil {
		return err
	}
	if dev == nil {
		return core.KeyNotFoundError{Which: "device"}
	}
	if dev.Revoked != nil {
		return core.RevokeError("device already revoked")
	}

	gt, err := dev.Key.DstRole.GreaterThan(r.devkey.GetRole())
	if err != nil {
		return err
	}
	if gt {
		return core.RevokeError("device has higher role")
	}

	eq, err := core.PublicPrivateSuiterEqual(r.target, r.devkey)
	if err != nil {
		return err
	}
	r.selfRevoke = eq
	rk, err := core.ImportRole(r.target.GetRole())
	if err != nil {
		return err
	}
	r.targetRole = *rk

	if r.targetRole.Typ == proto.RoleType_OWNER {
		c, err := r.uw.CountOwnerDevices()
		if err != nil {
			return err
		}
		if c == 1 {
			return core.RevokeError("cannot revoke last owner device")
		}
	}
	return nil
}

func (r *rotateMgr) loadUser(m MetaContext) error {
	uw, err := LoadMe(m, r.uc)
	if err != nil {
		return err
	}
	r.uw = uw

	dk, err := r.uc.Devkey(m.Ctx())
	if err != nil {
		return err
	}
	r.devkey = dk

	if r.targetEid == nil {
		return nil
	}
	dkPub, err := dk.EntityPublic()
	if err != nil {
		return err
	}
	r.selfRevoke = dkPub.GetEntityID().Eq(r.targetEid)

	targetDI, err := r.uw.FindDevice(r.targetEid)
	if err != nil {
		return err
	}
	if targetDI == nil {
		return core.KeyNotFoundError{Which: "device"}
	}
	targetPS, err := core.ImportPublicSuite(&targetDI.Key, r.uw.Hepks, r.uw.fqu.HostID)
	if err != nil {
		return err
	}
	r.target = targetPS
	return nil
}

func Revoke(
	m MetaContext,
	uc *UserContext,
	eid proto.EntityID,
) error {
	r := rotateMgr{uc: uc, targetEid: eid}
	return r.run(m)
}

func RotatePUKs(
	m MetaContext,
	uc *UserContext,
	sk *StaleKeys,
) error {
	r := rotateMgr{uc: uc, forceRotateRole: sk.Keys}
	return r.run(m)
}

// RotateStalePUKs loads a user to find any stale
// PUKs. If it finds any, it will call RotatePUKs
// as normal.
func RotateStalePUKs(
	m MetaContext,
	uc *UserContext,
	uw *UserWrapper,
) (bool, error) {

	staleKeys := uw.StalePUKs()
	if staleKeys.IsEmpty() {
		return false, nil
	}
	fqus, err := uc.FQU().StringErr()
	if err != nil {
		return false, err
	}

	m.Infow("RotateStalePUKs", "staleKeys", staleKeys.Keys, "fqu", fqus)

	err = RotatePUKs(m, uc, staleKeys)
	if err != nil {
		return false, err
	}
	return true, nil
}
