// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"slices"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type TeamKeysForRole struct {
	sync.Mutex

	role core.RoleKey

	pub []*lcl.SharedKeyWithInfo // must start at gen=0, and not have holes

	// a sequence of parcels, that when taken together, the seedchains
	// form the whole sequence.
	privBoxed []proto.SharedKeyParcel

	// Unboxed private keys, starting at gen=0, and not having holes.
	priv []core.SharedPrivateSuiter
}

// TeamKeyRing has all of the relevant PTKs, at all relevant generations.
// Can be shraed across go-routines.
type TeamKeyRing struct {
	sync.Mutex
	t     map[core.RoleKey]*TeamKeysForRole
	i     map[proto.FixedEntityID]*lcl.SharedKeyWithInfo
	hepks *core.HEPKSet
}

func (r *TeamKeyRing) sortedKeys() []core.RoleKey {
	var roleKeys []core.RoleKey
	for rk := range r.t {
		roleKeys = append(roleKeys, rk)
	}
	slices.SortFunc(roleKeys, func(a, b core.RoleKey) int { return a.Cmp(b) })
	return roleKeys
}

func (t *TeamKeysForRole) HasPrivates() bool {
	t.Lock()
	defer t.Unlock()
	return len(t.priv) > 0
}

func (t *TeamKeysForRole) PublicGens() int {
	t.Lock()
	defer t.Unlock()
	return len(t.pub)
}

func (t *TeamKeysForRole) At(g proto.Generation) core.SharedPrivateSuiter {
	t.Lock()
	defer t.Unlock()
	idx := g.ToIndex()
	if idx < 0 || idx >= len(t.priv) {
		return nil
	}
	key := t.priv[idx]
	if key == nil {
		return nil
	}
	return key
}

func (t *TeamKeysForRole) CurrentPublic() *lcl.SharedKeyWithInfo {
	t.Lock()
	defer t.Unlock()
	if len(t.pub) == 0 {
		return nil
	}
	return core.Last(t.pub)
}

func (t *TeamKeysForRole) Current() core.SharedPrivateSuiter {
	t.Lock()
	defer t.Unlock()
	if len(t.priv) == 0 {
		return nil
	}
	return core.Last(t.priv)
}

func (t *TeamKeysForRole) LastGen() proto.Generation {
	t.Lock()
	defer t.Unlock()
	idx := len(t.pub) - 1
	return proto.GenerationFromIndex(idx)
}

var _ SharedKeySequence = (*TeamKeysForRole)(nil)
var _ SharedKeyManager = (*TeamKeyRing)(nil)

func (r *TeamKeyRing) ToKeyGens() team.KeyGens {
	r.Lock()
	defer r.Unlock()
	ret := team.NewKeyGens()
	for _, rk := range r.sortedKeys() {
		v := r.t[rk].pub
		if len(v) > 0 {
			lst := core.Last(v)
			ret[rk] = lst.Sk.Gen
		}
	}
	return ret
}

func (r *TeamKeyRing) AdminOrOwnerKey() *TeamKeysForRole {
	r.Lock()
	defer r.Unlock()
	for _, rk := range []core.RoleKey{core.AdminRole, core.OwnerRole} {
		if ret := r.t[rk]; ret != nil {
			return ret
		}
	}
	return nil
}

func (r *TeamKeyRing) Export() ([]lcl.SharedKeyWithInfo, []proto.SharedKeyParcel) {
	r.Lock()
	defer r.Unlock()
	var pub []lcl.SharedKeyWithInfo
	var privBoxed []proto.SharedKeyParcel
	for _, rk := range r.sortedKeys() {
		v := r.t[rk].pub
		for _, item := range v {
			pub = append(pub, *item)
		}
		w := r.t[rk].privBoxed
		if len(w) > 0 {
			privBoxed = append(privBoxed, w...)
		}
	}
	return pub, privBoxed

}

func (r *TeamKeyRing) ExportPTKsPub() []lcl.SharedKeyWithInfo {
	r.Lock()
	defer r.Unlock()
	srk := r.sortedKeys()
	var ret []lcl.SharedKeyWithInfo
	for _, rk := range srk {
		for _, item := range r.t[rk].pub {
			ret = append(ret, *item)
		}
	}
	return ret
}

func (r *TeamKeyRing) ExportToPTKGens() []proto.SharedKeyGen {
	r.Lock()
	defer r.Unlock()
	var ret []proto.SharedKeyGen
	for _, rk := range r.sortedKeys() {
		v := r.t[rk].pub
		if len(v) > 0 {
			ret = append(ret, proto.SharedKeyGen{
				Role: rk.Export(),
				Gen:  v[len(v)-1].Sk.Gen,
			})
		}
	}
	return ret
}

func (r *TeamKeyRing) HaveKeysFor() []proto.SharedKeyGen {
	r.Lock()
	defer r.Unlock()
	type tmpItem struct {
		role core.RoleKey
		gen  proto.Generation
	}
	var lst []tmpItem
	for rk, seq := range r.t {
		l := len(seq.privBoxed)
		if l > 0 {
			lst = append(lst, tmpItem{
				role: rk,
				gen:  seq.privBoxed[l-1].Box.Gen,
			})
		}
	}
	slices.SortFunc(lst, func(a, b tmpItem) int { return a.role.Cmp(b.role) })
	var ret []proto.SharedKeyGen
	for _, item := range lst {
		ret = append(ret, proto.SharedKeyGen{
			Role: item.role.Export(),
			Gen:  item.gen,
		})
	}
	return ret
}

func (r *TeamKeyRing) KeysForRole(rk core.RoleKey) *TeamKeysForRole {
	r.Lock()
	defer r.Unlock()
	return r.keysForRoleLocked(rk)
}

func (r *TeamKeyRing) highestRole() *core.RoleKey {
	r.Lock()
	defer r.Unlock()
	var ret *core.RoleKey
	for rk, v := range r.t {
		if v.HasPrivates() && (ret == nil || rk.Cmp(*ret) > 0) {
			tmp := rk
			ret = &tmp
		}
	}
	return ret
}

func (r *TeamKeyRing) PrivateKeysForHighestRole(m MetaContext) (SharedKeySequence, error) {
	rk := r.highestRole()
	if rk == nil {
		return nil, core.TeamKeyError("no admin or owner key")
	}
	return r.PrivateKeysForRole(m, rk.Export())
}

func (r *TeamKeyRing) PrivateKeysForRole(m MetaContext, role proto.Role) (SharedKeySequence, error) {
	rk, err := core.ImportRole(role)
	if err != nil {
		return nil, err
	}
	seq := r.KeysForRole(*rk)
	if seq == nil || !seq.HasPrivates() {
		return nil, nil
	}
	return seq, nil
}

func (r *TeamKeyRing) keysForRoleLocked(rk core.RoleKey) *TeamKeysForRole {
	seq, found := r.t[rk]
	if !found {
		seq = &TeamKeysForRole{role: rk}
		r.t[rk] = seq
	}
	return seq
}

func (r *TeamKeyRing) CurrentPublicKeyAtRole(rk core.RoleKey) *lcl.SharedKeyWithInfo {
	seq := r.KeysForRole(rk)
	if seq == nil {
		return nil
	}
	return seq.CurrentPublic()
}

func (r *TeamKeyRing) CurrentPrivateKeyAtRole(rk core.RoleKey) core.SharedPrivateSuiter {
	seq := r.KeysForRole(rk)
	if seq == nil {
		return nil
	}
	return seq.Current()
}

func (r *TeamKeyRing) PrivateKeyForRoleAt(rk core.RoleKey, gen proto.Generation) core.SharedPrivateSuiter {
	seq := r.KeysForRole(rk)
	if seq == nil {
		return nil
	}
	return seq.At(gen)
}

func (r *TeamKeyRing) AddPub(k lcl.SharedKeyWithInfo) error {
	r.Lock()
	defer r.Unlock()
	rk, err := core.ImportRole(k.Sk.Role)
	if err != nil {
		return err
	}
	kfr := r.keysForRoleLocked(*rk)
	if kfr == nil {
		return nil
	}
	kfr.Lock()
	defer kfr.Unlock()
	nPubKeys := len(kfr.pub)
	nextGen := nPubKeys + int(proto.FirstGeneration)
	if nextGen != int(k.Sk.Gen) {
		return core.ChainLoaderError{
			Err: core.CLBadKeySequenceError{
				Which: "pub",
				Gen:   k.Sk.Gen,
				Role:  k.Sk.Role,
			},
		}
	}

	// This key revokes the prior key, so write down revoke info there.
	if nPubKeys > int(proto.FirstGeneration) {
		kfr.pub[nPubKeys-1].Ri = &proto.RevokeInfo{
			Revoker: k.Pi.Signer,
			Chain:   k.Pi.Chain,
		}
	}

	p := &k

	kfr.pub = append(kfr.pub, p)
	fe, err := k.Sk.VerifyKey.Fixed()
	if err != nil {
		return err
	}
	r.i[fe] = p
	return nil
}

func (r *TeamKeyRing) AddPrivBoxed(p proto.SharedKeyParcel) error {
	r.Lock()
	defer r.Unlock()
	rk, err := core.ImportRole(p.Box.Role)
	if err != nil {
		return err
	}
	kfr := r.keysForRoleLocked(*rk)
	if kfr == nil {
		return nil
	}
	kfr.Lock()
	defer kfr.Unlock()
	if len(kfr.pub) == 0 {
		return core.TeamKeyError("cannot add privBoxed before pub")
	}
	kfr.privBoxed = append(kfr.privBoxed, p)
	return nil
}

func (k *TeamKeysForRole) FindDecryptKey(fp *proto.HEPKFingerprint) (core.SharedPrivateSuiter, error) {
	k.Lock()
	defer k.Unlock()
	if len(k.priv) == 0 {
		return nil, core.KeyNotFoundError{Which: "DH priv"}
	}
	// Start with newest key first, we should probably hit that first.
	for i := len(k.priv) - 1; i >= 0; i-- {
		ptk := k.priv[i]
		hepk, err := ptk.ExportHEPK()
		if err != nil {
			return nil, err
		}
		thisFp, err := core.HEPK(hepk).Fingerprint()
		if err != nil {
			return nil, err
		}
		if thisFp.Eq(fp) {
			return ptk, nil
		}
	}
	return nil, core.KeyNotFoundError{Which: "DH priv"}
}

func (r *TeamKeyRing) FindDecryptKey(k core.RoleKey, fp *proto.HEPKFingerprint) (core.SharedPrivateSuiter, error) {
	kfr := r.KeysForRole(k)
	if kfr == nil {
		return nil, core.KeyNotFoundError{Which: "DH priv"}
	}
	return kfr.FindDecryptKey(fp)
}

func (t *TeamKeysForRole) Role() core.RoleKey {
	t.Lock()
	defer t.Unlock()
	return t.role
}

func (r *TeamKeyRing) All() []*TeamKeysForRole {
	r.Lock()
	defer r.Unlock()
	var ret []*TeamKeysForRole
	for _, v := range r.t {
		ret = append(ret, v)
	}
	return ret
}

func NewTeamKeyRing() *TeamKeyRing {
	return &TeamKeyRing{
		t: make(map[core.RoleKey]*TeamKeysForRole),
		i: make(map[proto.FixedEntityID]*lcl.SharedKeyWithInfo),
	}
}

type PTKSequence []core.SharedPrivateSuiter

func (p PTKSequence) startGen() proto.Generation {
	return p[0].Metadata().Gen
}

func (p PTKSequence) endGen() proto.Generation {
	return p[len(p)-1].Metadata().Gen + 1
}

// take in 2 PTK sequences, and merge them into a continuous sequence.
// it won't work if they don't overlap.
func (l PTKSequence) merge(r PTKSequence) PTKSequence {
	if len(l) == 0 && len(r) == 0 {
		return nil
	}
	if len(l) == 0 {
		return r
	}
	if len(r) == 0 {
		return l
	}
	if l.startGen() > r.startGen() {
		l, r = r, l
	}

	// They don't overlap, so return nil
	if l.endGen() < r.startGen() {
		return nil
	}
	if l.endGen() >= r.endGen() {
		return l
	}
	return append(l, r[l.endGen()-r.startGen():]...)
}

// ptkUnbox is the key method for unboxing a PTK, given a candidate set of receeiver DH keys, which can
// either be PUKs in the case of direct team membership, or PTKs in the case of one team being a member
// of another. The parcel is the boxed PTK that came down from server along with the Team chain. The
// hostID is the host from which this was pulled. The goal of this function is return a unboxed PTK,
// which can elsewhere be checked for sanity against the public PTK advertised in the chain. The team
// roster is needed so that we can lookup DH keys given the stated sender
func (r *TeamKeysForRole) ptkUnbox(
	m MetaContext,
	hepks *core.HEPKSet,
	parc proto.SharedKeyParcel,
	rcvr TeamUnboxReceiver,
	hostID proto.HostID,
	roster *team.Roster,
	histSend *HistoricalSenders,
) (
	PTKSequence,
	error,
) {

	sks, err := ptkUnboxDH(m, hepks, parc, rcvr, hostID, roster, histSend)
	if err != nil {
		return nil, err
	}
	ptk, err := r.openPTKFromSeed(*sks, hostID)
	if err != nil {
		return nil, err
	}

	ret := []core.SharedPrivateSuiter{ptk}
	prev := ptk
	gen := ptk.Metadata().Gen - 1
	for i := len(parc.SeedChain) - 1; i >= 0; i-- {
		seed := parc.SeedChain[i]
		if seed.Gen != gen {
			return nil, core.TeamKeyError("bad generation in seedchain")
		}
		var sks proto.SharedKeySeed
		key := prev.SecretBoxKey()
		err := core.OpenSecretBoxInto(&sks, seed.Box, &key)
		if err != nil {
			return nil, err
		}
		ptk, err := r.openPTKFromSeed(sks, hostID)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ptk)
		gen--
		prev = ptk
	}
	core.Reverse(ret)
	return ret, nil
}

func ptkUnboxDH(
	m MetaContext,
	hepks *core.HEPKSet,
	parc proto.SharedKeyParcel,
	rcvr TeamUnboxReceiver,
	hostID proto.HostID,
	roster *team.Roster,
	histSenders *HistoricalSenders,
) (*proto.SharedKeySeed, error) {

	rcvrSPS := rcvr.Keys.At(parc.Box.Targ.Gen)
	if rcvrSPS == nil {
		return nil, core.TeamKeyError("cannot find key for box")
	}

	var senderKeys *proto.TeamMemberKeys

	// For boxes, we have a sender encryption key. We need to map
	// the verifyKey that the keys with to the corresponding
	// encryption key, stored as a Hybrid Encryption Public Key Fingerprint
	// (HepkFp). We can find this in one of two places: the roster,
	// if it's a current key, or the historical senders, if it's an
	// older key.

	histSender, err := histSenders.Lookup(parc.Sender)
	if err != nil {
		return nil, err
	}
	if histSender != nil {
		senderKeys = &proto.TeamMemberKeys{
			VerifyKey: parc.Sender,
			HepkFp:    *histSender,
		}
	} else {
		// It's important to note that only the most recent
		// verify/HEPK pair is stored in the "roster". But the
		// older pairs will be stored in HistoricalSenders, which will
		// be persisted to disk.
		_, senderKeys, err = roster.LookupMemberByVerifyKey(parc.Sender, hostID)
		if err != nil {
			return nil, err
		}
		err = histSenders.Push(senderKeys.ToSenderPair())
		if err != nil {
			return nil, err
		}
	}

	sender, err := core.ImportPublicSuiterFromTeamMemberKeys(*senderKeys, hepks, hostID, proto.OwnerRole)
	if err != nil {
		return nil, err
	}

	var sks proto.SharedKeySeed
	err = core.OpenBoxInSet(
		&sks,
		parc.Box.Box,
		parc.TempDHKeySigned,
		&parc.BoxId,
		sender,
		rcvrSPS,
	)
	if err != nil {
		return nil, err
	}

	if sks.Gen != parc.Box.Gen {
		return nil, core.TeamKeyError("gen mismatch (inside of box vs outside)")
	}
	err = sks.Role.AssertEq(parc.Box.Role, core.TeamKeyError("role mismatch (insider of box vs outside)"))
	if err != nil {
		return nil, err
	}
	return &sks, nil
}

func (r *TeamKeysForRole) openPTKFromSeed(sks proto.SharedKeySeed, h proto.HostID) (core.SharedPrivateSuiter, error) {
	ptk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_PTKVerify,
		sks.Role,
		sks.Seed,
		sks.Gen,
		h,
	)
	if err != nil {
		return nil, err
	}

	if !sks.Gen.IsValid() {
		return nil, core.TeamKeyError("invalid key generation")
	}
	// Reccall the indices are 1-indexed, and the r.pub array is 0-indexed
	idx := int(sks.Gen) - 1
	if idx < 0 {
		return nil, core.TeamKeyError("gen < 0")
	}
	if idx >= len(r.pub) {
		return nil, core.TeamKeyError("gen too high")
	}
	pubExpected := r.pub[idx]
	err = ptk.AssertEqPub(pubExpected.Sk, core.TeamKeyError("pub key mismatch"))
	if err != nil {
		return nil, err
	}
	return ptk, nil
}

type TeamUnboxReceiver struct {
	Keys SharedKeySequence
	Host proto.HostID
}

func (r *TeamKeysForRole) Unbox(
	m MetaContext,
	hepks *core.HEPKSet,
	rcvr TeamUnboxReceiver,
	teamHost proto.HostID,
	roster *team.Roster,
	histSend *HistoricalSenders,
) error {
	r.Lock()
	defer r.Unlock()

	if len(r.pub) == 0 {
		return core.TeamKeyError("no pub keys")
	}

	// All done, no need for further work
	if len(r.pub) == len(r.priv) {
		return nil
	}

	left := PTKSequence(append([]core.SharedPrivateSuiter{}, r.priv...))
	var right PTKSequence

	for i := len(r.privBoxed) - 1; i >= 0; i-- {
		pb := r.privBoxed[i]
		tmp, err := r.ptkUnbox(m, hepks, pb, rcvr, teamHost, roster, histSend)
		if err != nil {
			return err
		}
		right = tmp.merge(right)
		if len(right) == 0 {
			return core.TeamKeyError("no overlap in privBoxed keys")
		}
		ret := left.merge(right)
		if len(ret) > 0 && ret.startGen().IsFirst() {
			r.priv = ret
			return nil
		}
	}
	return core.TeamKeyError("ran out of privBoxed keys")
}
