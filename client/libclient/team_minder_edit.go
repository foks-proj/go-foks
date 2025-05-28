// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type CryptoPartier interface {
	PrivateKeyAt(MetaContext, proto.Generation) (core.SharedPrivateSuiter, error)
	CurrentAdminKey(MetaContext) (core.SharedPrivateSuiter, error)
	FQParty() proto.FQParty
	SrcRole() proto.Role

	// In CLKR, we need to be sure that the cryptopartier used to load a team
	// isn't stale for when we edit it, so we'll call into the Refresh. For a user
	// the team minder is ignored, but for a team, it's used to call LoadTeamWithFQTeam
	Refresh(MetaContext, *TeamMinder) (CryptoPartier, error)
}

func IsUser(c CryptoPartier) bool { return c.FQParty().Party.IsUser() }
func IsTeam(c CryptoPartier) bool { return c.FQParty().Party.IsTeam() }

type keyAndRole struct {
	key     core.SPSBoxer
	dstRole proto.Role
}

type RemoteTokenPackage struct {
	Rmvtbp proto.TeamRemoteMemberViewTokenBoxPayload
	Rjtok  proto.TeamRSVP
}

type TeamEditor struct {
	// parameters for making edits; not needed for creates
	tl    *TeamLoader          // Fully initialized loader for target team
	tw    *TeamWrapper         // the team wrapper of the loaded team
	tok   *rem.TeamBearerToken // the token to work with
	cp    CryptoPartier        // the actor making the edit (maybe a team or a user)
	hepks *core.HEPKSet        // public keys in changes
	lvpf  []proto.PartyID      // local view perms for
	cfg   *rem.TeamConfig      // needs to be preloaded and fetched from the server

	id proto.TeamID // ID of the target team

	// For new team, needs to be an empty new roster; for an existing team, this needs to be
	// the roster right before the edit.
	pre *team.Roster // the roster before the edit

	// paramaters passed in from caller
	changes []proto.MemberRole
	rtps    []RemoteTokenPackage
	cmd     []proto.ChangeMetadata

	// state updated along the way
	signPriv       core.SharedPrivateSuiter // the private key of the actor
	encryptPriv    core.SharedPrivateSuiter // the private key of the actor for sending DH encryptions
	newKeyOnRotate proto.EntityID           // the new key on a self-rotation (null otherwise)
	sched          *team.KeySchedule
	rosterPost     *team.Roster
	boxSet         *proto.SharedKeyBoxSet
	newMembers     map[team.MemberID]*keyAndRole
	newPtks        []core.SharedPrivateSuiter
	mlr            *core.MakeLinkResBase
	newAdminPtk    core.SharedPrivateSuiter
	seqno          proto.Seqno
	removalKeys    []rem.TeamRemovalBoxData
	removals       []rem.TeamRemovalAndComm
	treeRoot       *proto.TreeRoot
	tac            *rem.TeamAdminClient
	seedChain      []proto.SeedChainBox
	rmvtk          []proto.TeamRemoteMemberViewToken
	changeMap      map[team.MemberID]int
}

func teamEditorFromTeamRecord(tr *TeamRecord) *TeamEditor {
	return &TeamEditor{
		tl:  tr.ldr,
		tw:  tr.tw,
		id:  tr.ldr.TeamID(),
		pre: tr.ldr.rosterPost,
		cp:  tr.member,
	}
}

func (t *TeamEditor) activeUser(m MetaContext) (*UserContext, error) {
	ret := m.G().ActiveUser()
	if ret == nil {
		return nil, core.NoActiveUserError{}
	}
	return ret, nil
}

func (t *TeamEditor) teamAdminClient(m MetaContext) (*rem.TeamAdminClient, error) {
	if t.tac != nil {
		return t.tac, nil
	}
	au, err := t.activeUser(m)
	if err != nil {
		return nil, err
	}
	tac, err := au.TeamAdminClient(m)
	if err != nil {
		return nil, err
	}
	t.tac = tac
	return tac, nil
}

// findSelfChangeGen finds if the changer (given by t.cp) is changing itself,
// maybe to a new version of its own PTK/PUK on a rotation. It will return 0, nil
// if not found. We should never be called in the case of a team creation, the only
// time when we can add ourselves as gen=0 to a team.
func (t *TeamEditor) findSelfChangeGen(m MetaContext) (proto.Generation, error) {
	var ret proto.Generation
	var found bool
	host := t.cp.FQParty().Host
	for _, ch := range t.changes {
		if ch.Member.Id.WithHost(host).Eq(t.cp.FQParty().FQEntity()) {
			eq, err := ch.Member.SrcRole.Eq(t.cp.SrcRole())
			if err != nil {
				return ret, err
			}
			if !eq {
				continue
			}
			if found {
				return ret, core.InternalError("multiple self changes")
			}
			found = true
			typ, err := ch.Member.Keys.GetT()
			if err != nil {
				return ret, err
			}
			if typ != proto.MemberKeysType_Team {
				return ret, core.InternalError("expected team keys")
			}
			ret = ch.Member.Keys.Team().Gen
		}
	}
	return ret, nil
}

// setPrivateKeys sets the private keys used for signing the team chain update,
// and for encryption new boxes introduces in this change. Usually they one in the
// same, but in the case of a self-rotation (as in a CLKR), the signing key must be the
// one previously advertised in the team chain, and the encryption key needs to be the one
// we are upgrading to. It's important that the encryption key in case the previous
// key was compromised; we don't want the adversary breaking into future boxes. Also,
// in terms of how team chain playback plays out, the roster changes are applied before
// the keys are unboxed, so by the time the player is looking to unbox, the roster has
// already been updated to the new key generation.
func (t *TeamEditor) setPrivateKeys(
	m MetaContext,
) error {

	mbmr, err := t.tw.GetMember(t.cp.FQParty(), t.cp.SrcRole())
	if err != nil {
		return err
	}
	if mbmr == nil {
		return core.NotFoundError("member not found")
	}
	typ, err := mbmr.Mr.Member.Keys.GetT()
	if err != nil {
		return err
	}
	if typ != proto.MemberKeysType_Team {
		return core.InternalError("expected team keys")
	}
	key, err := t.cp.PrivateKeyAt(m, mbmr.Mr.Member.Keys.Team().Gen)
	if err != nil {
		return err
	}
	if key == nil {
		return core.KeyNotFoundError{Which: "team PTK"}
	}

	newGen, err := t.findSelfChangeGen(m)
	if err != nil {
		return err
	}

	senderKey := key

	// This is very tricky. If we're rotating our own key, and then
	// signing a new link, the signature has to be with the existing key,
	// but the encryption needs to use the sender key that we're about
	// to upgrade to. This is first and foremost more secure, since the
	// old key might be compromised. But it's also the way the team player
	// works. The roster changes are applied first (bumping the sender PUK/PTK
	// version to the updated version), and then the unboxing happens.
	if newGen > key.Metadata().Gen {
		key, err := t.cp.PrivateKeyAt(m, newGen)
		if err != nil {
			return err
		}
		senderKey = key
		t.newKeyOnRotate, err = senderKey.EntityID()
		if err != nil {
			return err
		}
	}

	t.signPriv = key
	t.encryptPriv = senderKey

	m.Infow("setPrivateSuite", "signGen", t.signPriv.Metadata().Gen, "encryptGen", t.encryptPriv.Metadata().Gen)
	return nil
}

func (t *TeamEditor) checkArgs(m MetaContext, mdOnly bool) error {
	fields := 0
	if t.tl != nil {
		fields++
	}
	if t.tok != nil {
		fields++
	}
	if t.tw != nil {
		fields++
	}
	if fields != 0 && fields != 3 {
		return core.InternalError("team editor: tl, tw and tok must be provided together")
	}
	if t.cp == nil {
		return core.InternalError("team editor: cryptoPartier (cp) must be provided")
	}
	isUser := t.cp.FQParty().Party.IsUser()
	if fields == 0 && !isUser {
		return core.InternalError("for new team, CP must be a user")
	}
	if t.pre == nil && !mdOnly {
		return core.InternalError("team editor: rosterPre must be provided")
	}
	return nil
}

func (t *TeamEditor) keyOwner() proto.KeyOwner {
	return proto.KeyOwner{
		Party:   t.cp.FQParty().Party,
		SrcRole: t.cp.SrcRole(),
	}
}

func (t *TeamEditor) runGameplan(m MetaContext) error {
	mrq := make([]proto.MemberRoleSeqno, len(t.changes))
	for i, v := range t.changes {
		mrq[i] = proto.MemberRoleSeqno{
			Mr: v,
		}
	}
	vk, err := t.signPriv.EntityPublic()
	if err != nil {
		return err
	}
	roster, sched, err := t.pre.Gameplan(
		t.keyOwner(),
		t.cp.FQParty().Host,
		mrq,
		vk.GetEntityID(),
		nil,
	)
	if err != nil {
		return err
	}
	t.sched = sched
	t.rosterPost = roster

	return nil
}

func (t *TeamEditor) runBoxes(m MetaContext) error {

	host := t.cp.FQParty().Host

	var seedChain []proto.SeedChainBox
	var newPtks []core.SharedPrivateSuiter

	newPtkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)

	newMembers := make(map[team.MemberID]*keyAndRole)

	for _, newMem := range t.sched.Additions {
		newMembers[newMem] = &keyAndRole{}
	}

	skb, err := core.NewSharedKeyBoxer(host, t.encryptPriv)
	if err != nil {
		return err
	}

	loadHEPKs := t.tw.hepks.Merge(t.hepks)

	for _, item := range t.sched.Items {
		var ptk core.SharedPrivateSuiter
		if t.tw != nil {
			ptk = t.tw.KeyRing().CurrentPrivateKeyAtRole(item.Role)
		}

		if item.NewKeyGen {
			ss := core.RandomSecretSeed32()
			gen := proto.FirstGeneration

			if ptk != nil {
				gen = ptk.Metadata().Gen + 1
			}

			newPtk, err := core.NewSharedPrivateSuite25519(
				proto.EntityType_PTKVerify,
				item.Role.Export(),
				ss,
				gen,
				host,
			)
			if err != nil {
				return err
			}

			if t.hepks == nil {
				t.hepks = core.NewHEPKSet()
			}
			hepk, err := newPtk.ExportHEPK()
			if err != nil {
				return err
			}
			err = t.hepks.Add(*hepk)
			if err != nil {
				return err
			}

			if ptk != nil {
				cleartext := ptk.ExportToBoxCleartext(t.cp.FQParty().FQEntity())
				sboxKey := newPtk.SecretBoxKey()
				box, err := core.SealIntoSecretBox(&cleartext, &sboxKey)
				if err != nil {
					return err
				}
				seedChain = append(seedChain, proto.SeedChainBox{
					Box:  *box,
					Gen:  ptk.Metadata().Gen,
					Role: item.Role.Export(),
				})
			}
			newPtkMap[item.Role] = newPtk
			ptk = newPtk
			newPtks = append(newPtks, newPtk)

			// If we made a new admin PTK, we might need it further down below,
			// so hold onto it here.
			if item.Role.Eq(core.AdminRole) {
				t.newAdminPtk = newPtk
			}
		} else {

			if ptk == nil {
				return core.KeyNotFoundError{Which: "PTK"}
			}
			if ptk.Metadata().Gen != item.Gen {
				return core.KeyMismatchError{}
			}
		}

		for _, mem := range item.Members {
			aux := t.rosterPost.Mks.Members[mem]
			if aux == nil {
				return core.KeyNotFoundError{Which: "TMK"}
			}
			ps, err := core.ImportSPSBoxer(
				proto.FQEntityFixed(mem.Fqe).Unfix(),
				loadHEPKs,
				*aux,
				mem.SrcRole.Export(),
			)
			if err != nil {
				return err
			}
			err = skb.Box(ptk, ps)
			if err != nil {
				return err
			}

			if kandr := newMembers[mem]; kandr != nil {
				kandr.dstRole = item.Role.Export()
				kandr.key = *ps
			}
		}
	}
	boxSet, err := skb.Finish()
	if err != nil {
		return err
	}
	t.boxSet = boxSet
	t.newMembers = newMembers
	t.newPtks = newPtks
	t.seedChain = seedChain

	return nil
}

func (t *TeamEditor) makeTeamLink(m MetaContext) error {
	au, err := t.activeUser(m)
	if err != nil {
		return err
	}
	ma, err := au.MerkleAgent(m)
	if err != nil {
		return err
	}
	tr, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return err
	}
	var seqno proto.Seqno
	var prev proto.LinkHash
	if t.tw != nil {
		seqno = t.tw.Prot().Tail.Base.Seqno + 1
		prev = t.tw.Prot().LastHash
	}
	mlr, err := team.MakeTeamLink(
		t.cp.FQParty().Host,
		t.id,
		t.keyOwner(),
		t.signPriv,
		t.changes,
		t.newPtks,
		seqno,
		prev,
		tr,
		t.cmd,
	)
	if err != nil {
		return err
	}
	t.mlr = mlr
	t.seqno = seqno
	t.treeRoot = &tr
	return nil
}

func (t *TeamEditor) newAdminBoxer(m MetaContext) (*core.SPSBoxer, error) {
	key := t.newAdminPtk
	if key == nil {
		if t.tw == nil {
			return nil, core.KeyNotFoundError{Which: "admin PTK"}
		}
		key = t.tw.KeyRing().CurrentPrivateKeyAtRole(core.AdminRole)
	}
	if key == nil {
		return nil, core.KeyNotFoundError{Which: "admin PTK"}
	}
	return core.PublicizeToSPSBoxer(key, t.cp.FQParty())
}

func (t *TeamEditor) fqTeam() proto.FQTeam {
	return proto.FQTeam{
		Host: t.cp.FQParty().Host,
		Team: t.id,
	}
}

func (t *TeamEditor) makeChangeMap(m MetaContext) error {

	host := t.fqTeam().Host

	// Make a lookup map of user changed -> index in the change vector
	cmap := make(map[team.MemberID]int)
	for i, c := range t.changes {
		key, err := team.MemberRoleToMemberID(&c, host)
		if err != nil {
			return err
		}
		_, found := cmap[*key]
		if found {
			return core.InternalError("duplicate member in changes")
		}
		cmap[*key] = i
	}
	t.changeMap = cmap
	return nil
}

func (t *TeamEditor) makeRemovalKeys(m MetaContext) error {

	var removalKeys []rem.TeamRemovalBoxData
	admin, err := t.newAdminBoxer(m)
	if err != nil {
		return err
	}

	for _, newMem := range t.sched.Additions {
		kandr, ok := t.newMembers[newMem]
		if !ok || kandr == nil {
			return core.InternalError("new member not found")
		}
		party, err := newMem.Fqe.Unfix().FQParty()
		if err != nil {
			return err
		}
		box, key, err := team.NewBoxedTeamRemovalKey(
			t.signPriv,
			admin,
			&kandr.key,
			rem.TeamRemovalKeyMetadata{
				Tm:      t.fqTeam(),
				Member:  *party,
				SrcRole: newMem.SrcRole.Export(),
				Dst: proto.RoleAndSeqno{
					Seqno: t.seqno,
					Role:  kandr.dstRole,
				},
			},
		)
		if err != nil {
			return err
		}
		removalKeys = append(removalKeys, *box)
		comm, err := core.ComputeKeyCommitment(key)
		if err != nil {
			return err
		}
		i, ok := t.changeMap[newMem]
		if !ok {
			return core.InternalError("new member not found in changes")
		}
		err = t.changes[i].Member.AddRemovalKeyCommitment(comm)
		if err != nil {
			return err
		}
	}
	t.removalKeys = removalKeys
	return nil
}

func (t *TeamEditor) makeTeamID(m MetaContext) error {
	if !t.id.IsZero() {
		return nil
	}
	if t.newAdminPtk == nil {
		return core.InternalError("new admin PTK not found")
	}
	eid, err := t.newAdminPtk.EntityID()
	if err != nil {
		return err
	}
	peid, err := eid.Persistent()
	if err != nil {
		return err
	}
	tid, err := peid.ToTeamID()
	if err != nil {
		return err
	}
	t.id = tid
	return nil
}

func (t *TeamEditor) prepareRemoval(
	m MetaContext,
	mid team.MemberID,
) (
	*rem.TeamRemovalAndComm,
	error,
) {
	fqparty, err := mid.Fqe.Unfix().FQParty()
	if err != nil {
		return nil, err
	}
	arg := rem.LoadRemovalKeyBoxForTeamAdminArg{
		Tok:     *t.tok,
		Member:  *fqparty,
		SrcRole: mid.SrcRole.Export(),
	}
	cli, err := t.teamAdminClient(m)
	if err != nil {
		return nil, err
	}
	box, err := cli.LoadRemovalKeyBoxForTeamAdmin(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}
	rk, err := core.ImportRole(box.EncKey.Role)
	if err != nil {
		return nil, err
	}
	dec := t.tw.KeyRing().PrivateKeyForRoleAt(*rk, box.EncKey.Gen)
	if dec == nil {
		return nil, core.KeyNotFoundError{Which: "PTK"}
	}
	var payload rem.TeamRemovalKeyBoxPayload
	_, err = dec.UnboxFor(&payload, box.Box, nil)
	if err != nil {
		return nil, err
	}
	if !t.fqTeam().Eq(payload.Md.Tm) {
		return nil, core.ValidationError("team mismatch in removal key unbox")
	}
	if !fqparty.Eq(payload.Md.Member) {
		return nil, core.ValidationError("member mismatch in removal key unbox")
	}
	ok, err := payload.Md.SrcRole.Eq(mid.SrcRole.Export())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.ValidationError("src role mismatch in removal key unbox")
	}
	mp := rem.TeamRemovalMACPayload{
		Team:    payload.Md.Tm,
		Member:  payload.Md.Member,
		SrcRole: payload.Md.SrcRole,
		Admin:   t.cp.FQParty(),
		Root:    *t.treeRoot,
		Tm:      proto.Now(),
	}
	hmk := proto.HMACKey(payload.Key)
	hmac, err := core.Hmac(&mp, &hmk)
	if err != nil {
		return nil, err
	}
	comm, err := core.ComputeKeyCommitment(&payload.Key)
	if err != nil {
		return nil, err
	}
	ret := rem.TeamRemovalAndComm{
		Rm: rem.TeamRemoval{
			Mac:     *hmac,
			Payload: mp,
		},
		Comm: *comm,
	}

	return &ret, nil
}

func (t *TeamEditor) prepareAllRemovals(m MetaContext) error {

	if t.tok == nil {
		return core.InternalError("no token, which is needed to load removal keys")
	}
	var rks []rem.TeamRemovalAndComm
	for _, r := range t.sched.Removals {
		rk, err := t.prepareRemoval(m, r)
		if err != nil {
			return err
		}
		rks = append(rks, *rk)
	}
	t.removals = rks
	return nil
}

func (t *TeamEditor) boxOneRemoteMemberViewToken(
	m MetaContext,
	rtp RemoteTokenPackage,
	ptk core.SharedPrivateSuiter,
) error {
	skey := ptk.SecretBoxKey()
	sbox, err := core.SealIntoSecretBox(&rtp.Rmvtbp, &skey)
	if err != nil {
		return err
	}
	jrt, err := rtp.Rjtok.Remote()
	if err != nil {
		return err
	}
	mlf := t.tw.MemberLoadFloor()

	rmvtk := proto.TeamRemoteMemberViewToken{
		Team: t.id,
		Inner: proto.TeamRemoteMemberViewTokenInner{
			SecretBox: *sbox,
			PtkGen:    ptk.Metadata().Gen,
			Member:    rtp.Rmvtbp.Party,
			PtkRole:   mlf,
		},
		Jrt: *jrt,
	}
	t.rmvtk = append(t.rmvtk, rmvtk)
	return nil
}

func (t *TeamEditor) boxAllRemoteMemberViewTokens(m MetaContext) error {
	if len(t.rtps) == 0 {
		return nil
	}
	mlf := t.tw.MemberLoadFloor()
	mlfRk, err := core.ImportRole(mlf)
	if err != nil {
		return err
	}

	ptk := t.tw.KeyRing().CurrentPrivateKeyAtRole(*mlfRk)
	if ptk == nil {
		return core.KeyNotFoundError{Which: "PTK"}
	}
	for _, rtp := range t.rtps {
		err := t.boxOneRemoteMemberViewToken(m, rtp, ptk)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TeamEditor) post(m MetaContext) error {
	arg := rem.EditTeamArg{
		Link:             *t.mlr.Link,
		NextTreeLocation: *t.mlr.NextTreeLocation,
		Obd: rem.OffchainBoxData{
			SeedChain:              t.seedChain,
			RemoteMemberViewTokens: t.rmvtk,
			RemovalKeys:            t.removalKeys,
			Removals:               t.removals,
			NewKeyOnRotate:         t.newKeyOnRotate,
		},
		Tok: t.tok,
	}
	if t.hepks != nil {
		arg.Obd.Hepks = t.hepks.Export()
	}
	if t.boxSet != nil {
		arg.Obd.PtkBoxes = *t.boxSet
	}

	// Pass along any local view perms to the server.
	arg.InsLocalPermsFor = t.lvpf

	cli, err := t.teamAdminClient(m)
	if err != nil {
		return err
	}
	_, err = cli.EditTeam(m.Ctx(), arg)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamEditor) RunMetadataOnly(m MetaContext) error {
	err := t.checkArgs(m, true)
	if err != nil {
		return err
	}
	err = t.setPrivateKeys(m)
	if err != nil {
		return err
	}
	err = t.makeTeamLink(m)
	if err != nil {
		return err
	}
	err = t.post(m)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamEditor) checkKeyLimits(m MetaContext) error {
	if t.cfg == nil {
		return core.InternalError("team config not loaded")
	}
	nKeys := t.rosterPost.KeyGens.Num()
	if nKeys >= 0 && uint64(nKeys) > t.cfg.MaxRoles {
		return core.TeamRosterError("too many roles in team")
	}
	return nil
}

func (t *TeamEditor) Run(m MetaContext) error {

	m = m.WithLogTag("team-edit")
	m.Infow("team-edit", "team", t.fqTeam(), "changes", t.changes)

	err := t.checkArgs(m, false)
	if err != nil {
		return err
	}

	err = t.setPrivateKeys(m)
	if err != nil {
		return err
	}

	err = t.runGameplan(m)
	if err != nil {
		return err
	}

	err = t.checkKeyLimits(m)
	if err != nil {
		return err
	}

	err = t.makeChangeMap(m)
	if err != nil {
		return err
	}

	err = t.runBoxes(m)
	if err != nil {
		return err
	}

	err = t.makeTeamID(m)
	if err != nil {
		return err
	}

	// needs to be done prior to makeTeamLink, since we added the removal key commitments, which then
	// get signed into the link.
	err = t.makeRemovalKeys(m)
	if err != nil {
		return err
	}

	err = t.makeTeamLink(m)
	if err != nil {
		return err
	}

	err = t.prepareAllRemovals(m)
	if err != nil {
		return err
	}

	err = t.boxAllRemoteMemberViewTokens(m)
	if err != nil {
		return err
	}

	err = t.post(m)
	if err != nil {
		return err
	}

	return nil
}
