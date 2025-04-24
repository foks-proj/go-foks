// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/keybase/saltpack/encoding/basex"
	"github.com/stretchr/testify/require"
)

type teamObj struct {
	id             proto.EntityID
	host           proto.HostID
	nm             proto.NameUtf8
	roster         *team.Roster
	ptks           map[core.RoleKey]core.SharedPrivateSuiter
	seqno          proto.Seqno
	prev           proto.LinkHash
	membChainSeqno proto.Seqno
	membChainPrev  *proto.LinkHash
	ptk0Admin      core.SharedPrivateSuiter
	ptkMatrix      testKeyMatrix
	removalKeys    map[team.MemberID]rem.TeamRemovalKey
	hepks          *core.HEPKSet
	tir            *core.RationalRange
}

func (tm *teamObj) absorb(x *core.HEPKSet) {
	tm.hepks = tm.hepks.Merge(x)
}

func (tm *teamObj) ToFQTeamParsed(t *testing.T) *proto.FQTeamParsed {
	tmid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	hn := proto.NewParsedHostnameWithFalse(tm.host)
	return &proto.FQTeamParsed{
		Team: proto.NewParsedTeamWithFalse(tmid),
		Host: &hn,
	}
}

func makeTeamBearerToken(t *testing.T, u *TestUser, tm *teamObj, role core.RoleKey) rem.TeamBearerToken {
	ctx := context.Background()
	tcli, closer := u.newTeamAdminClient(t, ctx)
	defer closer()
	ptk := tm.ptks[role]
	require.NotNil(t, ptk)
	tmid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	tok, err := tcli.MakeInertTeamBearerToken(ctx, rem.MakeInertTeamBearerTokenArg{
		Team: tmid,
		Role: role.Export(),
		Gen:  ptk.Metadata().Gen,
	})
	require.NoError(t, err)
	sig, obj, err := team.SignBearerTokenChallenge(
		u.FQUser(), tmid, role.Export(), ptk.Metadata().Gen, tok, ptk)
	require.NoError(t, err)
	err = tcli.ActivateTeamBearerToken(ctx, rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	require.NoError(t, err)
	return tok
}

func makeTeamMembershipLinkFull(
	t *testing.T,
	m shared.MetaContext,
	src *teamObj,
	dst *teamObj,
	ptk core.SharedPrivateSuiter,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	srcRole proto.Role,
	deets proto.TeamMembershipApprovedDetails,
) *core.MakeLinkRes {
	if !seqno.IsValid() {
		panic("bad chain seqno")
	}
	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    dst.FQTeam(t),
			SrcRole: srcRole,
			State: proto.NewTeamMembershipDetailsWithApproved(
				deets,
			),
		},
	)
	tr := getCurrentTreeRootWithHostID(t, m, &src.host)
	glink, err := core.MakeGenericLink(
		src.id,
		src.host,
		ptk,
		glp,
		seqno,
		prev,
		tr,
	)
	require.NoError(t, err)
	require.NotNil(t, glink)
	return glink
}

func randomTeamname(t *testing.T) proto.NameUtf8 {
	var buf [6]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err)
	suffx := basex.Base58StdEncoding.EncodeToString(buf[:])
	return proto.NameUtf8("t_" + suffx)
}

func (tm *teamObj) KeySeq(t *testing.T, r proto.Role) libclient.SharedKeySequence {
	return tm.ptkMatrix.Seq(t, r)
}

func (o *teamObj) FQTeam(t *testing.T) proto.FQTeam {
	tid, err := o.id.ToTeamID()
	require.NoError(t, err)
	return proto.FQTeam{
		Host: o.host,
		Team: tid,
	}
}

func (o *teamObj) toMemberRole(
	t *testing.T,
	srcRole proto.Role,
	dstRole proto.Role,
) proto.MemberRole {
	return o.toMemberRoleWithLocalFlag(t, srcRole, dstRole, true)
}

func (o *teamObj) toMemberRoleRemote(
	t *testing.T,
	srcRole proto.Role,
	dstRole proto.Role,
) proto.MemberRole {
	return o.toMemberRoleWithLocalFlag(t, srcRole, dstRole, false)
}

func (o *teamObj) toMemberRoleWithLocalFlag(
	t *testing.T,
	srcRole proto.Role,
	dstRole proto.Role,
	isLocal bool,
) proto.MemberRole {
	rk, err := core.ImportRole(srcRole)
	require.NoError(t, err)
	ptk, ok := o.ptks[*rk]
	require.True(t, ok)
	pub, hepk, err := ptk.ExportToSharedKey()
	require.NoError(t, err)

	err = o.hepks.Add(*hepk)
	require.NoError(t, err)

	ret := proto.MemberRole{
		DstRole: dstRole,
		Member: proto.Member{
			Id: proto.FQEntityInHostScope{
				Entity: o.id,
			},
			SrcRole: pub.Role,
		},
	}
	if !isLocal {
		ret.Member.Id.Host = &o.host
	}
	if dstRole.T != proto.RoleType_NONE {
		ret.Member.Keys = proto.NewMemberKeysWithTeam(
			pub.ToTeamMemberKeys(o.tir.ExportP()),
		)
	}
	return ret
}

type makeTeamForOwnerEvilOpts struct {
	puker                func() core.SharedPrivateSuiter
	wrongRemovalKey      bool
	missingRemovalKeyBox bool
}

func (to *teamObj) addRemovalKey(
	t *testing.T,
	member proto.FQParty,
	role core.RoleKey,
	key rem.TeamRemovalKey,
) {
	if to.removalKeys == nil {
		to.removalKeys = make(map[team.MemberID]rem.TeamRemovalKey)
	}
	fqef, err := member.FQEntity().Fixed()
	require.NoError(t, err)
	to.removalKeys[team.MemberID{
		Fqe:     *fqef,
		SrcRole: role,
	}] = key
}

func (to *teamObj) getRemovalKeyCommitment(
	t *testing.T,
	member proto.FQParty,
	role core.RoleKey,
) proto.KeyCommitment {
	fqef, err := member.FQEntity().Fixed()
	require.NoError(t, err)
	key, ok := to.removalKeys[team.MemberID{
		Fqe:     *fqef,
		SrcRole: role,
	}]
	if !ok {
		t.Fatalf("well crap")
	}
	comm, err := core.ComputeKeyCommitment(&key)
	require.NoError(t, err)
	return *comm
}

func (te *TestEnvWrapper) makeTeamForOwnerEvil(t *testing.T, u *TestUser, opts makeTeamForOwnerEvilOpts) (*teamObj, error) {

	nm := randomTeamname(t)
	m := te.MetaContext()
	ptkMatrix := newTestKeyMarix()
	hepks := core.NewHEPKSet()

	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	defer closer()

	nnm, err := core.NormalizeName(nm)
	if err != nil {
		return nil, err
	}

	rnr, err := tcli.ReserveTeamname(m.Ctx(), nnm)
	if err != nil {
		return nil, err
	}

	var puk core.SharedPrivateSuiter
	if opts.puker != nil {
		puk = opts.puker()
	} else {
		tmp, ok := u.puks[core.OwnerRole]
		if !ok {
			return nil, core.InternalError("no owner puk found")
		}
		puk = &tmp
	}

	var ptks []core.SharedPrivateSuiter
	ptkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)

	roles := team.EldestRoles()

	skb, err := core.NewSharedKeyBoxer(u.host, puk)
	if err != nil {
		return nil, err
	}
	mePub, err := core.PublicizeToSPSBoxer(puk, u.FQUser().FQParty())
	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		ss := core.RandomSecretSeed32()
		ptk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_Team,
			role,
			ss,
			proto.FirstGeneration,
			u.host,
		)
		require.NoError(t, err)
		ptks = append(ptks, ptk)
		collectHEPKToMap(t, hepks, ptk)

		err = skb.Box(ptk, mePub)
		if err != nil {
			return nil, err
		}

		rk, err := core.ImportRole(role)
		if err != nil {
			return nil, err
		}
		ptkMap[*rk] = ptk
		ptkMatrix.add(t, ptk)
	}
	boxes, err := skb.Finish()
	if err != nil {
		return nil, err
	}

	tr := u.getCurrentTreeRoot(t, m)

	nc := rem.NameCommitment{
		Name: nnm,
		Seq:  rnr.Seq,
	}

	ko := proto.KeyOwner{
		Party:   u.uid.ToPartyID(),
		SrcRole: proto.OwnerRole,
	}

	rmkey, err := team.NewTeamRemovalKey()
	if err != nil {
		return nil, err
	}
	comm, err := core.ComputeKeyCommitment(rmkey)
	if err != nil {
		return nil, err
	}

	mlr, err := team.MakeEldestLink(
		u.host,
		nc,
		ko,
		puk,
		ptks,
		tr,
		*comm,
	)
	if err != nil {
		return nil, err
	}

	hsh, err := core.LinkHash(mlr.Link)
	if err != nil {
		return nil, err
	}

	tid, err := mlr.TeamID.ToTeamID()
	require.NoError(t, err)
	fqt := proto.FQTeam{
		Team: tid,
		Host: u.host,
	}
	ownerPtk, ok := ptkMap[core.OwnerRole]
	require.True(t, ok)
	ownerPtkPub, err := core.PublicizeToSPSBoxer(ownerPtk, fqt.FQParty())
	require.NoError(t, err)

	if opts.wrongRemovalKey {
		rmkey, err = team.NewTeamRemovalKey()
		require.NoError(t, err)
	}

	trkbp, err := team.BoxTeamRemovalKey(
		puk,
		ownerPtkPub,
		mePub,
		rem.TeamRemovalKeyMetadata{
			Tm:      fqt,
			Member:  u.FQUser().FQParty(),
			SrcRole: proto.OwnerRole,
			Dst: proto.RoleAndSeqno{
				Role:  proto.OwnerRole,
				Seqno: proto.ChainEldestSeqno,
			},
		},
		rmkey,
	)
	require.NoError(t, err)

	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			SrcRole: proto.OwnerRole,
			Team:    fqt,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst: proto.RoleAndSeqno{
						Seqno: proto.ChainEldestSeqno,
						Role:  proto.OwnerRole,
					},
					KeyComm: trkbp.Comm,
				},
			),
		},
	)
	glink, err := core.MakeGenericLink(u.uid.EntityID(), u.host, u.devices[0], glp, u.teamMembSeqno, u.teamMembPrev, tr)
	require.NoError(t, err)

	var removalKeyBoxes []rem.TeamRemovalBoxData
	if !opts.missingRemovalKeyBox {
		removalKeyBoxes = append(removalKeyBoxes, *trkbp)
	}

	err = tcli.CreateTeam(
		m.Ctx(), rem.CreateTeamArg{
			NameUtf8:                 nm,
			TeamnameCommitmentKey:    *mlr.TeamnameCommitmentKey,
			SubchainTreeLocationSeed: *mlr.SubchainTreeLocationSeed,
			Rnr:                      rnr,
			Eta: rem.EditTeamArg{
				Link:             *mlr.Link,
				NextTreeLocation: *mlr.NextTreeLocation,
				Obd: rem.OffchainBoxData{
					PtkBoxes:    *boxes,
					RemovalKeys: removalKeyBoxes,
					Hepks:       hepks.Export(),
				},
			},
			TeamMembershipLink: rem.PostGenericLinkArg{
				Link:             *glink.Link,
				NextTreeLocation: *glink.NextTreeLocation,
			},
		},
	)
	if err != nil {
		return nil, err
	}
	u.teamMembSeqno++

	roster, _, err := team.NewEmptyRoster().Gameplan(
		ko,
		u.host,
		[]proto.MemberRoleSeqno{
			{
				Mr:    u.toMemberRole(t, proto.OwnerRole, hepks),
				Seqno: proto.ChainEldestSeqno,
			},
		},
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	tir := core.NewDefaultRange()
	return &teamObj{
		id:             mlr.TeamID,
		host:           u.host,
		nm:             nm,
		roster:         roster,
		ptks:           ptkMap,
		prev:           *hsh,
		ptk0Admin:      ptkMap[core.AdminRole],
		ptkMatrix:      ptkMatrix,
		hepks:          hepks,
		tir:            &tir,
		seqno:          proto.ChainEldestSeqno,
		membChainSeqno: proto.ChainEldestSeqno,
	}, nil
}

func (te *TestEnvWrapper) makeTeamForOwner(t *testing.T, u *TestUser) *teamObj {

	nm := randomTeamname(t)
	m := te.MetaContext()
	ptkMatrix := newTestKeyMarix()

	hepks := core.NewHEPKSet()

	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	defer closer()

	nnm, err := core.NormalizeName(nm)
	require.NoError(t, err)

	rnr, err := tcli.ReserveTeamname(m.Ctx(), nnm)
	require.NoError(t, err)

	puk, ok := u.puks[core.OwnerRole]
	require.True(t, ok)

	var ptks []core.SharedPrivateSuiter
	ptkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)

	roles := team.EldestRoles()

	skb, err := core.NewSharedKeyBoxer(u.host, &puk)
	require.NoError(t, err)
	mePub, err := core.PublicizeToSPSBoxer(&puk, u.FQUser().FQParty())
	require.NoError(t, err)

	for _, role := range roles {
		ss := core.RandomSecretSeed32()
		ptk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_PTKVerify,
			role,
			ss,
			proto.FirstGeneration,
			u.host,
		)
		require.NoError(t, err)
		ptks = append(ptks, ptk)

		collectHEPKToMap(t, hepks, ptk)

		err = skb.Box(ptk, mePub)
		require.NoError(t, err)

		rk, err := core.ImportRole(role)
		require.NoError(t, err)
		ptkMap[*rk] = ptk
		ptkMatrix.add(t, ptk)
	}
	boxes, err := skb.Finish()
	require.NoError(t, err)

	tr := u.getCurrentTreeRoot(t, m)

	nc := rem.NameCommitment{
		Name: nnm,
		Seq:  rnr.Seq,
	}

	ko := proto.KeyOwner{
		Party:   u.uid.ToPartyID(),
		SrcRole: proto.OwnerRole,
	}
	rmkey, err := team.NewTeamRemovalKey()
	require.NoError(t, err)
	comm, err := core.ComputeKeyCommitment(rmkey)
	require.NoError(t, err)

	mlr, err := team.MakeEldestLink(
		u.host,
		nc,
		ko,
		&puk,
		ptks,
		tr,
		*comm,
	)
	require.NoError(t, err)

	hsh, err := core.LinkHash(mlr.Link)
	require.NoError(t, err)

	tid, err := mlr.TeamID.ToTeamID()
	require.NoError(t, err)

	fqt := proto.FQTeam{
		Team: tid,
		Host: u.host,
	}

	ownerPtk, ok := ptkMap[core.OwnerRole]
	require.True(t, ok)

	ownerPtkPub, err := core.PublicizeToSPSBoxer(ownerPtk, fqt.FQParty())
	require.NoError(t, err)

	trkbp, err := team.BoxTeamRemovalKey(
		&puk,
		ownerPtkPub,
		mePub,
		rem.TeamRemovalKeyMetadata{
			Tm:      fqt,
			Member:  u.FQUser().FQParty(),
			SrcRole: proto.OwnerRole,
			Dst: proto.RoleAndSeqno{
				Role:  proto.OwnerRole,
				Seqno: proto.ChainEldestSeqno,
			},
		},
		rmkey,
	)
	require.NoError(t, err)

	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			SrcRole: proto.OwnerRole,
			Team:    fqt,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst: proto.RoleAndSeqno{
						Seqno: proto.ChainEldestSeqno,
						Role:  proto.OwnerRole,
					},
					KeyComm: trkbp.Comm,
				},
			),
		},
	)
	glink, err := core.MakeGenericLink(u.uid.EntityID(), u.host, u.devices[0], glp, u.teamMembSeqno, u.teamMembPrev, tr)
	require.NoError(t, err)
	ghsh, err := core.LinkHash(glink.Link)
	require.NoError(t, err)
	u.teamMembSeqno++
	u.teamMembPrev = ghsh

	err = tcli.CreateTeam(
		m.Ctx(), rem.CreateTeamArg{
			NameUtf8:                 nm,
			TeamnameCommitmentKey:    *mlr.TeamnameCommitmentKey,
			SubchainTreeLocationSeed: *mlr.SubchainTreeLocationSeed,
			Rnr:                      rnr,
			Eta: rem.EditTeamArg{
				Link:             *mlr.Link,
				NextTreeLocation: *mlr.NextTreeLocation,
				Obd: rem.OffchainBoxData{
					PtkBoxes:    *boxes,
					RemovalKeys: []rem.TeamRemovalBoxData{*trkbp},
					Hepks:       hepks.Export(),
				},
			},
			TeamMembershipLink: rem.PostGenericLinkArg{
				Link:             *glink.Link,
				NextTreeLocation: *glink.NextTreeLocation,
			},
		},
	)
	require.NoError(t, err)

	roster, _, err := team.NewEmptyRoster().Gameplan(
		ko,
		u.host,
		[]proto.MemberRoleSeqno{
			{
				Mr:    u.toMemberRole(t, proto.OwnerRole, hepks),
				Seqno: proto.ChainEldestSeqno,
			},
		},
		nil,
		nil,
	)
	require.NoError(t, err)

	tir := core.NewDefaultRange()
	ret := &teamObj{
		id:             mlr.TeamID,
		host:           u.host,
		nm:             nm,
		roster:         roster,
		ptks:           ptkMap,
		prev:           *hsh,
		ptk0Admin:      ptkMap[core.AdminRole],
		ptkMatrix:      ptkMatrix,
		hepks:          hepks,
		tir:            &tir,
		seqno:          proto.ChainEldestSeqno,
		membChainSeqno: proto.ChainEldestSeqno,
	}

	ret.addRemovalKey(t, u.FQUser().FQParty(), core.OwnerRole, *rmkey)
	return ret
}

func doublePoke(t *testing.T, m shared.MetaContext) {
	common.PokeMerklePipelineInTest(t, m)
	common.PokeMerklePipelineInTest(t, m)
}

type makeChangesKnobs struct {
	teamSigPuker     func() core.SharedPrivateSuiter
	gamePlanPuker    func() core.SharedPrivateSuiter
	gameplanOpts     *team.GameplanOpts
	rpcCompleteHook  func()
	treeRoot         *proto.TreeRoot
	md               []proto.ChangeMetadata
	insLocalPermsFor []proto.PartyID
}

func (tm *teamObj) makeChanges(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	mr []proto.MemberRole,
	vtk []proto.TeamRemoteMemberViewToken,
) {
	_, err := tm.makeChangesFull(t, m, u, mr, vtk, makeChangesKnobs{})
	require.NoError(t, err)
}

func (tm *teamObj) setIndexRange(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	ih core.RationalRange,
) {
	_, err := tm.makeChangesFull(t, m, u, nil, nil, makeChangesKnobs{
		md: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithTeamindexrange(
				ih.Export(),
			),
		},
	})
	require.NoError(t, err)
	tm.tir = &ih
}

func (tm *teamObj) makeChangesFull(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	mr []proto.MemberRole,
	vtk []proto.TeamRemoteMemberViewToken,
	knobs makeChangesKnobs,
) (
	*rem.EditTeamRes,
	error,
) {
	puk, ok := u.puks[core.OwnerRole]
	require.True(t, ok)

	var gamePlanPuk core.SharedPrivateSuiter
	if knobs.gamePlanPuker != nil {
		gamePlanPuk = knobs.gamePlanPuker()
	} else {
		gamePlanPuk = &puk
	}

	vk, err := gamePlanPuk.EntityPublic()
	require.NoError(t, err)

	mrq := make([]proto.MemberRoleSeqno, len(mr))
	for i, mr := range mr {
		mrq[i] = proto.MemberRoleSeqno{Mr: mr}
	}
	cmap := make(map[team.MemberID]int)
	for i, x := range mr {
		key, err := team.MemberRoleToMemberID(&x, u.host)
		require.NoError(t, err)
		cmap[*key] = i
	}

	roster, sched, err := tm.roster.Gameplan(u.uid.ToOwnerKeyOwner(), u.host, mrq, vk.GetEntityID(), knobs.gameplanOpts)
	if err != nil {
		return nil, err
	}
	require.NotNil(t, sched)

	var newPtks []core.SharedPrivateSuiter
	var seedChain []proto.SeedChainBox

	skb, err := core.NewSharedKeyBoxer(u.host, &puk)
	require.NoError(t, err)

	newPtkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)

	type keyAndRole struct {
		key     core.SPSBoxer
		dstRole proto.Role
	}

	newMembers := make(map[team.MemberID]*keyAndRole)
	var removalKeys []rem.TeamRemovalKey

	for _, newMem := range sched.Additions {
		newMembers[newMem] = &keyAndRole{}

		// now make a removal key for each new member
		rk, err := team.NewTeamRemovalKey()
		require.NoError(t, err)
		removalKeys = append(removalKeys, *rk)
		i := cmap[newMem]
		comm, err := core.ComputeKeyCommitment(rk)
		require.NoError(t, err)
		err = mr[i].Member.AddRemovalKeyCommitment(comm)
		require.NoError(t, err)
	}

	for _, item := range sched.Items {

		ptk := tm.ptks[item.Role]
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
				u.host,
			)
			require.NoError(t, err)
			collectHEPKToMap(t, tm.hepks, newPtk)

			if ptk != nil {
				cleartext := ptk.ExportToBoxCleartext(u.FQE())
				sboxKey := newPtk.SecretBoxKey()
				box, err := core.SealIntoSecretBox(&cleartext, &sboxKey)
				require.NoError(t, err)
				seedChain = append(seedChain, proto.SeedChainBox{
					Box:  *box,
					Gen:  ptk.Metadata().Gen,
					Role: item.Role.Export(),
				})
			}

			require.NoError(t, err)
			newPtkMap[item.Role] = newPtk
			ptk = newPtk
			newPtks = append(newPtks, newPtk)
			tm.ptkMatrix.add(t, newPtk)
		} else {
			require.NotNil(t, ptk)
			require.Equal(t, item.Gen, ptk.Metadata().Gen)
		}

		for _, mem := range item.Members {
			aux := roster.Mks.Members[mem]
			require.NotNil(t, aux)
			ps, err := core.ImportSPSBoxer(
				proto.FQEntityFixed(mem.Fqe).Unfix(),
				tm.hepks,
				*aux,
				mem.SrcRole.Export(),
			)
			require.NoError(t, err)
			err = skb.Box(ptk, ps)
			require.NoError(t, err)

			if kandr := newMembers[mem]; kandr != nil {
				kandr.dstRole = item.Role.Export()
				kandr.key = *ps
			}

		}
	}

	boxSet, err := skb.Finish()
	require.NoError(t, err)

	var tr proto.TreeRoot
	if knobs.treeRoot != nil {
		tr = *knobs.treeRoot
	} else {
		tr = u.getCurrentTreeRoot(t, m)
	}
	tmid, err := tm.id.ToTeamID()
	require.NoError(t, err)

	var mtlPuk core.SharedPrivateSuiter
	if knobs.teamSigPuker != nil {
		mtlPuk = knobs.teamSigPuker()
	} else {
		mtlPuk = &puk
	}

	seqno := tm.seqno + 1

	mlr, err := team.MakeTeamLink(
		u.host,
		tmid,
		u.uid.ToOwnerKeyOwner(),
		mtlPuk,
		mr,
		newPtks,
		seqno,
		tm.prev,
		tr,
		knobs.md,
	)
	require.NoError(t, err)

	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	defer closer()

	newAdminPtk, ok := newPtkMap[core.AdminRole]
	if !ok {
		newAdminPtk = tm.ptks[core.AdminRole]
	}

	newAdminPtkPub, err := core.PublicizeToSPSBoxer(newAdminPtk, tm.FQTeam(t).FQParty())
	require.NoError(t, err)

	var removalKeyBoxes []rem.TeamRemovalBoxData

	for i, newMem := range sched.Additions {
		keyAndRole, ok := newMembers[newMem]
		require.True(t, ok)
		require.NotNil(t, keyAndRole.key)
		party, err := newMem.Fqe.Unfix().FQParty()
		require.NoError(t, err)
		rk, err := team.BoxTeamRemovalKey(
			mtlPuk,
			newAdminPtkPub,
			&keyAndRole.key,
			rem.TeamRemovalKeyMetadata{
				Tm:      tm.FQTeam(t),
				Member:  *party,
				SrcRole: newMem.SrcRole.Export(),
				Dst: proto.RoleAndSeqno{
					Seqno: seqno,
					Role:  keyAndRole.dstRole,
				},
			},
			&removalKeys[i],
		)
		require.NoError(t, err)
		removalKeyBoxes = append(removalKeyBoxes, *rk)
		tm.addRemovalKey(t, *party, newMem.SrcRole, removalKeys[i])
	}

	var removals []rem.TeamRemovalAndComm

	for _, rmvl := range sched.Removals {
		key, ok := tm.removalKeys[rmvl]
		require.True(t, ok)

		party, err := rmvl.Fqe.Unfix().FQParty()
		require.NoError(t, err)

		payload := rem.TeamRemovalMACPayload{
			Team:    tm.FQTeam(t),
			Member:  *party,
			SrcRole: rmvl.SrcRole.Export(),
			Admin:   u.FQUser().FQParty(),
			Root:    tr,
			Tm:      proto.Now(),
		}
		hmk := proto.HMACKey(key)

		hmac, err := core.Hmac(&payload, &hmk)
		require.NoError(t, err)
		comm, err := core.ComputeKeyCommitment(&key)
		require.NoError(t, err)
		removal := rem.TeamRemovalAndComm{
			Rm: rem.TeamRemoval{
				Mac:     *hmac,
				Payload: payload,
			},
			Comm: *comm,
		}
		removals = append(removals, removal)
	}

	arg := rem.EditTeamArg{
		Link: *mlr.Link,
		Obd: rem.OffchainBoxData{
			PtkBoxes:               *boxSet,
			SeedChain:              seedChain,
			RemoteMemberViewTokens: vtk,
			RemovalKeys:            removalKeyBoxes,
			Removals:               removals,
			Hepks:                  tm.hepks.Export(),
		},
		NextTreeLocation: *mlr.NextTreeLocation,
		InsLocalPermsFor: knobs.insLocalPermsFor,
	}
	ret, err := tcli.EditTeam(m.Ctx(), arg)
	if knobs.rpcCompleteHook != nil {
		knobs.rpcCompleteHook()
	}
	if err != nil {
		return nil, err
	}

	hsh, err := core.LinkHash(mlr.Link)
	require.NoError(t, err)
	tm.roster = roster
	tm.prev = *hsh
	tm.seqno = seqno
	for k, v := range newPtkMap {
		tm.ptks[k] = v
	}
	return &ret, nil
}

func (u *TestUser) toMemberRole(t *testing.T, r proto.Role, hepks *core.HEPKSet) proto.MemberRole {
	return u.toMemberRoleWithLocal(t, r, true, hepks)
}

func (u *TestUser) toMemberRoleRemote(t *testing.T, r proto.Role, hepks *core.HEPKSet) proto.MemberRole {
	return u.toMemberRoleWithLocal(t, r, false, hepks)
}

func (u *TestUser) toMemberRoleWithLocal(t *testing.T, r proto.Role, lcl bool, hepks *core.HEPKSet) proto.MemberRole {

	puk := u.puks[core.OwnerRole]

	pub, hepk, err := puk.ExportToSharedKey()
	require.NoError(t, err)
	if hepks != nil {
		err = hepks.Add(*hepk)
		require.NoError(t, err)
	}

	ret := proto.MemberRole{
		DstRole: r,
		Member: proto.Member{
			Id: proto.FQEntityInHostScope{
				Entity: u.uid.EntityID(),
				Host:   core.Include(!lcl, u.host),
			},
			SrcRole: pub.Role,
		},
	}

	if r.T != proto.RoleType_NONE {
		ret.Member.Keys = proto.NewMemberKeysWithTeam(
			pub.ToTeamMemberKeys(nil),
		)
	}

	return ret
}

func makeTeamInvite(t *testing.T, tm *teamObj, user *TestUser) proto.TeamInvite {
	ptk := tm.ptks[core.AdminRole]
	require.NotNil(t, ptk)
	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	require.NotNil(t, cert)
	ctx := context.Background()
	teamBearerTok := makeTeamBearerToken(t, user, tm, core.OwnerRole)
	tcli, closer := user.newTeamAdminClient(t, ctx)
	defer closer()
	err = tcli.PutTeamCert(ctx, rem.PutTeamCertArg{
		Tok:  teamBearerTok,
		Cert: *cert,
	})
	require.NoError(t, err)
	var hsh proto.TeamCertHash
	err = core.PrefixedHashInto(cert, hsh[:])
	require.NoError(t, err)
	i1 := proto.TeamInviteV1{
		Hsh:  hsh,
		Host: user.host,
	}
	invite := proto.NewTeamInviteWithV1(i1)
	return invite
}

func runRemoteJoinSequenceForUser(
	t *testing.T,
	m shared.MetaContext,
	tm *teamObj,
	joiner *TestUser,
	admin *TestUser,
	role proto.Role,
) proto.PermissionToken {
	hepks := core.NewHEPKSet()
	joinerPuk := joiner.puks[core.OwnerRole]
	joinerRole := joiner.toMemberRoleRemote(t, role, hepks)
	joinerParty := joiner.FQUser().FQParty()
	grant := func(ctx context.Context) proto.PermissionToken {
		jcli, closer := joiner.newUserCertAndClient(t, m.Ctx())
		defer closer()
		vtok, err := jcli.GrantRemoteViewPermissionForUser(m.Ctx(),
			rem.GrantRemoteViewPermissionPayload{
				Viewee: joinerParty.Party,
				Viewer: tm.FQTeam(t).FQParty(),
				Tm:     proto.Now(),
			},
		)
		require.NoError(t, err)
		return vtok
	}

	return runRemoteJoinSequence(t, m, hepks, tm, grant, joinerParty, &joinerPuk, joinerRole, admin)
}

func runRemoteJoinSequenceForTeam(
	t *testing.T,
	m shared.MetaContext,
	targetTeam *teamObj,
	joiningTeam *teamObj,
	targetTeamAdmin *TestUser,
	joiningTeamAdmin *TestUser,
	srcRole proto.Role,
	dstRole proto.Role,
) proto.PermissionToken {

	isLocal := targetTeam.host.Eq(joiningTeam.host)
	memRole := joiningTeam.toMemberRoleWithLocalFlag(t, srcRole, dstRole, isLocal)
	srcRoleKey, err := core.ImportRole(srcRole)
	require.NoError(t, err)
	ptk := joiningTeam.ptks[*srcRoleKey]
	joinerParty := joiningTeam.FQTeam(t).FQParty()

	grant := func(ctx context.Context) proto.PermissionToken {
		payload := rem.GrantRemoteViewPermissionPayload{
			Viewee: joinerParty.Party,
			Viewer: targetTeam.FQTeam(t).FQParty(),
			Tm:     proto.Now(),
		}
		sig, err := ptk.Sign(&payload)
		require.NoError(t, err)
		sksig := rem.SharedKeySig{
			Role: srcRole,
			Gen:  ptk.Metadata().Gen,
			Sig:  *sig,
		}
		arg := rem.GrantRemoteViewPermissionForTeamArg{
			P:   payload,
			Sig: sksig,
		}
		tcli, closer := joiningTeamAdmin.newTeamMemberClient(t, m.Ctx())
		defer closer()
		vtok, err := tcli.GrantRemoteViewPermissionForTeam(m.Ctx(), arg)
		require.NoError(t, err)
		return vtok
	}

	// this map has the HEPKs for the joiningTeam, needed in runRemoteJoinSequence
	hepks := joiningTeam.hepks

	return runRemoteJoinSequence(t, m, hepks, targetTeam, grant, joinerParty, ptk, memRole, targetTeamAdmin)
}

func runRemoteJoinSequence(
	t *testing.T,
	m shared.MetaContext,
	hepks *core.HEPKSet,
	tm *teamObj,
	doGrant func(context.Context) proto.PermissionToken,
	joinerParty proto.FQParty,
	joinerPuk core.SharedPrivateSuiter,
	joinerRole proto.MemberRole,
	admin *TestUser,
) proto.PermissionToken {

	ptk := tm.ptks[core.AdminRole]
	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	teamBearerTok := makeTeamBearerToken(t, admin, tm, core.OwnerRole)
	tcli, closer := admin.newTeamAdminClient(t, m.Ctx())
	defer closer()
	err = tcli.PutTeamCert(m.Ctx(), rem.PutTeamCertArg{
		Tok:  teamBearerTok,
		Cert: *cert,
	})
	require.NoError(t, err)

	var certHash proto.TeamCertHash
	err = core.PrefixedHashInto(cert, certHash[:])
	require.NoError(t, err)

	vtok := doGrant(m.Ctx())
	invite := proto.NewTeamInviteWithV1(proto.TeamInviteV1{
		Hsh:  certHash,
		Host: tm.host,
	})

	rjrp := rem.TeamRemoteJoinReqPayload{
		Joiner: joinerParty,
		Tok:    vtok,
		Tm:     proto.Now(),
	}
	spsboxer, err := core.PublicizeToSPSBoxer(ptk, admin.FQUser().FQParty())
	require.NoError(t, err)
	box, err := joinerPuk.BoxFor(&rjrp, spsboxer, core.BoxOpts{IncludePublicKey: true})
	require.NoError(t, err)

	jr := rem.TeamRemoteJoinReq{
		Box:    *box,
		HepkFp: spsboxer.HepkFp,
	}
	jgcli, jcloser := admin.newTeamGuestClient(t, m.Ctx())
	defer jcloser()
	jrtok, err := jgcli.AcceptInviteRemote(m.Ctx(), rem.AcceptInviteRemoteArg{
		Jr: jr,
		I:  invite,
	})
	require.NoError(t, err)

	vtbp := proto.TeamRemoteMemberViewTokenBoxPayload{
		Tok:   vtok,
		Tm:    proto.Now(),
		Party: joinerParty,
	}
	skey := ptk.SecretBoxKey()
	sbox, err := core.SealIntoSecretBox(&vtbp, &skey)
	require.NoError(t, err)
	trmvt := proto.TeamRemoteMemberViewToken{
		Team: tm.FQTeam(t).Team,
		Inner: proto.TeamRemoteMemberViewTokenInner{
			Member:    joinerParty,
			PtkGen:    ptk.Metadata().Gen,
			SecretBox: *sbox,
		},
		Jrt: jrtok,
	}

	tm.absorb(hepks)

	tm.makeChanges(
		t,
		m,
		admin,
		[]proto.MemberRole{joinerRole},
		[]proto.TeamRemoteMemberViewToken{trmvt},
	)
	return vtok
}

func runLocalJoinSequenceForTeam(
	t *testing.T,
	m shared.MetaContext,
	targetTeam *teamObj,
	joiningTeam *teamObj,
	targetTeamAdmin *TestUser,
	joiningTeamAdmin *TestUser,
	srcRole proto.Role,
	dstRole proto.Role,
) {

	membRole := joiningTeam.toMemberRole(t, srcRole, dstRole)
	accept := func(ctx context.Context, invite proto.TeamInvite) {

		rk, err := core.ImportRole(srcRole)
		require.NoError(t, err)
		tok := makeTeamBearerToken(t, joiningTeamAdmin, joiningTeam, *rk)

		ptk := joiningTeam.ptks[core.AdminRole]
		require.NotNil(t, ptk)

		lh, garg := acceptedInviteMembershipLink(t, m,
			joiningTeam.FQTeam(t).FQParty(),
			ptk,
			targetTeam.FQTeam(t),
			joiningTeam.membChainSeqno,
			joiningTeam.membChainPrev,
			srcRole,
		)

		cli, closer := joiningTeamAdmin.newTeamMemberClient(t, m.Ctx())
		defer closer()
		_, err = cli.AcceptInviteLocal(m.Ctx(), rem.AcceptInviteLocalArg{
			I:                  invite,
			SrcRole:            srcRole,
			Tok:                &tok,
			TeamMembershipLink: &garg,
		})
		require.NoError(t, err)
		joiningTeam.membChainSeqno++
		joiningTeam.membChainPrev = &lh
	}
	runLocalJoinSequence(t, m, joiningTeam.hepks, targetTeam, accept, membRole, targetTeamAdmin, dstRole, nil)
}

func acceptedInviteMembershipLink(
	t *testing.T,
	m shared.MetaContext,
	joiner proto.FQParty,
	signer core.PrivateSuiter,
	joining proto.FQTeam,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	srcRole proto.Role,
) (
	proto.LinkHash,
	rem.PostGenericLinkArg,
) {
	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    joining,
			SrcRole: srcRole,
			State: proto.NewTeamMembershipDetailsDefault(
				proto.TeamMembershipLinkState_Requested,
			),
		},
	)
	tr := getCurrentTreeRootWithHostID(t, m, &joiner.Host)
	glink, err := core.MakeGenericLink(
		joiner.Party.EntityID(),
		joiner.Host,
		signer,
		glp,
		seqno,
		prev,
		tr,
	)
	require.NoError(t, err)
	var ret proto.LinkHash
	err = core.LinkHashInto(glink.Link, ret[:])
	require.NoError(t, err)
	return ret, rem.PostGenericLinkArg{
		Link:             *glink.Link,
		NextTreeLocation: *glink.NextTreeLocation,
	}
}

type localJoinHooks struct {
	preTeamEdit func()
}

func runLocalJoinSequenceForUser(
	t *testing.T,
	m shared.MetaContext,
	tm *teamObj,
	admin *TestUser,
	joiner *TestUser,
	dstRole proto.Role,
	hooks *localJoinHooks,
) {
	hepks := core.NewHEPKSet()
	srcRole := proto.OwnerRole
	membRole := joiner.toMemberRole(t, dstRole, hepks)
	accept := func(ctx context.Context, invite proto.TeamInvite) {
		cli, closer := joiner.newTeamMemberClient(t, m.Ctx())
		defer closer()
		devKey := joiner.eldest
		lh, garg := acceptedInviteMembershipLink(t, m,
			joiner.FQUser().FQParty(),
			devKey,
			tm.FQTeam(t),
			joiner.teamMembSeqno,
			joiner.teamMembPrev,
			srcRole,
		)
		_, err := cli.AcceptInviteLocal(m.Ctx(), rem.AcceptInviteLocalArg{
			I:                  invite,
			SrcRole:            srcRole,
			TeamMembershipLink: &garg,
		})
		require.NoError(t, err)
		joiner.teamMembSeqno++
		joiner.teamMembPrev = &lh
	}
	runLocalJoinSequence(t, m, hepks, tm, accept, membRole, admin, dstRole, hooks)
}

func runLocalJoinSequence(
	t *testing.T,
	m shared.MetaContext,
	hepks *core.HEPKSet,
	tm *teamObj,
	accept func(context.Context, proto.TeamInvite),
	joinerRole proto.MemberRole,
	admin *TestUser,
	role proto.Role,
	hooks *localJoinHooks,
) {
	ptk := tm.ptks[core.AdminRole]
	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	teamBearerTok := makeTeamBearerToken(t, admin, tm, core.OwnerRole)
	tcli, closer := admin.newTeamAdminClient(t, m.Ctx())
	defer closer()
	err = tcli.PutTeamCert(m.Ctx(), rem.PutTeamCertArg{
		Tok:  teamBearerTok,
		Cert: *cert,
	})
	require.NoError(t, err)

	var certHash proto.TeamCertHash
	err = core.PrefixedHashInto(cert, certHash[:])
	require.NoError(t, err)
	i1 := proto.TeamInviteV1{
		Hsh:  certHash,
		Host: tm.host,
	}
	invite := proto.NewTeamInviteWithV1(i1)
	accept(m.Ctx(), invite)

	if hooks != nil && hooks.preTeamEdit != nil {
		hooks.preTeamEdit()
	}

	tm.absorb(hepks)

	tm.makeChanges(
		t,
		m,
		admin,
		[]proto.MemberRole{joinerRole},
		nil,
	)
}
