// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestTeamMembershipLoader(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	nirvana := tew.NewTestUserOpts(t, nil)
	joey := tew.NewTestUser(t)
	billy := tew.NewTestUser(t)
	coco := tew.NewTestUser(t)
	tew.DirectMerklePokeForLeafCheck(t)

	var teams []*teamObj
	m := tew.MetaContext()
	indices := []core.RationalRange{index3, index2, index1}
	for i := 0; i < 3; i++ {
		team := tew.makeTeamForOwner(t, nirvana)
		team.setIndexRange(t, m, nirvana, indices[i])
		teams = append(teams, team)
	}
	tew.DirectDoubleMerklePokeInTest(t)

	teams[2].makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{
			coco.toMemberRole(t, proto.AdminRole, teams[2].hepks),
		},
		nil,
	)
	none := proto.NewRoleDefault(proto.RoleType_NONE)
	memb := proto.NewRoleWithMember(0)

	teams[1].absorb(teams[2].hepks)
	teams[1].makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{
			joey.toMemberRole(t, proto.AdminRole, teams[1].hepks),
			billy.toMemberRole(t, proto.AdminRole, teams[1].hepks),
			teams[2].toMemberRole(t, proto.AdminRole, memb),
		},
		nil,
	)

	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, nirvana)
	nirvanaTML, err := libclient.NewTMLUser(mc, proto.OwnerRole)
	require.NoError(t, err)
	w, err := libclient.LoadTeamMembership(mc, nirvanaTML)
	require.NoError(t, err)
	require.NotNil(t, w)

	// force a rotation of teams[1]
	teams[1].makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{
			joey.toMemberRole(t, none, nil),
		},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	// teams1 is added a member to team0
	teams[0].absorb(teams[1].hepks)
	teams[0].makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{
			teams[1].toMemberRole(t, proto.AdminRole, memb),
		},
		nil,
	)

	// It should now show up in team1's membership chain that it's a member of team0
	mlres := makeTeamMembershipLinkFull(t, m, teams[1], teams[0], teams[1].ptks[core.AdminRole],
		proto.ChainEldestSeqno,
		nil,
		proto.AdminRole,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  memb,
				Seqno: proto.ChainEldestSeqno,
			},
		},
	)
	require.NotNil(t, mlres)

	tcli, closer := nirvana.newTeamAdminClient(t, m.Ctx())
	defer closer()

	tok := makeTeamBearerToken(t, nirvana, teams[1], core.AdminRole)
	err = tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok: tok,
		Link: rem.PostGenericLinkArg{
			Link:             *mlres.Link,
			NextTreeLocation: *mlres.NextTreeLocation,
		},
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	// force another rotation of teams[1]
	teams[1].makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{
			billy.toMemberRole(t, none, nil),
		},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	tmlt, err := libclient.NewTMLTeam(mc, libclient.LoadTeamArg{
		Team:    teams[1].FQTeam(t),
		As:      nirvana.FQUser().FQParty(),
		SrcRole: proto.OwnerRole,
		Keys:    nirvana.KeySeq(t, proto.OwnerRole),
	}, proto.OwnerRole)
	require.NoError(t, err)
	require.NotNil(t, tmlt)

	w, err = libclient.LoadTeamMembership(mc, tmlt)
	require.NoError(t, err)
	require.NotNil(t, w)

	typ, err := w.Prot.Payload.GetT()
	require.NoError(t, err)
	require.Equal(t, proto.ChainType_TeamMembership, typ)
	tm := w.Prot.Payload.Teammembership()
	require.Equal(t, 1, len(tm.Teams))
	require.Equal(t, proto.TeamMembershipLinkState_Approved, tm.Teams[0].State.T)
	require.Equal(t, teams[0].FQTeam(t), tm.Teams[0].Team)
	require.Equal(t, proto.AdminRole, tm.Teams[0].SrcRole)
	require.Equal(t, memb, tm.Teams[0].State.Approved().Dst.Role)

	// coco is going to lead the membership chain of team[1] via team[2]
	_, t2w, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
		Team:    teams[2].FQTeam(t),
		As:      coco.FQUser().FQParty(),
		Keys:    coco.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, t2w)

	sched := t2w.KeyRing().KeysForRole(core.AdminRole)
	require.NotNil(t, sched)

	tmlt2, err := libclient.NewTMLTeam(mc, libclient.LoadTeamArg{
		Team:    teams[1].FQTeam(t),
		As:      teams[2].FQTeam(t).FQParty(),
		SrcRole: proto.AdminRole,
		Keys:    sched,
	}, proto.OwnerRole)
	require.NoError(t, err)
	require.NotNil(t, tmlt2)

	// Make sure this loading style gets the same data as the prior style.
	w2, err := libclient.LoadTeamMembership(mc, tmlt2)
	require.NoError(t, err)
	require.Equal(t, w, w2)
}

func TestTeamMembershipMinder(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	socks := tew.NewTestUser(t)

	tew.DirectMerklePokeForLeafCheck(t)
	var teams []*teamObj
	for i := 0; i < 2; i++ {
		tm := tew.makeTeamForOwner(t, bluey)
		teams = append(teams, tm)
	}

	m := tew.MetaContext()
	tew.DirectDoubleMerklePokeInTest(t)

	memb := proto.NewRoleWithMember(0)

	teams[0].makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			bingo.toMemberRole(t, proto.AdminRole, teams[0].hepks),
		},
		nil,
	)

	teams[1].makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			socks.toMemberRole(t, memb, teams[1].hepks),
		},
		nil,
	)

	tew.DirectDoubleMerklePokeInTest(t)

	teams[0].makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			socks.toMemberRole(t, proto.AdminRole, teams[0].hepks),
		},
		nil,
	)

	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, socks)
	au := mc.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	_, err := tmm.Explore(mc)
	require.NoError(t, err)

	var key libclient.FQTeamSrcRole
	err = key.Import(
		teams[0].FQTeam(t),
		proto.OwnerRole,
	)
	require.NoError(t, err)
	l0, found := tmm.UserTMW().Wrapper.Map[key]
	require.True(t, found)
	require.Equal(t, proto.TeamMembershipLinkState_Approved, l0.State.T)
	require.Equal(t, proto.OwnerRole, l0.SrcRole)
	require.Equal(t, proto.AdminRole, l0.State.Approved().Dst.Role)
	require.Equal(t, proto.Seqno(3), l0.State.Approved().Dst.Seqno)

	err = key.Import(
		teams[1].FQTeam(t),
		proto.OwnerRole,
	)
	require.NoError(t, err)
	l1, found := tmm.UserTMW().Wrapper.Map[key]
	require.True(t, found)
	require.Equal(t, proto.TeamMembershipLinkState_Approved, l1.State.T)
	require.Equal(t, proto.OwnerRole, l1.SrcRole)
	require.Equal(t, memb, l1.State.Approved().Dst.Role)
	require.Equal(t, proto.Seqno(2), l1.State.Approved().Dst.Seqno)
}

func postTeamMembmershipLinkForTeam(
	t *testing.T,
	user *TestUser,
	m shared.MetaContext,
	src *teamObj,
	dst *teamObj,
	ptk core.SharedPrivateSuiter,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	srcRole proto.Role,
	deets proto.TeamMembershipApprovedDetails,
) {
	tok := makeTeamBearerToken(t, user, src, core.AdminRole)
	require.NotNil(t, tok)
	mlres := makeTeamMembershipLinkFull(t, m, src, dst, ptk, seqno, prev, srcRole, deets)
	tcli, tcloser := user.newTeamAdminClient(t, m.Ctx())
	defer tcloser()
	err := tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok: tok,
		Link: rem.PostGenericLinkArg{
			Link:             *mlres.Link,
			NextTreeLocation: *mlres.NextTreeLocation,
		},
	})
	require.NoError(t, err)
}
