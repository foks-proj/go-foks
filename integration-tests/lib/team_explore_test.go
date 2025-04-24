// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestTeamMembershipMinderExplore(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)

	m := tew.MetaContext()
	tew.DirectMerklePokeForLeafCheck(t)

	// t0 is a local team on bluey's host
	t0 := tew.makeTeamForOwner(t, bluey)
	t0.setIndexRange(t, m, bluey, index0)
	t0.makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			bingo.toMemberRole(t, proto.AdminRole, t0.hepks),
		},
		nil,
	)

	// t1 is another local team that t0 is a member of.
	t1 := tew.makeTeamForOwner(t, bluey)
	t1.setIndexRange(t, m, bluey, index1)

	t1.absorb(t0.hepks)
	t1.makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			t0.toMemberRole(t, proto.AdminRole, proto.AdminRole),
		},
		nil,
	)

	tew.DirectDoubleMerklePokeInTest(t)

	// Bluey posts that t0's chain shows that t0 is a member of t1.
	postTeamMembmershipLinkForTeam(t,
		bluey,
		m,
		t0, t1, t0.ptks[core.AdminRole],
		proto.ChainEldestSeqno,
		nil,
		proto.AdminRole,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  proto.AdminRole,
				Seqno: proto.Seqno(2),
			},
			KeyComm: t1.getRemovalKeyCommitment(t, t0.FQTeam(t).FQParty(), core.AdminRole),
		},
	)

	mem := proto.NewRoleWithMember(0)

	// t2 is a remote team on coco's host
	t2 := tew.makeTeamForOwner(t, coco)
	t2.setIndexRange(t, m, coco, index2)
	t2.absorb(t1.hepks)
	t2.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t1.toMemberRoleRemote(t, proto.AdminRole, mem),
		},
		nil,
	)

	// Bluey posts that t1's chain shows that t1 is a member of t2
	postTeamMembmershipLinkForTeam(t,
		bluey,
		m,
		t1, t2, t1.ptks[core.AdminRole],
		proto.ChainEldestSeqno,
		nil,
		proto.AdminRole,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  mem,
				Seqno: proto.Seqno(2),
			},
			KeyComm: t2.getRemovalKeyCommitment(t, t1.FQTeam(t).FQParty(), core.AdminRole),
		},
	)

	tew.DirectDoubleMerklePokeInTest(t)

	// Now complete a DAG, t0 becomes another member of t2
	t2.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t0.toMemberRoleRemote(t, proto.AdminRole, mem),
		},
		nil,
	)

	// Coco posts to t2's chain to show that t2 is a member of t0
	postTeamMembmershipLinkForTeam(t,
		coco,
		m,
		t2, t0, t2.ptks[core.AdminRole],
		proto.ChainEldestSeqno,
		nil,
		proto.AdminRole,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  mem,
				Seqno: proto.Seqno(2),
			},
			KeyComm: t2.getRemovalKeyCommitment(t, t0.FQTeam(t).FQParty(), core.AdminRole),
		},
	)

	// Now bingo tries to explore the team graph. He should
	// get to all 4 teams, and not wind up in a cycle. But note
	// he isn't taking an repair actions, since nothing is broken.
	// Going forward, repair actions are: (1) marking a user
	// removed from a team, and also rotating a PTK if needs be.
	mc := tew.NewClientMetaContext(t, bingo)
	au := mc.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	exstate, err := tmm.Explore(mc)
	require.NoError(t, err)

	allTeams := []*teamObj{t0, t1, t2}

	for _, tm := range allTeams {
		require.NotNil(t, exstate.Teams[tm.FQTeam(t)])
		require.True(t, exstate.Visisted[tm.FQTeam(t)])
	}
	require.Equal(t, 3, len(exstate.Visisted))
	require.Equal(t, 3, len(exstate.Teams))

	// remove t1 as a member of t2
	none := proto.NewRoleDefault(proto.RoleType_NONE)
	t2.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t1.toMemberRoleRemote(t, proto.AdminRole, none),
		},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	estate, err := tmm.Explore(mc)
	require.NoError(t, err)
	require.Equal(t, 1, len(estate.Warnings))
	wrn := estate.Warnings[t2.FQTeam(t)]
	require.NotNil(t, wrn)
	require.True(t, core.IsPermissionError(wrn.Err))

	tew.DirectDoubleMerklePokeInTest(t)
	estate, err = tmm.Explore(mc)
	require.NoError(t, err)
	require.Equal(t, 0, len(estate.Warnings))

}

func TestExactRolesInTeamGraphRemovals(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)
	use := func(a any) {}
	use(coco)

	m := tew.MetaContext()
	tew.DirectMerklePokeForLeafCheck(t)

	// t0 is a local team on bluey's host
	t0 := tew.makeTeamForOwner(t, bingo)
	t0.setIndexRange(t, m, bingo, index0)
	t0.makeChanges(
		t,
		m,
		bingo,
		[]proto.MemberRole{
			bluey.toMemberRole(t, proto.AdminRole, t0.hepks),
		},
		nil,
	)

	// Note we don't need to post to Bluey's chain that he's a member of t0
	// because it's done automtically in the call to Explore (later on).

	tew.DirectDoubleMerklePokeInTest(t)

	mem := proto.NewRoleWithMember(0)
	memRk, err := core.ImportRole(mem)
	require.NoError(t, err)
	bot := proto.NewRoleWithMember(-10)

	// t2 is a remote team on coco's host
	t1 := tew.makeTeamForOwner(t, coco)
	t1.setIndexRange(t, m, coco, index1)
	t1.absorb(t0.hepks)
	t1.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t0.toMemberRoleRemote(t, mem, bot),
		},
		nil,
	)

	// Bingo posts that t0 is now a member of t1.
	postTeamMembmershipLinkForTeam(t,
		bingo,
		m,
		t0, t1, t0.ptks[core.OwnerRole],
		proto.ChainEldestSeqno,
		nil,
		mem,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  bot,
				Seqno: proto.Seqno(1),
			},
			KeyComm: t1.getRemovalKeyCommitment(t, t0.FQTeam(t).FQParty(), *memRk),
		},
	)

	tew.DirectDoubleMerklePokeInTest(t)

	// Now bluey tries to explore the team graph. He should get to both teams
	mc := tew.NewClientMetaContext(t, bluey)
	au := mc.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	exstate, err := tmm.Explore(mc)
	require.NoError(t, err)

	checkTeams := func(state *libclient.ExploreState, teams []*teamObj, visitTeams []*teamObj) {
		if visitTeams == nil {
			visitTeams = teams
		}
		for _, tm := range teams {
			require.NotNil(t, state.Teams[tm.FQTeam(t)])
		}
		for _, tm := range visitTeams {
			require.True(t, state.Visisted[tm.FQTeam(t)])
		}
		require.Equal(t, len(visitTeams), len(exstate.Visisted))
		require.Equal(t, len(teams), len(exstate.Teams))
	}
	checkTeams(exstate, []*teamObj{t0, t1}, nil)

	// remove t0 as a member of t1
	none := proto.NewRoleDefault(proto.RoleType_NONE)
	t1.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t0.toMemberRoleRemote(t, mem, none),
		},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	exstate, err = tmm.Explore(mc)
	require.NoError(t, err)
	require.Equal(t, 1, len(exstate.Warnings))
	wrn := exstate.Warnings[t1.FQTeam(t)]
	require.NotNil(t, wrn)
	require.True(t, core.IsPermissionError(wrn.Err))
	// in this intermediary state, we visited t1 but it's not considered a team
	// since we failed to load it. Hence we need both team lists passed to
	// checkTeams.
	checkTeams(exstate, []*teamObj{t0}, []*teamObj{t0, t1})

	tew.DirectDoubleMerklePokeInTest(t)
	exstate, err = tmm.Explore(mc)
	require.NoError(t, err)
	require.Equal(t, 0, len(exstate.Warnings))
	checkTeams(exstate, []*teamObj{t0}, nil)
}

func TestTeamFixViaUpgrade(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)

	tew.DirectMerklePokeForLeafCheck(t)

	// t0 is a local team on bluey's host
	t0 := tew.makeTeamForOwner(t, bluey)
	fqt := t0.FQTeam(t)
	tew.DirectMerklePokeForLeafCheck(t)

	m := tew.MetaContext()
	mc := tew.NewClientMetaContext(t, bingo)
	au := mc.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)

	runLocalJoinSequenceForUser(t, m, t0, bluey, bingo, proto.AdminRole,
		&localJoinHooks{
			preTeamEdit: func() {
				tew.DirectMerklePokeInTest(t)
				estate, err := tmm.Explore(mc)
				require.NoError(t, err)
				require.NotNil(t, estate)
				require.Equal(t, 0, len(estate.Teams))
				require.Equal(t, 1, len(estate.Warnings))
				w := estate.Warnings[fqt]
				require.NotNil(t, w)
				require.Equal(t,
					core.PermissionError("team member permission failed (vo bearer token)"),
					w.Err,
				)
				require.False(t, w.Node.Details.Approved)
			},
		},
	)
	tew.DirectMerklePokeInTest(t)
	estate, err := tmm.Explore(mc)
	require.NoError(t, err)
	require.NotNil(t, estate)
	require.Equal(t, 1, len(estate.Teams))
	require.Equal(t, 0, len(estate.Warnings))
	tm := estate.Teams[fqt]
	require.NotNil(t, tm)
}
