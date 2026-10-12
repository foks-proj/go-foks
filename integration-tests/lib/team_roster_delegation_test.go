// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// Flip the host's roster_delegation switch. The config object is shared with
// the in-process servers, which read it per request, so the change is live.
func setRosterDelegation(t *testing.T, tew *TestEnvWrapper, on bool) {
	cfg, ok := tew.MetaContext().G().Config().(*shared.ConfigJSonnet)
	require.True(t, ok)
	cfg.Lock()
	defer cfg.Unlock()
	if cfg.Data.Team == nil {
		cfg.Data.Team = &shared.TeamConfigJSON{}
	}
	cfg.Data.Team.RosterDelegation_ = on
}

func (tm *teamObj) setDelegationFloor(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	floor proto.Role,
	mr []proto.MemberRole,
) error {
	_, err := tm.makeChangesFull(t, m, u, mr, nil, makeChangesKnobs{
		md: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithRosterdelegationfloor(floor),
		},
	})
	return err
}

func loadDelegationFloorFromDB(
	t *testing.T,
	tew *TestEnvWrapper,
	tm *teamObj,
) *proto.Role {
	m := tew.MetaContext()
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	tmid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	flr, err := shared.LoadRosterDelegationFloor(m, db, tmid)
	require.NoError(t, err)
	return flr
}

func TestRosterDelegationFloorSetLoadAndClear(t *testing.T) {
	tew := testEnvBeta(t)
	setRosterDelegation(t, tew, true)
	owner := tew.NewTestUser(t)
	stew := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, owner)
	m := tew.MetaContext()

	floor := proto.NewRoleWithMember(100)

	// The floor role needs a PTK after the link, so grant m/100 in the
	// same link that sets the floor: the shape a team uses to appoint its
	// first delegate.
	err := tm.setDelegationFloor(t, m, owner, floor, []proto.MemberRole{
		stew.toMemberRole(t, floor, tm.hepks),
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	// The server stored it.
	stored := loadDelegationFloorFromDB(t, tew, tm)
	require.NotNil(t, stored)
	rk, err := team.RosterDelegationFloorActive(stored)
	require.NoError(t, err)
	require.NotNil(t, rk)
	require.True(t, rk.Eq(core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: 100}))

	// A client replaying the chain sees it.
	mc := tew.NewClientMetaContext(t, owner)
	load := func() *libclient.TeamWrapper {
		wrp, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
			Team:    tm.FQTeam(t),
			As:      owner.FQUser().FQParty(),
			Keys:    owner.KeySeq(t, proto.OwnerRole),
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
		return wrp
	}
	wrp := load()
	require.NotNil(t, wrp.RosterDelegationFloor())
	rk, err = team.RosterDelegationFloorActive(wrp.RosterDelegationFloor())
	require.NoError(t, err)
	require.NotNil(t, rk)
	require.True(t, rk.Eq(core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: 100}))

	// NONE clears it; the client sees the clear on an incremental reload of
	// the same cached chain state.
	err = tm.setDelegationFloor(t, m, owner, proto.NewRoleDefault(proto.RoleType_NONE), nil)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	stored = loadDelegationFloorFromDB(t, tew, tm)
	require.NotNil(t, stored)
	rk, err = team.RosterDelegationFloorActive(stored)
	require.NoError(t, err)
	require.Nil(t, rk)

	wrp = load()
	rk, err = team.RosterDelegationFloorActive(wrp.RosterDelegationFloor())
	require.NoError(t, err)
	require.Nil(t, rk)
}

func TestRosterDelegationFloorRefusals(t *testing.T) {
	tew := testEnvBeta(t)
	setRosterDelegation(t, tew, true)
	owner := tew.NewTestUser(t)
	stew := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, owner)
	m := tew.MetaContext()
	memberFloor := func(v proto.VizLevel) proto.Role { return proto.NewRoleWithMember(v) }

	// Illegal values: refused at link-open time, whoever signs.
	for _, bad := range []proto.Role{
		memberFloor(0),
		memberFloor(-5),
		proto.NewRoleDefault(proto.RoleType_ADMIN),
		proto.NewRoleDefault(proto.RoleType_OWNER),
	} {
		err := tm.setDelegationFloor(t, m, owner, bad, nil)
		require.Error(t, err)
	}

	// Two floor entries in one link.
	_, err := tm.makeChangesFull(t, m, owner, nil, nil, makeChangesKnobs{
		md: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithRosterdelegationfloor(memberFloor(100)),
			proto.NewChangeMetadataWithRosterdelegationfloor(memberFloor(101)),
		},
	})
	require.Error(t, err)

	// A floor whose role has no PTK: nobody could ever act at it.
	err = tm.setDelegationFloor(t, m, owner, memberFloor(50), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "no PTK")

	// Nothing was stored by any refused attempt.
	require.Nil(t, loadDelegationFloorFromDB(t, tew, tm))

	// With the host switch off, even a well-formed link is refused.
	setRosterDelegation(t, tew, false)
	err = tm.setDelegationFloor(t, m, owner, memberFloor(100), []proto.MemberRole{
		stew.toMemberRole(t, memberFloor(100), tm.hepks),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "not enabled")
	require.Nil(t, loadDelegationFloorFromDB(t, tew, tm))
}

// A link that carries a metadata type this build does not know must still be
// accepted by the server and replayed by the client: that is what lets teams
// adopt new link metadata (such as the delegation floor) without stranding
// every client built before it.
func TestTeamLinkUnknownMetadataTypeIgnored(t *testing.T) {
	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, owner)
	m := tew.MetaContext()

	_, err := tm.makeChangesFull(t, m, owner, nil, nil, makeChangesKnobs{
		md: []proto.ChangeMetadata{
			{T: proto.ChangeType(99)},
			proto.NewChangeMetadataWithTeamindexrange(index0.Export()),
		},
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, owner)
	wrp, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:    tm.FQTeam(t),
		As:      owner.FQUser().FQParty(),
		Keys:    owner.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, wrp)
}

// A client from before the floor skips the floor-setting link's metadata
// and saves its chain state with no floor. Once that device upgrades, the
// loader must not resume from that state, or it reports delegation as off
// until the floor next changes; it replays from scratch and re-saves.
func TestPreFloorCachedStateIsReplayed(t *testing.T) {
	tew := testEnvBeta(t)
	setRosterDelegation(t, tew, true)
	owner := tew.NewTestUser(t)
	stew := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, owner)
	m := tew.MetaContext()

	floor := proto.NewRoleWithMember(100)
	err := tm.setDelegationFloor(t, m, owner, floor, []proto.MemberRole{
		stew.toMemberRole(t, floor, tm.hepks),
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	mco := tew.NewClientMetaContext(t, owner)
	arg := libclient.LoadTeamArg{
		Team:    tm.FQTeam(t),
		As:      owner.FQUser().FQParty(),
		Keys:    owner.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	}
	_, err = libclient.LoadTeam(mco, arg)
	require.NoError(t, err)

	// Rewrite the saved state the way a pre-floor client wrote it.
	scoper := mco.G().ActiveUser().FQU()
	var st lcl.TeamChainState
	_, err = mco.DbGet(&st, libclient.DbTypeSoft, &scoper, lcl.DataType_TeamChainState, arg)
	require.NoError(t, err)
	require.True(t, st.RosterDelegationFloorTracked)
	st.RosterDelegationFloor = nil
	st.RosterDelegationFloorTracked = false
	err = mco.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scoper,
		Typ:   lcl.DataType_TeamChainState,
		Val:   &st,
		Key:   arg,
	})
	require.NoError(t, err)

	wrp, err := libclient.LoadTeam(mco, arg)
	require.NoError(t, err)
	require.NotNil(t, wrp.RosterDelegationFloor(), "resumed from the pre-floor state")
	require.Equal(t, floor, *wrp.RosterDelegationFloor())

	st = lcl.TeamChainState{}
	_, err = mco.DbGet(&st, libclient.DbTypeSoft, &scoper, lcl.DataType_TeamChainState, arg)
	require.NoError(t, err)
	require.True(t, st.RosterDelegationFloorTracked)
	require.Equal(t, floor, *st.RosterDelegationFloor)
}
