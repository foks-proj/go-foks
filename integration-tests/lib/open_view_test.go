// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func toFQParsedPartyAndRole(u *TestUser) lcl.FQPartyParsedAndRole {
	return lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithTrue(
				proto.PartyName{
					IsTeam: false,
					Name:   u.name,
				},
			),
		},
	}
}

func TestOpenUserViewAndTeamAdd(t *testing.T) {
	tew := testEnvBeta(t)

	// #4 we'll reserve for making an "open vhost"
	vHostID := tew.VHostMakeI(t, 4)
	require.NotNil(t, vHostID)
	alice := tew.NewTestUserAtVHost(t, vHostID)
	bob := tew.NewTestUserAtVHost(t, vHostID)
	carole := tew.NewTestUserAtVHost(t, vHostID)
	debbie := tew.NewTestUserAtVHost(t, vHostID)
	tew.DirectDoubleMerklePokeInTest(t)

	acli := tew.userCli(t, alice)
	m := tew.MetaContext()
	arg := rem.LoadUserChainArg{
		Uid:   bob.uid,
		Auth:  rem.NewLoadUserChainAuthWithOpenvhost(),
		Start: proto.ChainEldestSeqno,
	}
	_, err := acli.LoadUserChain(m.Ctx(), arg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("no open viewership mode"), err)

	m = m.WithHostID(&vHostID.HostID)

	err = shared.VHostSetUserViewership(m, proto.ViewershipMode_OpenToAll)
	require.NoError(t, err)

	// don't forget to change it back so other tests don't fail
	defer func() {
		err = shared.VHostSetUserViewership(m, proto.ViewershipMode_Closed)
		require.NoError(t, err)
	}()
	_, err = acli.LoadUserChain(m.Ctx(), arg)
	require.NoError(t, err)

	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)

	_, err = tm.makeChangesFull(
		t,
		m,
		alice,
		[]proto.MemberRole{
			bob.toMemberRole(t, proto.AdminRole, tm.hepks),
		},
		nil,
		makeChangesKnobs{
			insLocalPermsFor: []proto.PartyID{bob.uid.ToPartyID()},
		},
	)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	// check permission got added to the table
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	rows, err := db.Query(m.Ctx(),
		`SELECT target_eid FROM local_view_permissions
		WHERE short_host_id = $1 AND viewer_eid = $2`,
		m.ShortHostID().ExportToDB(),
		tm.id.ExportToDB(),
	)
	require.NoError(t, err)
	defer rows.Close()
	found := make(map[proto.UID]struct{})
	for rows.Next() {
		var raw []byte
		err = rows.Scan(&raw)
		require.NoError(t, err)
		var uid proto.UID
		err = uid.ImportFromDB(raw)
		require.NoError(t, err)
		found[uid] = struct{}{}
	}
	require.Len(t, found, 2)
	require.Contains(t, found, alice.uid)
	require.Contains(t, found, bob.uid)

	// Check that we can load users via username lookup
	mc := tew.NewClientMetaContext(t, alice)
	uw, err := libclient.LoadUser(mc, libclient.LoadUserArg{
		ActiveUser: mc.G().ActiveUser(),
		Username:   bob.name,
		LoadMode:   libclient.LoadModeOpenOthers,
	})
	require.NoError(t, err)
	require.NotNil(t, uw)
	require.Equal(t, uw.ProtoWithMetadata().Fqu.Uid, bob.uid)

	tMinder, err := mc.TeamMinder()
	require.NoError(t, err)

	fqtp := tm.ToFQTeamParsed(t)

	err = tMinder.Add(mc, lcl.TeamAddArg{
		Team: *fqtp,
		Members: []lcl.FQPartyParsedAndRole{
			toFQParsedPartyAndRole(carole),
			toFQParsedPartyAndRole(debbie),
		},
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	mcDeb := tew.NewClientMetaContext(t, debbie)
	tmindDeb, err := mcDeb.G().TeamMinder()
	tmindDeb.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	require.NoError(t, err)
	membs, err := tmindDeb.ListMemberships(mcDeb)
	require.NoError(t, err)
	require.Len(t, membs.Teams, 1)
	require.Equal(t, membs.Teams[0].Team.Name, tm.nm)
	require.Equal(t, membs.Teams[0].SrcRole, proto.OwnerRole)
	require.Equal(t, membs.Teams[0].DstRole, proto.DefaultRole)
}

func TestOpenViewTeamList(t *testing.T) {
	tew := testEnvBeta(t)

	// #4 we'll reserve for making an "open vhost"
	vHostID := tew.VHostMakeI(t, 4)
	require.NotNil(t, vHostID)
	alice := tew.NewTestUserAtVHost(t, vHostID)
	bob := tew.NewTestUserAtVHost(t, vHostID)
	carole := tew.NewTestUserAtVHost(t, vHostID)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()
	m = m.WithHostID(&vHostID.HostID)
	err := shared.VHostSetUserViewership(m, proto.ViewershipMode_OpenToAll)
	require.NoError(t, err)

	// don't forget to change it back so other tests don't fail
	defer func() {
		err := shared.VHostSetUserViewership(m, proto.ViewershipMode_Closed)
		require.NoError(t, err)
	}()

	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)

	mca := tew.NewClientMetaContext(t, alice)
	tMinder, err := mca.TeamMinder()
	require.NoError(t, err)

	fqtp := tm.ToFQTeamParsed(t)

	doAdd := func(user *TestUser, role proto.Role) {
		err := tMinder.Add(mca, lcl.TeamAddArg{
			Team: *fqtp,
			Members: []lcl.FQPartyParsedAndRole{
				toFQParsedPartyAndRole(user),
			},
			DstRole: &role,
		})
		require.NoError(t, err)
		tew.DirectMerklePokeInTest(t)
	}
	doAdd(bob, proto.DefaultRole)
	caroleRole := proto.NewRoleWithMember(-4)
	doAdd(carole, caroleRole)

	testLoadFor := func(user *TestUser) {
		mc := tew.NewClientMetaContext(t, user)
		twr, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
			Team:        tm.FQTeam(t),
			As:          user.FQUser().FQParty(),
			SrcRole:     proto.OwnerRole,
			Keys:        user.KeySeq(t, proto.OwnerRole),
			LoadMembers: true,
		},
		)
		require.NoError(t, err)
		require.NotNil(t, twr)

		expected := map[proto.NameUtf8]struct {
			role proto.Role
			uid  proto.UID
		}{
			alice.name: {
				role: proto.OwnerRole,
				uid:  alice.uid,
			},
			bob.name: {
				role: proto.DefaultRole,
				uid:  bob.uid,
			},
			carole.name: {
				role: caroleRole,
				uid:  carole.uid,
			},
		}
		x, err := twr.ExportToRoster()
		require.NoError(t, err)
		require.Equal(t, len(expected), len(x.Members))
		for _, m := range x.Members {
			require.Greater(t, len(m.Mem.Name), 0, "member name should not be empty")
			e, ok := expected[m.Mem.Name]
			require.True(t, ok, "unexpected member %s", m.Mem.Name)
			require.Equal(t, e.role, m.DstRole)
			require.True(t, m.Mem.Fqp.Party.IsUser())
			uid, err := m.Mem.Fqp.Party.UID()
			require.NoError(t, err)
			require.Equal(t, e.uid, uid, "member %s has unexpected uid", m.Mem.Name)
		}
	}

	testLoadFor(bob)
	testLoadFor(alice)
	testLoadFor(carole)

}
