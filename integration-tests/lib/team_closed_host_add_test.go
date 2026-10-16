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
	"github.com/stretchr/testify/require"
)

// TeamMinder.Add on a host with closed user viewership (the test
// environment's default). The new member first grants the team a local view
// permission on their user; an admin then adds them by UID, and the
// TeamMinder loads their chain on the team's behalf. This is step 7 of the
// social signup flow on a closed host (docs/social_signup_spec.md).

type closedHostTeam struct {
	tew   *TestEnvWrapper
	alice *TestUser
	tm    *teamObj
	tid   proto.TeamID
}

func newClosedHostTeam(t *testing.T) *closedHostTeam {
	tew := testEnvBeta(t)
	alice := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	return &closedHostTeam{tew: tew, alice: alice, tm: tm, tid: tid}
}

// newUser makes a user who, if grant is set, grants the team a local view
// permission on themself.
func (c *closedHostTeam) newUser(t *testing.T, grant bool) *TestUser {
	u := c.tew.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
	c.tew.DirectDoubleMerklePokeInTest(t)
	if grant {
		cli := c.tew.userCli(t, u)
		_, err := cli.GrantLocalViewPermissionForUser(
			c.tew.MetaContext().Ctx(),
			rem.GrantLocalViewPermissionPayload{
				Viewee: u.uid.ToPartyID(),
				Viewer: c.tid.ToPartyID(),
			},
		)
		require.NoError(t, err)
	}
	return u
}

func (c *closedHostTeam) add(t *testing.T, member lcl.FQPartyParsedAndRole) error {
	mc := c.tew.NewClientMetaContext(t, c.alice)
	tmind, err := mc.TeamMinder()
	require.NoError(t, err)
	err = tmind.Add(mc, lcl.TeamAddArg{
		Team:    *c.tm.ToFQTeamParsed(t),
		Members: []lcl.FQPartyParsedAndRole{member},
	})
	if err == nil {
		c.tew.DirectDoubleMerklePokeInTest(t)
	}
	return err
}

func byUID(u *TestUser) lcl.FQPartyParsedAndRole {
	return lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithFalse(u.uid.ToPartyID()),
		},
	}
}

// memberMinder returns u's TeamMinder with the merkle poke hook that lets
// ListMemberships post u's membership-chain link.
func memberMinder(t *testing.T, tew *TestEnvWrapper, u *TestUser) (libclient.MetaContext, *libclient.TeamMinder) {
	mc := tew.NewClientMetaContext(t, u)
	tm, err := mc.G().TeamMinder()
	require.NoError(t, err)
	tm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	return mc, tm
}

func TestTeamClosedHostAddByUID(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	require.NoError(t, c.add(t, byUID(bob)))

	mc, tm := memberMinder(t, c.tew, bob)
	membs, err := tm.ListMemberships(mc, nil)
	require.NoError(t, err)
	require.Len(t, membs.Teams, 1)
	require.Equal(t, c.tm.nm, membs.Teams[0].Team.Name)
	require.Equal(t, proto.DefaultRole, membs.Teams[0].DstRole)

	chain, err := tm.DumpMembershipChain(mc)
	require.NoError(t, err)
	found := false
	for _, e := range chain {
		if e.Team.Team.Eq(c.tid) {
			found = true
		}
	}
	require.True(t, found, "team not in the new member's membership chain")
}

// Naming the team's own host alongside the UID is still a local add.
func TestTeamClosedHostAddByUIDAtLocalHost(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	host := proto.NewParsedHostnameWithFalse(c.alice.host)
	require.NoError(t, c.add(t, lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithFalse(bob.uid.ToPartyID()),
			Host:  &host,
		},
	}))
}

func TestTeamClosedHostAddOtherHostRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	other := c.tew.VHostMakeI(t, 4)
	host := proto.NewParsedHostnameWithFalse(other.HostID.Id)
	err := c.add(t, lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithFalse(bob.uid.ToPartyID()),
			Host:  &host,
		},
	})
	require.Error(t, err)
	require.IsType(t, core.HostMismatchError{}, err)
}

func TestTeamClosedHostAddNeedsGrant(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, false)
	err := c.add(t, byUID(bob))
	require.Error(t, err)
	var cle core.ChainLoaderError
	require.ErrorAs(t, err, &cle)
	require.ErrorIs(t, cle.Err, core.PermissionError("no view permission"))
}

// Loading a team on a closed host loads every member on the team's behalf, so
// an ordinary member other than the admin must be able to load the new member
// through the grant the new member made.
func TestTeamClosedHostOtherMemberLoadsRoster(t *testing.T) {
	c := newClosedHostTeam(t)
	carol := c.newUser(t, true)
	require.NoError(t, c.add(t, byUID(carol)))
	bob := c.newUser(t, true)
	require.NoError(t, c.add(t, byUID(bob)))

	mc, tm := memberMinder(t, c.tew, carol)
	_, err := tm.ListMemberships(mc, nil)
	require.NoError(t, err)
	tr, err := tm.LoadTeamWithFQTeam(
		mc,
		proto.FQTeam{Team: c.tid, Host: c.alice.host},
		libclient.LoadTeamOpts{Refresh: true, Members: libclient.MemberLoadFull},
	)
	require.NoError(t, err)
	require.NotNil(t, tr)
}

// Closed viewership refuses username resolution, so users must be named by UID.
func TestTeamClosedHostAddByNameRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	err := c.add(t, toFQParsedPartyAndRole(bob))
	require.Error(t, err)
	require.IsType(t, core.BadArgsError(""), err)
}

// Adding a team as a member still needs open viewership.
func TestTeamClosedHostAddTeamRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	sub := c.tew.makeTeamForOwner(t, c.alice)
	c.tew.DirectDoubleMerklePokeInTest(t)
	subID, err := sub.id.ToTeamID()
	require.NoError(t, err)
	err = c.add(t, lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithFalse(subID.ToPartyID()),
		},
	})
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)
}

// Re-adding a member must not silently rewrite their membership at the
// default role (which would demote an admin or owner).
func TestTeamClosedHostReAddRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	require.NoError(t, c.add(t, byUID(bob)))
	err := c.add(t, byUID(bob))
	require.Error(t, err)
	require.IsType(t, core.TeamRosterError(""), err)
}

func TestTeamOpenHostReAddRefused(t *testing.T) {
	tew := testEnvBeta(t)
	vhost := tew.openVHost(t)
	alice := tew.NewTestUserAtVHost(t, vhost)
	bob := tew.NewTestUserAtVHost(t, vhost)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, alice)
	tmind, err := mc.TeamMinder()
	require.NoError(t, err)
	arg := lcl.TeamAddArg{
		Team:    *tm.ToFQTeamParsed(t),
		Members: []lcl.FQPartyParsedAndRole{toFQParsedPartyAndRole(bob)},
	}
	require.NoError(t, tmind.Add(mc, arg))
	tew.DirectDoubleMerklePokeInTest(t)
	err = tmind.Add(mc, arg)
	require.Error(t, err)
	require.IsType(t, core.TeamRosterError(""), err)
}
