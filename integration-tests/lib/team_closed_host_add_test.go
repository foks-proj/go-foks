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
// permission on themself at the default role.
func (c *closedHostTeam) newUser(t *testing.T, grant bool) *TestUser {
	u := c.tew.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
	c.tew.DirectDoubleMerklePokeInTest(t)
	if grant {
		c.grant(t, u, nil)
	}
	return u
}

// grant gives the team a local view permission on u, usable by members at
// role or above (the default member-load floor if nil).
func (c *closedHostTeam) grant(t *testing.T, u *TestUser, role *proto.Role) {
	cli := c.tew.userCli(t, u)
	_, err := cli.GrantLocalViewPermissionForUser(
		c.tew.MetaContext().Ctx(),
		rem.GrantLocalViewPermissionPayload{
			Viewee:     u.uid.ToPartyID(),
			Viewer:     c.tid.ToPartyID(),
			ViewerRole: role,
		},
	)
	require.NoError(t, err)
}

func atHost(u *TestUser, host proto.ParsedHostname) lcl.FQPartyParsedAndRole {
	return lcl.FQPartyParsedAndRole{
		Fqp: proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithFalse(u.uid.ToPartyID()),
			Host:  &host,
		},
	}
}

func hostnameOnly(h proto.Hostname) proto.ParsedHostname {
	return proto.NewParsedHostnameWithTrue(proto.NewTCPAddrPortOpt(h, nil))
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

// Naming the team's own host alongside the UID, by host ID or by hostname, is
// still a local add.
func TestTeamClosedHostAddByUIDAtLocalHost(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	require.NoError(t, c.add(t, atHost(bob, proto.NewParsedHostnameWithFalse(c.alice.host))))
	dave := c.newUser(t, true)
	require.NoError(t, c.add(t, atHost(dave, hostnameOnly(c.tew.Hostname()))))
}

func TestTeamClosedHostAddOtherHostRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, true)
	other := c.tew.VHostMakeI(t, 4)
	for _, host := range []proto.ParsedHostname{
		proto.NewParsedHostnameWithFalse(other.HostID.Id),
		hostnameOnly(other.Hostname),
	} {
		err := c.add(t, atHost(bob, host))
		require.Error(t, err)
		require.IsType(t, core.HostMismatchError{}, err)
	}
}

func TestTeamClosedHostAddNeedsGrant(t *testing.T) {
	c := newClosedHostTeam(t)
	bob := c.newUser(t, false)
	err := c.add(t, byUID(bob))
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)
	require.Contains(t, err.Error(), "no view permission")
	require.Contains(t, err.Error(), "member-load floor")
}

// A grant usable only at admin would let the admin's add through, but the
// members at the member-load floor could not load the new member afterwards.
// The add is checked at the floor, so it fails instead.
func TestTeamClosedHostAddGrantAboveFloorRefused(t *testing.T) {
	c := newClosedHostTeam(t)
	carol := c.newUser(t, true)
	require.NoError(t, c.add(t, byUID(carol)))

	dave := c.newUser(t, false)
	c.grant(t, dave, &proto.AdminRole)
	err := c.add(t, byUID(dave))
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)

	// Asking to be checked at a role above the token's own does not widen
	// what the token can load: carol, a member, cannot load dave as owner.
	mc, tm := memberMinder(t, c.tew, carol)
	_, err = tm.ListMemberships(mc, nil)
	require.NoError(t, err)
	tr, err := tm.LoadTeamWithFQTeam(
		mc,
		proto.FQTeam{Team: c.tid, Host: c.alice.host},
		libclient.LoadTeamOpts{Refresh: true},
	)
	require.NoError(t, err)
	// Without the token the loader would fall back to carol's own view, which
	// fails the same way and would prove nothing.
	tok := tr.Tw().VOBearerToken()
	require.NotNil(t, tok)
	_, err = libclient.LoadUser(mc, libclient.LoadUserArg{
		Uid:               dave.uid,
		LoadMode:          libclient.LoadModeOthers,
		TeamVOBearerToken: tok,
		AsTeamRole:        &proto.OwnerRole,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, core.PermissionError("no view permission"))
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
