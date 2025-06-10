// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

// i == vhost ID, between 0 and 3, since we have 4 vhosts.
func newUserWithAgentAtVHost(t *testing.T, a *testAgent, i int) {
	name := proto.DeviceName("device A.1")
	vh := vHost(t, i)
	signupUi := newMockSignupUI().withDeviceKey().withDeviceName(name).withServer(vh.Addr)
	a.runCmdWithUIs(t, libclient.UIs{Signup: signupUi}, "--simple-ui", "signup")
}

func TestCreateInviteSequence(t *testing.T) {

	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)
	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)
	merklePoke(t)

	var res lcl.TeamCreateRes
	x.runCmdToJSON(t, &res, "team", "create", "aa.bb")
	out, err := json.Marshal(res)
	require.NoError(t, err)
	fmt.Printf("Output: %s\n", string(out))
	merklePoke(t)

	x.runCmd(t, nil, "team", "index-range", "raise", "aa.bb")
	merklePoke(t)

	var res2 lcl.TeamRoster
	x.runCmdToJSON(t, &res2, "team", "ls", "aa.bb")
	require.Equal(t, 1, len(res2.Members))
	require.Equal(t, res2.Fqp.Fqp.Party, res.Id.ToPartyID())
	require.Equal(t, res2.Fqp.Name, proto.NameUtf8("aa.bb"))

	var usr lcl.UserMetadataAndSigchainState
	x.runCmdToJSON(t, &usr, "user", "load-me")

	require.Equal(t, usr.State.Username.B.NameUtf8, res2.Members[0].Mem.Name)
	require.Equal(t, usr.Hostname, res2.Fqp.Host)
	require.Equal(t, usr.Fqu.ToFQParty(), res2.Members[0].Mem.Fqp)

	var res3 proto.TeamInvite
	x.runCmdToJSON(t, &res3, "team", "invite", "aa.bb")
	inviteStr, err := team.ExportTeamInvite(res3)
	require.NoError(t, err)

	// expect a minimum length on the invite stringified
	require.Greater(t, 120, len(inviteStr))

	y := newTestAgent(t)
	y.runAgent(t)
	defer y.stop(t)
	newUserWithAgentAtVHost(t, y, 0)
	merklePoke(t)
	merklePoke(t)
	var userY lcl.UserMetadataAndSigchainState
	y.runCmdToJSON(t, &userY, "user", "load-me")

	y.runCmd(t, nil, "team", "accept", inviteStr)
	merklePoke(t)
	err = y.runCmdErr(nil, "team", "accept", inviteStr)
	require.Error(t, err)
	require.Equal(t, core.TeamInviteAlreadyAcceptedError{}, err)

	z := newTestAgent(t)
	z.runAgent(t)
	defer z.stop(t)
	newUserWithAgentAtVHost(t, z, 1)
	merklePoke(t)
	merklePoke(t)
	z.runCmd(t, nil, "team", "accept", inviteStr)

	var userZ lcl.UserMetadataAndSigchainState
	z.runCmdToJSON(t, &userZ, "user", "load-me")

	var create2Res lcl.TeamCreateRes
	y.runCmdToJSON(t, &create2Res, "team", "create", "cc.ee")
	merklePoke(t)
	merklePoke(t)
	y.runCmd(t, nil, "team", "index-range", "lower", "cc.ee")
	merklePoke(t)
	y.runCmd(t, nil, "team", "accept", "-t", "cc.ee", inviteStr)

	var create3res lcl.TeamCreateRes
	z.runCmdToJSON(t, &create3res, "team", "create", "ff.gg")
	merklePoke(t)
	merklePoke(t)
	z.runCmd(t, nil, "team", "index-range", "set", "ff.gg", "01-02.de")
	merklePoke(t)
	var rr proto.RationalRange
	z.runCmdToJSON(t, &rr, "team", "index-range", "get", "ff.gg")
	require.Equal(t, proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x01}, Exp: 0},
		High: proto.Rational{Base: []byte{0x02, 0xde}, Exp: -1},
	}, rr)

	z.runCmd(t, nil, "team", "accept", "-t", "ff.gg", inviteStr)

	var inb lcl.TeamInbox
	x.runCmdToJSON(t, &inb, "team", "inbox", "aa.bb")

	// Check some basic properties of the inbox. One rows for each of the acceptances above.
	require.Equal(t, 4, len(inb.Rows))
	for i := 0; i < len(inb.Rows)-1; i++ {
		require.GreaterOrEqual(t, inb.Rows[i].Time, inb.Rows[i+1].Time)
	}

	require.Equal(t, userY.State.Username.B.NameUtf8, inb.Rows[3].Nfqp.Name)
	require.Equal(t, userY.Hostname, inb.Rows[3].Nfqp.Host)
	require.Equal(t, userZ.State.Username.B.NameUtf8, inb.Rows[2].Nfqp.Name)
	require.Equal(t, userZ.Hostname, inb.Rows[2].Nfqp.Host)
	require.Equal(t, proto.NameUtf8("cc.ee"), inb.Rows[1].Nfqp.Name)
	require.Equal(t, userY.Hostname, inb.Rows[1].Nfqp.Host)
	require.Equal(t, proto.NameUtf8("ff.gg"), inb.Rows[0].Nfqp.Name)
	require.Equal(t, userZ.Hostname, inb.Rows[0].Nfqp.Host)

	// Now add userY to the team, acting on the invite.
	x.runCmd(t, nil, "team", "admit", "aa.bb", string(inb.Rows[3].Tok.String())+"/a")
	merklePoke(t)
	var roster lcl.TeamRoster
	x.runCmdToJSON(t, &roster, "team", "ls", "aa.bb")
	require.Equal(t, 2, len(roster.Members))
	require.Equal(t, userY.Fqu.ToFQParty(), roster.Members[1].Mem.Fqp)
	require.Equal(t, proto.AdminRole, roster.Members[1].DstRole)
	require.Equal(t, proto.OwnerRole, roster.Members[1].SrcRole)
	require.Equal(t, proto.Seqno(3), roster.Members[1].Added.Seqno)
	require.Equal(t, proto.Seqno(1), roster.Members[0].Added.Seqno)
	require.Less(t, roster.Members[0].Added.Time, roster.Members[1].Added.Time)

	x.runCmd(t, nil, "team", "admit", "aa.bb",
		string(inb.Rows[2].Tok.String())+"/m/-1",
		string(inb.Rows[1].Tok.String())+"/m/-2",
		string(inb.Rows[0].Tok.String())+"/m/-3",
	)
	merklePoke(t)
	x.runCmdToJSON(t, &roster, "team", "ls", "aa.bb")
	require.Equal(t, 5, len(roster.Members))
	require.Equal(t, proto.NameUtf8("ff.gg"), roster.Members[4].Mem.Name)
	require.Equal(t, userZ.Hostname, roster.Members[4].Mem.Host)
	require.Equal(t,
		proto.NewRoleWithMember(-3),
		roster.Members[4].DstRole,
	)
	require.Equal(t, proto.NameUtf8("cc.ee"), roster.Members[3].Mem.Name)
	require.Equal(t, userY.Hostname, roster.Members[3].Mem.Host)
	require.Equal(t,
		proto.NewRoleWithMember(-2),
		roster.Members[3].DstRole,
	)
	require.Equal(t, userZ.Fqu.ToFQParty(), roster.Members[2].Mem.Fqp)
	require.Equal(t,
		proto.NewRoleWithMember(-1),
		roster.Members[2].DstRole,
	)
}

func TestCreateAdmitLoad(t *testing.T) {
	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)

	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)
	merklePoke(t)

	var res lcl.TeamCreateRes
	teamName := "yodos"
	x.runCmdToJSON(t, &res, "team", "create", teamName)
	merklePoke(t)

	var res3 proto.TeamInvite
	x.runCmdToJSON(t, &res3, "team", "invite", teamName)
	inviteStr, err := team.ExportTeamInvite(res3)
	require.NoError(t, err)

	var xUser lcl.UserMetadataAndSigchainState
	x.runCmdToJSON(t, &xUser, "user", "load-me")

	y := newTestAgent(t)
	y.runAgent(t)
	defer y.stop(t)
	newUserWithAgentAtVHost(t, y, 0)
	merklePoke(t)
	merklePoke(t)
	y.runCmd(t, nil, "team", "accept", inviteStr)

	var inb lcl.TeamInbox
	x.runCmdToJSON(t, &inb, "team", "inbox", teamName)
	require.Equal(t, 1, len(inb.Rows))
	x.runCmd(t, nil, "team", "admit", teamName, string(inb.Rows[0].Tok.String())+"/a")
	merklePoke(t)

	var ros lcl.TeamRoster
	y.runCmdToJSON(t, &ros, "team", "ls", teamName)
	team := ros.Fqp
	require.Equal(t, 2, len(ros.Members))

	var yUser lcl.UserMetadataAndSigchainState
	y.runCmdToJSON(t, &yUser, "user", "load-me")

	z := newTestAgent(t)
	z.runAgent(t)
	defer z.stop(t)
	newUserWithAgentAtVHost(t, z, 1)
	merklePoke(t)
	merklePoke(t)
	z.runCmd(t, nil, "team", "accept", inviteStr)

	var zUser lcl.UserMetadataAndSigchainState
	z.runCmdToJSON(t, &zUser, "user", "load-me")

	x.runCmdToJSON(t, &inb, "team", "inbox", teamName)
	require.Equal(t, 1, len(inb.Rows))
	x.runCmd(t, nil, "team", "admit", teamName, string(inb.Rows[0].Tok.String())+"/m/0")
	merklePoke(t)
	hostId, err := team.Fqp.Host.StringErr()
	require.NoError(t, err)
	z.runCmdToJSON(t, &ros, "team", "ls", teamName+"@"+hostId)
	require.Equal(t, 3, len(ros.Members))

	require.Equal(t, xUser.Fqu.ToFQParty(), ros.Members[0].Mem.Fqp)
	require.Equal(t, yUser.Fqu.ToFQParty(), ros.Members[1].Mem.Fqp)
	require.Equal(t, zUser.Fqu.ToFQParty(), ros.Members[2].Mem.Fqp)

}

// We start with:
//   - host 0
//   - user alice
//   - team t
//   - team index range (80-)
//
// We then have:
//   - host 1
//   - user bob
//   - team v
//   - team index range (70-90)
//
// In phase II we have:
//   - host 0
//   - user charlie
//   - team w
//   - team index range (70-90)
//
// Steps are:
// I. Remote:
//  1. Alice makes an invite
//  2. Bob accepts the invite on a doctored client, so it doesn't fail on the cycle check (as it should)
//  3. Posts acceptance to Host 1, which can't reject it, since it doesn't have the ability to load the team.
//  4. Alice loads inbox, and sees the problem. It autorejects this row, and reports it to the user.
//  5. Alice loads inbox a second time, and all good.
//
// II. Remote:
//  1. Bob accepts invite on doctored client, so it doesn't fail on the cycle check (as it should)
//  2. Posts acceptance to Host 0, which **rejects it** since it can check locally that the team index range is not compatible
func TestAutoRejectTeamCycleFromMaliciousClient(t *testing.T) {

	alice := newTestAgent(t)
	alice.runAgent(t)
	defer alice.stop(t)

	newUserWithAgentAtVHost(t, alice, 0)
	merklePoke(t)
	merklePoke(t)

	var res lcl.TeamCreateRes
	alice.runCmdToJSON(t, &res, "team", "create", "team-t")
	merklePoke(t)
	alice.runCmd(t, nil, "team", "index-range", "raise", "team-t")
	merklePoke(t)

	var res3 proto.TeamInvite
	alice.runCmdToJSON(t, &res3, "team", "invite", "team-t")
	inviteStr, err := team.ExportTeamInvite(res3)
	require.NoError(t, err)

	bob := newTestAgent(t)
	bob.runAgent(t)
	defer bob.stop(t)
	newUserWithAgentAtVHost(t, bob, 1)
	merklePoke(t)
	merklePoke(t)

	joiner := proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x70}},
		High: proto.Rational{Base: []byte{0x90}},
	}
	joinee := proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x80}},
		High: proto.Rational{Infinity: true},
	}
	cycleError := core.TeamCycleError{
		TeamCycleError: proto.TeamCycleError{
			Joiner: joiner,
			Joinee: joinee,
		},
	}

	createTeamAndFailAccept := func(s string, u *testAgent) string {

		var res lcl.TeamCreateRes
		u.runCmdToJSON(t, &res, "team", "create", s)
		merklePoke(t)
		u.runCmd(t, nil, "team", "index-range", "set", s, "70-90")
		merklePoke(t)

		var st lcl.AgentStatus
		u.runCmdToJSON(t, &st, "status")

		err = u.runCmdErr(nil, "team", "accept", "--team", s, inviteStr)
		require.Error(t, err)
		require.Equal(t, cycleError, err)

		fqt := proto.FQTeam{
			Host: st.Users[0].Info.Fqu.HostID,
			Team: res.Id,
		}
		teamStr, err := fqt.StringErr()
		require.NoError(t, err)
		return teamStr
	}

	teamStr := createTeamAndFailAccept("team-v", bob)

	// 2. Bob accepts the invite on a doctored client, so it doesn't fail on the cycle check (as it should)
	bob.runCmd(t, nil, "test", "set-fake-team-index-range", teamStr, "20-40")

	// 3. Posts acceptance to Host 1, which can't reject it, since it doesn't have the ability to load the team.
	bob.runCmd(t, nil, "team", "accept", "--team", "team-v", inviteStr)

	// 4. Alice loads inbox, and sees the problem. It autorejects this row, and reports it to the user.
	var inb lcl.TeamInbox
	alice.runCmdToJSON(t, &inb, "team", "inbox", "team-t")

	require.Equal(t, 1, len(inb.Rows))
	require.NotNil(t, inb.Rows[0].AutofixStatus)
	require.Equal(t, proto.NewStatusWithOk(), *inb.Rows[0].AutofixStatus)
	require.Equal(t, proto.NewStatusWithTeamIndexRangeError("joining team's index weirdly grew"), inb.Rows[0].Status)

	// 5. Reload should show clearing of the bad row.
	alice.runCmdToJSON(t, &inb, "team", "inbox", "team-t")
	require.Equal(t, 0, len(inb.Rows))

	// II.1. while we are here, let's do the same for a local team, which should fail on invite
	// accept POST.
	charlie := newTestAgent(t)
	charlie.runAgent(t)
	defer charlie.stop(t)
	newUserWithAgentAtVHost(t, charlie, 0)
	merklePoke(t)
	merklePoke(t)

	teamW := createTeamAndFailAccept("team-w", charlie)
	charlie.runCmd(t, nil, "test", "set-fake-team-index-range", teamW, "70-90")

	err = charlie.runCmdErr(nil, "team", "accept", "--team", "team-w", inviteStr)
	require.Error(t, err)
	require.Equal(t, cycleError, err)
}

// On an "open viewership host", we can test team additions.
func TestTeamAddOpenViewership(t *testing.T) {
	x, _ := createTeamOpenViewership(t, nil)
	defer x.stop(t)
}

func createTeamOpenViewership(
	t *testing.T,
	f func(*testAgent),
) (
	*testAgent,
	*proto.FQUser,
) {
	x := newTestAgent(t)
	x.runAgent(t)

	// VHost "4" is the host we're dedicating to open viewership (as in lib/ tests)
	newUserWithAgentAtVHost(t, x, 4)
	merklePoke(t)
	merklePoke(t)

	var res lcl.TeamCreateRes
	rs, err := core.RandomBase36String(5)
	require.NoError(t, err)
	teamName := "team_" + rs
	x.runCmdToJSON(t, &res, "team", "create", teamName)
	merklePoke(t)

	var xUser lcl.UserMetadataAndSigchainState
	x.runCmdToJSON(t, &xUser, "user", "load-me")

	if f != nil {
		f(x)
	}

	phid := xUser.Fqu.HostID
	m := globalTestEnv.MetaContext()
	chid, err := m.G().HostIDMap().LookupByHostID(m, phid)
	require.NoError(t, err)
	m = m.WithHostID(chid)

	err = shared.VHostSetUserViewership(m, proto.ViewershipMode_Open)
	require.NoError(t, err)

	y := newTestAgent(t)
	y.runAgent(t)
	defer y.stop(t)

	newUserWithAgentAtVHost(t, y, 4)
	merklePoke(t)
	merklePoke(t)

	var yUser lcl.UserMetadataAndSigchainState
	y.runCmdToJSON(t, &yUser, "user", "load-me")

	yuid, err := yUser.Fqu.StringErr()
	require.NoError(t, err)

	err = x.runCmdErr(nil, "team", "add", teamName, yuid+"/a")
	require.Error(t, err)
	require.Equal(t, core.KeyNotFoundError{Which: "puk at role"}, err)
	x.runCmd(t, nil, "team", "add", teamName, yuid+"/o")
	merklePoke(t)

	return x, &yUser.Fqu
}

// If we're acting on behalf of a team, our access token might time
// out. We need to refresh it.
func TestTeamRefresh(t *testing.T) {

	x := newTestAgent(t)
	cl := clockwork.NewFakeClockAt(time.Now())
	x.runAgentWithHook(t, func(m libclient.MetaContext) error {
		m.G().SetClock(cl)
		return nil
	})
	defer x.stop(t)

	newUserWithAgentAtVHost(t, x, 1)
	merklePoke(t)
	merklePoke(t)

	var res lcl.TeamCreateRes
	teamName := "slackers"
	x.runCmdToJSON(t, &res, "team", "create", teamName)
	merklePoke(t)

	g := globalTestEnv.G
	g.SetClock(cl)
	defer g.SetClock(nil)

	x.runCmd(t, nil, "kv", "mkdir", "-t", teamName, "-p", "/a/b/c")
	cl.Advance(time.Hour * 24)
	x.runCmd(t, nil, "kv", "mkdir", "-t", teamName, "-p", "/a/d")

}

// Issue 241 had the following problem:
//  1. Team is created with 1 link.
//  2. Team is loaded with 1 link, and written to disk.
//  3. New link added to team.
//  4. Load link 0 from disk, link 1 from server but don't correctly transfer
//     the sctls field.
//  5. subsequently fail a team membership load due to a zero sctls
//
// Confirmed that this test works as is, but if fails when the line labeled "Issue 241 fix"
// in file libclient/team_loader.go is commented out.
func TestIssue241(t *testing.T) {

	x, _ := createTeamOpenViewership(t, func(x *testAgent) {
		x.runCmd(t, nil, "util", "trigger-bg-clkr")
	})
	merklePoke(t)
	defer x.stop(t)
	x.runCmd(t, nil, "util", "trigger-bg-clkr")
	x.runCmd(t, nil, "util", "trigger-bg-clkr")
}

func TestTeamAddTeam(t *testing.T) {

	x, yUser := createTeamOpenViewership(t, nil)
	defer x.stop(t)

	var membs lcl.ListMembershipsRes
	x.runCmdToJSON(t, &membs, "team", "list-memberships")

	require.Equal(t, 1, len(membs.Teams))
	t1 := membs.Teams[0].Team.Name

	// create a second team
	var res lcl.TeamCreateRes
	rs, err := core.RandomBase36String(5)
	require.NoError(t, err)
	t2 := "team_" + rs
	x.runCmdToJSON(t, &res, "team", "create", t2)
	merklePoke(t)

	x.runCmd(t, nil, "team", "index-range", "raise", t1.String())
	merklePoke(t)
	x.runCmd(t, nil, "team", "index-range", "lower", t2)
	merklePoke(t)

	// add the admins of the second team as readers to the first team
	x.runCmd(t, nil, "team", "add", "--role", "m/0", t1.String(), "t:"+t2+"/a")
	merklePoke(t)

	var rost lcl.TeamRoster
	x.runCmdToJSON(t, &rost, "team", "ls", t1.String())
	require.Equal(t, 3, len(rost.Members))

	var nFound int
	for _, m := range rost.Members {
		if m.Mem.Fqp.Party.IsTeam() {
			require.Equal(t, t2, m.Mem.Name.String())
			require.Equal(t, proto.NewRoleWithMember(0), m.DstRole)
			require.Equal(t, proto.AdminRole, m.SrcRole)
			nFound++
		}
	}
	require.Equal(t, 1, nFound)

	// change the role of team from m/0 to m/1; first it should fail since we got the
	// source role wrong.
	err = x.runCmdErr(nil, "team", "change-roles", t1.String(), "t:"+t2+"/m/3->m/1")
	require.Error(t, err)
	require.Equal(t,
		core.TeamRosterError("party at position 0 with given source role not found in team"),
		err,
	)

	x.runCmd(t, nil, "team", "change-roles", t1.String(), "t:"+t2+"->m/1")
	merklePoke(t)

	// now change again to be an admin
	x.runCmd(t, nil, "team", "change-roles", t1.String(), "t:"+t2+"/a->a")
	merklePoke(t)

	yUserString, err := yUser.StringErr()
	require.NoError(t, err)

	// Demote user y to a reader @ -4 visibility level
	x.runCmd(t, nil, "team", "change-roles", t1.String(), yUserString+"->m/-4")
	merklePoke(t)

	// now test that we can change 2 roles at once
	x.runCmd(t, nil, "team", "change-roles",
		t1.String(),
		"t:"+t2+"/a->m/0",
		yUserString+"->m/0",
	)
	merklePoke(t)

	// finally test removal
	x.runCmd(t, nil, "team", "change-roles", t1.String(), yUserString+"->n")
}
