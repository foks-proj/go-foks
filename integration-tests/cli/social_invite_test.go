// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// The social signup flow (docs/social_signup_spec.md) end to end through the
// CLI and the agent, on a host with closed user viewership.

const socialInviteVHost = 2

func setVHostViewership(t *testing.T, a *testAgent, mode proto.ViewershipMode) {
	var u lcl.UserMetadataAndSigchainState
	a.runCmdToJSON(t, &u, "user", "load-me")
	m := globalTestEnv.MetaContext()
	chid, err := m.G().HostIDMap().LookupByHostID(m, u.Fqu.HostID)
	require.NoError(t, err)
	m = m.WithHostID(chid)
	require.NoError(t, shared.VHostSetUserViewership(m, mode))
}

type socialInviteRun struct {
	alice *testAgent
	bob   *testAgent
	team  string
	seed  string
	host  string
}

// newSocialInviteRun has alice create a team and an invitation into it, and
// bob read the invitation before he has an account.
func newSocialInviteRun(t *testing.T, team string) *socialInviteRun {
	x := newTestAgent(t)
	x.runAgent(t)
	t.Cleanup(func() { x.stop(t) })
	newUserWithAgentAtVHost(t, x, socialInviteVHost)
	merklePoke(t)
	merklePoke(t)
	setVHostViewership(t, x, proto.ViewershipMode_Closed)

	var tres lcl.TeamCreateRes
	x.runCmdToJSON(t, &tres, "team", "create", team)
	merklePoke(t)

	var cres lcl.SocialInviteCreateRes
	x.runCmdToJSON(t, &cres, "social-invite", "create", team, "join us?")
	seed := core.ExportSocialInviteSeed(cres.Seed)
	host := string(vHost(t, socialInviteVHost).Addr)

	y := newTestAgent(t)
	y.runAgent(t)
	t.Cleanup(func() { y.stop(t) })
	var view lcl.SocialInviteLocalView
	y.runCmdToJSON(t, &view, "social-invite", "fetch", "--host", host, seed)
	require.Equal(t, cres.Id, view.Id)
	require.Equal(t, proto.SocialInviteState_Open, view.State)
	require.Len(t, view.Msgs, 1)
	require.Equal(t, "join us?", view.Msgs[0].Text)
	require.Equal(t, proto.SocialInviteParty_Inviter, view.Msgs[0].Sender)
	require.NotNil(t, view.Msgs[0].Team)
	require.Equal(t, tres.Id, view.Msgs[0].Team.Team)

	newUserWithAgentAtVHost(t, y, socialInviteVHost)
	merklePoke(t)
	merklePoke(t)
	return &socialInviteRun{alice: x, bob: y, team: team, seed: seed, host: host}
}

func (r *socialInviteRun) aliceRow(t *testing.T) lcl.SocialInviteLocalRow {
	var rows []lcl.SocialInviteLocalRow
	r.alice.runCmdToJSON(t, &rows, "social-invite", "list")
	require.Len(t, rows, 1)
	require.Equal(t, r.seed, core.ExportSocialInviteSeed(rows[0].Seed))
	return rows[0]
}

func (r *socialInviteRun) bobView(t *testing.T) lcl.SocialInviteLocalView {
	var view lcl.SocialInviteLocalView
	r.bob.runCmdToJSON(t, &view, "social-invite", "fetch", "--host", r.host, r.seed)
	return view
}

func TestSocialInviteClosedHostCLI(t *testing.T) {
	stopper := runMerkleActivePoker(t)
	defer stopper()
	r := newSocialInviteRun(t, "si.closed")

	var bob lcl.UserMetadataAndSigchainState
	r.bob.runCmdToJSON(t, &bob, "user", "load-me")
	r.bob.runCmd(t, nil, "social-invite", "reply", r.seed, "1", "it's me")

	row := r.aliceRow(t)
	require.Equal(t, proto.SocialInviteState_Replied, row.State)
	require.Len(t, row.Msgs, 2)
	require.Equal(t, proto.SocialInviteParty_Invitee, row.Msgs[1].Sender)
	require.Equal(t, "it's me", row.Msgs[1].Text)
	require.NotNil(t, row.Msgs[1].User)
	require.Equal(t, bob.Fqu.Uid, row.Msgs[1].User.Uid)

	// The reply granted the team view of bob, so alice can add him by the
	// UID inside his reply on this closed host.
	uid, err := row.Msgs[1].User.Uid.StringErr()
	require.NoError(t, err)
	r.alice.runCmd(t, nil, "team", "add", r.team, uid)
	merklePoke(t)
	r.alice.runCmd(t, nil, "social-invite", "close", core.ExportSocialInviteID(row.Id), "accepted")

	var roster lcl.TeamRoster
	r.bob.runCmdToJSON(t, &roster, "team", "ls", r.team)
	require.Len(t, roster.Members, 2)
	require.Equal(t, proto.SocialInviteState_Accepted, r.bobView(t).State)
}

func TestSocialInviteAskAgainCLI(t *testing.T) {
	stopper := runMerkleActivePoker(t)
	defer stopper()
	r := newSocialInviteRun(t, "si.again")

	r.bob.runCmd(t, nil, "social-invite", "reply", r.seed, "1", "it's me")
	r.alice.runCmd(t, nil, "social-invite", "ask-again", r.seed, "which summer?")

	view := r.bobView(t)
	require.Equal(t, proto.SocialInviteState_AskAgain, view.State)
	require.Len(t, view.Msgs, 3)
	require.Equal(t, "which summer?", view.Msgs[2].Text)

	// Answering the superseded turn fails; answering the new one appends.
	err := r.bob.runCmdErr(nil, "social-invite", "reply", r.seed, "1", "stale")
	require.Error(t, err)
	r.bob.runCmd(t, nil, "social-invite", "reply", r.seed, "3", "2019, at the lake")

	row := r.aliceRow(t)
	require.Equal(t, proto.SocialInviteState_Replied, row.State)
	require.Len(t, row.Msgs, 4)
	require.Equal(t, "2019, at the lake", row.Msgs[3].Text)
}
