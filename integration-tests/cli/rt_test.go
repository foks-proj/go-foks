// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// TestRTChannelMakeAndList exercises the CLI integration for making channels
// (`rt new-channel`) and reading them back (`rt list-channels`), in both JSON
// and columnar-text form. It's a lighter-weight companion to the librt-level
// test in ../lib/rt_test.go; it doesn't test the race-and-retry paths.
func TestRTChannelMakeAndList(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	// Without read/write roles, `new-channel` creates admin-class channels.
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "foo", "--description", "foobars and doobars")
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "hotels", "--description", "zips and dips and blips")
	// The default channel has the empty name and (necessarily) no description.
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm)

	// Re-creating a channel with an existing name should fail.
	err := b.runCmdErr(nil, "rt", "new-channel", "-t", tm, "--name", "foo", "--description", "whoopsies")
	require.Error(t, err)
	require.Equal(t, core.RTChannelExistsError{}, err)

	// Read the channels back as JSON.
	var set lcl.RTChannelSetForTeam
	b.runCmdToJSON(t, &set, "rt", "list-channels", "-t", tm)
	require.Len(t, set.Channels, 3)

	// Channels come back sorted by class (admin first) and then by name; the
	// default channel's empty name sorts first.
	assertChannel := func(idx int, klass proto.RTChannelClass, name proto.RTChannelName) {
		require.Equal(t, klass, set.Channels[idx].Klass)
		require.Equal(t, name, set.Channels[idx].Name)
	}
	assertChannel(0, proto.RTChannelClass_Admin, "")
	assertChannel(1, proto.RTChannelClass_Admin, "foo")
	assertChannel(2, proto.RTChannelClass_Admin, "hotels")

	// The columnar text output renders the default channel as "#general" and
	// prefixes named channels with "#".
	var terminalUI terminalUI
	uis := libclient.UIs{
		Terminal: &terminalUI,
	}
	err = b.runCmdErrWithUIs(uis, "rt", "list-channels", "-t", tm)
	require.NoError(t, err)
	out := terminalUI.String()
	require.Contains(t, out, "#general")
	require.Contains(t, out, "#foo")
	require.Contains(t, out, "#hotels")
}

// TestRTSendAndRead exercises the `rt send` / `rt read` CLI for a single user:
// send a few messages into a channel, read them back (newest-first), and check
// that the agent resolved the sender's UID to a username (the sender here is the
// reader themselves, loaded via the team).
func TestRTSendAndRead(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "foo", "--description", "the foo channel")

	bodies := []string{"hello world", "second message", "a third one"}
	for _, body := range bodies {
		b.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "foo", body)
	}

	var thread lcl.RTThreadView
	b.runCmdToJSON(t, &thread, "rt", "read", "-t", tm, "--channel", "foo")
	require.Len(t, thread.Msgs, len(bodies))

	// GetThreadRecentMsgs returns newest-first.
	for i, body := range bodies {
		msg := thread.Msgs[len(bodies)-1-i]
		require.Equal(t, body, string(msg.Body))
		require.Equal(t, proto.RTMsgType_Basic, msg.Typ)
		require.NotNil(t, msg.Sender)
		require.NotNil(t, msg.SenderName)
		require.Equal(t, bob.username, *msg.SenderName)
	}

	// Sending to a non-existent channel should fail.
	err := b.runCmdErr(nil, "rt", "send", "-t", tm, "--channel", "nope", "lost message")
	require.Error(t, err)
}

// TestRTSendAndReadCrossMember verifies sender-name resolution across two
// distinct members of a (closed-viewership) team: each reads the other's
// message and sees the other's username, which only works if the agent loads
// the sender mediated through the shared team (AsLocalTeam), since closed
// viewership forbids direct peer user loads.
func TestRTSendAndReadCrossMember(t *testing.T) {
	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)

	stopper := runMerkleActivePoker(t)
	defer stopper()

	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)
	merklePoke(t)
	xName := getActiveUser(t, x).Info.Username.NameUtf8

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	x.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	// Create a member-readable channel (read/write at the default member role)
	// so an ordinary member can read and write it.
	x.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "foo", "--description", "the foo channel",
		"--read-role", "m/0", "--write-role", "m/0")

	// Invite a second user y and admit them as an ordinary member.
	var invite proto.TeamInvite
	x.runCmdToJSON(t, &invite, "team", "invite", tm)
	inviteStr, err := team.ExportTeamInvite(invite)
	require.NoError(t, err)

	y := newTestAgent(t)
	y.runAgent(t)
	defer y.stop(t)
	newUserWithAgentAtVHost(t, y, 0)
	merklePoke(t)
	merklePoke(t)
	yName := getActiveUser(t, y).Info.Username.NameUtf8

	y.runCmd(t, nil, "team", "accept", inviteStr)
	var inb lcl.TeamInbox
	x.runCmdToJSON(t, &inb, "team", "inbox", tm)
	require.Equal(t, 1, len(inb.Rows))
	x.runCmd(t, nil, "team", "admit", tm, string(inb.Rows[0].Tok.String())+"/m/0")
	merklePoke(t)

	// x sends; y reads and should see x's name.
	x.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "foo", "hello from x")

	var thread lcl.RTThreadView
	y.runCmdToJSON(t, &thread, "rt", "read", "-t", tm, "--channel", "foo")
	require.Len(t, thread.Msgs, 1)
	require.Equal(t, "hello from x", string(thread.Msgs[0].Body))
	require.NotNil(t, thread.Msgs[0].SenderName)
	require.Equal(t, xName, *thread.Msgs[0].SenderName)

	// y sends; x reads and should see both messages with names resolved for
	// each distinct sender.
	y.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "foo", "hello back from y")

	x.runCmdToJSON(t, &thread, "rt", "read", "-t", tm, "--channel", "foo")
	require.Len(t, thread.Msgs, 2)
	// newest-first
	require.Equal(t, "hello back from y", string(thread.Msgs[0].Body))
	require.NotNil(t, thread.Msgs[0].SenderName)
	require.Equal(t, yName, *thread.Msgs[0].SenderName)
	require.Equal(t, "hello from x", string(thread.Msgs[1].Body))
	require.NotNil(t, thread.Msgs[1].SenderName)
	require.Equal(t, xName, *thread.Msgs[1].SenderName)
}

// TestRTChannelGeneralNameReserved checks that the "general" name is reserved
// for the default (empty-name) channel and can't be claimed explicitly. The
// minder rejects it case-insensitively; a leading '#' is stripped by the CLI
// before the check, so "#general" is rejected the same way.
func TestRTChannelGeneralNameReserved(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	// "general", "General" (case-folded), and "#general" ('#' stripped) are all
	// rejected as the reserved default-channel name.
	for _, nm := range []string{"general", "General", "#general"} {
		err := b.runCmdErr(nil, "rt", "new-channel", "-t", tm, "--name", nm)
		require.Error(t, err, "name %q", nm)
		require.Equal(t, core.RTGenericError("cannot make channel named #general"), err, "name %q", nm)
	}

	// None of the rejected attempts created anything.
	var set lcl.RTChannelSetForTeam
	b.runCmdToJSON(t, &set, "rt", "list-channels", "-t", tm)
	require.Len(t, set.Channels, 0)
}

// TestRTChannelNameNoHashPrefix verifies the '#' is purely a display
// convention. The CLI strips a leading '#' from --name, so "#foo" creates a
// channel stored as "foo"; the text renderer then re-adds exactly one '#',
// yielding "#foo" and never "##foo".
func TestRTChannelNameNoHashPrefix(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	// Create with a leading '#'; the '#' is stripped before parsing.
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "#foo")

	// The stored name is "foo", with no leading '#'.
	var set lcl.RTChannelSetForTeam
	b.runCmdToJSON(t, &set, "rt", "list-channels", "-t", tm)
	require.Len(t, set.Channels, 1)
	require.Equal(t, proto.RTChannelName("foo"), set.Channels[0].Name)

	// The text renderer adds exactly one '#': "#foo", never "##foo".
	var terminalUI terminalUI
	uis := libclient.UIs{
		Terminal: &terminalUI,
	}
	err := b.runCmdErrWithUIs(uis, "rt", "list-channels", "-t", tm)
	require.NoError(t, err)
	out := terminalUI.String()
	require.Contains(t, out, "#foo")
	require.NotContains(t, out, "##foo")

	// Re-creating it without the '#' collides with the stripped original.
	err = b.runCmdErr(nil, "rt", "new-channel", "-t", tm, "--name", "foo")
	require.Error(t, err)
	require.Equal(t, core.RTChannelExistsError{}, err)
}

// TestRTChannelNameCaseFoldCollision verifies channel names are case-folded:
// "bar" and "Bar" both normalize to "bar", so within the same class the second
// create collides with the first.
func TestRTChannelNameCaseFoldCollision(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "bar")

	// "Bar" normalizes to "bar" -- same name, same (admin) class -> collision.
	err := b.runCmdErr(nil, "rt", "new-channel", "-t", tm, "--name", "Bar")
	require.Error(t, err)
	require.Equal(t, core.RTChannelExistsError{}, err)

	// Only the one channel exists, stored lowercased.
	var set lcl.RTChannelSetForTeam
	b.runCmdToJSON(t, &set, "rt", "list-channels", "-t", tm)
	require.Len(t, set.Channels, 1)
	require.Equal(t, proto.RTChannelName("bar"), set.Channels[0].Name)
}

// TestRTChannelClassFlag exercises the --channel-class flag on `rt send` / `rt
// read`. A name may live in two classes at once (an admin "dup" and a
// bottom/member "dup"); without a class the name is ambiguous, and the flag
// ("a"/"admin" vs "d"/"default"/"bottom") picks one. An unknown class is a
// bad-args error.
func TestRTChannelClassFlag(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	// "dup" in two classes: no roles -> admin class; member roles -> bottom class.
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "dup")
	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "dup",
		"--read-role", "m/0", "--write-role", "m/0")

	var set lcl.RTChannelSetForTeam
	b.runCmdToJSON(t, &set, "rt", "list-channels", "-t", tm)
	require.Len(t, set.Channels, 2)

	// Addressing "dup" with no class is ambiguous.
	err := b.runCmdErr(nil, "rt", "send", "-t", tm, "--channel", "dup", "no class")
	require.Error(t, err)
	require.Equal(t, core.RTAmbiguousChannelError{Name: "dup"}, err)

	// The flag disambiguates: short and long forms of each class.
	b.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "dup", "--channel-class", "a", "to admin")
	b.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "dup", "--channel-class", "d", "to bottom")

	// Each class's channel holds only its own message.
	var adminThread lcl.RTThreadView
	b.runCmdToJSON(t, &adminThread, "rt", "read", "-t", tm, "--channel", "dup", "--channel-class", "admin")
	require.Len(t, adminThread.Msgs, 1)
	require.Equal(t, "to admin", string(adminThread.Msgs[0].Body))

	var bottomThread lcl.RTThreadView
	b.runCmdToJSON(t, &bottomThread, "rt", "read", "-t", tm, "--channel", "dup", "--channel-class", "bottom")
	require.Len(t, bottomThread.Msgs, 1)
	require.Equal(t, "to bottom", string(bottomThread.Msgs[0].Body))

	// An unrecognized class is a bad-args error.
	err = b.runCmdErr(nil, "rt", "send", "-t", tm, "--channel", "dup", "--channel-class", "bogus", "nope")
	require.Error(t, err)
	require.Equal(t, core.BadArgsError("bad channel class"), err)
}

// TestRTReadPaging walks backwards through a thread with `rt read --before`,
// checking page contents, the atBeginning flag, and the single-message window at
// the very top (which exercises GetThreadBookended's inclusive start==end path).
func TestRTReadPaging(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	b.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	b.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "foo", "--description", "the foo channel")

	const n = 5
	for i := 1; i <= n; i++ {
		b.runCmd(t, nil, "rt", "send", "-t", tm, "--channel", "foo", fmt.Sprintf("msg-%d", i))
	}

	// Pages come back newest-first.
	read := func(num uint, before int) lcl.RTThreadView {
		var page lcl.RTThreadView
		b.runCmdToJSON(t, &page, "rt", "read", "-t", tm, "--channel", "foo",
			"-n", fmt.Sprintf("%d", num), "--before", fmt.Sprintf("%d", before))
		return page
	}
	requireSeqs := func(page lcl.RTThreadView, seqs ...int) {
		require.Len(t, page.Msgs, len(seqs))
		for i, s := range seqs {
			require.Equal(t, proto.RTMsgSeq(s), page.Msgs[i].Seq)
		}
	}

	// Most recent page of 2 -> seqs 5,4; more remains above.
	page := read(2, 0)
	requireSeqs(page, 5, 4)
	require.False(t, page.AtBeginning)

	// Page back before seq 4 -> seqs 3,2; still more above.
	page = read(2, 4)
	requireSeqs(page, 3, 2)
	require.False(t, page.AtBeginning)

	// Page back before seq 2 -> only seq 1 (single-message window), at beginning.
	page = read(2, 2)
	requireSeqs(page, 1)
	require.True(t, page.AtBeginning)

	// Nothing before seq 1.
	page = read(2, 1)
	requireSeqs(page)
	require.True(t, page.AtBeginning)
}

// TestRTUnreadableChannelHiddenFromInbox checks the server's read-role gating of
// the channel list within the member tier. A bottom-class channel is sealed at
// member viz 5; a member at viz 0 still receives it (the class gate admits all
// members to bottom-class channels) but is below the read role, so its
// description/last-message are withheld and it's flagged unreadable and hidden
// from the inbox. Its name is still returned, though, so client-side collision
// detection reserves it -- the lower member can't create a same-named channel.
//
// The team only has a key at viz 5 because a member actually sits there: an
// unoccupied viz level has no provisioned key (see lib/team keyAtLevel), so we
// admit z at m/5 before sealing the channel to it.
func TestRTUnreadableChannelHiddenFromInbox(t *testing.T) {
	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)

	stopper := runMerkleActivePoker(t)
	defer stopper()

	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)
	merklePoke(t)

	tm := "t-" + strings.ToLower(fsRandomString(t, 8))
	var teamRes lcl.TeamCreateRes
	x.runCmdToJSON(t, &teamRes, "team", "create", tm)
	merklePoke(t)

	var invite proto.TeamInvite
	x.runCmdToJSON(t, &invite, "team", "invite", tm)
	inviteStr, err := team.ExportTeamInvite(invite)
	require.NoError(t, err)

	// admit brings up a fresh user/agent, accepts the (multi-use) invite, and has
	// x admit them at the given role string (e.g. "m/5").
	admit := func(role string) *testAgent {
		u := newTestAgent(t)
		u.runAgent(t)
		newUserWithAgentAtVHost(t, u, 0)
		merklePoke(t)
		merklePoke(t)
		u.runCmd(t, nil, "team", "accept", inviteStr)
		var inb lcl.TeamInbox
		x.runCmdToJSON(t, &inb, "team", "inbox", tm)
		require.Equal(t, 1, len(inb.Rows))
		x.runCmd(t, nil, "team", "admit", tm, string(inb.Rows[0].Tok.String())+"/"+role)
		merklePoke(t)
		return u
	}

	// z sits at member viz 5; admitting them provisions the team's m/5 key, which
	// we then seal the channel to.
	z := admit("m/5")
	defer z.stop(t)

	// A bottom-class channel readable only at member viz 5.
	x.runCmd(t, nil, "rt", "new-channel", "-t", tm, "--name", "secret",
		"--description", "eyes only", "--read-role", "m/5", "--write-role", "m/5")

	// y sits at viz 0, below the channel's read role.
	y := admit("m/0")
	defer y.stop(t)

	// x (owner) and z (m/5) are at or above the read role and see the channel.
	var xset lcl.RTChannelSetForTeam
	x.runCmdToJSON(t, &xset, "rt", "list-channels", "-t", tm)
	require.Len(t, xset.Channels, 1)
	require.Equal(t, proto.RTChannelName("secret"), xset.Channels[0].Name)

	var zset lcl.RTChannelSetForTeam
	z.runCmdToJSON(t, &zset, "rt", "list-channels", "-t", tm)
	require.Len(t, zset.Channels, 1)
	require.Equal(t, proto.RTChannelName("secret"), zset.Channels[0].Name)

	// y (m/0, below the read role) does not see it in the inbox.
	var yset lcl.RTChannelSetForTeam
	y.runCmdToJSON(t, &yset, "rt", "list-channels", "-t", tm)
	require.Len(t, yset.Channels, 0)

	// ...but the name is still reserved: y can't create a colliding bottom-class
	// "secret" channel, because collision detection still sees it.
	err = y.runCmdErr(nil, "rt", "new-channel", "-t", tm, "--name", "secret")
	require.Error(t, err)
	require.Equal(t, core.RTChannelExistsError{}, err)
}
