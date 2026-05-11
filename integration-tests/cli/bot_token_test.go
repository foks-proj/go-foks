// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestBotTokenNewAndLoad(t *testing.T) {
	defer common.DebugEntryAndExit()()

	stopper := runMerkleActivePoker(t)
	defer stopper()

	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	var res lcl.BotTokenString
	b.runCmdToJSON(t, &res, "bot-token", "new")
	fmt.Printf("%+v\n", res)

	status := bob.agent.status(t)
	require.Equal(t, 1, len(status.Users))
	host := status.Users[0].Info.HostAddr

	c := newTestAgent(t)
	c.runAgent(t)
	defer c.stop(t)

	c.runCmd(t, nil, "bot-token", "load",
		"--host", host.String(),
		"--token", string(res),
	)

	var bt core.BotToken
	err := bt.Import(res)
	require.NoError(t, err)
	ks, err := bt.KeySuite(proto.OwnerRole, proto.HostID{})
	require.NoError(t, err)
	bkid, err := ks.EntityID()
	require.NoError(t, err)

	var klres lcl.KeyListRes
	c.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 2, len(klres.CurrUserAllKeys))
	require.Equal(t, 1, len(klres.AllUsers))
	nm := bt.Name()

	active := func(lst []lcl.ActiveDeviceInfo) lcl.ActiveDeviceInfo {
		for _, d := range lst {
			if d.Active {
				return d
			}
		}
		t.Fatal("no active device")
		return lcl.ActiveDeviceInfo{}
	}

	ad := active(klres.CurrUserAllKeys)
	require.Equal(t, nm, ad.Di.Dn.Name)
	require.Equal(t, bkid, ad.Di.Key.Member.Id.Entity)
	require.Equal(t, proto.DeviceType_BotToken, ad.Di.Dn.Label.DeviceType)

	newDevName := proto.DeviceName("dodo0")
	c.runCmd(t, nil, "key", "dev", "perm", "--name", string(newDevName), "--role", "o")

	c.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 3, len(klres.CurrUserAllKeys))
	ad = active(klres.CurrUserAllKeys)
	require.Equal(t, newDevName, ad.Di.Dn.Name)
	require.Equal(t, proto.DeviceType_Computer, ad.Di.Dn.Label.DeviceType)

	d := newTestAgent(t)
	d.runAgent(t)
	defer d.stop(t)

	var termui terminalUI
	termui.inputLine = string(res) + "\n"
	uis := libclient.UIs{
		Terminal: &termui,
	}

	d.runCmdWithUIs(t, uis, "key", "use-bot-token",
		"--host", host.String(),
	)
	require.Equal(t, 0, len(termui.inputLine))
	d.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 3, len(klres.CurrUserAllKeys))
	require.Equal(t, 1, len(klres.AllUsers))
	ad = active(klres.CurrUserAllKeys)
	require.Equal(t, nm, ad.Di.Dn.Name)
	require.Equal(t, bkid, ad.Di.Key.Member.Id.Entity)
	require.Equal(t, proto.DeviceType_BotToken, ad.Di.Dn.Label.DeviceType)

	// Revoke the bot token key (issue #231 repro).
	bkidStr, err := bkid.StringErr()
	require.NoError(t, err)
	b.runCmd(t, nil, "key", "revoke", bkidStr)
}

// TestBotTokenAgentRestart reproduces issue #263: after a bot user is
// provisioned via `key use-bot-token` and the agent is restarted, the user
// is correctly left in a locked state (the agent has no way to reload the
// token on its own). The bug is purely in the error surface: CLI ops emit
// the generic "key not found" error, which is indistinguishable from a
// genuinely-missing KV entry — downstream tools (e.g. fnox) can't pattern-
// match on it to decide whether to re-run `foks bot use`. The agent's own
// `status` also bottoms out at "unhandled locked key scenario", a catch-
// all InternalError, instead of a recognizable lock state.
func TestBotTokenAgentRestart(t *testing.T) {
	defer common.DebugEntryAndExit()()

	stopper := runMerkleActivePoker(t)
	defer stopper()

	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)

	var tok lcl.BotTokenString
	b.runCmdToJSON(t, &tok, "bot-token", "new")

	status := b.status(t)
	require.Equal(t, 1, len(status.Users))
	host := status.Users[0].Info.HostAddr

	// d is the bot-user agent — it provisions itself with the bot token,
	// then we restart it and observe the resulting user-facing errors.
	d := newTestAgent(t)
	d.runAgent(t)
	defer d.stop(t)
	var termui terminalUI
	termui.inputLine = string(tok) + "\n"
	uis := libclient.UIs{Terminal: &termui}
	d.runCmdWithUIs(t, uis, "key", "use-bot-token", "--host", host.String())

	// Sanity-check: with a freshly-loaded bot token, kv ops and key list
	// both work.
	d.runCmd(t, nil, "kv", "put", "/sentinel", "hello")
	out := d.runCmdToBytes(t, "kv", "get", "/sentinel", "-")
	require.Equal(t, "hello", string(out))
	var klres lcl.KeyListRes
	d.runCmdToJSON(t, &klres, "key", "list")
	require.NotEmpty(t, klres.CurrUserAllKeys)

	// Restart the agent. The in-memory key material is gone; the bot
	// user is now locked. Failures from this point on are expected —
	// what we're testing is that they're *clearly labeled* as a lock.
	d.stop(t)
	d.runAgent(t)

	// The agent's self-report must not bottom out at the catch-all
	// "unhandled locked key scenario" InternalError — that string is
	// the agent confessing it has no model for this state.
	st := d.status(t)
	require.Equal(t, 1, len(st.Users))

	// The lock status should be handled, and not giving us an internal error.
	// This is the bug we saw in #263.
	require.Equal(t, proto.StatusCode_BOT_TOKEN_LOCKED_ERROR, st.Users[0].LockStatus.Sc)

	// this one would kill the test correctly!
	// require.True(t, false)
	err := d.runCmdErr(nil, "kv", "get", "/sentinel", "-")

	require.Error(t, err)
	require.ErrorIs(t, err, core.BotTokenLockedError{})

	err = d.runCmdErr(nil, "key", "list")
	require.Error(t, err)
	require.ErrorIs(t, err, core.BotTokenLockedError{})
}
