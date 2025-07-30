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
}
