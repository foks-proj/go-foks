// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"strings"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
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
