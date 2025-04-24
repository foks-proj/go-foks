// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"testing"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/stretchr/testify/require"
)

func TestNagAndClear(t *testing.T) {
	defer common.DebugEntryAndExit()()

	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)
	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)

	var nag bool

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.True(t, nag)

	// Should be no rate limit in test
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.True(t, nag)

	// With rate limit, it shouldn't show...
	x.runCmdToJSON(t, &nag, "test", "get-device-nag", "--rate-limit")
	require.False(t, nag)

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.True(t, nag)

	x.runCmd(t, nil, "notify", "clear-device-nag")

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.False(t, nag)

	x.runCmd(t, nil, "notify", "clear-device-nag", "--reset")
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.True(t, nag)

	var res lcl.BackupHESP
	x.runCmdToJSON(t, &res, "backup", "new")

	// Once we add a new device, no more nag
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	require.False(t, nag)

}
