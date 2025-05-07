// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"testing"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestDeviceNagAndClear(t *testing.T) {
	defer common.DebugEntryAndExit()()

	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)
	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)

	var nag lcl.UnifiedNagRes

	assertDeviceNag := func(nag lcl.UnifiedNagRes) {
		require.Equal(t, 1, len(nag.Nags))
		typ, err := nag.Nags[0].GetT()
		require.NoError(t, err)
		require.Equal(t, lcl.NagType_TooFewDevices, typ)
		donag := nag.Nags[0].Toofewdevices().DoNag
		require.True(t, donag)
	}

	assertNoNag := func(nag lcl.UnifiedNagRes) {
		require.Equal(t, 0, len(nag.Nags))
	}

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertDeviceNag(nag)

	// Should be no rate limit in test
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertDeviceNag(nag)

	// With rate limit, it shouldn't show...
	x.runCmdToJSON(t, &nag, "test", "get-device-nag", "--rate-limit")
	assertNoNag(nag)

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertDeviceNag(nag)

	x.runCmd(t, nil, "notify", "clear-device-nag")

	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertNoNag(nag)

	x.runCmd(t, nil, "notify", "clear-device-nag", "--reset")
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertDeviceNag(nag)

	var res lcl.BackupHESP
	x.runCmdToJSON(t, &res, "backup", "new")

	// Once we add a new device, no more nag
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")
	assertNoNag(nag)
}

func TestVersionNags(t *testing.T) {
	defer common.DebugEntryAndExit()()

	env := globalTestEnv

	x := newTestAgentWithOpts(t, agentOpts{env: env})
	x.runAgent(t)
	defer x.stop(t)

	cfg, ok := env.G.Config().(*shared.ConfigJSonnet)
	require.True(t, ok)

	wrapVers := func(s proto.SemVer) *core.ParsedSemVer {
		return &core.ParsedSemVer{SemVer: s}
	}

	minVers := proto.SemVer{Major: 1000, Minor: 4, Patch: 10}
	newest := proto.SemVer{Major: 1002, Minor: 7, Patch: 5}

	cfg.Data.Client = &shared.ClientConfigJSON{
		ClientVersion_: &shared.ClientVersionConfigJSON{
			MinVersion_:    wrapVers(minVers),
			NewestVersion_: wrapVers(newest),
		},
	}
	defer func() {
		cfg.Data.Client.ClientVersion_ = nil
	}()

	var nag lcl.UnifiedNagRes
	x.runCmdToJSON(t, &nag, "test", "get-device-nag")

	// No nags since we don't have a user yet to check against the server
	require.Equal(t, 0, len(nag.Nags))

	newUserWithAgentAtVHost(t, x, 0)
	merklePoke(t)

	type assertNagTypeOpts struct {
		rateLimit bool
	}

	assertNagType := func(typ lcl.NagType, opts *assertNagTypeOpts) {
		var rl bool
		if opts != nil && opts.rateLimit {
			rl = true
		}
		args := []string{"test", "get-device-nag"}
		if rl {
			args = append(args, "--rate-limit")
		}
		x.runCmdToJSON(t, &nag, args...)
		if typ != lcl.NagType_None {
			require.Equal(t, 1, len(nag.Nags))
			n0 := nag.Nags[0]
			typ2, err := n0.GetT()
			require.NoError(t, err)
			require.Equal(t, typ, typ2)
		} else {
			require.Equal(t, 0, len(nag.Nags))
		}
	}

	assertNagType(lcl.NagType_ClientVersionCritical, nil)

	cfg.Data.Client.ClientVersion_.MinVersion_ = wrapVers(core.CurrentClientVersion)

	assertNagType(lcl.NagType_TooFewDevices, nil)

	var res lcl.BackupHESP
	x.runCmdToJSON(t, &res, "backup", "new")
	merklePoke(t)

	assertNagType(lcl.NagType_ClientVersionUpgradeAvailable, nil)

	// no snooze unless we ask for a rate-limit
	assertNagType(lcl.NagType_ClientVersionUpgradeAvailable, nil)

	// with a rate-limit, should not get another nag right away
	assertNagType(lcl.NagType_None, &assertNagTypeOpts{rateLimit: true})

	// but without rate-limit, still get the nag
	assertNagType(lcl.NagType_ClientVersionUpgradeAvailable, nil)

	// snooze the nag
	x.runCmd(t, nil, "notify", "snooze-upgrade-nag")

	// nag-free situation
	assertNagType(lcl.NagType_None, nil)

	cfg.Data.Client.ClientVersion_.NewestVersion_.Patch++

	// we get a nag for the new version even if we snoozed the old one
	assertNagType(lcl.NagType_ClientVersionUpgradeAvailable, nil)
}
