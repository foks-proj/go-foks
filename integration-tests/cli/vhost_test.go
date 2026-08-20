// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestVhostSimpleSignup(t *testing.T) {
	defer common.DebugEntryAndExit()()

	env := globalTestEnv
	merklePoke(t)
	tvh := env.VHostInit(t, "bozo")

	agentOpts := agentOpts{dnsAliases: []proto.Hostname{tvh.Hostname}}

	x := newTestAgentWithOpts(t, agentOpts)
	x.runAgent(t)
	defer x.stop(t)

	// It's OK to reuse a yubi since we don't have any other
	// signups on this virtual host.
	uis := libclient.UIs{
		Signup: newMockSignupUI().
			withServer(tvh.ProbeAddr).
			withForceYubiReuse(),
	}
	x.runCmdWithUIs(t, uis, "--simple-ui", "signup")

	var st lcl.AgentStatus
	x.runCmdToJSON(t, &st, "status")
	require.Equal(t, len(st.Users), 1)
	require.Equal(t, st.Users[0].Info.Fqu.HostID, tvh.HostID.Id)

	// now try a provision up onto Y.
	y := newTestAgentWithOpts(t, agentOpts)
	y.runAgent(t)
	defer y.stop(t)

	runProvisionOnAgents(
		t,
		provOpts{
			enterHespOnX: true,
			x:            x,
			y:            y,
			noSignup:     true,
			probeAddr:    &tvh.ProbeAddr,
		},
	)

	y.runCmdToJSON(t, &st, "status")
	require.Equal(t, len(st.Users), 1)
	require.Equal(t, st.Users[0].Info.Fqu.HostID, tvh.HostID.Id)

	// Refresh the vhost's public zone via WritePublicZoneForVHost (the
	// engine behind `foks-tool write-public-zone --vhost`). First doctor the
	// stored zone the way a naive refresh would (nil hostname map, so
	// services get the config's external addresses rather than the vhost's
	// own hostname), then check the refresh restores the vhost-shaped zone.
	m := env.MetaContext().WithHostID(&tvh.HostID)

	zoneServices := func() []proto.TCPAddr {
		spz, err := shared.LoadPublicZone(m)
		require.NoError(t, err)
		pz, err := spz.Inner.AllocAndDecode(core.DecoderFactory{})
		require.NoError(t, err)
		return []proto.TCPAddr{
			pz.Services.Probe, pz.Services.Reg, pz.Services.User,
			pz.Services.MerkleQuery, pz.Services.KvStore, pz.Services.Realtime,
		}
	}
	requireAllAtHost := func(hn proto.Hostname) {
		for _, addr := range zoneServices() {
			require.Equal(t, hn.Normalize(), addr.Hostname().Normalize())
		}
	}

	requireAllAtHost(tvh.Hostname)

	ioer, err := m.PrivateHostKeyIOer(tvh.HostID.Id, proto.EntityType_HostMetadataSigner)
	require.NoError(t, err)
	hk, err := shared.ReadHostKey(m.Ctx(), ioer)
	require.NoError(t, err)
	err = shared.StorePublicZoneWithProbe(m, *hk, nil)
	require.NoError(t, err)

	// the doctored zone must actually differ, or the refresh proves nothing
	require.NotEqual(t,
		tvh.Hostname.Normalize(),
		zoneServices()[0].Hostname().Normalize(),
	)

	err = shared.WritePublicZoneForVHost(env.MetaContext(), tvh.Hostname)
	require.NoError(t, err)
	requireAllAtHost(tvh.Hostname)
}
