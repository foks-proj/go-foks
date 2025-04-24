// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func RandomDomain(t *testing.T) string {
	ret, err := core.RandomDomain()
	require.NoError(t, err)
	return ret
}

func TestBeaconProbe(t *testing.T) {
	domain := RandomDomain(t)
	probeHostname := proto.Hostname("probe." + domain)

	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{probeHostname},
			},
		},
	)
	defer tew.Shutdown()
	m := tew.MetaContext()
	common.PokeMerklePipelineInTest(t, m)

	_, ext, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Probe)
	require.NoError(t, err)
	hostname := ext.Hostname()
	addr, ok := tew.ProbeSrv().ListenerAddr().(*net.TCPAddr)
	require.True(t, ok)
	port := proto.Port(addr.Port)
	hostID := m.G().HostID().Id

	tester := func() {

		err = shared.BeaconRegisterSrv(m, hostname, port, hostID, time.Hour)
		require.NoError(t, err)
		ret, err := shared.BeaconLookup(m, hostID)
		require.NoError(t, err)
		require.Equal(t, ret.Hostname(), hostname)
	}

	tester()

	// Advance the root a few times
	pumpSigchain(t, m, 3)

	tester()

	hostID[5] ^= 0x01
	err = shared.BeaconRegisterSrv(m, hostname, port, hostID, time.Hour)
	require.Error(t, err)
	require.Equal(t, core.HostMismatchError{Which: "hostID"}, err)

	// return hostid to previous valid value
	hostID[5] ^= 0x01

	// Now test the client beacon library
	a := tew.NewTestUserFakeRoot(t)
	ma := tew.NewClientMetaContext(t, a)

	res, err := ma.ResolveHostID(hostID, nil)
	require.NoError(t, err)
	require.Equal(t, res.Addr.Hostname(), hostname)
	require.True(t, res.Addr.Hostname().NormEq(res.Probe.Hostname()))

}

func TestBeaconHostnames(t *testing.T) {

	domain := RandomDomain(t)
	p1 := proto.Hostname("probe." + domain)
	p2 := proto.Hostname("probe-alias." + domain)

	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{p1, p2},
			},
		},
	)
	defer tew.Shutdown()
	m := tew.MetaContext()
	common.PokeMerklePipelineInTest(t, m)

	addr, ok := tew.ProbeSrv().ListenerAddr().(*net.TCPAddr)
	require.True(t, ok)
	port := proto.Port(addr.Port)
	hostID := m.G().HostID().Id

	// It still works to connect to p1 via the alias p2, but
	// we check hostname equality in the beacon registration, and it
	// should fail.
	err := shared.BeaconRegisterSrv(m, p2, port, hostID, time.Hour)
	require.Error(t, err)
	require.Equal(t, core.HostMismatchError{Which: "hostname"}, err)

	err = shared.BeaconRegisterSrv(m, proto.Hostname(strings.ToUpper(string(p1))), port, hostID, time.Hour)
	require.NoError(t, err)

	ret, err := shared.BeaconLookup(m, hostID)
	require.NoError(t, err)
	require.Equal(t, ret.Hostname(), p1)
}
