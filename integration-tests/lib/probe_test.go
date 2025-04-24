// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func pumpSigchain(t *testing.T, m shared.MetaContext, n int) {
	dir, err := os.MkdirTemp("", "hostkeys")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	hk := m.G().HostChain()

	for i := range n {

		typ := proto.EntityType_HostMetadataSigner
		fn := core.Path(filepath.Join(dir, fmt.Sprintf("host.mds-%d.key", i)))
		err = hk.NewKey(m, fn, typ)
		require.NoError(t, err)

		common.PokeMerklePipelineInTest(t, m)
	}
}

func makeCliMetaContext(t *testing.T) (libclient.MetaContext, func()) {
	cm := libclient.NewMetaContextMain()
	tmp, err := os.MkdirTemp("", "foks_libclient_test")
	require.NoError(t, err)
	cm.G().Cfg().TestSetHomeCLIFlag(tmp)
	cm.G().Cfg().TestDisableSecretKeyEncryption()
	err = cm.Configure()
	require.NoError(t, err)
	return cm, func() { os.RemoveAll(tmp) }
}

func makeProbe(t *testing.T, env *common.TestEnv, sm shared.MetaContext, cm libclient.MetaContext, poke bool) *chains.Probe {
	addr := env.ProbeSrv().ListenerAddr().String()
	rootCAs, _, err := sm.G().Config().ProbeRootCAs(sm.Ctx())
	require.NoError(t, err)

	if poke {
		common.PokeMerklePipelineInTest(t, sm)
	}

	probe, err := cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs,
		Addr:    proto.TCPAddr(addr),
		Fresh:   true,
	})

	require.NoError(t, err)
	return probe
}

func TestProbe(t *testing.T) {
	env := globalTestEnv.Fork(t, common.SetupOpts{
		MerklePollWait: time.Hour,
	})
	defer func() {
		_ = env.ShutdownFn()
	}()
	m := env.MetaContext()

	// Setup the client-side context
	cm, clean := makeCliMetaContext(t)
	defer clean()

	addr := env.ProbeSrv().ListenerAddr().String()
	rootCAs, _, err := m.G().Config().ProbeRootCAs(m.Ctx())
	require.NoError(t, err)

	common.PokeMerklePipelineInTest(t, m)

	probe, err := cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs,
		Addr:    proto.TCPAddr(addr),
		Fresh:   true,
	})
	require.NoError(t, err)

	// We can pass our frontend root CAs in two ways -- via the server config file
	// and via the hostchain. The latter is the preferred method, but let's check
	// that we get equality. Note that currently, we are sending back the hardcoded CA
	// in the config, and also the one we store in the DB via CKS. We're should eventually
	// deprecate and remove the former.
	cas, err := probe.Chain().RootCACertPool()
	require.NoError(t, err)
	var hn proto.Hostname
	tmp, err := m.G().CertMgr().Pool(m, nil, proto.CKSAssetType_HostchainFrontendCA, hn)
	require.NoError(t, err)
	require.NotNil(t, cas)
	require.True(t, tmp.Equal(cas))

	// Now pump some new links and check that we can verify it's a subchain
	// of the old.
	pumpSigchain(t, m, 3)

	probe, err = cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs,
		Addr:    proto.TCPAddr(addr),
		Fresh:   true,
	})
	require.NoError(t, err)

	// Also try to load via hostID
	_, err = cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs,
		HostID:  probe.Chain().HostID(),
		Fresh:   true,
	})
	require.NoError(t, err)
}

func TestProbeMerkleRace(t *testing.T) {

	env := globalTestEnv.Fork(t, common.SetupOpts{
		MerklePollWait: time.Hour,
	})
	defer func() {
		_ = env.Shutdown()
	}()
	m := env.MetaContext()

	// Setup the client-side context
	cm := libclient.NewMetaContextMain()
	tmp, err := os.MkdirTemp("", "foks_agent_test_")
	require.NoError(t, err)
	cm.G().Cfg().TestSetHomeCLIFlag(tmp)
	err = cm.Configure()
	require.NoError(t, err)

	addr := env.ProbeSrv().ListenerAddr().String()
	rootCAs, _, err := m.G().Config().ProbeRootCAs(m.Ctx())
	require.NoError(t, err)

	common.PokeMerklePipelineInTest(t, m)

	mkProbe := func() *chains.Probe {
		pr, er := cm.G().DiscoveryMgr().MakeProbe(cm, chains.ProbeArg{
			Timeout: time.Hour,
			RootCAs: rootCAs,
			Addr:    proto.TCPAddr(addr),
			Fresh:   true,
		})
		require.NoError(t, er)
		return pr
	}

	// Set up 2 racing probes for the same host.
	p1 := mkProbe()
	p2 := mkProbe()

	waitCh := make(chan struct{})
	doneProbeCh := make(chan struct{})
	doneCh := make(chan error)
	p1.TestWaitCh = waitCh
	p1.TestDoneProbeCh = doneProbeCh

	// Run p1 in the background
	go func() {
		doneCh <- p1.Run(cm)
	}()

	// Wait til the slow guy makes his first network call
	<-doneProbeCh

	// Advance the root a few times, and run a fast probe.
	pumpSigchain(t, m, 3)
	err = p2.Run(cm)
	require.NoError(t, err)

	// Now unblock the slow guy
	waitCh <- struct{}{}

	// Now wait for p1 to be done. It should have worked, but it should have had to retry.
	err = <-doneCh
	require.NoError(t, err)
	require.True(t, p1.TestRetryOnMerkleRace)

}

func TestHostPin(t *testing.T) {

	rd := RandomDomain(t)
	hn := proto.Hostname("probe." + rd)

	setupEnv := func() (shared.MetaContext, proto.TCPAddr, *x509.CertPool, func() error) {
		env := globalTestEnv.Fork(t, common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{hn},
			},
		})
		m := env.MetaContext()

		tcpAddr, ok := env.ProbeSrv().ListenerAddr().(*net.TCPAddr)
		require.True(t, ok)
		port := tcpAddr.Port
		rootCAs, _, err := m.G().Config().ProbeRootCAs(m.Ctx())
		require.NoError(t, err)
		common.PokeMerklePipelineInTest(t, m)
		addr := proto.NewTCPAddr(hn, proto.Port(port))

		return m, addr, rootCAs, env.Shutdown
	}

	m1, addr1, rootCAs1, shutdown1 := setupEnv()
	defer func() {
		_ = shutdown1()
	}()

	// Setup the client-side context
	cm := libclient.NewMetaContextMain()
	tmp, err := os.MkdirTemp("", "foks_agent_test_")
	require.NoError(t, err)
	cm.G().Cfg().TestSetHomeCLIFlag(tmp)
	cm.G().SetCnameResolver(m1.G().CnameResolver())
	err = cm.Configure()
	require.NoError(t, err)

	// The first probe will hit the first server instance
	_, err = cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs1,
		Addr:    addr1,
		Fresh:   true,
	})
	require.NoError(t, err)

	m2, addr2, rootCAs2, shutdown2 := setupEnv()
	defer func() {
		_ = shutdown2()
	}()

	// Second probe hits the second server instance, which has stole the
	// first server's hostname, but is not advertising a different HostID.
	// So it should make a "pin" failure.
	_, err = cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs2,
		Addr:    addr2,
		Fresh:   true,
	})

	require.Error(t, err)
	require.Equal(t, core.HostPinError(
		proto.HostPinError{
			Host: hn,
			Old:  m1.G().HostID().Id,
			New:  m2.G().HostID().Id,
		},
	), err)
}

func TestProbeByHostID(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	mu := tew.NewClientMetaContext(t, u)
	vHostID := tew.VHostMakeI(t, 0)

	_, err := mu.Probe(chains.ProbeArg{
		HostID:  vHostID.Id,
		Timeout: time.Hour,
		Fresh:   true,
	})
	require.NoError(t, err)
}
