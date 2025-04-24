// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"crypto/x509"
	"net"
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

func (w TestEnvWrapper) NewTestUserAtVHost(t *testing.T, id *core.HostIDAndName) *TestUser {
	return w.NewTestUserAtVHostWithOpts(t, id, &TestUserOpts{RealTreeRoot: true, HostID: id})
}

func (w TestEnvWrapper) NewTestUserAtVHostWithOpts(
	t *testing.T,
	id *core.HostIDAndName,
	opts *TestUserOpts,
) *TestUser {
	user, err := w.NewTestUserAtVHostWithOptsAndErr(t, id, opts)
	require.NoError(t, err)
	return user
}

func (w TestEnvWrapper) NewTestUserAtVHostWithOptsAndErr(
	t *testing.T,
	id *core.HostIDAndName,
	opts *TestUserOpts,
) (*TestUser, error) {
	m := w.MetaContext()
	rcli, closeFn, err := newRegClientFromEnv(m, w.TestEnv)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	err = rcli.SelectVHost(m.Ctx(), id.Id)
	if err != nil {
		return nil, err
	}
	ret, err := GenerateNewTestUserWithRegCliAndErr(t, w.TestEnv, rcli, opts)
	if err != nil {
		return nil, err
	}
	ret.vhost = id
	return ret, nil
}

func (u *TestUser) getCurrentTreeRoot(t *testing.T, m shared.MetaContext) proto.TreeRoot {
	return getCurrentTreeRootWithHostID(t, m, &u.host)
}

// For hosting various "vanity" domains like "foks.okta.com" and "foks.nike.com"
// on the same host, we use a differnt certificate management solution: we put certs
// like 'foks.okta.com.cert' and 'foks.okta.com.key' in a directory, and the appropriate
// cert if picked up by GetCertificate based on the SNI. This test tests that mechanism.
func TestVHostCertsDir(t *testing.T) {
	defer common.DebugEntryAndExit()()

	var hostnames []proto.Hostname
	for i := 0; i < 3; i++ {
		d := "foks." + RandomDomain(t)
		hostnames = append(hostnames, proto.Hostname(d))
	}

	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: hostnames,
			},
			UseCertDirs: true,
		},
	)
	defer tew.Shutdown()

	// Now try to create a user at each of the hostnames.
	for _, h := range hostnames {
		vhostId := tew.VHostMake(t, h)
		tew.NewTestUserAtVHost(t, vhostId)
	}

}

func TestVHostsHappyPath(t *testing.T) {
	defer common.DebugEntryAndExit()()

	domain := RandomDomain(t)
	p1 := proto.Hostname("cutiepie." + domain)
	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{p1},
			},
		},
	)
	defer tew.Shutdown()
	vhostId := tew.VHostMake(t, p1)
	tew.NewTestUserAtVHost(t, vhostId)
}

func TestVhostIFromTestEnvBeta(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	vHostID := tew.VHostMakeI(t, 0)
	require.NotNil(t, vHostID)
	tew.NewTestUserAtVHost(t, vHostID)
}

func CAPoolForHostname(t *testing.T, m shared.MetaContext, hostname proto.Hostname) *x509.CertPool {
	rootCAs, err := m.G().CertMgr().Pool(m, nil, proto.CKSAssetType_HostchainFrontendCA, hostname)
	require.NoError(t, err)
	return rootCAs
}

func TestVhostReconnect(t *testing.T) {
	defer common.DebugEntryAndExit()()

	domain := RandomDomain(t)
	p1 := proto.Hostname("cutiepie." + domain)
	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			MerklePollWait: time.Hour,
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{p1},
			},
		},
	)
	defer tew.Shutdown()
	vhostId := tew.VHostMake(t, p1)
	u := tew.NewTestUserAtVHost(t, vhostId)
	tew.DirectMerklePoke(t)

	m := tew.MetaContext()
	cmc := tew.NewClientMetaContext(t, u)

	// Fetch the port from the listener
	port := tew.MerkleQuerySrv().Listener.Addr().(*net.TCPAddr).Port

	// Create a proto.TCPAddr from the virtual host name and the port from just above.
	addr := proto.NewTCPAddr(vhostId.Hostname, proto.Port(port))
	rootCAs := CAPoolForHostname(t, m, addr.Hostname())
	ma := libclient.NewMerkleAgent(cmc.G(), vhostId.Id, addr, rootCAs)

	mr, err := ma.GetLatestRootFromServer(cmc.Ctx())
	require.NoError(t, err)

	// It would be better to reset on the server-side, but there isn't a good way
	// to do that. So instead we just reset on the client side.
	ma.Reset()

	mr2, err := ma.GetLatestRootFromServer(cmc.Ctx())
	require.NoError(t, err)
	require.Equal(t, mr.V1(), mr2.V1())

	base := m.HostID()
	require.NotEqual(t, base.Id, vhostId.Id)

	// Ensure that we weren't getting the same base root the whole time.
	ma = libclient.NewMerkleAgent(cmc.G(), base.Id, addr, rootCAs)
	mr3, err := ma.GetLatestRootFromServer(cmc.Ctx())
	require.NoError(t, err)
	require.NotEqual(t, mr.V1(), mr3.V1())

}

func TestProbeByHostnaameAndID(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	vhostID := tew.VHostMakeI(t, 0)
	u := tew.NewTestUserAtVHost(t, vhostID)
	cm := tew.NewClientMetaContext(t, u)
	m := tew.MetaContext()
	_, probeAddr, _, err := m.G().ListenParams(cm.Ctx(), proto.ServerType_Probe)
	require.NoError(t, err)
	probeAddr, err = probeAddr.WithHostname(u.vhost.Hostname)
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		Addr:  probeAddr,
		Fresh: true,
	})
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		HostID: u.vhost.Id,
		Fresh:  true,
	})
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		HostID: u.vhost.Id,
		Addr:   probeAddr,
		Fresh:  true,
	})
	require.NoError(t, err)
	badId := u.vhost.Id
	badId[5] ^= 0x1
	_, err = cm.Probe(chains.ProbeArg{
		HostID: badId,
		Addr:   probeAddr,
		Fresh:  true,
	})
	require.Error(t, err)
	require.Equal(t, core.HostIDNotFoundError{}, err)

	probeAddr, err = probeAddr.WithHostname(tew.Hostname())
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		HostID: u.vhost.Id,
		Addr:   probeAddr,
		Fresh:  true,
	})
	require.Error(t, err)
	require.Equal(t, core.HostMismatchError{Which: "hostID"}, err)

	probeAddr, err = probeAddr.WithHostname("127.0.0.1")
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		Addr:   probeAddr,
		HostID: u.vhost.Id,
		Fresh:  true,
	})
	require.NoError(t, err)

	// A totally unkonwn hostname will map to the base hostname, which will cause a mismatch as above.
	hn := "xxx-" + tew.Hostname()
	cm.G().CnameResolver().Add(hn, "127.0.0.1")
	probeAddr, err = probeAddr.WithHostname(hn)
	require.NoError(t, err)
	_, err = cm.Probe(chains.ProbeArg{
		Addr:   probeAddr,
		HostID: u.vhost.Id,
		Fresh:  true,
	})
	require.Error(t, err)
	require.Equal(t, core.HostMismatchError{Which: "hostID"}, err)

}
