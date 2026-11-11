// Copyright (c) 2026 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

// Only GetLatestRootFromCache is reachable in the same-epoch disagreement.
// Any unexpected access to the other embedded methods fails the test instead
// of manufacturing a successful network or persistence result.
type r2RootCache struct {
	merkle.AgentLocalStorage
	root proto.MerkleRoot
}

func (c *r2RootCache) GetLatestRootFromCache(context.Context) (*proto.MerkleRoot, error) {
	return &c.root, nil
}

// The probe is hydrated through the existing offline identity-cache path.
// It is a fixture for a previously cached host, not an assertion that the
// synthetic host identity itself has undergone online verification.
type r2Discovery struct {
	chains.DiscoveryInterface
	host  proto.HostID
	agent *merkle.Agent
	zone  proto.PublicZone
}

func (d *r2Discovery) MakeRpcClient(chains.MetaContext, proto.TCPAddr, *x509.CertPool, *tls.Certificate, *core.RpcClientOpts) (*core.RpcClient, error) {
	return nil, core.NewConnectError("offline probe fixture", errors.New("offline"))
}

func (d *r2Discovery) LoadHostchainFromDB(chains.MetaContext, proto.HostID) (*core.Hostchain, error) {
	return core.NewHostchainSkeleton(d.host, proto.LinkHash{}, proto.Seqno(1)), nil
}

func (d *r2Discovery) LoadPublicZoneFromDB(chains.MetaContext, proto.HostID) (*proto.PublicZone, error) {
	return &d.zone, nil
}

func (d *r2Discovery) MakeMerkleAgent(chains.MetaContext, proto.HostID, proto.TCPAddr, *x509.CertPool) (*merkle.Agent, error) {
	return d.agent, nil
}

type r2TeamRPC struct {
	rem.TeamLoaderInterface
	reply    rem.TeamChain
	requests chan rem.LoadTeamChainArg
}

func (s *r2TeamRPC) LoadTeamChain(_ context.Context, a rem.LoadTeamChainArg) (rem.TeamChain, error) {
	s.requests <- a
	return s.reply, nil
}

func (s *r2TeamRPC) ErrorWrapper() func(error) proto.Status { return core.ErrorToStatus }

// This is a test-only loopback RPC peer, not the FOKS server or its integration
// environment. It mirrors lib/core/rpc_client_test.go's TLS transport setup.
func r2RPCClient(t *testing.T, g *GlobalContext, handler rem.TeamLoaderInterface) *core.RpcClient {
	t.Helper()
	caKey, caDER, err := core.GenCAInMem()
	require.NoError(t, err)
	key, certDER, err := core.MakeCertificateInMem([]string{"127.0.0.1"}, caKey, caDER)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
	})
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	serverErrors := make(chan error, 1)
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			serverErrors <- err
			return
		}
		defer conn.Close()
		stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stopClose()
		wrapper := rem.TeamLoaderMakeGenericErrorWrapper(core.ErrorToStatus)
		xp := rpc.NewTransport(ctx, conn, rpc.NewSimpleLogFactory(rpc.NilLogOutput{}, nil), nil, wrapper, core.RpcMaxSz)
		server := rpc.NewServer(xp, wrapper)
		if err := server.RegisterV2(rem.TeamLoaderProtocol(handler)); err != nil {
			serverErrors <- err
			return
		}
		<-server.Run()
	}()
	opts := core.NewRpcClientOpts()
	opts.Timeout = 5 * time.Second
	opts.NumConnectAttempts = 1
	client := NewRpcClient(g, proto.TCPAddr(listener.Addr().String()), pool, nil, opts)
	t.Cleanup(func() {
		cancel()
		client.Shutdown()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("loopback team RPC peer did not stop")
		}
		select {
		case err := <-serverErrors:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("loopback team RPC peer: %v", err)
			}
		default:
		}
	})
	return client
}

// R2 in docs/offline_verified_reads.md requires verification before persistence.
// A rejected refresh must preserve the cached snapshot, even without new links.
func TestTeamSnapshotUnchangedOnMerkleRootFailure(t *testing.T) {
	ctx := context.Background()
	g := NewGlobalContext()
	g.Cfg().TestSetHomeCLIFlag(t.TempDir())
	g.Cfg().TestSetLogTargets("stdout", "stderr")
	g.Cfg().TestSetTestingMode()
	require.NoError(t, g.Configure(ctx))
	t.Cleanup(g.Shutdown)
	clock := clockwork.NewFakeClockAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	g.SetClock(clock)
	m := NewMetaContext(ctx, g)
	hostEntity, err := proto.EntityType_Host.MakeEntityID(make([]byte, proto.EntityType_Host.Len()-1))
	require.NoError(t, err)
	host, err := hostEntity.ToHostID()
	require.NoError(t, err)
	userEntity, err := proto.EntityType_User.MakeEntityID(make([]byte, proto.EntityType_User.Len()-1))
	require.NoError(t, err)
	uid, err := userEntity.ToUID()
	require.NoError(t, err)
	au := &UserContext{Info: proto.UserInfo{Fqu: proto.FQUser{Uid: uid, HostID: host}}}
	fqt := proto.FQTeam{Team: mkTestTeamID(t, proto.EntityType_NamedTeam), Host: host}
	permissionToken := proto.PermissionToken{}
	arg := LoadTeamArg{Team: fqt, As: au.FQU().FQParty(), SrcRole: team.UserSrcRole, Tok: &permissionToken}
	name, err := core.NewNameBundle("before")
	require.NoError(t, err)
	seed := lcl.TeamChainState{
		Fqt:        fqt,
		Tail:       proto.HidingChainer{Base: proto.BaseChainer{Seqno: proto.Seqno(2)}},
		Name:       proto.NameAndSeqnoBundle{B: name},
		VerifiedAt: proto.ExportTime(clock.Now()),
	}
	scoper := au.FQU()
	require.NoError(t, m.DbPut(DbTypeSoft, PutArg{Scope: &scoper, Typ: lcl.DataType_TeamChainState, Key: arg, Val: &seed}))
	var before lcl.TeamChainState
	beforeMtime, err := m.DbGet(&before, DbTypeSoft, &scoper, lcl.DataType_TeamChainState, arg)
	require.NoError(t, err)
	require.Equal(t, seed, before)

	v1 := proto.MerkleRootV1{Epno: proto.MerkleEpno(1)}
	trusted := proto.NewMerkleRootWithV1(v1)
	v1.RootNode[0] = 1
	rejected := proto.NewMerkleRootWithV1(v1)
	cache := &r2RootCache{root: trusted}
	agent := merkle.NewAgent(m, cache, nil, host)
	di := &r2Discovery{host: host, agent: agent, zone: proto.PublicZone{Services: proto.PublicServices{Probe: "127.0.0.1:443", MerkleQuery: "127.0.0.1:443"}}}
	probe, err := chains.NewDiscoveryMgr(di).MakeProbe(m, chains.ProbeArg{HostID: host, Addr: "127.0.0.1:443", DefPort: 443, RootCAs: x509.NewCertPool()})
	require.NoError(t, err)
	require.NoError(t, probe.Run(m))
	au.SetHomeServer(probe)
	peer := &r2TeamRPC{reply: rem.TeamChain{TeamnameUtf8: "after", Merkle: proto.MerklePathsCompressed{Root: rejected}}, requests: make(chan rem.LoadTeamChainArg, 1)}
	au.userGCli = r2RPCClient(t, g, peer)
	clock.Advance(time.Hour)

	loaded, err := NewTeamLoader(au, arg).Run(m)
	require.Nil(t, loaded)
	var loaderError core.ChainLoaderError
	require.ErrorAs(t, err, &loaderError)
	var verificationError core.MerkleVerifyError
	require.ErrorAs(t, err, &verificationError)
	require.Equal(t, core.MerkleVerifyError("hash mismatch at epno 1"), verificationError)
	select {
	case request := <-peer.requests:
		require.Equal(t, proto.Seqno(3), request.Start)
	default:
		t.Fatal("the real loader did not request a snapshot refresh")
	}
	var after lcl.TeamChainState
	afterMtime, err := m.DbGet(&after, DbTypeSoft, &scoper, lcl.DataType_TeamChainState, arg)
	require.NoError(t, err)
	require.Equal(t, before, after, "failed Merkle verification must not change the persisted team snapshot")
	require.Equal(t, beforeMtime, afterMtime, "failed Merkle verification must not rewrite the snapshot row")
}
