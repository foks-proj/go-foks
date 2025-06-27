// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/engine"
	kvStore "github.com/foks-proj/go-foks/server/kv-store"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/app"
	"github.com/stretchr/testify/require"
)

// Only used in tests, but we don't put it in _test.go, since we want other libraries
// to be able to use it.
//
// The dependency order is shared <- engine <- integration_tests, so be careful not
// to break that or to introduce a cycle.
type TestEnv struct {
	ShutdownFn          func() error
	regSrv              engine.RegServer
	userSrv             engine.UserServer
	queueSrv            engine.QueueServer
	internalCaSrv       engine.InternalCAServer
	probeSrv            engine.ProbeServer
	merkleQuerySrv      engine.MerkleQueryServer
	merkleBatcherSrv    *engine.MerkleBatcherServer
	merkleBuilderSrv    *engine.MerkleBuilderServer
	merkleSignerSrv     *engine.MerkleSignerServer
	beaconSrv           engine.BeaconServer
	kvStoreSrv          kvStore.Server
	webAdminSrv         *app.WebServer
	autocertSrv         engine.AutocertServer
	quotaSrv            engine.QuotaServer
	config              *shared.JSonnetTemplate
	stripe              *FakeStripe
	G                   *shared.GlobalContext
	x509m               *X509Material
	dir                 core.Path
	wildcardVhostDomain string
	nVHosts             int
	vHostMap            map[int]*core.HostIDAndName
	hostname            proto.Hostname
	ydisp               *libyubi.Dispatch
}

func (e *TestEnv) Dir() core.Path           { return e.dir }
func (e *TestEnv) Hostname() proto.Hostname { return e.hostname }
func (e *TestEnv) SetHostname(h proto.Hostname) {
	e.hostname = h
}

func VHostnameIReturnErr(i int, tot int, d string) (proto.Hostname, error) {
	if d == "" {
		return "", errors.New("empty domain")
	}
	if i >= tot {
		return "", errors.New("i >= tot")
	}
	return proto.Hostname(string([]byte{'a' + byte(i)}) + "." + d), nil

}

func VHostnameI(t *testing.T, i int, tot int, d string) proto.Hostname {
	ret, err := VHostnameIReturnErr(i, tot, d)
	require.NoError(t, err)
	return ret
}

func (e *TestEnv) VHostnameI(t *testing.T, i int) proto.Hostname {
	return VHostnameI(t, i, e.nVHosts, e.wildcardVhostDomain)
}

func (e *TestEnv) VHostMakeI(t *testing.T, i int) *core.HostIDAndName {
	if e.vHostMap == nil {
		e.vHostMap = make(map[int]*core.HostIDAndName)
	}
	ret := e.vHostMap[i]
	if ret != nil {
		return ret
	}
	ret = e.VHostMake(t, e.VHostnameI(t, i))
	e.vHostMap[i] = ret
	return ret
}

func (e *TestEnv) VHostDomain(t *testing.T, h string) proto.Hostname {
	require.NotEqual(t, "", e.wildcardVhostDomain)
	return proto.Hostname(h + "." + e.wildcardVhostDomain)
}

func (t *TestEnv) RegSrv() *engine.RegServer {
	return &t.regSrv
}

func (t *TestEnv) UserSrv() *engine.UserServer {
	return &t.userSrv
}

func (t *TestEnv) ProbeSrv() *engine.ProbeServer {
	return &t.probeSrv
}

func (t *TestEnv) BeaconSrv() *engine.BeaconServer {
	return &t.beaconSrv
}

func (t *TestEnv) QuotaSrv() *engine.QuotaServer {
	return &t.quotaSrv
}

func (t *TestEnv) MerkleBatcherSrv() *engine.MerkleBatcherServer {
	return t.merkleBatcherSrv
}

func (t *TestEnv) MerkleBuilderSrv() *engine.MerkleBuilderServer {
	return t.merkleBuilderSrv
}

func (t *TestEnv) MerkleSignerSrv() *engine.MerkleSignerServer {
	return t.merkleSignerSrv
}

func (t *TestEnv) MerkleQuerySrv() *engine.MerkleQueryServer {
	return &t.merkleQuerySrv
}

func (t *TestEnv) KvStoreSrv() *kvStore.Server {
	return &t.kvStoreSrv
}

func (t *TestEnv) X509Material() *X509Material {
	return t.x509m
}

func (e *TestEnv) YubiDisp(t *testing.T) *libyubi.Dispatch {
	if e.ydisp == nil {
		var err error
		e.ydisp, err = libyubi.AllocDispatchTest()
		require.NoError(t, err)
	}
	return e.ydisp
}

func (t *TestEnv) AllServers() []shared.Server {
	return []shared.Server{
		&t.regSrv, &t.userSrv, &t.queueSrv, &t.internalCaSrv, &t.probeSrv, &t.merkleQuerySrv,
		t.merkleBatcherSrv, t.merkleBuilderSrv, t.merkleSignerSrv, &t.beaconSrv,
		&t.kvStoreSrv, &t.quotaSrv, t.webAdminSrv, &t.autocertSrv,
	}
}

func NewTestEnv() *TestEnv {
	return &TestEnv{
		merkleBatcherSrv: engine.NewMerkleBatcherServer(),
		merkleBuilderSrv: engine.NewMerkleBuilderServer(),
		merkleSignerSrv:  engine.NewMerkleSignerServer(),
		webAdminSrv:      app.NewWebServer().WithTest(),
	}
}

func (t *TestEnv) Shutdown() error {
	return t.ShutdownFn()
}

func randomHostPartErr() (string, error) {
	return core.RandomBase36String(6)
}

func (e *TestEnv) Fork(t *testing.T, opts SetupOpts) *TestEnv {
	ret := NewTestEnv()

	// Make a new config file but copy over the Dbs from our
	// base image
	config := shared.JSonnetTemplate{}
	config.Listen = make(map[string]shared.ListenConfigJSON)
	config.Db = e.config.Db
	config.DbKVShards = e.config.DbKVShards
	opts.ForkFrom = &config
	opts.ForkFromHostname = e.Hostname()

	err := ret.Setup(opts)
	require.NoError(t, err)
	return ret
}

func (t *TestEnv) Setup(opts SetupOpts) error {
	err := opts.Init()
	if err != nil {
		return err
	}
	t.wildcardVhostDomain = opts.WildcardVhostDomain
	t.nVHosts = opts.NVHosts
	t.hostname = opts.PrimaryHostname

	if t.hostname.IsZero() {
		return core.InternalError("hostname not set")
	}

	var smr *ServerMainRes
	servers := t.AllServers()

	dbs := shared.ManageDBsConfig{
		Dbs: shared.AllDBs,
		KVShards: []shared.KVShardDescriptor{
			{
				Name:   "foks_kv_store_1",
				Index:  proto.KVShardID(1),
				Active: true,
			},
			{
				Name:   "foks_kv_store_2",
				Index:  proto.KVShardID(2),
				Active: true,
			},
		},
	}

	t.ShutdownFn, smr, err = ServerMain(
		servers,
		dbs,
		opts,
	)
	if err != nil {
		if t.ShutdownFn != nil {
			_ = t.ShutdownFn()
		}
		t.G.Shutdown()
		return err
	}
	t.G = smr.G
	t.x509m = smr.X509M
	t.config = smr.Config
	t.dir = smr.Dir
	t.stripe = smr.Stripe
	return nil
}

func (t *TestEnv) MetaContext() shared.MetaContext {
	return shared.NewMetaContextBackground(t.G)
}

func testCli[T any](
	t *testing.T,
	m shared.MetaContext,
	serverType proto.ServerType,
	mk func(*core.RpcClient) *T,
) (*T, func() error) {
	opts := core.NewRpcClientOpts()
	opts.Timeout = time.Hour // Give us time to debug!
	bec := shared.NewBackendClient(
		m.G(),
		serverType,
		proto.ServerType_Tools,
		opts,
	)
	cli, err := bec.Cli(m.Ctx())
	require.NoError(t, err)

	return mk(cli), bec.Close
}

func TestMerkleBatcherCli(t *testing.T, m shared.MetaContext) (*proto.MerkleBatcherClient, func() error) {
	return testCli(t, m, proto.ServerType_MerkleBatcher, func(cli *core.RpcClient) *proto.MerkleBatcherClient {
		return &proto.MerkleBatcherClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
}

func TestMerkleBuilderCli(t *testing.T, m shared.MetaContext) (*proto.MerkleBuilderClient, func() error) {
	return testCli(t, m, proto.ServerType_MerkleBuilder, func(cli *core.RpcClient) *proto.MerkleBuilderClient {
		return &proto.MerkleBuilderClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
}

func TestMerkleSignerCli(t *testing.T, m shared.MetaContext) (*proto.MerkleSignerClient, func() error) {
	return testCli(t, m, proto.ServerType_MerkleSigner, func(cli *core.RpcClient) *proto.MerkleSignerClient {
		return &proto.MerkleSignerClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
}

func TestMerkleQueryCli(t *testing.T, m shared.MetaContext) (*rem.MerkleQueryClient, func() error) {
	return testCli(t, m, proto.ServerType_MerkleQuery, func(cli *core.RpcClient) *rem.MerkleQueryClient {
		ret := core.NewMerkleQueryClient(cli, m)
		return &ret
	})
}

func TestQuotaSrvCli(t *testing.T, m shared.MetaContext) (*infra.QuotaClient, func() error) {
	return testCli(t, m, proto.ServerType_Quota, func(cli *core.RpcClient) *infra.QuotaClient {
		return &infra.QuotaClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
}

func PokeMerklePipelineInTest(t *testing.T, m shared.MetaContext) {
	btch, btchClean := TestMerkleBatcherCli(t, m)
	defer func() {
		err := btchClean()
		require.NoError(t, err)
	}()
	err := btch.Poke(m.Ctx())
	require.NoError(t, err)
	build, buildClean := TestMerkleBuilderCli(t, m)
	defer func() {
		err := buildClean()
		require.NoError(t, err)
	}()
	err = build.Poke(m.Ctx())
	require.NoError(t, err)
	sig, sigClean := TestMerkleSignerCli(t, m)
	defer func() {
		err := sigClean()
		require.NoError(t, err)
	}()
	err = sig.Poke(m.Ctx())
	require.NoError(t, err)
}

func (e *TestEnv) PokeMerkle(t *testing.T) {
	PokeMerklePipelineInTest(t, e.MetaContext())
}

func (e *TestEnv) DirectMerklePoke() error {
	ctx := context.Background()
	err := e.merkleBatcherSrv.Poke(ctx)
	if err != nil {
		return err
	}
	err = e.merkleBuilderSrv.Poke(ctx)
	if err != nil {
		return err
	}
	err = e.merkleSignerSrv.Poke(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (e *TestEnv) DirectMerklePokeInTest(t *testing.T) {
	err := e.DirectMerklePoke()
	require.NoError(t, err)
}

func (e *TestEnv) DirectDoubleMerklePokeInTest(t *testing.T) {
	e.DirectMerklePokeInTest(t)
	e.DirectMerklePokeInTest(t)
}

func TestExtHostname(t *testing.T, m shared.MetaContext) proto.Hostname {
	_, ext, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Probe)
	require.NoError(t, err)
	return ext.Hostname()
}

func (w *TestEnv) BeaconRegister(t *testing.T) {
	err := w.BeaconRegisterReturnErr()
	require.NoError(t, err)
}

func (w *TestEnv) BeaconRegisterReturnErr() error {
	m := w.MetaContext()
	_, ext, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Probe)
	if err != nil {
		return err
	}
	hostname := ext.Hostname()
	addr, ok := w.probeSrv.ListenerAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("cannot find listen addr")
	}
	port := proto.Port(addr.Port)
	hostID := m.G().HostID().Id
	err = shared.BeaconRegisterSrv(m, hostname, port, hostID, time.Hour)
	return err

}

func (w *TestEnv) VHostProbeAddr(t *testing.T, host proto.Hostname) proto.TCPAddr {
	addr, ok := w.probeSrv.ListenerAddr().(*net.TCPAddr)
	require.True(t, ok)
	port := proto.Port(addr.Port)
	return proto.NewTCPAddr(host, port)
}

func (e *TestEnv) DirectMerklePokeForLeafCheck(t *testing.T) {

	err := (func() error {
		ctx := context.Background()
		err := e.merkleBatcherSrv.Poke(ctx)
		if err != nil {
			return err
		}
		err = e.merkleBuilderSrv.Poke(ctx)
		if err != nil {
			return err
		}
		err = e.merkleSignerSrv.Poke(ctx)
		if err != nil {
			return err
		}
		err = e.merkleBatcherSrv.Poke(ctx)
		if err != nil {
			return err
		}
		return nil
	})()

	require.NoError(t, err)
}

type LoopUntilStop struct {
	f  func()
	ch chan struct{}
}

func NewLoopUntilStop(f func()) *LoopUntilStop {
	return &LoopUntilStop{
		f:  f,
		ch: make(chan struct{}),
	}
}

func (b *LoopUntilStop) Run() {
	for {
		select {
		case <-b.ch:
			return
		default:
		}
		b.f()
	}
}

func (b *LoopUntilStop) Stop() {
	b.ch <- struct{}{}
}

func (e *TestEnv) Beacon(t *testing.T) *shared.GlobalService {
	m := e.MetaContext()
	_, ext, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Beacon)
	require.NoError(t, err)
	rootCAs, _, err := m.G().Config().ProbeRootCAs(m.Ctx())
	require.NoError(t, err)
	return &shared.GlobalService{
		Addr: ext,
		CAs:  rootCAs,
	}
}
func (e *TestEnv) VHostMake(
	t *testing.T,
	hostname proto.Hostname,
) *core.HostIDAndName {
	return e.VHostMakeWithOpts(t, hostname, shared.VHostInitOpts{
		Config: proto.HostConfig{
			Typ: proto.HostType_BigTop,
		},
	})
}

func (e *TestEnv) VHostMakeWithOpts(
	t *testing.T,
	hostname proto.Hostname,
	opts shared.VHostInitOpts,
) *core.HostIDAndName {

	ctx := context.Background()
	m := shared.NewMetaContext(ctx, e.G)

	e.AddDNSAlias(t, hostname)

	gs := e.Beacon(t)
	opts.Beacon = gs
	opts.MerklePoke = func() error {
		PokeMerklePipelineInTest(t, m)
		return nil
	}

	// Generate a cert for the probe servre using our fake RootPKI CA.
	// In prod, we'll of course get a Cert for let's encrypt.
	opts.MakeProbeCert = func(m shared.MetaContext) error {
		return EmulateLetsEncrypt(m, []proto.Hostname{hostname}, nil,
			e.x509m.ProbeCA,
			proto.CKSAssetType_RootPKIFrontendX509Cert,
		)
	}

	vhostId, err := shared.VHostInit(m, hostname, opts)
	require.NoError(t, err)
	err = CopyMultiUseInviteCode(m, vhostId.Short)
	require.NoError(t, err)

	if opts.Icr == proto.InviteCodeRegime_CodeOptional {
		m = m.WithHostID(vhostId)
		err = SetInviteCodeOptional(m)
		require.NoError(t, err)
	}

	return &core.HostIDAndName{
		HostID:   *vhostId,
		Hostname: hostname,
	}
}

type TestVHost struct {
	Hostname  proto.Hostname
	ProbeAddr proto.TCPAddr
	HostID    core.HostID
}

func (e *TestEnv) VHostInit(
	t *testing.T,
	host string,
) *TestVHost {
	full := e.VHostDomain(t, host)
	hid := e.VHostMake(t, full)
	probe := e.VHostProbeAddr(t, full)
	return &TestVHost{
		Hostname:  full,
		ProbeAddr: probe,
		HostID:    hid.HostID,
	}
}

func (e *TestEnv) AddDNSAlias(t *testing.T, hn proto.Hostname) {

	cnr := e.G.CnameResolver()
	scnr, ok := cnr.(*core.SimpleCNameResolver)
	if cnr == nil || !ok {
		scnr = core.NewSimpleCNameResolver()
		e.G.SetCnameResolver(scnr)
	}
	scnr.Add(hn, "localhost")
}

func RandomPlanName(t *testing.T) string {
	var sffx [8]byte
	err := core.RandomFill(sffx[:])
	require.NoError(t, err)
	nm := "plan-" + hex.EncodeToString(sffx[:])
	return nm
}

func RandomDomain(t *testing.T) string {
	rd, err := core.RandomDomain()
	require.NoError(t, err)
	return rd
}

func (t *TestEnv) HttpTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("only tcp supported")
			}
			raw, port, err := net.SplitHostPort(addrStr)
			if err != nil {
				return nil, err
			}
			host := proto.Hostname(raw)
			newHost := t.G.CnameResolver().Resolve(proto.Hostname(host))
			if newHost != "" {
				host = newHost
			}
			return net.Dial(network, net.JoinHostPort(string(host), port))
		},
	}
}

func (t *TestEnv) HttpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: t.HttpTransport(),
		Timeout:   timeout,
	}
}
