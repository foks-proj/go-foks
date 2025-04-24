// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/sso"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/clockwork"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Agenter interface{}

type RpcClienter interface {
	rpc.GenericClient
	Close()
}

type GlobalContextMode int

const (
	GlobalContextModeNormal GlobalContextMode = iota
	GlobalContextModeGitRemhoteHelper
)

func (m GlobalContextMode) NeedSecrets() bool {
	switch m {
	case GlobalContextModeNormal:
		return true
	case GlobalContextModeGitRemhoteHelper:
		return false
	default:
		return true
	}
}

// Global context fields used in testing
type TestingGlobalContext struct {
	sync.Mutex
	loopbackSignError  error
	selfProvisionCrash error
}

func (t *TestingGlobalContext) SetLoopbackSignError(e error) {
	t.Lock()
	defer t.Unlock()
	t.loopbackSignError = e
}

func (t *TestingGlobalContext) LoopbackSignError() error {
	t.Lock()
	defer t.Unlock()
	return t.loopbackSignError
}

func (t *TestingGlobalContext) SetSelfProvisionCrash(e error) {
	t.Lock()
	defer t.Unlock()
	t.selfProvisionCrash = e
}

func (t *TestingGlobalContext) SelfProvisionCrash() error {
	t.Lock()
	defer t.Unlock()
	return t.selfProvisionCrash
}

type GlobalContext struct {
	sync.Mutex
	name string
	ss   *SecretStore

	cfg           *Config
	service       Dialer
	loopbackAgent Agenter
	dbs           *DBs
	rootCAs       *x509.CertPool
	uis           UIs
	merkleEracer  func(ctx context.Context, e error) error // In test, a synchronous hook to erase races
	clock         clockwork.Clock

	shutdownHook func()

	// Currently active user, and other users loaded in
	userMu sync.RWMutex
	curr   *UserContext
	users  map[core.LocalUserIndex](*UserContext)

	discovery *chains.DiscoveryMgr

	logMu sync.RWMutex
	log   *zap.Logger

	// Might eventually want to hide this behind an interface, but for now, go with this.
	yubiDispatch *libyubi.Dispatch

	// For testing we can resolve "foo.bar.org" -> "localhost"
	// so that way we can test what it's like to have multiple
	// hostnames.
	cnameResolver core.CNameResolver

	// For testing, we can set a network conditioner
	// to simulate bad network conditions.
	netCon core.NetworkConditioner

	// For Oauth2, cache configuration sets we don't have to spam info endpoint repeatedly
	oauth2ConfigSet *sso.OAuth2IdPConfigSet

	mode GlobalContextMode

	deviceNameCache DeviceNameCache

	// Other fields that are only set in test
	Testing *TestingGlobalContext
}

func (d *GlobalContext) DeviceNameCache() *DeviceNameCache {
	d.Lock()
	defer d.Unlock()
	return &d.deviceNameCache
}

func (g *GlobalContext) PushShutdownHook(h func()) {
	g.Lock()
	defer g.Unlock()
	hook := g.shutdownHook
	if hook == nil {
		g.shutdownHook = h
	} else {
		g.shutdownHook = func() {
			hook()
			h()
		}
	}
}

func (g *GlobalContext) Now() time.Time {
	g.Lock()
	defer g.Unlock()
	if g.clock == nil {
		return time.Now()
	}
	return g.clock.Now()
}

func (g *GlobalContext) Clock() clockwork.Clock {
	g.Lock()
	defer g.Unlock()
	return g.clock
}

func (g *GlobalContext) SetClock(c clockwork.Clock) {
	g.Lock()
	defer g.Unlock()
	g.clock = c
}

func (g *GlobalContext) CnameResolver() core.CNameResolver {
	g.Lock()
	defer g.Unlock()
	return g.cnameResolver
}

func (g *GlobalContext) SetCnameResolver(c core.CNameResolver) {
	g.Lock()
	defer g.Unlock()
	g.cnameResolver = c
}

func (g *GlobalContext) SetNetworkConditioner(c core.NetworkConditioner) {
	g.Lock()
	defer g.Unlock()
	g.netCon = c
}

func (g *GlobalContext) NetworkConditioner() core.NetworkConditioner {
	g.Lock()
	defer g.Unlock()
	return g.netCon
}

func (g *GlobalContext) DiscoveryMgr() *chains.DiscoveryMgr {
	g.Lock()
	defer g.Unlock()
	return g.discovery
}

func (g *GlobalContext) UIs() UIs {
	g.Lock()
	defer g.Unlock()
	return g.uis
}

func (g *GlobalContext) SetUIs(u UIs) {
	g.Lock()
	defer g.Unlock()
	g.uis = u
}

func (g *GlobalContext) Shutdown() {
	g.Lock()
	defer g.Unlock()
	_ = g.log.Sync()
	hook := g.shutdownHook
	if hook == nil {
		return
	}
	g.shutdownHook = nil
	hook()
}

func (g *GlobalContext) UserInfos() []proto.UserInfo {
	g.userMu.RLock()
	defer g.userMu.RUnlock()
	var ret []proto.UserInfo
	for _, u := range g.users {
		ret = append(ret, u.Info)
	}
	return ret
}

func (g *GlobalContext) AllUsers() []*UserContext {
	g.userMu.RLock()
	defer g.userMu.RUnlock()
	var ret []*UserContext
	for _, u := range g.users {
		ret = append(ret, u)
	}
	return ret
}

func (g *GlobalContext) Log() *zap.Logger {
	g.logMu.RLock()
	defer g.logMu.RUnlock()
	return g.log
}

func NewGlobalContext() *GlobalContext {
	cfg := zap.NewProductionConfig()
	if isatty.IsTerminal(os.Stdout.Fd()) {
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	log := zap.Must(cfg.Build())
	return &GlobalContext{
		name:            "cmd",
		log:             log,
		cfg:             &Config{},
		users:           make(map[core.LocalUserIndex](*UserContext)),
		dbs:             NewDBs(),
		cnameResolver:   core.PassthroughCNameResolver{},
		discovery:       chains.NewDiscoveryMgr(&DiscoveryEngine{}),
		mode:            GlobalContextModeNormal,
		oauth2ConfigSet: sso.NewOAuth2ConfigSet(),
		Testing:         &TestingGlobalContext{},
	}
}

func (g *GlobalContext) SetMode(m GlobalContextMode) {
	g.Lock()
	defer g.Unlock()
	g.mode = m
}

func (g *GlobalContext) SetName(s string) {
	g.Lock()
	defer g.Unlock()
	g.name = s
}

func (g *GlobalContext) OAuth2IdPConfigSet() *sso.OAuth2IdPConfigSet {
	g.Lock()
	defer g.Unlock()
	return g.oauth2ConfigSet
}

func (g *GlobalContext) Setup(ctx context.Context, cmd *cobra.Command) error {
	return g.cfg.Setup(ctx, cmd)
}

func (g *GlobalContext) ThinLog(ctx context.Context) core.ThinLogger {
	return core.NewThinLog(ctx, g.Log())
}

func (g *GlobalContext) configureSecrets(ctx context.Context) error {
	if !g.mode.NeedSecrets() {
		return nil
	}

	path, err := g.cfg.SecretKeyFile()
	if err != nil {
		return nil
	}
	g.ss = NewSecretStore(path)
	err = g.ss.LoadOrCreate(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (g *GlobalContext) SecretStore() *SecretStore {
	g.Lock()
	defer g.Unlock()
	return g.ss
}

func (g *GlobalContext) configureLogging(ctx context.Context) error {
	level, err := g.cfg.LogLevel()
	if err != nil {
		return err
	}
	cfg := zap.NewProductionConfig()
	cfg.Sampling = nil // don't drop spammy logs on the client side
	plev, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return err
	}
	cfg.Level = plev
	out, err := g.cfg.LogsOutFile(g.name)
	if err != nil {
		return err
	}
	errLog, err := g.cfg.LogsErrFile(g.name)
	if err != nil {
		return err
	}
	cfg.OutputPaths = []string{out}
	cfg.ErrorOutputPaths = []string{errLog}
	log := zap.Must(cfg.Build())
	tmp := g.log
	_ = tmp.Sync()
	g.logMu.Lock()
	g.log = log
	g.logMu.Unlock()
	return nil
}

func (g *GlobalContext) configureCnameResolver(ctx context.Context) error {
	rslvr, err := g.cfg.GetDNSAliases()
	if err != nil {
		return err
	}
	if rslvr != nil {
		g.cnameResolver = rslvr
	}
	return nil
}

func assertRPCConstantUniqueness() {
	allUniques := rpc.AllUniques()
	seen := make(map[uint64]bool)
	for _, u := range allUniques {
		if seen[u] {
			panic(fmt.Sprintf("duplicate RPC unique: 0x%x", u))
		}
		seen[u] = true
	}
}

func (g *GlobalContext) Configure(ctx context.Context) error {
	g.Lock()
	defer g.Unlock()

	assertRPCConstantUniqueness()

	err := g.cfg.Configure(ctx, g.ThinLog(ctx))
	if err != nil {
		return err
	}

	err = g.configureLogging(ctx)
	if err != nil {
		return err
	}

	err = g.configureSecrets(ctx)
	if err != nil {
		return err
	}

	err = g.configureCnameResolver(ctx)
	if err != nil {
		return err
	}
	err = g.configureYubi(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (g *GlobalContext) YubiDispatch() *libyubi.Dispatch {
	g.Lock()
	defer g.Unlock()
	return g.yubiDispatch
}

func (g *GlobalContext) SetYubiDispatch(d *libyubi.Dispatch) {
	g.Lock()
	defer g.Unlock()
	g.yubiDispatch = d
}

func (g *GlobalContext) configureYubi(ctx context.Context) error {

	// In test, for instance, we sometimes prefill this field.
	if g.yubiDispatch != nil {
		return nil
	}

	seed, err := g.cfg.GetMockYubiSeed()
	if err != nil {
		return err
	}
	yd, err := libyubi.AllocDispatch(seed)
	if err != nil {
		return err
	}
	g.yubiDispatch = yd
	return nil
}

func (g *GlobalContext) Cfg() *Config {
	g.Lock()
	defer g.Unlock()
	return g.cfg
}

func (g *GlobalContext) SetLoopback(a Agenter, d Dialer) {
	g.loopbackAgent = a
	g.service = d
}

func (g *GlobalContext) SetService(d Dialer) {
	g.service = d
}

func (g *GlobalContext) ProbeRootCAs(ctx context.Context) (*x509.CertPool, error) {
	g.Lock()
	defer g.Unlock()
	if g.rootCAs != nil {
		return g.rootCAs, nil
	}
	ret, _, err := g.cfg.ProbeRootCAs(ctx)
	if err != nil {
		return nil, err
	}
	g.rootCAs = ret
	return ret, nil
}

func (g *GlobalContext) ConnectToAgent(ctx context.Context) (net.Conn, error) {
	if g.service == nil {
		return nil, core.ConfigError("no service available")
	}
	return g.service.Dial(ctx)
}

func (g *GlobalContext) ConnectToAgentCli(ctx context.Context) (*rpc.Client, func(), error) {
	c, err := g.ConnectToAgent(ctx)
	if err != nil {
		return nil, nil, err
	}
	return makeCli(ctx, c)
}

func (g *GlobalContext) ConnectToRemoteHost(ctx context.Context, addr proto.TCPAddr, cas *x509.CertPool, clientCert *tls.Certificate) (*tls.Conn, error) {
	tlsConfig := tls.Config{
		RootCAs: cas,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := tls.Dial("tcp", string(addr), &tlsConfig)
	if err != nil {
		return nil, err
	}
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (g *GlobalContext) ConnectToRemoteHostCli(ctx context.Context, addr proto.TCPAddr, cas *x509.CertPool, clientCert *tls.Certificate) (*rpc.Client, func(), error) {
	conn, err := g.ConnectToRemoteHost(ctx, addr, cas, clientCert)
	if err != nil {
		return nil, nil, err
	}
	return makeCli(ctx, conn)
}

func makeCli(ctx context.Context, conn net.Conn) (*rpc.Client, func(), error) {
	retFn := func() { conn.Close() }
	lf := rpc.NewSimpleLogFactory(rpc.NilLogOutput{}, nil)
	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	xp := rpc.NewTransport(ctx, conn, lf, nil, wef, core.RpcMaxSz)
	gcli := rpc.NewClient(xp, nil, nil)
	return gcli, retFn, nil
}

func (g *GlobalContext) Probe(ctx context.Context, h proto.HostID, timeout time.Duration) (*chains.Probe, error) {
	m := NewMetaContext(ctx, g)
	return g.discovery.Probe(m, chains.ProbeArg{HostID: h, Timeout: timeout})
}

func (g *GlobalContext) ProbeWithAddr(ctx context.Context, h proto.HostID, addr proto.TCPAddr, timeout time.Duration) (*chains.Probe, error) {
	m := NewMetaContext(ctx, g)
	return g.discovery.Probe(m, chains.ProbeArg{HostID: h, Addr: addr, Timeout: timeout})
}

func (g *GlobalContext) ProbeByAddr(ctx context.Context, addr proto.TCPAddr, timeout time.Duration) (*chains.Probe, error) {
	return NewMetaContext(ctx, g).ProbeByAddr(addr, timeout)
}

func (g *GlobalContext) ResolveHostID(ctx context.Context, hid proto.HostID, opts *chains.ResolveOpts) (*chains.ResolveRes, error) {
	return NewMetaContext(ctx, g).ResolveHostID(hid, opts)
}

type MerkleConfig struct {
	Eracer func(ctx context.Context, e error) error // In test, a synchronous hook to erase races
	Cfg    MerkleRaceRetryConfig
}

func (g *GlobalContext) SetMerkleEracer(eracer func(ctx context.Context, e error) error) {
	g.Lock()
	defer g.Unlock()
	g.merkleEracer = eracer
}

func (g *GlobalContext) MerkleRaceConfig() (*MerkleConfig, error) {
	g.Lock()
	defer g.Unlock()
	cfg, err := g.cfg.MerkleRaceRetryConfig()
	if err != nil {
		return nil, err
	}

	tmp := *cfg

	// If we have an eracer hook, at least 3 tries.
	if g.merkleEracer != nil && tmp.NumRetries == 0 {
		tmp.NumRetries = 3
	}

	return &MerkleConfig{
		Eracer: g.merkleEracer,
		Cfg:    tmp,
	}, nil
}
