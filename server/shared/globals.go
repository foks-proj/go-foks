// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/sso"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/keybase/clockwork"
	"github.com/mattn/go-isatty"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type GlobalContext struct {
	sync.RWMutex
	log         *zap.SugaredLogger
	logCfg      zap.Config
	cfg         Config
	dbpools     map[DbType](*pgxpool.Pool)
	typ         proto.ServerType
	hostchain   *HostChain
	didShutdown bool
	clock       clockwork.Clock

	// payment interface
	stripe Striper

	// Vanity domain builder helper; access to DNS resolution,
	// posting new CNAMEs to the DNS system, and getting certs
	// from Let's Encrypt. For most use cases, it's fine to
	// leave this nil.
	vanityHelper VanityHelper

	// In test, we might set autocert doer to be a mock. This variable is only
	// ever read by the autocert service. But even in test, we want to check the
	// plumbing of web vanity management calling through to the autocert service.
	autocertDoer AutocertDoer

	// In a world we we can serve multiple virtual host IDs with one
	// server, this is the map from HostID -> ShortId. We keep this
	// map warm in memory but can fallback to DB on a cache miss.
	hostIDMap *HostIDMap

	// the HostID we're set to run as. Doesn't change once it's
	// set on startup. Note that HostKeyChain also specifies
	// a host ID, but we'll ignore that one and use this one.
	// If this value is specified on initialization, then
	// we'll use it. Otherwise, we'll read from CLI args,
	// or from the config file, in that order. Note that this is the
	// hostID of the "base host". Each base service process might be
	// acting on behalf of multiple virtual hosts, but that host context
	// is captured in the hostID in the MetaContext, which varies according
	// to callstack and call context.
	hostID core.HostID

	// On prod, might be Amazon SQS, etc. In test, it's the queue service.
	qs QueueServer

	// A lot of services might need to poll the Merkle Query service. Available here
	merkleGCli *BackendClient

	// true if we're in testing or not. Testing here means "running integration/lib" tests or something
	// simiilar.
	testing bool

	// For Oauth2, cache configuration sets we don't have to spam info endpoint repeatedly
	oauth2ConfigSet *sso.OAuth2IdPConfigSet

	// Manage X509 CAs and Certs
	certMgr CertManager

	// When testing, services will get random ports assigned at runtime; we store them here.
	// In prod, this map won't be very intersting, since all of the services won't be
	// running in the same process.
	testPorts              map[proto.ServerType]int
	testMultiUseInviteCode rem.InviteCode

	// For testing versioning scenarios
	TestWarner         func(s string, args ...interface{})
	TestCheckArgHeader func(ctx context.Context, h proto.Header) error
	TestMakeResHeader  func() proto.Header

	// In test, this might be something other than a passthrough.
	cnameResolver core.CNameResolver

	// KV-Sharder helps map a party to its sharded databases.
	// Keeps an in-memory mapping to avoid an extra DB hit.
	kvShardMgr *KVShardMgr
}

type GlobalContextOpts struct {
	Stripe  Striper
	Testing bool
}

func (g *GlobalContext) ShuntLogToFile(path string) error {
	g.Lock()
	defer g.Unlock()
	if path == "" {
		return core.BadArgsError("path cannot be empty")
	}
	g.logCfg.OutputPaths = []string{path}
	return g.swapLog()
}

func NewGlobalContext(opts *GlobalContextOpts) *GlobalContext {
	cfg := zap.NewProductionConfig()
	if isatty.IsTerminal(os.Stdout.Fd()) {
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	var stripe Striper
	var testing bool
	if opts != nil {
		stripe = opts.Stripe
		testing = opts.Testing
	}
	if stripe == nil {
		stripe = NewRealStripe()
	}

	log := zap.Must(cfg.Build())
	return &GlobalContext{
		log:             log.Sugar(),
		logCfg:          cfg,
		cfg:             &EmptyConfig{},
		dbpools:         make(map[DbType](*pgxpool.Pool)),
		testPorts:       make(map[proto.ServerType]int),
		cnameResolver:   core.PassthroughCNameResolver{},
		hostIDMap:       NewHostIDMap(),
		stripe:          stripe,
		clock:           clockwork.NewRealClock(),
		kvShardMgr:      NewKVShardMgr(),
		testing:         testing,
		oauth2ConfigSet: sso.NewOAuth2ConfigSet(),
	}
}

func (g *GlobalContext) CertMgr() CertManager {
	g.RLock()
	defer g.RUnlock()
	return g.certMgr
}

func (g *GlobalContext) Clock() clockwork.Clock {
	g.RLock()
	defer g.RUnlock()
	return g.clock
}

func (g *GlobalContext) SetClock(c clockwork.Clock) {
	g.Lock()
	defer g.Unlock()
	if c == nil {
		c = clockwork.NewRealClock()
	}
	g.clock = c
}

func (g *GlobalContext) SetVanityHelper(v VanityHelper) {
	g.Lock()
	defer g.Unlock()
	g.vanityHelper = v
}

func (g *GlobalContext) SetAutocertDoer(a AutocertDoer) {
	g.Lock()
	defer g.Unlock()
	g.autocertDoer = a
}

func (g *GlobalContext) AutocertDoer() AutocertDoer {
	g.Lock()
	defer g.Unlock()
	ret := g.autocertDoer
	if ret == nil {
		ret = NewRealAutocertDoer()
	}
	return ret
}

func (g *GlobalContext) AutocertDoerAtAddr(ctx context.Context, port proto.Port) (AutocertDoer, error) {
	doer := g.AutocertDoer()
	cfg, err := g.Config().AutocertServiceConfig(ctx)
	if err != nil {
		return nil, err
	}
	ba := cfg.BindAddr()
	if port != 0 {
		ba = proto.NewTCPAddr(ba.Hostname(), port)
	}
	doer.SetBindAddr(ba)
	return doer, nil
}

func (g *GlobalContext) VanityHelper() VanityHelper {
	g.RLock()
	defer g.RUnlock()
	return g.vanityHelper
}

func (g *GlobalContext) KVShardMgr() *KVShardMgr {
	g.RLock()
	defer g.RUnlock()
	return g.kvShardMgr
}

func (g *GlobalContext) Now() time.Time {
	g.RLock()
	defer g.RUnlock()
	if g.clock == nil {
		return time.Now()
	}
	return g.clock.Now()
}

func (g *GlobalContext) HostIDMap() *HostIDMap {
	g.RLock()
	defer g.RUnlock()
	return g.hostIDMap
}

func (g *GlobalContext) Stripe() Striper {
	g.RLock()
	defer g.RUnlock()
	return g.stripe
}

func (g *GlobalContext) Log() *zap.SugaredLogger {
	g.RLock()
	defer g.RUnlock()
	return g.log
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

func (g *GlobalContext) Shutdown() {
	if g == nil {
		return
	}
	g.Lock()
	defer g.Unlock()
	if g.didShutdown {
		return
	}
	g.didShutdown = true
	_ = g.log.Sync()
	if g.merkleGCli != nil {
		g.merkleGCli.Close()
	}
}

func (g *GlobalContext) SetHostChain(hkc *HostChain) {
	g.Lock()
	defer g.Unlock()
	g.hostchain = hkc
	g.hostID = hkc.HostID()
}

func (g *GlobalContext) HostChain() *HostChain {
	g.RLock()
	defer g.RUnlock()
	return g.hostchain
}

func (g *GlobalContext) GetServerType() proto.ServerType {
	g.RLock()
	defer g.RUnlock()
	return g.typ
}

func (g *GlobalContext) TakeServerConfig(s Server, listener net.Listener) {
	g.Lock()
	defer g.Unlock()
	g.typ = s.ServerType()
	g.testPorts[g.typ] = port(listener)
}

func (g *GlobalContext) swapLog() error {
	newLog, err := g.logCfg.Build()
	if err != nil {
		return err
	}
	oldLog := g.log
	g.log = newLog.Sugar()
	_ = oldLog.Sync()
	return nil
}

type GlobalCLIConfigOpts struct {
	ConfigPath   core.Path
	LogLevel     string
	ForceJSONLog bool
	LogRemoteIP  bool
	ShortHostID  uint
	SkipNetwork  bool
	SkipConfig   bool
	DNSAliases   []string
	Refork       bool
	ReforkChild  bool
	NoStartupMsg bool
}

func (g GlobalCLIConfigOpts) GetConfigPath() core.Path {
	if g.ConfigPath != "" {
		return g.ConfigPath
	}
	cp := os.Getenv("FOKS_CONFIG_PATH")
	if cp != "" {
		return core.Path(cp)
	}
	return ""
}

func (g *GlobalContext) QueueServer(ctx context.Context) QueueServer {
	g.RLock()
	defer g.RUnlock()
	return g.qs
}

func (g *GlobalContext) ConfigureHostID(ctx context.Context) (core.HostID, error) {
	g.Lock()
	defer g.Unlock()

	err := g.readHostIDFromDB(ctx)
	if err != nil {
		return g.hostID, err
	}

	return g.hostID, nil
}

func (g *GlobalContext) setHostID(ctx context.Context, cliVal uint) error {

	if !g.hostID.IsZero() {
		return nil
	}

	if cliVal != 0 {
		g.hostID.Short = core.ShortHostID(cliVal)
		return nil
	}

	if g.cfg != nil {
		var err error
		g.hostID, err = g.cfg.HostID()
		if err != nil {
			return err
		}
		return nil
	}

	return core.HostIDNotFoundError{}
}

func (g *GlobalContext) configureLogLevel(s string) error {
	lev, err := zap.ParseAtomicLevel(s)
	if err != nil {
		return err
	}
	g.logCfg.Level = lev
	err = g.swapLog()
	if err != nil {
		return err
	}
	return nil
}

func (g *GlobalContext) GetTestPort(t proto.ServerType) int {
	var ret int
	g.RLock()
	defer g.RUnlock()
	if !g.testing {
		return 0
	}
	ret = g.testPorts[t]
	return ret
}

func (g *GlobalContext) ListenParams(ctx context.Context, typ proto.ServerType) (BindAddr, proto.TCPAddr, *tls.Config, error) {
	return g.Config().ListenParams(ctx, typ, g.GetTestPort(typ))
}

func (g *GlobalContext) configureConfigFile(ctx context.Context, s core.Path) error {

	cfg := NewConfigJSonnet(s)
	err := cfg.Load(ctx)
	if err != nil {
		return err
	}
	g.cfg = cfg

	if logConfig := cfg.LogConfig(ctx); logConfig != nil {
		g.logCfg = *logConfig
		err = g.swapLog()
		if err != nil {
			return err
		}
	}
	cfg.logHook = g.getLog
	return nil
}

func (g *GlobalContext) getLog() *zap.Logger {
	g.RLock()
	defer g.RUnlock()
	return g.log.Desugar()
}

func (g *GlobalContext) configDNSAliases(ctx context.Context, cmd []string) error {
	var rslvr core.CNameResolver
	if len(cmd) > 0 {
		lst, err := core.ParseCNameAliases(cmd)
		if err != nil {
			return err
		}
		rslvr = core.NewSimpleCNameResolver().WithObjs(lst)
	} else {
		var err error
		rslvr, err = g.cfg.GetDNSAliases(ctx)
		if err != nil {
			return err
		}
	}
	if rslvr != nil {
		g.cnameResolver = rslvr
	}
	return nil
}

func (g *GlobalContext) Configure(ctx context.Context, opts GlobalCLIConfigOpts) error {
	g.Lock()
	defer g.Unlock()

	if opts.ForceJSONLog {
		g.logCfg.Encoding = "json"
		err := g.swapLog()
		if err != nil {
			return err
		}
	}

	if opts.LogLevel != "" {
		err := g.configureLogLevel(opts.LogLevel)
		if err != nil {
			return err
		}
	}

	cp := opts.GetConfigPath()
	if cp != "" && !opts.SkipConfig {

		err := g.configureConfigFile(ctx, cp)
		if err != nil {
			return err
		}
		ca, err := NewCertVaultCKS(ctx, g)
		if err != nil {
			return err
		}
		g.certMgr = ca
	} else {
		g.certMgr = &EmptyCertManager{}
	}

	if opts.SkipNetwork {
		return nil
	}

	return g.configureNetwork(ctx, opts)
}

func (g *GlobalContext) configureNetwork(ctx context.Context, opts GlobalCLIConfigOpts) error {

	err := g.configureQueueService(ctx)
	if err != nil {
		return err
	}

	err = g.configDNSAliases(ctx, opts.DNSAliases)
	if err != nil {
		return err
	}

	err = g.setHostID(ctx, opts.ShortHostID)
	if err != nil {
		return err
	}

	return nil
}

func (g *GlobalContext) SetTestMultiUseInviteCode(p rem.InviteCode) {
	g.Lock()
	defer g.Unlock()
	g.testMultiUseInviteCode = p
}

func (g *GlobalContext) TestMultiUseInviteCode() rem.InviteCode {
	g.Lock()
	defer g.Unlock()
	return g.testMultiUseInviteCode
}

func (g *GlobalContext) configureQueueService(ctx context.Context) error {
	g.qs = &NullQueueServer{}
	qcfg, err := g.cfg.QueueServiceConfig(ctx)
	if err != nil {
		return err
	}
	if qcfg != nil && qcfg.Native {
		g.qs = NewNativeQueueService(g, g.typ)
	}
	return nil
}

func (g *GlobalContext) Config() Config {
	g.RLock()
	defer g.RUnlock()
	return g.cfg
}

// LogRemoteIP is true if we're supposed to log remote IPs out to logfile
// Right now it can only be set via Config file, but perhaps there should
// be a notion of "in-mmemory" configuration that cna be hot-enabled.
func (g *GlobalContext) LogRemoteIP(ctx context.Context) bool {
	ret, _ := g.Config().LogRemoteIP(ctx)
	return ret
}

// RPCLogOptions reads parsed RPC log options out of the configuration file.
// It can return an error and useful data. Errors of bad flags might be warned
// but there is not need to die.
func (g *GlobalContext) RPCLogOptions(ctx context.Context) (rpc.LogOptions, error) {
	return g.Config().RPCLogOptions(ctx)
}

func (g *GlobalContext) ShortHostID() core.ShortHostID {
	g.RLock()
	defer g.RUnlock()
	return g.hostID.Short
}

func (g *GlobalContext) HostID() core.HostID {
	g.RLock()
	defer g.RUnlock()
	return g.hostID
}

func (g *GlobalContext) SetShortHostID(i core.ShortHostID) {
	g.RLock()
	defer g.RUnlock()
	g.hostID.Short = i
}

func (g *GlobalContext) getAutocertGCli(ctx context.Context, requestor proto.ServerType) *BackendClient {
	g.Lock()
	defer g.Unlock()
	return NewBackendClient(g, proto.ServerType_Autocert, requestor, nil)
}

func (g *GlobalContext) getMerkleGCli(ctx context.Context, reqestor proto.ServerType) *BackendClient {
	g.Lock()
	defer g.Unlock()
	if g.merkleGCli == nil {
		g.merkleGCli = NewBackendClient(g, proto.ServerType_MerkleQuery, reqestor, nil)
	}
	return g.merkleGCli

}

func (g *GlobalContext) AutocertCli(ctx context.Context) (*infra.AutocertClient, func(), error) {
	bec := g.getAutocertGCli(ctx, g.typ)
	gcli, err := bec.Cli(ctx)
	if err != nil {
		return nil, nil, err
	}
	ret := infra.AutocertClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	closer := func() { bec.Close() }
	return &ret, closer, nil
}

func (g *GlobalContext) MerkleCli(ctx context.Context) (*rem.MerkleQueryClient, error) {
	gcli, err := g.getMerkleGCli(ctx, g.typ).Cli(ctx)
	if err != nil {
		return nil, err
	}
	m := NewMetaContext(ctx, g)
	ret := core.NewMerkleQueryClient(gcli, m)
	return &ret, nil
}

func (g *GlobalContext) WarnwWithContext(
	ctx context.Context,
	msg string,
	keysAndValues ...interface{},
) {
	// Test that warnings are generated properly, we hook in here
	if g.TestWarner != nil {
		g.TestWarner(msg, keysAndValues...)
	}
	core.WarnwWithContext(ctx, g.getLog(), msg, keysAndValues...)
}
