// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type RegServerConfigJSON struct {
	UsernameReservationTimeoutSeconds Seconds        `json:"username_reservation_timeout_sec"`
	VHostMgmtAddr_                    *proto.TCPAddr `json:"vhost_mgmt_addr"`
}

type ListenConfigJSON struct {
	Port         uint16        `json:"port"`
	AutocertPort uint16        `json:"autocert_port"`
	BindAddr     string        `json:"bind_addr"`
	NoTLS        bool          `json:"no_tls"`
	ExternalAddr proto.TCPAddr `json:"external_addr"`
	RefreshMsec  Milliseconds  `json:"refresh_msec"`
}

type StripeConfigJSON struct {
	SecretKey_       StripeSecretKey      `json:"sk"`
	PublicKey_       StripePublicKey      `json:"pk"`
	WebhookSecret_   StripeWebhookSecret  `json:"whsec"`
	SessionDuration_ core.Duration        `json:"session_duration"`
	Callbacks_       *StripeCallbacksJSON `json:"callbacks"`
}

type StripeCallbacksJSON struct {
	Success_ proto.URLString `json:"success"`
	Cancel_  proto.URLString `json:"cancel"`
	Webhook_ proto.URLString `json:"webhook"`
}

type AWSCredentialsJSON struct {
	AccessKeyID_     string `json:"access_key_id"`
	SecretAccessKey_ string `json:"secret_access_key"`
	Region_          string `json:"region"`
}

type DNSZoneJSON struct {
	ZoneID_ proto.ZoneID   `json:"zone_id"`
	Domain_ proto.Hostname `json:"domain"`
}

func (d DNSZoneJSON) Domain() proto.Hostname { return d.Domain_ }
func (d DNSZoneJSON) ZoneID() proto.ZoneID   { return d.ZoneID_ }

var _ DNSZoner = (*DNSZoneJSON)(nil)

type VanityConfigJSON struct {
	DNSResolvers_ struct {
		Hosts   []string      `json:"hosts"`
		Timeout core.Duration `json:"timeout"`
	} `json:"dns_resolvers"`
	HostingDomain_ DNSZoneJSON `json:"hosting_domain"`
}

type VHostsConfigJSON struct {
	Vanity          *VanityConfigJSON   `json:"vanity"`
	CannedDomains_  []DNSZoneJSON       `json:"canned_domains"`
	PrivateKeysDir  string              `json:"private_keys_dir"`
	AWSCreds        *AWSCredentialsJSON `json:"aws_credentials"`
	DNSSetStrategy_ string              `json:"dns_set_strategy"`
}

var _ StripeConfigger = (*StripeConfigJSON)(nil)
var _ VHostsConfigger = (*VHostsConfigJSON)(nil)

type UserServerConfigJSON struct {
	BadLoginRateLimit_ RateLimit `json:"bad_login_rate_limit"`
}
type KVStoreServerConfigJSON struct {
	BlobStorePath_ string `json:"blob_store_path"`
}

type LooperConfigJSON struct {
	PollWaitMilliseconds_  Milliseconds `json:"poll_wait_msec"`
	RunlockTimeoutSeconds_ Seconds      `json:"runlock_timeout_sec"`
	WorkTimeoutSeconds_    Seconds      `json:"work_timeout_sec"`
	BatchSize_             int          `json:"batch_size"`
}

type MerkleConfigJSON struct {
	LooperConfigJSON
	SigningKey_ string `json:"signing_key"`
}

type QuotaConfigJSON struct {
	LooperConfigJSON
	Slacks         *SlacksJSON `json:"slacks"`
	Delay          Seconds     `json:"delay_sec"`
	NoPlanMaxTeams int         `json:"no_plan_max_teams"`
}

type SlacksJSON struct {
	FloatingTeam *uint64 `json:"floating_team"`
	NoPlanUser   *uint64 `json:"no_plan_user"`
	PlanUser     *uint64 `json:"plan_user"`
	PaidThrough  string  `json:"paid_through"`
}

func (s *SlacksJSON) Fill(def infra.Slacks) (*infra.Slacks, error) {
	sel := func(u *uint64, s proto.Size) proto.Size {
		if u != nil {
			return proto.Size(*u)
		}
		return s
	}

	ret := infra.Slacks{
		FloatingTeam: sel(s.FloatingTeam, def.FloatingTeam),
		NoPlanUser:   sel(s.NoPlanUser, def.NoPlanUser),
		PlanUser:     sel(s.PlanUser, def.PlanUser),
	}

	ret.PaidThrough = def.PaidThrough

	if s.PaidThrough != "" {
		val, err := time.ParseDuration(s.PaidThrough)
		if err != nil {
			return nil, err
		}
		ret.PaidThrough = proto.ExportDurationSecs(val)
	}

	return &ret, nil
}

// * Probe root CAs are used only by the probe server, to facilitate DNS->hostid lookups via root X509 PKI.
//
// In prod, the Probe CAs will just be the system CAs like digicert, etc. In test and dev, it's useful
// to use fake ones.
type RootCAsConfig struct {
	Probe core.CAPool `json:"probe"`
}

type GlobalServiceJSON struct {
	Addr proto.TCPAddr `json:"addr"` // Host:port net.TCPAddr format
	CAs  core.CAPool   `json:"CAs"`  // Root CAs to use when validating (if null then system defaults are used)
}

type WebConfigJSON struct {
	UseTLS_          bool              `json:"use_tls"`
	ExternalPort_    proto.Port        `json:"external_port"` /* external port might differ from the port we're listening on */
	SessionParam_    string            `json:"session_param"`
	SessionDuration_ core.Duration     `json:"session_duration"`
	StaticDir_       string            `json:"static_dir"`
	DebugDelay_      core.Duration     `json:"debug_delay"`
	OAuth2_          *OAuth2ConfigJSON `json:"oauth2"`
}

type AutocertServiceConfig struct {
	Batch_           *LooperConfigJSON `json:"batch"`
	BindAddr_        *proto.TCPAddr    `json:"bind_addr"`
	BindPort_        *proto.Port       `json:"bind_port"`
	ExpireIn_        *core.Duration    `json:"expire_in"`
	RefreshIn_       *core.Duration    `json:"refresh_in"`
	InitialBackoffs_ []core.Duration   `json:"initial_backoffs"`
	RefreshBackoff_  *core.Duration    `json:"refresh_backoff"`
	AcmeTimeout_     *core.Duration    `json:"acme_timeout"`
}

type OAuth2ConfigJSON struct {
	Callback_        proto.URLString `json:"callback_uri"`
	RefreshInterval_ core.Duration   `json:"refresh_interval"`
	RequestTimeout_  core.Duration   `json:"request_timeout"`
	Tiny_            proto.URLString `json:"tiny"`
}

type CKSConfigJSON struct {
	EncKeys_         []proto.CKSEncKeyString `json:"enc_keys"`
	RefreshInterval_ core.Duration           `json:"refresh_interval"`
}

type TeamConfigJSON struct {
	MaxRoles_ uint `json:"max_roles"`
}

type PKIXConfigJSON struct {
	Country_          []string `json:"country"`
	Organization_     []string `json:"organization"`
	OrganizationUnit_ []string `json:"organization_unit"`
	Locality_         []string `json:"locality"`
	Province_         []string `json:"province"`
	StreetAddress_    []string `json:"street_address"`
	PostalCode_       []string `json:"postal_code"`
}

func (p *PKIXConfigJSON) Name() pkix.Name {
	if p == nil {
		return pkix.Name{}
	}
	ret := pkix.Name{
		Country:            p.Country_,
		Organization:       p.Organization_,
		OrganizationalUnit: p.OrganizationUnit_,
		Locality:           p.Locality_,
		Province:           p.Province_,
		StreetAddress:      p.StreetAddress_,
		PostalCode:         p.PostalCode_,
	}
	return ret
}

func (a *AutocertServiceConfig) BindAddr() proto.TCPAddr {

	def := (DefaultAutocertServiceConfig{}).BindAddr()
	if a == nil {
		return def
	}
	if a.BindAddr_ != nil {
		return *a.BindAddr_
	}
	if a.BindPort_ != nil && *a.BindPort_ > 0 {
		return proto.NewTCPAddr(def.Hostname(), *a.BindPort_)
	}
	return def
}
func (a *AutocertServiceConfig) GetLooperConfigger() ServerLooperConfigger {
	if a == nil || a.Batch_ == nil {
		return DefaultAutocertServiceConfig{}.GetLooperConfigger()
	}
	return a.Batch_
}
func (a *AutocertServiceConfig) ExpireIn() time.Duration {
	if a == nil || a.ExpireIn_ == nil {
		return (DefaultAutocertServiceConfig{}).ExpireIn()
	}
	return a.ExpireIn_.Duration
}
func (a *AutocertServiceConfig) RefreshIn() time.Duration {
	if a == nil || a.RefreshIn_ == nil {
		return (DefaultAutocertServiceConfig{}).RefreshIn()
	}
	return a.RefreshIn_.Duration
}
func (a *AutocertServiceConfig) InitialBackoffs() []time.Duration {
	if a == nil || len(a.InitialBackoffs_) == 0 {
		return (DefaultAutocertServiceConfig{}).InitialBackoffs()
	}
	return core.Map(a.InitialBackoffs_, func(d core.Duration) time.Duration { return d.Duration })
}
func (a *AutocertServiceConfig) RefreshBackoff() time.Duration {
	if a == nil || a.RefreshBackoff_ == nil {
		return (DefaultAutocertServiceConfig{}).RefreshBackoff()
	}
	return a.RefreshBackoff_.Duration
}
func (a *AutocertServiceConfig) AcmeTimeout() time.Duration {
	if a == nil || a.AcmeTimeout_ == nil {
		return (DefaultAutocertServiceConfig{}).AcmeTimeout()
	}
	return a.AcmeTimeout_.Duration
}

var _ AutocertServiceConfigger = (*AutocertServiceConfig)(nil)

// JSonnetTemplateNoLog is the template for the JSON config file, minus
// the logging config. We separate it out because we can't encode
// zap.Config in JSON -- it contains fields that cannot be marshalled.
// In test we need to encode config files.
type JSonnetTemplateNoLog struct {
	Db              map[string]DbConfigJSON     `json:"db"`
	DbKVShards      []KVShardConfigJSON         `json:"db_kv_shards"`
	Listen          map[string]ListenConfigJSON `json:"listen"`
	QueueService    QueueServiceConfig          `json:"queue_service"`
	AutocertService *AutocertServiceConfig      `json:"autocert_service"`
	RootCAs         RootCAsConfig               `json:"root_CAs"`
	HostID          core.HostID                 `json:"host_id"`
	GlobalServices  struct {
		Beacon *GlobalServiceJSON `json:"beacon"`
	} `json:"global_services"`
	Settings   Settings          `json:"settings"`
	DNSAliases []core.DNSAlias   `json:"dns_aliases"`
	Stripe     *StripeConfigJSON `json:"stripe"`
	Apps       struct {
		KvStore *KVStoreServerConfigJSON `json:"kv_store"`
		Reg     *RegServerConfigJSON     `json:"reg"`
		User    *UserServerConfigJSON    `json:"user"`
		Merkle  *MerkleConfigJSON        `json:"merkle"`
		Quota   *QuotaConfigJSON         `json:"quota"`
		Web     *WebConfigJSON           `json:"web"`
	} `json:"apps"`
	CKS    *CKSConfigJSON    `json:"cks"`
	PKIX   *PKIXConfigJSON   `json:"pkix"`
	VHosts *VHostsConfigJSON `json:"vhosts"`
	Client *ClientConfigJSON `json:"client"`
	Team   *TeamConfigJSON   `json:"team"`
}

type JSonnetTemplate struct {
	JSonnetTemplateNoLog
	Log struct {
		ZapConfig *zap.Config `json:"config"`
		RemoteIPs bool        `json:"remote_ips"`
		Options   string      `json:"options"`
	} `json:"log"`
}

type ConfigJSonnet struct {
	core.ConfigJSonnet[JSonnetTemplate]
	logHook        core.LogHook
	kvShardsConfig *kvShardsConfig
}

func NewConfigJSonnet(fn core.Path) *ConfigJSonnet {
	return &ConfigJSonnet{
		ConfigJSonnet: core.ConfigJSonnet[JSonnetTemplate]{
			Path: fn,
		},
	}
}

func (s StripeConfigJSON) SecretKey() StripeSecretKey         { return s.SecretKey_ }
func (s StripeConfigJSON) PublicKey() StripePublicKey         { return s.PublicKey_ }
func (s StripeConfigJSON) WebhookSecret() StripeWebhookSecret { return s.WebhookSecret_ }
func (s StripeConfigJSON) SessionDuration() time.Duration     { return s.SessionDuration_.Duration }

func (s StripeCallbacksJSON) Success() proto.URLString { return s.Success_ }
func (s StripeCallbacksJSON) Cancel() proto.URLString  { return s.Cancel_ }
func (s StripeCallbacksJSON) Webhook() proto.URLString { return s.Webhook_ }

var _ StripeCallbacker = (*StripeCallbacksJSON)(nil)

func (s StripeConfigJSON) Callbacks() StripeCallbacker {
	if s.Callbacks_ == nil {
		return DefaultStripeCallbacks{}
	}
	return s.Callbacks_
}

func portify(
	addr string,
	givenPort int,
	overridePort int,
	onlyOverridePortIfZero bool,
) (string, error) {
	var host string
	var port int
	var portStr string
	var err error
	if strings.IndexByte(addr, ':') >= 0 {
		host, portStr, err = net.SplitHostPort(addr)
		if err != nil {
			return "", err
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", err
		}
	} else {
		host = addr
	}
	if !onlyOverridePortIfZero || port == 0 {
		if givenPort > 0 {
			port = givenPort
		} else if overridePort > 0 {
			port = overridePort
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (e *ConfigJSonnet) DbConfig(ctx context.Context, which DbType) (*pgxpool.Config, error) {
	e.RLock()
	defer e.RUnlock()

	dbTypeStr := which.ToString()

	cfg, ok := e.Data.Db[dbTypeStr]
	if !ok {
		return nil, core.ConfigError("no database found for type " + dbTypeStr)
	}
	opts, err := pgxpool.ParseConfig(cfg.ToString())
	if err != nil {
		return nil, err
	}
	err = cfg.AddRootCAs(ctx, opts)
	if err != nil {
		return nil, err
	}
	return opts, nil
}

func (e *ConfigJSonnet) KVShardsConfig(ctx context.Context) (KVShardsConfig, error) {
	e.RLock()
	defer e.RUnlock()
	if e.kvShardsConfig == nil {
		e.kvShardsConfig = newKvShardsConfig(e.ConfigJSonnet.Data.DbKVShards)
	}
	if !e.kvShardsConfig.isValid() {
		return nil, core.ConfigError("invalid/empty kv shards config")
	}
	return e.kvShardsConfig, nil
}

type ListenPackage struct {
	BindAddr      BindAddr
	ConnectToAddr proto.TCPAddr
	Tls           *tls.Config
}

type AutocertPackage struct {
	Hostname   proto.Hostname
	HostID     proto.HostID
	Port       proto.Port
	ServerType proto.ServerType
	IsVanity   bool
	Timeout    time.Duration
}

func (c *ListenConfigJSON) buildForAutocert(ctx context.Context, defPort proto.Port) (*AutocertPackage, error) {
	if c.NoTLS {
		return nil, core.ConfigError("no TLS config found")
	}
	ret := &AutocertPackage{}
	if c.ExternalAddr == "" {
		return nil, core.ConfigError("no external addr found")
	}
	ret.Hostname = proto.Hostname(c.ExternalAddr)

	// Use the defport if it's specified. If no port, default to 80,
	// which is what Let's Encrypt always checks. Still, if there is upstream
	// port remapping, it might be useful to listen on a port other than 80.
	port := proto.Port(c.AutocertPort)
	if defPort != 0 {
		port = defPort
	}
	if port == 0 {
		port = 80
	}
	ret.Port = port

	return ret, nil
}

func (c *ListenConfigJSON) build(
	ctx context.Context,
	logHook core.LogHook,
	ovveridePort int,
) (*ListenPackage, error) {
	ba, err := portify(c.BindAddr, int(c.Port), ovveridePort, false)
	if err != nil {
		return nil, err
	}
	ea, err := portify(string(c.ExternalAddr), int(c.Port), ovveridePort, true)
	if err != nil {
		return nil, err
	}
	ret := &ListenPackage{
		BindAddr:      BindAddr(ba),
		ConnectToAddr: proto.TCPAddr(ea),
	}
	if !c.NoTLS {
		ret.Tls = &tls.Config{}
	}
	return ret, nil
}

func (c *ConfigJSonnet) AutocertPackage(
	ctx context.Context,
	which proto.ServerType,
	defPort proto.Port,
) (
	*AutocertPackage,
	error,
) {
	c.RLock()
	defer c.RUnlock()
	listenTypeStr := which.ToString()
	cfg, ok := c.Data.Listen[listenTypeStr]
	if !ok {
		return nil, core.ConfigError("no listen config found for type " + listenTypeStr)
	}
	return cfg.buildForAutocert(ctx, defPort)
}

func (c *ConfigJSonnet) ListenParams(
	ctx context.Context,
	which proto.ServerType,
	ovveridePort int,
) (
	BindAddr,
	proto.TCPAddr,
	*tls.Config,
	error,
) {

	// Need an exclusive lock since we mutate the object in the case
	// of building a TLS config.
	c.Lock()
	defer c.Unlock()

	listenTypeStr := which.ToString()
	cfg, ok := c.Data.Listen[listenTypeStr]
	if !ok {
		return "", "", nil, core.ConfigError("no listen config found for type " + listenTypeStr)
	}
	pkg, err := cfg.build(ctx, c.logHook, ovveridePort)
	if err != nil {
		return "", "", nil, err
	}
	return pkg.BindAddr, pkg.ConnectToAddr, pkg.Tls, nil
}

func (e *ConfigJSonnet) LogConfig(ctx context.Context) *zap.Config {
	e.RLock()
	defer e.RUnlock()
	return e.Data.Log.ZapConfig
}

func (e *ConfigJSonnet) LogRemoteIP(ctx context.Context) (bool, error) {
	e.RLock()
	defer e.RUnlock()
	return e.Data.Log.RemoteIPs, nil
}
func (c *ConfigJSonnet) RPCLogOptions(ctx context.Context) (rpc.LogOptions, error) {
	c.RLock()
	defer c.RUnlock()
	return rpc.ParseStandardLogOptions(c.Data.Log.Options)
}

func (r *RegServerConfigJSON) UsernameReservationTimeout() time.Duration {
	sec := Seconds(60 * 60) // default = 1 hour
	if r != nil && r.UsernameReservationTimeoutSeconds > 0 {
		sec = r.UsernameReservationTimeoutSeconds
	}
	return sec.Duration()
}

func (r *RegServerConfigJSON) VHostMgmtAddr() proto.TCPAddr {
	if r == nil || r.VHostMgmtAddr_ == nil {
		return ""
	}
	return *r.VHostMgmtAddr_
}

func (c *ConfigJSonnet) RegServerConfig(ctx context.Context) (RegServerConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Apps.Reg, nil
}

func (u *UserServerConfigJSON) BadLoginRateLimit() RateLimit {
	if u != nil {
		return u.BadLoginRateLimit_
	}
	return RateLimit{
		Num:        10,
		WindowSecs: 60,
	}
}

func (c *ConfigJSonnet) UserServerConfig(ctx context.Context) (UserServerConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Apps.User, nil
}

func (k *KVStoreServerConfigJSON) BlobStorePath() string {
	if k == nil {
		return ""
	}
	return k.BlobStorePath_
}

func (c *ConfigJSonnet) KVStoreServerConfig(ctx context.Context) (KVServerConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Apps.KvStore, nil
}

func (m *LooperConfigJSON) BatchSize() int {
	ret := (DefaultLooperConfig{}).BatchSize()
	if m != nil && m.BatchSize_ > 0 {
		ret = m.BatchSize_
	}
	return ret
}
func (m *MerkleConfigJSON) SigningKey() (HostKeyIOer, error) {
	if m == nil {
		return nil, nil
	}
	return NewHostKeyFile(core.Path(m.SigningKey_)), nil
}

func (m *QuotaConfigJSON) GetNoPlanMaxTeams() int {
	if m != nil && m.NoPlanMaxTeams >= 0 {
		return m.NoPlanMaxTeams
	}
	return (DefaultQuotaServerConfig{}).GetNoPlanMaxTeams()
}
func (m *QuotaConfigJSON) GetSlacks() (*infra.Slacks, error) {
	def, err := (DefaultQuotaServerConfig{}).GetSlacks()
	if err != nil {
		return nil, err
	}
	if m == nil || m.Slacks == nil {
		return def, nil
	}
	return m.Slacks.Fill(*def)
}
func (m *QuotaConfigJSON) GetDelay() time.Duration {
	if m != nil && m.Delay > 0 {
		return m.Delay.Duration()
	}
	return (DefaultQuotaServerConfig{}).GetDelay()
}
func (m *LooperConfigJSON) WorkTimeout() time.Duration {
	if m != nil && m.WorkTimeoutSeconds_ > 0 {
		return m.WorkTimeoutSeconds_.Duration()
	}
	return (DefaultLooperConfig{}).WorkTimeout()
}
func (m *LooperConfigJSON) PollWait() time.Duration {
	if m != nil && m.PollWaitMilliseconds_ > 0 {
		return m.PollWaitMilliseconds_.Duration()
	}
	return (DefaultLooperConfig{}).PollWait()
}
func (m *LooperConfigJSON) RunlockTimeout() time.Duration {
	if m != nil && m.RunlockTimeoutSeconds_ > 0 {
		return m.RunlockTimeoutSeconds_.Duration()
	}
	return (DefaultLooperConfig{}).RunlockTimeout()
}
func (c *ConfigJSonnet) MerkleBuilderServerConfig(ctx context.Context) (MerkleBuilderServerConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Apps.Merkle, nil
}
func (c *ConfigJSonnet) QuotaServerConfig(ctx context.Context) (QuotaServerConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Data.Apps.Quota != nil {
		return c.Data.Apps.Quota, nil
	}
	return DefaultQuotaServerConfig{}, nil
}
func (c *ConfigJSonnet) QueueServiceConfig(ctx context.Context) (*QueueServiceConfig, error) {
	c.RLock()
	defer c.RUnlock()
	return &c.Data.QueueService, nil
}
func (c *ConfigJSonnet) ProbeRootCAs(ctx context.Context) (*x509.CertPool, []string, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.RootCAs.Probe.CompileReturnRaw(ctx, core.CAPoolTypeDefaultToSystem)
}
func (c *ConfigJSonnet) HostID() (core.HostID, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.HostID, nil
}
func (c *ConfigJSonnet) Settings(ctx context.Context) (Settings, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Settings, nil
}

func (c *ConfigJSonnet) WebConfig(ctx context.Context) (WebConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.Apps.Web, nil
}

func (c *ConfigJSonnet) StripeConfig(ctx context.Context) (StripeConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Data.Stripe == nil {
		return nil, core.ConfigError("no stripe config found")
	}
	return c.Data.Stripe, nil
}

func (c *ConfigJSonnet) VHostsConfig(ctx context.Context) (VHostsConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Data.VHosts == nil {
		return DefaultVHostsConfig{}, nil
	}
	return c.Data.VHosts, nil
}

func (g *GlobalServiceJSON) Compile(ctx context.Context) (*GlobalService, error) {
	cas, err := g.CAs.Compile(ctx, core.CAPoolTypeDefaultToSystem)
	if err != nil {
		return nil, err
	}
	return &GlobalService{
		Addr: g.Addr,
		CAs:  cas,
	}, nil
}

func (c *ConfigJSonnet) BeaconGlobalService(ctx context.Context) (*GlobalService, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Data.GlobalServices.Beacon == nil {
		return nil, core.NoDefaultHostError{}
	}
	return c.Data.GlobalServices.Beacon.Compile(ctx)
}

func (c *ConfigJSonnet) AutocertServiceConfig(ctx context.Context) (AutocertServiceConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	ret := c.Data.AutocertService
	if ret == nil {
		return DefaultAutocertServiceConfig{}, nil
	}
	return ret, nil
}

func (c *VHostsConfigJSON) CannedDomains() []DNSZoner {
	if c == nil {
		return DefaultVHostsConfig{}.CannedDomains()
	}
	return core.Map(c.CannedDomains_, func(d DNSZoneJSON) DNSZoner { return d })
}

func (c *VHostsConfigJSON) AWSCredentials() AWSCredentialer {
	if c == nil || c.AWSCreds == nil {
		return DefaultVHostsConfig{}.AWSCredentials()
	}
	return c.AWSCreds
}

func (a *AWSCredentialsJSON) AccessKey() string { return a.AccessKeyID_ }
func (a *AWSCredentialsJSON) SecretKey() string { return a.SecretAccessKey_ }
func (a *AWSCredentialsJSON) Region() string    { return a.Region_ }

func (c *VHostsConfigJSON) PrivateKeyIOer(ctx context.Context, h proto.HostID, typ proto.EntityType) (HostKeyIOer, error) {
	dir := c.PrivateKeysDir
	if dir == "" {
		return nil, core.ConfigError("no vhosts keys dir found")
	}
	eh, err := h.StringErr()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "v"+eh, hostKeyFilename(typ))

	return NewHostKeyFile(core.Path(path)), nil
}

func (c *ConfigJSonnet) GetDNSAliases(ctx context.Context) (core.CNameResolver, error) {
	c.RLock()
	defer c.RUnlock()
	if len(c.Data.DNSAliases) == 0 {
		return nil, nil
	}
	ret := core.NewSimpleCNameResolver().WithObjs(c.Data.DNSAliases)
	return ret, nil
}

func (c *ConfigJSonnet) RawJSON() (string, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Raw, nil
}

func (w *WebConfigJSON) SessionParam() string {
	if w == nil || w.SessionParam_ == "" {
		return (DefaultWebConfig{}).SessionParam()
	}
	return w.SessionParam_
}

func (w *WebConfigJSON) SessionDuration() time.Duration {
	if w == nil || w.SessionDuration_.Duration == 0 {
		return (DefaultWebConfig{}).SessionDuration()
	}
	return w.SessionDuration_.Duration
}

func (w *WebConfigJSON) UseTLS() bool {
	if w == nil {
		return (DefaultWebConfig{}).UseTLS()
	}
	return w.UseTLS_
}

func (w *WebConfigJSON) GetExternalPort() proto.Port {
	if w == nil || w.ExternalPort_ == 0 {
		return (DefaultWebConfig{}).GetExternalPort()
	}
	return w.ExternalPort_
}

func (w *WebConfigJSON) OAuth2() OAuth2Configger {
	if w == nil || w.OAuth2_ == nil {
		return DefaultOAuthConfig{}
	}
	return w.OAuth2_
}

func (o *OAuth2ConfigJSON) Callback() proto.URLString {
	if o == nil || o.Callback_ == "" {
		return DefaultOAuthConfig{}.Callback()
	}
	return o.Callback_
}

func (o *OAuth2ConfigJSON) Tiny() proto.URLString {
	if o == nil {
		return DefaultOAuthConfig{}.Tiny()
	}
	return o.Tiny_
}

func (o *OAuth2ConfigJSON) RefreshInterval() time.Duration {
	if o == nil || o.RefreshInterval_.Duration == 0 {
		return DefaultOAuthConfig{}.RefreshInterval()
	}
	return o.RefreshInterval_.Duration
}

func (o *OAuth2ConfigJSON) RequestTimeout() time.Duration {
	if o == nil || o.RequestTimeout_.Duration == 0 {
		return DefaultOAuthConfig{}.RequestTimeout()
	}
	return o.RequestTimeout_.Duration
}

func (w *WebConfigJSON) DebugDelay() time.Duration {
	if w == nil {
		return time.Duration(0)
	}
	return w.DebugDelay_.Duration
}

func (v *VHostsConfigJSON) DNSResolvers() []proto.TCPAddr {
	if v == nil || v.Vanity == nil {
		return DefaultVHostsConfig{}.DNSResolvers()
	}
	ret := core.Map(v.Vanity.DNSResolvers_.Hosts, func(s string) proto.TCPAddr { return proto.TCPAddr(s) })
	return ret
}

func (v *VHostsConfigJSON) DNSResolveTimeout() time.Duration {
	if v == nil || v.Vanity == nil {
		return DefaultVHostsConfig{}.DNSResolveTimeout()
	}
	return v.Vanity.DNSResolvers_.Timeout.Duration
}

func (v *VHostsConfigJSON) DNSSetStrategy() DNSSetStrategy {
	if v == nil {
		return DefaultVHostsConfig{}.DNSSetStrategy()
	}
	switch strings.ToLower(v.DNSSetStrategy_) {
	case "aws", "route53":
		return DNSSetStrategyAWS
	default:
		return DNSSetStrategyNone
	}
}

func (v *VHostsConfigJSON) HostingDomain() (DNSZoner, error) {
	if v == nil || v.Vanity == nil ||
		v.Vanity.HostingDomain_.Domain_.IsZero() || v.Vanity.HostingDomain_.ZoneID_.IsZero() {
		return DefaultVHostsConfig{}.HostingDomain()
	}
	return &v.Vanity.HostingDomain_, nil
}

func (c *ConfigJSonnet) CKSConfig(ctx context.Context) (CKSConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	return c.Data.CKS, nil
}

func (t *TeamConfigJSON) MaxRoles() uint {
	if t == nil || t.MaxRoles_ == 0 {
		return DefaultTeamConfig{}.MaxRoles()
	}
	return t.MaxRoles_
}

func (c *ConfigJSonnet) TeamConfig(ctx context.Context) (TeamConfigger, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Data.Team == nil {
		return DefaultTeamConfig{}, nil
	}
	return c.Data.Team, nil
}

func (c *ConfigJSonnet) PKIXConfig(ctx context.Context) (PKIXConfigger, error) {
	if c == nil || c.Data.PKIX == nil {
		return &PKIXConfigJSON{}, nil
	}
	return c.Data.PKIX, nil
}

func (c *CKSConfigJSON) RefreshInterval() time.Duration {
	if c == nil || c.RefreshInterval_.Duration == 0 {
		return time.Minute
	}
	return c.RefreshInterval_.Duration
}

func (c *CKSConfigJSON) EncKeys() ([]cks.EncKey, error) {
	if c == nil {
		return nil, core.KeyNotFoundError{Which: "CKS keys"}
	}
	var ret []cks.EncKey
	for _, s := range c.EncKeys_ {
		key, err := s.Parse()
		if err != nil {
			return nil, err
		}
		ret = append(ret, cks.EncKey{CKSEncKey: *key})
	}
	return ret, nil
}

type ClientVersionConfigJSON struct {
	MinVersion_    *core.ParsedSemVer `json:"min"`
	NewestVersion_ *core.ParsedSemVer `json:"newest"`
	Message_       string             `json:"message"`
}

type ClientConfigJSON struct {
	ClientVersion_ *ClientVersionConfigJSON `json:"version"`
}

func (j *ClientVersionConfigJSON) MinVersion() *proto.SemVer {
	if j == nil || j.MinVersion_ == nil {
		return nil
	}
	return &j.MinVersion_.SemVer
}
func (j *ClientVersionConfigJSON) NewestVersion() *proto.SemVer {
	if j == nil || j.NewestVersion_ == nil {
		return nil
	}
	return &j.NewestVersion_.SemVer
}

func (j *ClientVersionConfigJSON) Message() string {
	if j == nil || j.Message_ == "" {
		return ""
	}
	return j.Message_
}

func (c *ClientConfigJSON) ClientVersion() ClientVersioner {
	if c == nil || c.ClientVersion_ == nil {
		return nil
	}
	return c.ClientVersion_
}

func (j *ConfigJSonnet) ClientConfig(ctx context.Context) (ClientConfigger, error) {
	j.RLock()
	defer j.RUnlock()
	if j.Data.Client == nil {
		return nil, nil
	}
	return j.Data.Client, nil
}

var _ WebConfigger = (*WebConfigJSON)(nil)
var _ Config = (*ConfigJSonnet)(nil)
