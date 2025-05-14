// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type DbType int

const (
	DbTypeNone     DbType = 0
	DbTypeTemplate DbType = 1 // Used for drop/create of other databases
	DbTypeUsers    DbType = 2

	// Will be on something like a dynamo in prod (sql-less that can scale horizontally)
	DbTypeMerkleTree DbType = 3

	// Will be etcd in prod
	DbTypeMerkleRaft DbType = 4

	// Can be something like S3 (bucket store) in prod
	DbTypeMerkleRaftArchive DbType = 5

	// Can be something like SQS or Kafka (queueing service) in prod
	DbTypeQueueService DbType = 6

	// Various server public keys (and some private keys) are stored here, that
	// all backend services will likely access.
	DbTypeServerConfig DbType = 7

	// Beacons are internet-wide directories that map hostIDs to DNS hostnames
	DbTypeBeacon DbType = 8

	// KV Store is a simple key-value store and metadata
	DbTypeKVStore DbType = 9
)

// do not include Template or KVStore; the latter we have shards of, so
// more configuation is needed.
var AllDBs []DbType = []DbType{
	DbTypeUsers,
	DbTypeMerkleTree,
	DbTypeMerkleRaft,
	DbTypeServerConfig,
	DbTypeBeacon,
}

type KVShardDescriptor struct {
	Name   string
	Index  proto.KVShardID
	Active bool
}

type ManageDBsConfig struct {
	Dbs      []DbType
	KVShards []KVShardDescriptor
}

func (a *ManageDBsConfig) Append(d DbType) {
	a.Dbs = append(a.Dbs, d)
}

type DBTypeNamePair struct {
	DbType DbType
	Name   string
}

func (a *ManageDBsConfig) All() []DBTypeNamePair {
	var ret []DBTypeNamePair
	for _, d := range a.Dbs {
		ret = append(ret, DBTypeNamePair{DbType: d, Name: d.ToString()})
	}
	for _, k := range a.KVShards {
		ret = append(ret, DBTypeNamePair{DbType: DbTypeKVStore, Name: k.Name})
	}
	return ret
}

func (t DbType) ToString() string {
	switch t {
	case DbTypeTemplate:
		return "template1"
	case DbTypeUsers:
		return "foks_users"
	case DbTypeMerkleTree:
		return "foks_merkle_tree"
	case DbTypeMerkleRaft:
		return "foks_merkle_raft"
	case DbTypeMerkleRaftArchive:
		return "foks_merkle_raft_archive"
	case DbTypeQueueService:
		return "foks_queue_service"
	case DbTypeServerConfig:
		return "foks_server_config"
	case DbTypeBeacon:
		return "foks_beacon"
	case DbTypeKVStore:
		return "foks_kv_store"
	default:
		return "<nil>"
	}
}

func ParseDbType(s string) (DbType, error) {
	switch s {
	case "users":
		return DbTypeUsers, nil
	case "merkle-tree":
		return DbTypeMerkleTree, nil
	case "merkle-raft":
		return DbTypeMerkleRaft, nil
	case "merkle-raft-archive":
		return DbTypeMerkleRaftArchive, nil
	case "queue-service":
		return DbTypeQueueService, nil
	case "server-config":
		return DbTypeServerConfig, nil
	case "beacon":
		return DbTypeBeacon, nil
	case "kv-store":
		return DbTypeKVStore, nil
	default:
		return DbTypeNone, errors.New("unknown DB type: " + s)
	}
}

type KVShardConfig interface {
	DbConfig(ctx context.Context) (*pgxpool.Config, error)
	Id() proto.KVShardID
	IsActive() bool
	Name() string
}

type KVShardsConfig interface {
	Get(proto.KVShardID) KVShardConfig
	All() []KVShardConfig
	Active() []KVShardConfig // might be several, in which case we'll round-robin
}

type AutocertServiceConfigger interface {
	BindAddr() proto.TCPAddr
	GetLooperConfigger() ServerLooperConfigger
	ExpireIn() time.Duration
	RefreshIn() time.Duration
	InitialBackoffs() []time.Duration
	RefreshBackoff() time.Duration
	AcmeTimeout() time.Duration
}

type CKSConfigger interface {
	EncKeys() ([]cks.EncKey, error)
	RefreshInterval() time.Duration
}

type PKIXConfigger interface {
	Name() pkix.Name
}

type TeamConfigger interface {
	MaxRoles() uint
}

type DefaultAutocertServiceConfig struct{}

var _ AutocertServiceConfigger = DefaultAutocertServiceConfig{}

func (d DefaultAutocertServiceConfig) BindAddr() proto.TCPAddr { return "0.0.0.0:80" }
func (d DefaultAutocertServiceConfig) GetLooperConfigger() ServerLooperConfigger {
	return DefaultLooperConfig{}
}
func (d DefaultAutocertServiceConfig) ExpireIn() time.Duration {
	return time.Hour * time.Duration(24*30*3)
}
func (d DefaultAutocertServiceConfig) RefreshIn() time.Duration {
	return time.Hour * time.Duration(24*80)
}
func (d DefaultAutocertServiceConfig) InitialBackoffs() []time.Duration {
	return []time.Duration{
		time.Second * 5,
		time.Second * 10,
		time.Second * 30,
		time.Minute,
	}
}
func (d DefaultAutocertServiceConfig) RefreshBackoff() time.Duration {
	return time.Hour * 12
}
func (d DefaultAutocertServiceConfig) AcmeTimeout() time.Duration {
	return time.Second * 30
}

type Config interface {
	Load(context.Context) error

	// Return the raw-JSON representation of the config
	RawJSON() (string, error)

	// Gets the DbConfig for the given databse
	DbConfig(ctx context.Context, which DbType) (*pgxpool.Config, error)

	// KV stores are sharded across multiple independent databases,
	// so we can scale out. This returns the set, and
	// it's possible to get individuals from it. The Users database
	// maps a Party to the KVShardID that it's stored on.
	KVShardsConfig(ctx context.Context) (KVShardsConfig, error)

	// Gets configuration for the Zap logging system
	LogConfig(ctx context.Context) *zap.Config

	LogRemoteIP(ctx context.Context) (bool, error)
	RPCLogOptions(ctx context.Context) (rpc.LogOptions, error)

	ListenParams(ctx context.Context, which proto.ServerType, port int) (BindAddr, proto.TCPAddr, *tls.Config, error)
	AutocertPackage(ctx context.Context, which proto.ServerType, defPort proto.Port) (*AutocertPackage, error)
	AutocertServiceConfig(ctx context.Context) (AutocertServiceConfigger, error)

	ProbeRootCAs(ctx context.Context) (*x509.CertPool, []string, error)

	QueueServiceConfig(ctx context.Context) (*QueueServiceConfig, error)

	// Service-specific configuration, not required for each service.
	RegServerConfig(ctx context.Context) (RegServerConfigger, error)
	UserServerConfig(ctx context.Context) (UserServerConfigger, error)
	KVStoreServerConfig(ctx context.Context) (KVServerConfigger, error)

	// Used for both the builder and the batcher for now, since they have very similar
	// configurations.
	MerkleBuilderServerConfig(ctx context.Context) (MerkleBuilderServerConfigger, error)
	QuotaServerConfig(ctx context.Context) (QuotaServerConfigger, error)

	// Get the address and x509 cert to use to connect to the external beacon service,
	// which for now is a single service running across all FOKS servers.
	BeaconGlobalService(ctx context.Context) (*GlobalService, error)

	Settings(ctx context.Context) (Settings, error)
	WebConfig(ctx context.Context) (WebConfigger, error)
	StripeConfig(ctx context.Context) (StripeConfigger, error)
	VHostsConfig(ctx context.Context) (VHostsConfigger, error)

	CKSConfig(ctx context.Context) (CKSConfigger, error)
	PKIXConfig(ctx context.Context) (PKIXConfigger, error)
	ClientConfig(ctx context.Context) (ClientConfigger, error)
	TeamConfig(ctx context.Context) (TeamConfigger, error)

	HostID() (core.HostID, error)
	GetDNSAliases(ctx context.Context) (core.CNameResolver, error)

	IsLoaded() bool
}

type RegServerConfigger interface {
	UsernameReservationTimeout() time.Duration
	VHostMgmtAddr() proto.TCPAddr
}
type UserServerConfigger interface {
	BadLoginRateLimit() RateLimit
}
type KVServerConfigger interface {
	BlobStorePath() string
}

type ServerLooperConfigger interface {
	PollWait() time.Duration
	RunlockTimeout() time.Duration
	WorkTimeout() time.Duration
	BatchSize() int
}

type DefaultLooperConfig struct{}

func (d DefaultLooperConfig) PollWait() time.Duration       { return time.Millisecond * time.Duration(500) }
func (d DefaultLooperConfig) RunlockTimeout() time.Duration { return time.Second * time.Duration(60) }
func (d DefaultLooperConfig) WorkTimeout() time.Duration    { return time.Second * time.Duration(60*2) }
func (d DefaultLooperConfig) BatchSize() int                { return 200 }

type DefaultVHostsConfig struct{}

func (d DefaultVHostsConfig) DNSResolvers() []proto.TCPAddr {
	return []proto.TCPAddr{"1.1.1.1:53", "8.8.8.8:53"}
}
func (d DefaultVHostsConfig) DNSResolveTimeout() time.Duration { return time.Second * 5 }
func (d DefaultVHostsConfig) DNSSetStrategy() DNSSetStrategy   { return DNSSetStrategyNone }
func (d DefaultVHostsConfig) AWSCredentials() AWSCredentialer  { return nil }
func (d DefaultVHostsConfig) HostingDomain() (DNSZoner, error) {
	return nil, core.NotFoundError("hosting domain not set")
}

func (d DefaultVHostsConfig) PrivateKeyIOer(ctx context.Context, hostID proto.HostID, typ proto.EntityType) (HostKeyIOer, error) {
	return nil, core.NotFoundError("private keys dir not set")
}
func (d DefaultVHostsConfig) CannedDomains() []DNSZoner     { return nil }
func (d DefaultVHostsConfig) CertDomains() []proto.Hostname { return nil }

var _ VHostsConfigger = DefaultVHostsConfig{}

type QuotaServerConfigger interface {
	ServerLooperConfigger
	GetSlacks() (*infra.Slacks, error)
	GetDelay() time.Duration
	GetNoPlanMaxTeams() int
}

var _ ServerLooperConfigger = DefaultLooperConfig{}

type DefaultQuotaServerConfig struct {
	DefaultLooperConfig
}

func (d DefaultQuotaServerConfig) GetSlacks() (*infra.Slacks, error) {
	return &infra.Slacks{
		FloatingTeam: proto.Size(1024 * 512),
		NoPlanUser:   proto.Size(1024 * 1024 * 3),
		PlanUser:     proto.Size(1024 * 1024 * 5),
		PaidThrough:  proto.ExportDurationSecs(3 * 24 * time.Hour),
	}, nil
}
func (d DefaultQuotaServerConfig) GetDelay() time.Duration { return time.Minute }
func (d DefaultQuotaServerConfig) GetNoPlanMaxTeams() int  { return 2 }

var _ QuotaServerConfigger = DefaultQuotaServerConfig{}

type DefaultTeamConfig struct{}

func (d DefaultTeamConfig) MaxRoles() uint { return 0x10 }

var _ TeamConfigger = DefaultTeamConfig{}

type MerkleBuilderServerConfigger interface {
	ServerLooperConfigger
	SigningKey() (HostKeyIOer, error)
}

func ExportQuotaConfig(c QuotaServerConfigger) (*infra.QuotaConfig, error) {

	npmt := c.GetNoPlanMaxTeams()
	if npmt < 0 {
		npmt = (DefaultQuotaServerConfig{}).GetNoPlanMaxTeams()
	}

	slacks, err := c.GetSlacks()
	if err != nil {
		return nil, err
	}

	return &infra.QuotaConfig{
		Slacks:         *slacks,
		NoPlanMaxTeams: int64(npmt),
	}, nil
}

type GlobalService struct {
	Addr proto.TCPAddr
	CAs  *x509.CertPool
}

type QueueServiceConfig struct {
	Native bool `json:"native"`
}

type Seconds int
type Milliseconds int

func (s Seconds) Duration() time.Duration      { return time.Duration(s) * time.Second }
func (m Milliseconds) Duration() time.Duration { return time.Duration(m) * time.Millisecond }

type RateLimit struct {
	Num        uint    `json:"num"`
	WindowSecs Seconds `json:"window_secs"`
}

type VHosts struct {
	KeysDir string `json:"keys_dir"`
}

type Settings struct {
	Testing bool          `json:"test"`
	Tbtl    core.Duration `json:"team_bearer_token_lifespan"`
	Cit     core.Duration `json:"connection_idle_timeout"`
	Wsd     core.Duration `json:"web_session_duration"`
}

type StripeSecretKey string
type StripePublicKey string
type StripeWebhookSecret string

func (s StripeSecretKey) IsZero() bool { return len(s) == 0 }
func (p StripePublicKey) IsZero() bool { return len(p) == 0 }

type DNSSetStrategy int

const (
	DNSSetStrategyNone DNSSetStrategy = 0
	DNSSetStrategyAWS  DNSSetStrategy = 1
)

type AWSCredentialer interface {
	AccessKey() string
	SecretKey() string
	Region() string
}

type DNSZoner interface {
	Domain() proto.Hostname
	ZoneID() proto.ZoneID
}

type VHostsConfigger interface {
	AWSCredentials() AWSCredentialer
	DNSResolvers() []proto.TCPAddr
	DNSResolveTimeout() time.Duration
	DNSSetStrategy() DNSSetStrategy
	HostingDomain() (DNSZoner, error)
	CannedDomains() []DNSZoner // Domains for which *.foo.com is available, on a wildcard cert

	// How to perform I/O on a host key (of any type) affiliated with a given
	// vhost, as specified by the hostID.
	PrivateKeyIOer(ctx context.Context, hostID proto.HostID, typ proto.EntityType) (HostKeyIOer, error)
}

type StripeCallbacker interface {
	Success() proto.URLString
	Cancel() proto.URLString
	Webhook() proto.URLString
}

type DefaultStripeCallbacks struct{}

func (d DefaultStripeCallbacks) Success() proto.URLString { return "/stripe/success" }
func (d DefaultStripeCallbacks) Cancel() proto.URLString  { return "/stripe/cancel" }
func (d DefaultStripeCallbacks) Webhook() proto.URLString { return "/stripe/webhook" }

var _ StripeCallbacker = DefaultStripeCallbacks{}

type StripeConfigger interface {
	SecretKey() StripeSecretKey
	PublicKey() StripePublicKey
	WebhookSecret() StripeWebhookSecret
	SessionDuration() time.Duration
	Callbacks() StripeCallbacker
}

type OAuth2Configger interface {
	Callback() proto.URLString
	RefreshInterval() time.Duration
	RequestTimeout() time.Duration
	Tiny() proto.URLString
}

type WebConfigger interface {
	UseTLS() bool
	GetExternalPort() proto.Port // Port of the internet-side of a load-balancer; will revert to GetPort() if 0
	SessionParam() string
	SessionDuration() time.Duration
	DebugDelay() time.Duration // Delay for debugging sppiners purposes
	OAuth2() OAuth2Configger
}

type DefaultWebConfig struct{}

func (d DefaultWebConfig) UseTLS() bool                   { return true }
func (d DefaultWebConfig) SessionParam() string           { return "s" }
func (d DefaultWebConfig) SessionDuration() time.Duration { return time.Hour * time.Duration(24*30) }
func (d DefaultWebConfig) DebugDelay() time.Duration      { return time.Duration(0) }
func (d DefaultWebConfig) GetExternalPort() proto.Port    { return proto.Port(0) }
func (d DefaultWebConfig) OAuth2() OAuth2Configger        { return DefaultOAuthConfig{} }

type DefaultOAuthConfig struct{}

func (d DefaultOAuthConfig) Callback() proto.URLString      { return "/oauth2/callback" }
func (d DefaultOAuthConfig) RefreshInterval() time.Duration { return time.Minute * time.Duration(10) }
func (d DefaultOAuthConfig) RequestTimeout() time.Duration  { return time.Second * time.Duration(30) }
func (d DefaultOAuthConfig) Tiny() proto.URLString          { return "/o" }

var _ WebConfigger = DefaultWebConfig{}

func (s Settings) TeamBearerTokenLifespan() time.Duration {
	var zed core.Duration
	if s.Tbtl == zed {
		return time.Duration(6) * time.Hour
	}
	return s.Tbtl.Duration
}

func (s Settings) ConnectionIdleTimeout() time.Duration {
	var zed core.Duration
	if s.Cit == zed {
		return time.Duration(6) * time.Hour
	}
	return s.Cit.Duration
}

type BindAddr string

func (b BindAddr) Export() proto.BindAddr {
	return proto.BindAddr(b)
}

type ClientVersioner interface {
	MinVersion() *proto.SemVer
	NewestVersion() *proto.SemVer
	Message() string
}

type ClientConfigger interface {
	ClientVersion() ClientVersioner
}

type EmptyConfig struct{}

var _ Config = (*EmptyConfig)(nil)

func (e *EmptyConfig) IsLoaded() bool             { return false }
func (e *EmptyConfig) Load(context.Context) error { return NewEmptyConfigError() }
func (e *EmptyConfig) DbConfig(ctx context.Context, which DbType) (*pgxpool.Config, error) {
	return nil, NewEmptyConfigError()
}
func (e *EmptyConfig) KVShardsConfig(ctx context.Context) (KVShardsConfig, error) {
	return nil, NewEmptyConfigError()
}
func (e *EmptyConfig) LogConfig(ctx context.Context) *zap.Config     { return nil }
func (e *EmptyConfig) LogRemoteIP(ctx context.Context) (bool, error) { return false, nil }

func (c *EmptyConfig) RPCLogOptions(ctx context.Context) (rpc.LogOptions, error) {
	return nil, nil
}
func (c *EmptyConfig) ListenParams(ctx context.Context, which proto.ServerType, ovveridePort int) (BindAddr, proto.TCPAddr, *tls.Config, error) {
	return "", "", nil, NewEmptyConfigError()
}
func (c *EmptyConfig) AutocertPackage(ctx context.Context, which proto.ServerType, port proto.Port) (*AutocertPackage, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) AutocertServiceConfig(ctx context.Context) (AutocertServiceConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) RegServerConfig(ctx context.Context) (RegServerConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) UserServerConfig(ctx context.Context) (UserServerConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) KVStoreServerConfig(ctx context.Context) (KVServerConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) MerkleBuilderServerConfig(ctx context.Context) (MerkleBuilderServerConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) QuotaServerConfig(ctx context.Context) (QuotaServerConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) QueueServiceConfig(ctx context.Context) (*QueueServiceConfig, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) BackendRootCAs(ctx context.Context) (*x509.CertPool, []string, error) {
	return nil, nil, NewEmptyConfigError()
}
func (c *EmptyConfig) ProbeRootCAs(ctx context.Context) (*x509.CertPool, []string, error) {
	return nil, nil, NewEmptyConfigError()
}
func (c *EmptyConfig) HostID() (core.HostID, error) {
	var ret core.HostID
	return ret, NewEmptyConfigError()
}
func (c *EmptyConfig) Settings(ctx context.Context) (Settings, error) {
	return Settings{}, NewEmptyConfigError()
}
func (c *EmptyConfig) WebConfig(ctx context.Context) (WebConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) StripeConfig(ctx context.Context) (StripeConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) VHostsConfig(ctx context.Context) (VHostsConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) BeaconGlobalService(ctx context.Context) (*GlobalService, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) VHostKeyIOer(ctx context.Context, hostID proto.HostID, typ proto.EntityType) (HostKeyIOer, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) GetDNSAliases(ctx context.Context) (core.CNameResolver, error) {
	return nil, nil
}
func (c *EmptyConfig) RawJSON() (string, error) {
	return "", NewEmptyConfigError()
}
func (c *EmptyConfig) CKSConfig(ctx context.Context) (CKSConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) PKIXConfig(ctx context.Context) (PKIXConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) ClientConfig(ctx context.Context) (ClientConfigger, error) {
	return nil, NewEmptyConfigError()
}
func (c *EmptyConfig) TeamConfig(ctx context.Context) (TeamConfigger, error) {
	return nil, NewEmptyConfigError()
}
