// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// For a regular server
type X509Pair struct {
	Key  core.Path // path to PEM-encoded private key
	Cert core.Path // path to PEM-encoded certificate

}

// For a CA
type X509CA struct {
	KeyFile  core.Path
	CertFile core.Path
	Key      crypto.PrivateKey
	Cert     []byte
}

func (x X509CA) ToKeyCertFilePair() core.KeyCertFilePair {
	return core.KeyCertFilePair{
		Key:  x.KeyFile,
		Cert: x.CertFile,
	}
}

func (x *X509CA) Generate(dir core.Path, stem string) error {
	x.CertFile = dir.JoinStrings(stem + ".cert")
	x.KeyFile = dir.JoinStrings(stem + ".key")
	var err error
	x.Key, x.Cert, err = core.GenCAInMem()
	if err != nil {
		return err
	}
	err = shared.WriteCACertAndKeyPEM(x.Key, x.Cert, x.KeyFile, x.CertFile)
	if err != nil {
		return err
	}
	return nil
}

type X509Material struct {
	RootCA     X509CA
	ClientCA   X509CA
	InternalCA X509CA
	Db         X509Pair
	Server     X509Pair

	// In a real deployment, the probe server would be the only one whose
	// cert is signed up to the root CAs (like digicert). This is because the
	// user needs to bootstrap a hostID with a traditional DNS name.
	ProbeCA X509CA
	Probe   X509Pair
	Beacon  X509Pair // beacon server can use the same CA as probe, but should get its own cert

	// If we're using the "cert dir" mechanism, we have a directory full of certs and keys here
	ProbeCertDir     core.Path
	HostchainCertDir core.Path
}

func (x *X509Pair) GenerateWithOpts(
	m shared.MetaContext,
	ca X509CA,
	which string,
	hosts []string,
	dir core.Path,
	opts core.X509WriteOpts,
) error {
	x.Key = dir.JoinStrings(which + ".key")
	x.Cert = dir.JoinStrings(which + ".cert")
	return shared.MakeCertificate(
		m.Ctx(),
		hosts, ca.KeyFile, ca.CertFile, x.Key, x.Cert, m.Infof, opts)
}
func (x *X509Pair) Generate(m shared.MetaContext, ca X509CA, which string, hosts []string, dir core.Path) error {
	return x.GenerateWithOpts(m, ca, which, hosts, dir, core.X509WriteOpts{})
}

func (x *X509Material) Generate(m shared.MetaContext, dir core.Path, setupOpts SetupOpts) error {

	var CAs = []struct {
		CA   *X509CA
		Stem string
	}{
		{&x.RootCA, "ca"},
		{&x.ClientCA, "client_ca"},
		{&x.InternalCA, "internal_ca"},
		{&x.ProbeCA, "probe_ca"},
	}
	for _, ca := range CAs {
		err := ca.CA.Generate(dir, ca.Stem)
		if err != nil {
			return err
		}
	}
	var hostnames Hostnames
	if setupOpts.Hostnames != nil {
		hostnames = *setupOpts.Hostnames
	}

	hosts := []string{"127.0.0.1", "::1", "localhost"}
	fixHosts := func(overrides []proto.Hostname) []string {
		if len(overrides) == 0 {
			return hosts
		}
		ret := make([]string, len(overrides))
		for i, h := range overrides {
			ret[i] = string(h)
		}
		return ret
	}

	err := x.Db.Generate(m, x.RootCA, "db", hosts, dir)
	if err != nil {
		return err
	}
	err = x.Server.Generate(m, x.RootCA, "server", fixHosts(hostnames.User), dir)
	if err != nil {
		return err
	}

	// We have two mechanisms for dealing with VHosts certs for a domain. The first is
	// the "cert dir" mechanism, where we have a directory full of certs and keys, and
	// the second is a wildcard domain, where we have a single cert and key for all the
	// subdomains. Note this is in addition to the normal one-off wildcard certs.
	if setupOpts.UseCertDirs {

		certDir := dir.JoinStrings("probe_tls")
		err = certDir.Mkdir(0o755)
		if err != nil {
			return err
		}
		x.ProbeCertDir = certDir

		for _, h := range hostnames.Probe {
			err = x.Probe.Generate(m, x.ProbeCA, h.String(), []string{h.String()}, certDir)
			if err != nil {
				return err
			}
		}

		certDirHostchain := dir.JoinStrings("hostchain_tls")
		err = certDirHostchain.Mkdir(0o755)
		if err != nil {
			return err
		}
		x.HostchainCertDir = certDirHostchain

	}

	// The probe server can also serve *.foobar.com wildcard domains, as we'd have
	// in a Vhosts setup. Setup a wildcard here and nowhere else.
	probeHosts := fixHosts(hostnames.Probe)
	if setupOpts.WildcardVhostDomain != "" {
		probeHosts = append(probeHosts, "*."+setupOpts.WildcardVhostDomain)
	}
	err = x.Probe.Generate(m, x.ProbeCA, "probe", probeHosts, dir)
	if err != nil {
		return err
	}

	err = x.Beacon.Generate(m, x.ProbeCA, "beacon", fixHosts(hostnames.Beacon), dir)
	if err != nil {
		return err
	}
	return nil
}

func ComposeHooks(hooks [](func() error)) func() error {
	return func() error {
		var err error
		for _, h := range hooks {
			tmp := h()
			if tmp != nil {
				err = tmp
			}
		}
		return err
	}
}

type cleanupHook func() error

func Compose(h1 cleanupHook, h2 cleanupHook) cleanupHook {
	return func() error {
		var e1, e2 error
		if h2 != nil {
			e2 = h2()
		}
		if h1 != nil {
			e1 = h1()
		}
		if e2 != nil {
			return e2
		}
		if e1 != nil {
			return e1
		}
		return nil
	}
}

func launchDatabase(
	m shared.MetaContext,
	dbs shared.ManageDBsConfig,
	config *shared.JSonnetTemplate,
) (func() error, error) {

	user := "foks"
	pw := "foks"

	plat := ""
	if runtime.GOARCH == "arm64" {
		plat = "arm64v8/"
	}

	req := testcontainers.ContainerRequest{
		Image:        plat + "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		AutoRemove:   true,
		Cmd:          []string{"-c", "max_connections=200"},
		Env: map[string]string{
			"POSTGRES_USER":     user,
			"POSTGRES_PASSWORD": pw,
			"POSTGRES_DB":       "sample",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	postgres, err := testcontainers.GenericContainer(m.Ctx(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}
	retFn := func() error {
		return postgres.Terminate(context.Background())
	}
	p, err := postgres.MappedPort(m.Ctx(), "5432")
	if err != nil {
		return retFn, err
	}
	port := p.Int()

	mkDb := func(name string) shared.DbConfigJSON {
		return shared.DbConfigJSON{
			Host:     "127.0.0.1",
			Port:     uint16(port),
			Name:     name,
			User:     user,
			NoTLS:    true,
			Password: pw,
		}
	}

	for _, w := range dbs.Dbs {
		config.Db[w.ToString()] = mkDb(w.ToString())
	}

	config.DbKVShards = []shared.KVShardConfigJSON{}
	for _, d := range dbs.KVShards {
		config.DbKVShards = append(config.DbKVShards, shared.KVShardConfigJSON{
			DbConfigJSON: mkDb(d.Name),
			ShardID:      d.Index,
			Active:       d.Active,
		})

	}

	m.Infow("db", "listen-port", port)
	return retFn, nil
}

func initDB(m shared.MetaContext, dbs shared.ManageDBsConfig) error {
	eng := shared.InitDB{
		Dbs: dbs,
	}
	err := eng.CreateAll(m)
	if err != nil {
		return err
	}
	err = eng.RunMakeTablesAll(m)
	if err != nil {
		return err
	}
	return nil
}

func configureServers(
	m shared.MetaContext,
	dir core.Path,
	x X509Material,
	config *shared.JSonnetTemplate,
	setupOpts SetupOpts,
) error {
	var beacon proto.TCPAddr
	for _, typ := range proto.AllServers {
		lcfg := shared.ListenConfigJSON{
			Port:         0,
			BindAddr:     "127.0.0.1:0",
			ExternalAddr: "localhost",
		}
		switch typ {

		// Probe and beacon servers use a different x509 cert, since it's signed by the real root CAs
		// and not the ones we can generate ourselves and shove in the hostchain.
		case proto.ServerType_Probe:
			if setupOpts.Hostnames != nil && len(setupOpts.Hostnames.Probe) > 0 {
				lcfg.ExternalAddr = proto.TCPAddr(setupOpts.Hostnames.Probe[0])
			}

		case proto.ServerType_Beacon:
			if setupOpts.Hostnames != nil && len(setupOpts.Hostnames.Beacon) > 0 {
				lcfg.ExternalAddr = proto.TCPAddr(setupOpts.Hostnames.Beacon[0])
			}
			beacon = lcfg.ExternalAddr

		// User and KV-Store are so far the only services that needs authenticated FOKS users via TLS client
		// certs.
		case proto.ServerType_User, proto.ServerType_KVStore:

		case proto.ServerType_Reg, proto.ServerType_MerkleQuery:

		// Internal services need authentication via our InternalCA client mechanism. Here the
		// "clients" are other backend severs, that want to talk to each other.
		case proto.ServerType_MerkleBuilder,
			proto.ServerType_Queue,
			proto.ServerType_MerkleBatcher,
			proto.ServerType_Quota,
			proto.ServerType_Autocert,
			proto.ServerType_MerkleSigner:

		}

		config.Listen[typ.ToString()] = lcfg
	}

	// user config
	config.Apps.User = &shared.UserServerConfigJSON{
		BadLoginRateLimit_: shared.RateLimit{
			Num:        2,
			WindowSecs: 60,
		},
	}

	config.Apps.KvStore = &shared.KVStoreServerConfigJSON{
		BlobStorePath_: "sql",
	}

	// merkle-batcher config; make the batch timeout really high so we can
	// drive the batcher explicitly with 'poke's
	merkleBuilderConfigData := shared.MerkleConfigJSON{
		LooperConfigJSON: shared.LooperConfigJSON{
			WorkTimeoutSeconds_: 30,
		},
		SigningKey_: dir.JoinStrings("merkle.host.key").String(),
	}
	if setupOpts.MerklePollWait > 0 {
		merkleBuilderConfigData.PollWaitMilliseconds_ = shared.Milliseconds(setupOpts.MerklePollWait.Milliseconds())
	}
	config.Apps.Merkle = &merkleBuilderConfigData

	config.Apps.Quota = &shared.QuotaConfigJSON{
		LooperConfigJSON: shared.LooperConfigJSON{
			PollWaitMilliseconds_: 1000 * 60 * 60, // one hour, so it basically is driven by active poking.
		},
	}

	probeCa := core.NewCAPool([]string{x.ProbeCA.CertFile.String()})
	config.RootCAs = shared.RootCAsConfig{
		Probe: *probeCa,
	}
	config.QueueService = shared.QueueServiceConfig{Native: true}
	config.Settings.Testing = true

	config.Apps.Web = &shared.WebConfigJSON{
		UseTLS_:       false,
		SessionParam_: "s",
	}

	// like RPC servers, the Web admin web server picks a random
	// port to listen on. For now we are not doing TLS in test.
	config.Listen[proto.ServerType_Web.ToString()] = shared.ListenConfigJSON{
		Port:         0,
		BindAddr:     "127.0.0.1:0",
		ExternalAddr: "localhost",
		NoTLS:        true,
	}
	config.Stripe = &shared.StripeConfigJSON{
		SecretKey_:       "sk_test_FAKEaabb",
		PublicKey_:       "pk_test_FAKEaabb",
		SessionDuration_: core.Duration{Duration: time.Hour},
	}

	// Set up the vhost keys directory
	config.VHosts = &shared.VHostsConfigJSON{
		PrivateKeysDir: dir.JoinStrings("vhost_keys").String(),
		Vanity:         &shared.VanityConfigJSON{},
	}
	wildBind := proto.NewTCPAddr("", 0)
	config.AutocertService = &shared.AutocertServiceConfig{
		BindAddr_: &wildBind,
	}

	// ProbeCA is our hack to simulate a real root CA, which the beacon server will
	// also use.
	config.GlobalServices.Beacon = &shared.GlobalServiceJSON{
		Addr: beacon,
		CAs:  *probeCa,
	}

	cksek, err := proto.NewCKSEncKey()
	if err != nil {
		return err
	}
	config.CKS = &shared.CKSConfigJSON{
		EncKeys_: []proto.CKSEncKeyString{cksek.KeyString()},
	}

	return nil
}

func cookConfig(m shared.MetaContext, dir core.Path, config shared.JSonnetTemplate, opts *shared.GlobalCLIConfigOpts) error {
	fn := dir.JoinStrings("foks.json")
	fh, err := fn.OpenFile(os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(fh)
	err = enc.Encode(config.JSonnetTemplateNoLog)
	if err != nil {
		return err
	}
	err = fh.Close()
	if err != nil {
		return err
	}
	opts.ConfigPath = fn
	return nil
}

func SetupEnv(
	m shared.MetaContext,
	dir core.Path,
	whichDBs shared.ManageDBsConfig,
) (
	func() error,
	*shared.JSonnetTemplate,
	error,
) {

	config := shared.JSonnetTemplate{
		JSonnetTemplateNoLog: shared.JSonnetTemplateNoLog{
			Db:     make(map[string]shared.DbConfigJSON),
			Listen: make(map[string]shared.ListenConfigJSON),
		},
	}

	// Need template DB type to create the other DBs
	whichDBs.Append(shared.DbTypeTemplate)

	dbShutdownHook, err := launchDatabase(m, whichDBs, &config)
	if err != nil {
		return nil, nil, err
	}

	return dbShutdownHook, &config, nil
}

func setupHostChain(
	m shared.MetaContext,
	dir core.Path,
	x509material *X509Material,
	hostname proto.Hostname,
) error {
	hkc := shared.NewHostChain().WithHostname(hostname)

	// We cleared the short host ID here, since it was set temporarily to write down the config file.
	// But ShortHostID=0 signals to the hostchain init sequence that the new host is a base host,
	// and not a virtual host, which is what we want.
	m.G().SetShortHostID(0)

	err := hkc.Forge(m, dir)
	if err != nil {
		return err
	}

	// NB -- this sets the host ID. For the base case, it will be set to 1 as above,
	// but for a forked test environment, it might bump to be > 1.
	m.G().SetHostChain(hkc)

	shid := m.G().ShortHostID()
	if shid == 0 {
		return core.InternalError("short host ID not set")
	}
	return nil
}

// Simulate actual DNS resolution by mapping the various hostnames
// given in opts.Hostnames to localhost. Eventually, this cname resolver
// is passed through to Client Contexts, we can all agree.
func setupResolver(m shared.MetaContext, opts SetupOpts) error {

	r := core.NewSimpleCNameResolver()
	lh := proto.Hostname("localhost")
	addAll := func(xs []proto.Hostname) {
		for _, x := range xs {
			r.Add(x, lh)
		}
	}
	if opts.Hostnames != nil {
		addAll(opts.Hostnames.Probe)
		addAll(opts.Hostnames.User)
		addAll(opts.Hostnames.Beacon)
	}
	addAll([]proto.Hostname{opts.PrimaryHostname})

	m.G().SetCnameResolver(r)
	return nil
}

func setupX509v2(m shared.MetaContext, x509m *X509Material, opts SetupOpts) error {

	ca := m.G().CertMgr()

	// Create CAs for the primary (base) host. We'll create more of these
	// whenever we make a VHost on top.
	for _, typ := range []proto.CKSAssetType{
		proto.CKSAssetType_InternalClientCA,
		proto.CKSAssetType_ExternalClientCA,
		proto.CKSAssetType_BackendCA,
	} {
		err := ca.GenCA(m, typ)
		if err != nil {
			return err
		}
	}
	locals := []proto.Hostname{"localhost", "127.0.0.1", "::1"}

	gencert := func(signWith proto.CKSAssetType, cert proto.CKSAssetType) error {
		return ca.GenServerCert(m, locals, nil, signWith, cert)
	}

	err := gencert(proto.CKSAssetType_HostchainFrontendCA, proto.CKSAssetType_HostchainFrontendX509Cert)
	if err != nil {
		return err
	}

	err = gencert(proto.CKSAssetType_BackendCA, proto.CKSAssetType_BackendX509Cert)
	if err != nil {
		return err
	}

	// For a probe and beacon cert, we're going to emulate what happens in production --- that let's encryption
	// will sign a cert with root CAs, and we won't generate the cert ourselves. Also, it usually
	// sends back RSA, so we try to emulate that too. We're also adding in a bunch of hosts that it's
	// OK for, but might seek to tighten that up in the future. Also, use of wildcards should soon
	// be deprecated.
	doFrontend := func(typ proto.CKSAssetType, aliases []proto.Hostname) error {
		hosts := append(locals, aliases...)
		if opts.WildcardVhostDomain != "" {
			hosts = append(hosts, proto.Hostname("*."+opts.WildcardVhostDomain))
		}
		return EmulateLetsEncrypt(m, hosts, aliases, x509m.ProbeCA, typ)
	}

	hn := opts.Hostnames
	if hn == nil {
		hn = &Hostnames{}
	}
	err = doFrontend(proto.CKSAssetType_RootPKIFrontendX509Cert, hn.Probe)
	if err != nil {
		return err
	}
	err = doFrontend(proto.CKSAssetType_RootPKIBeaconX509Cert, hn.Beacon)
	if err != nil {
		return err
	}
	return nil
}

func SetupServers(
	m shared.MetaContext,
	dbs shared.ManageDBsConfig,
	dir core.Path,
	config *shared.JSonnetTemplate,
	setupOpts SetupOpts,
) (
	*X509Material,
	error,
) {
	isFork := (setupOpts.ForkFrom != nil)
	newDb := !isFork

	var x509material X509Material
	var opts shared.GlobalCLIConfigOpts

	err := setupResolver(m, setupOpts)
	if err != nil {
		return nil, err
	}

	err = x509material.Generate(m, dir, setupOpts)
	if err != nil {
		return nil, err
	}

	err = configureServers(m, dir, x509material, config, setupOpts)
	if err != nil {
		return nil, err
	}

	if setupOpts.UseMockAutocertDoer {
		m.G().SetAutocertDoer(&FakeAutocertDoer{ProbeCA: x509material.ProbeCA})
	}

	// Enable remote IP logging for now
	config.Log.RemoteIPs = true

	// This is somewhat of a hack. We alway set the short host ID to 1 in the
	// config file, but we overwrite it in memory for forked environments.
	// (see setupHostChain where this happens). This isn't ideal, but there's
	// a cold-start problem otherwise.
	m.G().SetShortHostID(1)

	err = cookConfig(m, dir, *config, &opts)
	if err != nil {
		return nil, err
	}

	err = m.Configure(opts)
	if err != nil {
		return nil, err
	}

	if newDb {
		err = initDB(m, dbs)
		if err != nil {
			return nil, err
		}
	}

	err = setupHostChain(m, dir, &x509material, setupOpts.PrimaryHostname)
	if err != nil {
		return nil, err
	}

	err = setupX509v2(m, &x509material, setupOpts)
	if err != nil {
		return nil, err
	}

	err = configureTestInviteCode(m)
	if err != nil {
		return nil, err
	}

	err = shared.GenerateNewChallengeHMACKeys(m)
	if err != nil {
		return nil, err
	}

	err = initMerkleTree(m)
	if err != nil {
		return nil, err
	}

	return &x509material, nil
}

func initMerkleTree(m shared.MetaContext) error {
	s := shared.NewSQLStorage(m)
	err := merkle.InitTree(m, s)
	if err != nil {
		return err
	}
	return nil
}

func RandomMultiUseInviteCode() (*rem.MultiUseInviteCode, error) {
	b := make([]byte, 10)
	err := core.RandomFill(b)
	if err != nil {
		return nil, err
	}
	txt := rem.MultiUseInviteCode(core.Base36Encoding.EncodeToString(b))
	return &txt, nil
}

func InsertNewMutliuseInviteCode(m shared.MetaContext) (*rem.InviteCode, error) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	txt, err := RandomMultiUseInviteCode()
	if err != nil {
		return nil, err
	}
	code := rem.NewInviteCodeWithMultiuse(*txt)

	tags, err := db.Exec(m.Ctx(),
		`INSERT INTO multiuse_invite_codes(short_host_id, code, num_uses, valid)
         VALUES($1, $2, 0, TRUE)`,
		m.ShortHostID().ExportToDB(),
		txt,
	)

	if err != nil {
		return nil, err
	}
	if tags.RowsAffected() != 1 {
		return nil, core.InsertError("master_invite_codes failed insert")
	}
	return &code, nil
}

func CopyMultiUseInviteCode(m shared.MetaContext, to core.ShortHostID) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO multiuse_invite_codes(short_host_id, code, num_uses, valid)
		 SELECT $1, code, 0, TRUE FROM multiuse_invite_codes
		 WHERE short_host_id=$2`,
		to.ExportToDB(),
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to copy invite code")
	}
	return nil
}

func configureTestInviteCode(m shared.MetaContext) error {
	code, err := InsertNewMutliuseInviteCode(m)
	if err != nil {
		return err
	}
	m.G().SetTestMultiUseInviteCode(*code)
	return nil
}

func LaunchServer(m shared.MetaContext, s shared.Server) (func() error, error) {
	m, cancel := m.WithContextCancel()
	s.SetGlobalContext(m.G())
	retFn := func() error { return nil }

	err := s.InitHostID(m)
	if err != nil {
		return retFn, err
	}

	err = s.Setup(m)
	if err != nil {
		return retFn, err
	}

	launchCh := make(chan error)
	finishCh := make(chan error)

	go func() {
		finishCh <- shared.ServeWithSignals(m, s, launchCh)
	}()

	err = <-launchCh
	if err != nil {
		return retFn, err
	}

	retFn = Compose(retFn, func() error {
		cancel()
		return <-finishCh
	})

	return retFn, nil
}

func PostLaunch(m shared.MetaContext) error {
	hkc := m.G().HostChain()
	key := hkc.Key(proto.EntityType_Host)
	if key == nil {
		return core.HostKeyError("host key not found for signing endpoints")
	}

	mkey := hkc.Key(proto.EntityType_HostMetadataSigner)
	if mkey == nil {
		return core.HostKeyError("host key not found for signing metadata")
	}

	err := shared.StorePublicZone(m, *mkey)
	if err != nil {
		return err
	}

	return nil
}

type Hostnames struct {
	Probe  []proto.Hostname
	User   []proto.Hostname
	Beacon []proto.Hostname
}

type SetupOpts struct {
	ForkFrom              *shared.JSonnetTemplate
	MerklePollWait        time.Duration
	Hostnames             *Hostnames
	DoWildcardVhostDomain bool
	WildcardVhostDomain   string
	NVHosts               int
	UseCertDirs           bool
	UseMockAutocertDoer   bool
	PrimaryHostname       proto.Hostname
	ForkFromHostname      proto.Hostname
}

func (s *SetupOpts) initHostname() error {
	if !s.PrimaryHostname.IsZero() {
		return nil
	}
	if !s.ForkFromHostname.IsZero() {
		part, err := randomHostPartErr()
		if err != nil {
			return err
		}
		s.PrimaryHostname = proto.Hostname(
			fmt.Sprintf("f-%s.%s", part, s.ForkFromHostname.String()),
		)
		return nil
	}
	part, err := randomHostPartErr()
	if err != nil {
		return err
	}
	s.PrimaryHostname = proto.Hostname(
		fmt.Sprintf("base-%s.foks", part),
	)
	return nil
}

func (s *SetupOpts) Init() error {
	if s.DoWildcardVhostDomain && s.WildcardVhostDomain == "" {
		d, err := core.RandomDomain()
		if err != nil {
			return err
		}
		s.WildcardVhostDomain = d
	}

	err := s.initHostname()
	if err != nil {
		return err
	}

	return nil
}

type ServerMainRes struct {
	G      *shared.GlobalContext
	X509M  *X509Material
	Config *shared.JSonnetTemplate
	Dir    core.Path
	Stripe *FakeStripe
}

func ServerMain(
	srvs []shared.Server,
	dbs shared.ManageDBsConfig,
	opts SetupOpts,
) (
	func() error,
	*ServerMainRes,
	error,
) {
	fs := NewFakeStripe()
	m := shared.NewMetaContextMain(&shared.GlobalContextOpts{
		Stripe:  fs,
		Testing: true,
	})

	retFn := func() error { return nil }

	dir, err := core.MkdirTemp("go_foks_test")
	if err != nil {
		return retFn, nil, err
	}
	retFn = Compose(retFn, func() error {
		return dir.RemoveAll()
	})

	m.Infow("starting test", "dir", dir)

	var config *shared.JSonnetTemplate
	if opts.ForkFrom == nil {
		retFn, config, err = SetupEnv(m, dir, dbs)
		if err != nil {
			return retFn, nil, err
		}
	} else {
		config = opts.ForkFrom
	}

	x509m, err := SetupServers(m, dbs, dir, config, opts)
	if err != nil {
		return retFn, nil, err
	}

	for _, srv := range srvs {
		tmp, err := LaunchServer(m, srv)
		retFn = Compose(retFn, tmp)
		if err != nil {
			return retFn, nil, err
		}
	}
	err = PostLaunch(m)
	if err != nil {
		return retFn, nil, err
	}

	ret := ServerMainRes{
		G:      m.G(),
		X509M:  x509m,
		Config: config,
		Dir:    dir,
		Stripe: fs,
	}
	return retFn, &ret, nil
}
