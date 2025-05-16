// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/x509"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/spf13/cobra"
)

type bgJobConfigFlags struct {
	sleep  core.Duration
	pause  core.Duration
	jitter int32
}

type BgJobConfigFile struct {
	Sleep  core.Duration `json:"sleep"`
	Pause  core.Duration `json:"pause"`
	Jitter *uint16       `json:"jitter"`
}

type Flags struct {
	configFile string
	home       string
	standalone bool
	rpcLogOpts string
	db         struct {
		hard string
		soft string
	}
	hosts struct {
		probe  string
		beacon string
	}
	dbOpts      string
	secretsFile string
	timeouts    struct {
		usernameCache int64
		kex           int64
		probe         int64
		user          string
		teamCache     string
	}
	probeRootCAs []string
	log          struct {
		out   string
		err   string
		level string
	}
	debug struct {
		spinners bool
	}
	mockYubiSeed string
	socket       string
	json         bool
	agent        struct {
		processLabel string
		plist        struct {
			pathTemplate string
		}
		startupTimeout string
		stopperFile    string
		checkStopper   bool
	}
	merkleRace struct {
		numRetries int64
		waitMsec   int64
	}
	yubi struct {
		noForceUnlock bool
	}
	ui struct {
		simple bool
	}
	localKeyring struct {
		defaultEncryptionMode string
	}
	bg struct {
		tick core.Duration // tick interval (arbitrary duration)
		user bgJobConfigFlags
		clkr bgJobConfigFlags
	}
	dnsAliases     []string
	testing        bool
	noConfigCreate bool
	kv             struct {
		cacheRace struct {
			numRetries int64
			waitMsec   int64
		}
		lockTimeoutMsec int64
		listPageSize    int64
	}
	git struct {
		repackThreshhold int64
		timeout          string
	}
	profiler struct {
		port int64
	}
	test struct {
		killNetwork bool
	}
	oauth2 struct {
		refreshInterval core.Duration
		requestTimeout  core.Duration
	}
}

type JSONStringKVPair struct {
	K string `json:"k"`
	V string `json:"v"`
}

type JSONConfigData struct {
	Home       string `json:"home"`
	RPCLogOpts string `json:"rpc_log_options"`
	Db         struct {
		Hard string `json:"hard"`
		Soft string `json:"soft"`
	} `json:"db"`
	DbOpts      string `json:"db-opts"`
	SecretsFile string `json:"secrets-file"`
	Hosts       struct {
		Probe  string `json:"probe"`
		Beacon string `json:"beacon"`
	} `json:"hosts"`
	ProbeRootCAs core.CAPool `json:"probe_root_CAs"`
	Log          struct {
		Out   string `json:"out"`
		Err   string `json:"err"`
		Level string `json:"level"`
	} `json:"log"`
	Debug struct {
		Spinners bool `json:"spinners"`
	} `json:"debug"`
	Socket       string `json:"socket"`
	MockYubiSeed string `json:"mock_yubi_seed"`
	Agent        struct {
		ProcessLabel string `json:"process_label"`
		Plist        struct {
			PathTemplate string `json:"path_template"`
		}
		StartupTimeout string `json:"startup_timeout"`
		StopperFile    string `json:"stopper_file"`
		CheckStopper   bool   `json:"check_stopper"`
	} `json:"agent"`
	Timeouts struct {
		UsernameCache *uint64 `json:"username_cache"`
		Probe         *uint64 `json:"probe"`
		Kex           *uint64 `json:"kex"`
		User          string  `json:"user"`
		TeamCache     string  `json:"team_cache"`
	} `json:"timeouts"`
	Yubi struct {
		NoForceUnlock bool `json:"no_force_unlock"`
	} `json:"yubi"`
	Ui struct {
		Simple bool `json:"simple"`
	} `json:"ui"`
	MerkleRace struct {
		NumRetries *uint64 `json:"num_retries"`
		WaitMsec   *uint64 `json:"wait_msec"`
	} `json:"merkle_race"`
	LocalKeyring struct {
		DefaultEncryptionMode string `json:"default_encryption_mode"`
	} `json:"local_keyring"`
	Bg struct {
		Tick core.Duration   `json:"tick"`
		User BgJobConfigFile `json:"user"`
		Clkr BgJobConfigFile `json:"clkr"`
	} `json:"bg"`
	DNSAliases []core.DNSAlias `json:"dns_aliases"`
	Kv         struct {
		CacheRace struct {
			NumRetries *uint64 `json:"num_retries"`
			WaitMsec   *uint64 `json:"wait_msec"`
		} `json:"cache_retry"`
		ListPageSize    *uint64 `json:"list_page_size"`
		LockTimeoutMsec *uint64 `json:"lock_timeout_msec"`
	} `json:"kv"`
	Git struct {
		RepackThreshhold *uint64 `json:"repack_threshhold"`
		Timeout          string  `json:"timeout"`
	} `json:"git"`
	OAuth2 struct {
		RefreshInterval core.Duration `json:"refresh_interval"`
		RequestTimeout  core.Duration `json:"request_timeout"`
	} `json:"oauth2"`
	Profiler struct {
		Port *uint64 `json:"port"`
	} `json:"profiler"`
	Clkr struct {
		SleepDuration       core.Duration `json:"sleep_duration"`
		DelaySlot           core.Duration `json:"delay_slot"`
		RandomJitterPercent *uint16       `json:"random_jitter_percent"`
	} `json:"clkr"`
	Testing bool
}

type ConfigFile struct {
	core.ConfigJSonnet[JSONConfigData]
}

func newConfigFile(f core.Path) *ConfigFile {
	return &ConfigFile{
		ConfigJSonnet: core.ConfigJSonnet[JSONConfigData]{
			Path: f,
		},
	}
}

// Client config here
type Config struct {
	sync.Mutex
	fl   Flags
	file *ConfigFile
	tp   ConfigTestParams
}

type ConfigTestParams struct {
	localKeyDefaultEncryptionMode *proto.SecretKeyStorageType
	merkleRaceRetryConfig         *MerkleRaceRetryConfig
	fakeTeamIndexRanges           map[proto.FQTeam]core.RationalRange
}

func (c *Config) setupGlobalFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()

	pf.StringVarP(&c.fl.configFile, "config", "c", "", "config file to use")
	pf.StringVarP(&c.fl.home, "home", "H", "", "home directory to use")
	pf.StringVarP(&c.fl.rpcLogOpts, "rpc-log-opts", "", "", "RPC logger options")
	pf.StringVarP(&c.fl.db.hard, "db-hard", "", "", "sqlite3 database location (hard state)")
	pf.StringVarP(&c.fl.db.soft, "db-soft", "", "", "sqlite3 database location (soft state)")
	pf.StringVarP(&c.fl.dbOpts, "db-opts", "", "", "sqlite3 database options")
	pf.StringVarP(&c.fl.secretsFile, "secrets-file", "", "", "secret key file")
	pf.Int64Var(&c.fl.timeouts.usernameCache, "timeout-cache-username", -1, "cache timeout for username")
	pf.Int64Var(&c.fl.timeouts.probe, "timeout-probe", -1, "timeout for probe")
	pf.Int64Var(&c.fl.timeouts.kex, "timeout-kex", -1, "timeout for key exchange")
	pf.BoolVarP(&c.fl.standalone, "standalone", "s", false, "run in standalone mode with no backgound agent")
	pf.StringVarP(&c.fl.hosts.probe, "hosts-probe", "", "", "hostname/port of home probe server")
	pf.StringVarP(&c.fl.hosts.beacon, "hosts-beacon", "", "", "hostname/port of default beacon server")
	pf.StringVarP(&c.fl.log.out, "log-out", "", "", "where to put the output log file")
	pf.StringVarP(&c.fl.log.err, "log-err", "", "", "where to put the error log file")
	pf.StringVarP(&c.fl.log.level, "log-level", "", "", "log level output")
	pf.StringVarP(&c.fl.socket, "socket", "", "", "socket to use for RPCs to agent")
	pf.StringVarP(&c.fl.agent.processLabel, "agent-process-label", "", "", "For launchd and systemd, process label for agent")
	pf.StringVarP(&c.fl.agent.plist.pathTemplate, "agent-plist-path-template", "", "", "For launchd, path template for agent plist")
	pf.StringArrayVarP(&c.fl.probeRootCAs, "probe-root-cas", "", nil, "root CAs to use to connect to probe hosts")
	pf.BoolVarP(&c.fl.debug.spinners, "debug-spinners", "", false, "slow down page refresh to debug spinners")
	pf.StringVarP(&c.fl.mockYubiSeed, "mock-yubi-seed", "", "", "mock a Yubi key, with a deterministric seed (bas62-encoded)")
	pf.BoolVarP(&c.fl.ui.simple, "simple-ui", "", false, "use simple UI")
	pf.BoolVarP(&c.fl.yubi.noForceUnlock, "no-yubi-force-unlock", "", false, "don't force unlock YubiKey credentials")
	pf.BoolVarP(&c.fl.json, "json", "j", false, "output in JSON format")
	pf.Int64VarP(&c.fl.merkleRace.numRetries, "merkle-race-num-retries", "", -1, "number of retries on suspected Merkle race")
	pf.Int64VarP(&c.fl.merkleRace.waitMsec, "merkle-race-wait-msec", "", -1, "number of msec to wait on suspected Merkle race")
	pf.StringVarP(&c.fl.localKeyring.defaultEncryptionMode, "local-keyring-default-encryption-mode", "", "", "default encryption strategy for local keyring")
	pf.BoolVarP(&c.fl.testing, "testing", "", false, "testing mode; used internally for running regression tests")
	pf.Var(&c.fl.bg.tick, "bg-tick", "background tick interval (arbitrary Duration)")
	pf.Var(&c.fl.bg.user.sleep, "bg-user-sleep", "time between each run of user checks (arbitrary Duration)")
	pf.Var(&c.fl.bg.user.pause, "bg-user-pause", "pause between each user (arbitrary Duration)")
	pf.StringSliceVarP(&c.fl.dnsAliases, "dns-aliases", "", nil, "DNS aliases to use for testing (can spcify multiple in a=b form)")
	pf.Int64Var(&c.fl.kv.cacheRace.numRetries, "kv-cache-race-num-retries", -1, "number of retries on suspected cache race")
	pf.Int64Var(&c.fl.kv.cacheRace.waitMsec, "kv-cache-race-wait-msec", 0, "number of msec to wait on suspected cache race")
	pf.Int64Var(&c.fl.kv.listPageSize, "kv-list-page-size", -1, "page size for list operations")
	pf.Int64Var(&c.fl.kv.lockTimeoutMsec, "kv-lock-timeout-msec", -1, "timeout for lock operations")
	pf.BoolVar(&c.fl.noConfigCreate, "no-config-create", false, "don't create a config file if it doesn't exist")
	pf.Int64Var(&c.fl.git.repackThreshhold, "git-repack-threshhold", -1, "repack threshhold for git operations")
	pf.Int64Var(&c.fl.profiler.port, "profiler-port", -1, "port for profiler")
	pf.StringVar(&c.fl.git.timeout, "git-timeout", "", "timeout for git operations (in Go duration format)")
	pf.StringVar(&c.fl.agent.startupTimeout, "agent-startup-timeout", "", "timeout for agent startup (in Go duration format)")
	pf.StringVar(&c.fl.timeouts.user, "user-timeout", "", "timeout for user operations (in Go duration format)")
	pf.StringVar(&c.fl.timeouts.teamCache, "team-cached-timeout", "", "cache timeout for teams operations (in Go duration format)")
	pf.BoolVar(&c.fl.test.killNetwork, "test-kill-network", false, "kill network for testing (only works in testing mode)")
	pf.Var(&c.fl.oauth2.refreshInterval, "oauth2-refresh-interval", "refresh interval for OAuth2 tokens")
	pf.Var(&c.fl.oauth2.requestTimeout, "oauth2-request-timeout", "request timeout for OAuth2 tokens")
	pf.Var(&c.fl.bg.clkr.sleep, "bg-clkr-sleep-duration", "sleep duration between each full CLKR run")
	pf.Var(&c.fl.bg.clkr.pause, "bg-clkr-pause-duration", "delay slot between each team explored")
	pf.Int32Var(&c.fl.bg.clkr.jitter, "bg-clkr-random-jitter-percent", -1, "what %age of the duration to randomly jitter")
	pf.Int32Var(&c.fl.bg.user.jitter, "bg-user-random-jitter-percent", -1, "what %age of the duration to randomly jitter")
	pf.StringVar(&c.fl.agent.stopperFile, "agent-stopper-file", "", "file to check for to stop the agent")
	pf.BoolVar(&c.fl.agent.checkStopper, "agent-check-stopper", false, "check for the stopper file to stop the agent")
}

func ParseSecretKeyStorageType(s string) (*proto.SecretKeyStorageType, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	var tmp proto.SecretKeyStorageType
	switch s {
	case "plaintext":
		tmp = proto.SecretKeyStorageType_PLAINTEXT
	case "macos":
		tmp = proto.SecretKeyStorageType_ENC_MACOS_KEYCHAIN
	case "keychain":
		tmp = proto.SecretKeyStorageType_ENC_KEYCHAIN
	case "noise":
		tmp = proto.SecretKeyStorageType_ENC_NOISE_FILE
	case "passphrase":
		tmp = proto.SecretKeyStorageType_ENC_PASSPHRASE
	case "default", "":
		return nil, nil
	default:
		return nil, core.BadArgsError("unknown secret key storage type")
	}
	return &tmp, nil
}

func (c *Config) Setup(ctx context.Context, cmd *cobra.Command) error {
	c.Lock()
	defer c.Unlock()
	c.setupGlobalFlags(cmd)
	return nil
}

func prefixed(s string) string {
	return strings.ToUpper(AppName) + "_" + s
}

// To be used in testing -- set the home CLI flag, so that we can force testing into
// a sandbox temp directory
func (c *Config) TestSetHomeCLIFlag(h string) {
	c.Lock()
	defer c.Unlock()
	c.fl.home = h
}

func (c *Config) TestSetHostsBeacon(b string) {
	c.Lock()
	defer c.Unlock()
	c.fl.hosts.beacon = b
}

func (c *Config) TestSetProbeRootCAs(s []string) {
	c.Lock()
	defer c.Unlock()
	c.fl.probeRootCAs = s
}

func (c *Config) FakeTeamIndexRangeFor(t proto.FQTeam) *core.RationalRange {
	c.Lock()
	defer c.Unlock()
	if c.tp.fakeTeamIndexRanges == nil {
		return nil
	}
	ret, ok := c.tp.fakeTeamIndexRanges[t]
	if !ok {
		return nil
	}
	return &ret
}

func (c *Config) TestSetFakeRationalRange(fqt proto.FQTeam, tir core.RationalRange) error {
	c.Lock()
	defer c.Unlock()
	if c.tp.fakeTeamIndexRanges == nil {
		c.tp.fakeTeamIndexRanges = make(map[proto.FQTeam]core.RationalRange)
	}
	c.tp.fakeTeamIndexRanges[fqt] = tir
	return nil
}

func (c *Config) GetTestKillNetwork() bool {
	c.Lock()
	defer c.Unlock()
	return c.getTestingModeLocked() && c.fl.test.killNetwork
}

func (c *Config) getCAPoolLocked(cli []string, envKey string, cfg *core.CAPool, def []string) *core.CAPool {
	if len(cli) > 0 {
		return core.NewCAPool(cli)
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		return core.NewCAPool(strings.Split(raw, ","))
	}
	if cfg != nil && cfg.IsLoaded() {
		return cfg
	}
	if len(def) == 0 {
		return nil
	}
	return core.NewCAPool(def)
}

func (c *Config) GetCAPool(cli []string, envKey string, cfg *core.CAPool, def []string) *core.CAPool {
	c.Lock()
	defer c.Unlock()
	return c.getCAPoolLocked(cli, envKey, cfg, def)
}

func (c *Config) getString(cli string, envKey string, cfg string, def string) string {
	c.Lock()
	defer c.Unlock()
	return c.getStringLocked(cli, envKey, cfg, def)
}

func (c *Config) getStringLocked(cli string, envKey string, cfg string, def string) string {
	if cli != "" {
		return cli
	}
	ret := os.Getenv(envKey)
	if ret != "" {
		return ret
	}
	if cfg != "" {
		return cfg
	}
	return def
}

func (c *Config) ParseKVPairs(s []string) []JSONStringKVPair {
	var ret []JSONStringKVPair
	for _, v := range s {
		parts := strings.Split(v, "=")
		if len(parts) != 2 {
			continue
		}
		ret = append(ret, JSONStringKVPair{K: parts[0], V: parts[1]})
	}
	return ret
}

func (c *Config) getDNSAliasesLocked(cli []string, envKey string, cfg []core.DNSAlias) ([]core.DNSAlias, error) {
	if len(cli) > 0 {
		return core.ParseCNameAliases(cli)
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		return core.ParseCNameAliases(strings.Split(raw, ","))
	}
	if len(cfg) > 0 {
		return cfg, nil
	}
	return nil, nil
}

func (c *Config) GetDNSAliases() (core.CNameResolver, error) {
	c.Lock()
	defer c.Unlock()
	kvp, err := c.getDNSAliasesLocked(c.fl.dnsAliases, prefixed("DNS_ALIASES"), c.file.Data.DNSAliases)
	if err != nil {
		return nil, err
	}
	if len(kvp) == 0 {
		return nil, nil
	}
	ret := core.NewSimpleCNameResolver().WithObjs(kvp)
	return ret, nil
}

func (c *Config) GetAgentCheckStopper() bool {
	return c.getBool(
		c.fl.agent.checkStopper,
		prefixed("AGENT_CHECK_STOPPER"),
		c.file.Data.Agent.CheckStopper,
		false,
	)
}

func (c *Config) getBool(cli bool, envKey string, cfg bool, def bool) bool {
	c.Lock()
	defer c.Unlock()
	return c.getBoolLocked(cli, envKey, cfg, def)
}

func (c *Config) getDuration2Locked(
	cli core.Duration,
	envKey string,
	cfg core.Duration,
	def time.Duration,
) (time.Duration, error) {
	if !cli.IsZero() {
		return cli.Duration, nil
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		return time.ParseDuration(raw)
	}
	if !cfg.IsZero() {
		return cfg.Duration, nil
	}
	return def, nil
}

func (c *Config) getDurationLocked(cli string, envKey string, cfg string, def string) (time.Duration, error) {
	if cli != "" {
		return time.ParseDuration(cli)
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		return time.ParseDuration(raw)
	}
	if cfg != "" {
		return time.ParseDuration(cfg)
	}
	return time.ParseDuration(def)
}

func (c *Config) GitTimeoutDuration() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDurationLocked(
		c.fl.git.timeout,
		prefixed("GIT_TIMEOUT"),
		c.file.Data.Git.Timeout,
		"5h",
	)
}

func (c *Config) GetOAuth2RefreshInterval() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDuration2Locked(
		c.fl.oauth2.refreshInterval,
		prefixed("OAUTH2_REFRESH_INTERVAL"),
		c.file.Data.OAuth2.RefreshInterval,
		time.Minute*time.Duration(5),
	)
}

func (c *Config) GetOAuth2RequestTimeout() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDuration2Locked(
		c.fl.oauth2.requestTimeout,
		prefixed("OAUTH2_REQUEST_TIMEOUT"),
		c.file.Data.OAuth2.RequestTimeout,
		time.Second*time.Duration(15),
	)
}

func (c *Config) AgentStartupTimeout() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDurationLocked(
		c.fl.agent.startupTimeout,
		prefixed("AGENT_STARTUP_TIMEOUT"),
		c.file.Data.Agent.StartupTimeout,
		"5s",
	)
}

// UserTimeout is the amount of time to wait when trying to
// reconnect a user to its home server
func (c *Config) UserTimeout() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDurationLocked(
		c.fl.timeouts.user,
		prefixed("USER_TIMEOUT"),
		c.file.Data.Timeouts.User,
		"5s",
	)
}

func (c *Config) TeamCacheTimeout() (time.Duration, error) {
	c.Lock()
	defer c.Unlock()
	return c.getDurationLocked(
		c.fl.timeouts.teamCache,
		prefixed("TEAM_CACHE_TIMEOUT"),
		c.file.Data.Timeouts.TeamCache,
		"15s",
	)
}

func (c *Config) getMsecDurationLocked(cli int64, envKey string, cfg *uint64, def int64) time.Duration {

	conv := func(i int) time.Duration {
		return time.Duration(i) * time.Millisecond
	}

	getInt := func() int {
		if cli > 0 {
			return int(cli)
		}
		e := os.Getenv(envKey)
		if e != "" {
			i, err := strconv.Atoi(e)
			if err == nil {
				return i
			}
		}
		if cfg != nil {
			return int(*cfg)
		}
		return int(def)
	}

	return conv(getInt())
}

func (c *Config) getBoolLocked(cli bool, envKey string, cfg bool, def bool) bool {
	if cli {
		return cli
	}
	e := os.Getenv(envKey)
	if e == "0" {
		return false
	}
	if e != "" {
		return true
	}
	if cfg {
		return cfg
	}
	return def
}

func (c *Config) HomeFinder() HomeFinder {
	return NewHomeFinder(
		AppName,
		func() string { return c.fl.home },
		func() string {
			if c.file != nil {
				return c.file.Data.Home
			}
			return ""
		},
		nil,
		runtime.GOOS,
		func() RunMode { return RunModeProd },
		os.Getenv,
	)
}

func (c *Config) FileInRuntimeDir(log core.ThinLogger, s string) string {
	runtimeDir, err := c.HomeFinder().RuntimeDir()
	if err != nil {
		log.Errorw("Config.fileInRuntimeDir", "err", err)
		return ""
	}
	return filepath.Join(runtimeDir, s)
}

func (c *Config) FileInConfigDir(log core.ThinLogger, s string) string {
	cfgDir, err := c.HomeFinder().ConfigDir()
	if err != nil {
		log.Errorw("Config.fileInHome", "err", err)
		return ""
	}
	return filepath.Join(cfgDir, s)
}

func (c *Config) FileInDataDir(log core.ThinLogger, s string) string {
	dataDir, err := c.HomeFinder().DataDir()
	if err != nil {
		log.Errorw("Config.fileInDataDir", "err", err)
		return ""
	}
	return filepath.Join(dataDir, s)
}

func (c *Config) FileInCacheDir(log core.ThinLogger, s string) string {
	cacheDir, err := c.HomeFinder().CacheDir()
	if err != nil {
		log.Errorw("Config.fileInCacheDir", "err", err)
		return ""
	}
	return filepath.Join(cacheDir, s)
}

func (c *Config) KexTimeout() time.Duration {
	return c.getTimeout(c.fl.timeouts.kex, prefixed("KEX_TIMEOUT"), c.file.Data.Timeouts.Kex, 1800)
}

func (c *Config) ProbeTimeout() time.Duration {
	return c.getTimeout(c.fl.timeouts.probe, prefixed("PROBE_TIMEOUT"), c.file.Data.Timeouts.Probe, 20)
}

func (c *Config) getTimeout(cli int64, envKey string, cfg *uint64, def uint64) time.Duration {
	u := c.getUint(cli, envKey, cfg, def)
	return time.Duration(u) * time.Second
}

func (c *Config) getUint16(cli int32, envKey string, cfg *uint16, def uint16) uint16 {
	if cli >= 0 {
		return uint16(cli)
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		u, err := strconv.ParseUint(raw, 10, 16)
		if err == nil {
			return uint16(u)
		}
	}
	if cfg != nil {
		return uint16(*cfg)
	}
	return def
}

func (c *Config) getUint(cli int64, envKey string, cfg *uint64, def uint64) uint64 {
	if cli >= 0 {
		return uint64(cli)
	}
	raw := os.Getenv(envKey)
	if raw != "" {
		u, err := strconv.ParseUint(raw, 10, 64)
		if err == nil {
			return u
		}
	}
	if cfg != nil {
		return *cfg
	}
	return def
}

func (c *Config) getPath(typ DirType, cli string, envKey string, cfg string, def string) (string, error) {
	c.Lock()
	defer c.Unlock()
	return c.getPathLocked(typ, cli, envKey, cfg, def)
}

func (c *Config) getPathLocked(typ DirType, cli string, envKey string, cfg string, def string) (string, error) {
	base := c.getStringLocked(cli, envKey, cfg, def)
	if base == "" {
		return "", nil
	}
	if typ == DirTypeLog && (base == "stdout" || base == "stderr") {
		return base, nil
	}
	if filepath.IsAbs(base) {
		return base, nil
	}
	dir, err := HomeFindDir(c.HomeFinder(), typ)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, base), nil
}

func (c *Config) ConfigFile() (core.Path, error) {
	c.Lock()
	defer c.Unlock()
	return c.configFileLocked()
}

func (c *Config) GetAgentStopperFile() (*StopperFile, error) {
	s, err := c.getPath(
		DirTypeConfig,
		c.fl.agent.stopperFile,
		prefixed("AGENT_STOPPER_FILE"),
		c.file.Data.Agent.StopperFile,
		"agent.stopper",
	)
	if err != nil {
		return nil, err
	}
	ret := StopperFile{Path: core.Path(s)}
	return &ret, nil
}

func (c *Config) configFileLocked() (core.Path, error) {
	ret, err := c.getPathLocked(DirTypeConfig, c.fl.configFile, prefixed("CONFIG"), "", "config.jsonnet")
	return core.Path(ret), err
}

func (c *Config) LogsOutFile(app string) (string, error) {
	return c.getPath(DirTypeLog, c.fl.log.out, prefixed("LOG_OUT"), c.file.Data.Log.Out, app+".log")
}

func (c *Config) LogsErrFile(app string) (string, error) {
	return c.getPath(DirTypeLog, c.fl.log.err, prefixed("LOG_ERR"), c.file.Data.Log.Err, app+".err.log")
}

func (c *Config) LogLevel() (string, error) {
	c.Lock()
	defer c.Unlock()
	return c.getStringLocked(c.fl.log.level, prefixed("LOG_LEVEL"), c.file.Data.Log.Level, ""), nil
}

func (c *Config) SecretKeyFile() (string, error) {
	return c.getPath(DirTypeConfig, c.fl.secretsFile, prefixed("SECRETS_FILE"), c.file.Data.SecretsFile, "foks-secrets")
}

func (c *Config) SocketFile() (core.Path, error) {
	ret, err := c.getPath(DirTypeRuntime, c.fl.socket, prefixed("SOCKET_FILE"), c.file.Data.Socket, "foks.sock")
	return core.Path(ret), err
}

func (c *Config) KVListPageSize() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.getUint(c.fl.kv.listPageSize, prefixed("KV_LIST_PAGE_SIZE"), c.file.Data.Kv.ListPageSize, 100)
}

func (c *Config) ProfilerPort() int {
	c.Lock()
	defer c.Unlock()
	ret := c.getUint(c.fl.profiler.port, prefixed("PROFILER_PORT"), c.file.Data.Profiler.Port, 0)
	return int(ret)
}

func (c *Config) GitRepackThreshhold() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.getUint(c.fl.git.repackThreshhold, prefixed("GIT_REPACK_THRESHHOLD"), c.file.Data.Git.RepackThreshhold, 1024)
}

func (c *Config) GetMockYubiSeed() (libyubi.MockYubiSeed, error) {
	c.Lock()
	defer c.Unlock()
	if libyubi.GetRealForce() {
		return nil, nil
	}
	seed := c.getStringLocked(
		c.fl.mockYubiSeed,
		prefixed("MOCK_YUBI_SEED"),
		c.file.Data.MockYubiSeed,
		"",
	)
	if seed == "" {
		return nil, nil
	}
	buf, err := core.B62Decode(seed)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Config) RpcLogOpts() (string, error) {
	c.Lock()
	defer c.Unlock()
	return c.getStringLocked(c.fl.rpcLogOpts, prefixed("RPC_LOG_OPTS"), c.file.Data.RPCLogOpts, ""), nil
}

func (c *Config) PlistPathTeplate() (string, error) {
	c.Lock()
	defer c.Unlock()
	return c.getStringLocked(
		c.fl.agent.plist.pathTemplate,
		prefixed("AGENT_PLIST_PATH_TEMPLATE"),
		c.file.Data.Agent.Plist.PathTemplate,
		"{{.Home}}/Library/LaunchAgents/{{.Label}}.plist",
	), nil
}

func (c *Config) AgentProcessLabel() (string, error) {
	c.Lock()
	defer c.Unlock()
	return c.getStringLocked(
		c.fl.agent.processLabel,
		prefixed("AGENT_PROCESS_LABEL"),
		c.file.Data.Agent.ProcessLabel,
		"com.ne43.foks.agent",
	), nil
}

func (c *Config) DbFile(which DbType) (string, error) {
	switch which {
	case DbTypeHard:
		return c.getPath(DirTypeData, c.fl.db.hard, prefixed("DB_HARD"), c.file.Data.Db.Hard, AppName+".hard.sqlite")
	case DbTypeSoft:
		return c.getPath(DirTypeCache, c.fl.db.soft, prefixed("DB_SOFT"), c.file.Data.Db.Soft, AppName+".soft.sqlite")
	default:
		return "", core.InternalError("unknown db type")
	}
}

func (c *Config) DbOpts(log core.ThinLogger) string {
	return c.getString(c.fl.dbOpts, prefixed("DB_OPTS"), c.file.Data.DbOpts, "")
}

func (c *Config) ProbeRootCAs(ctx context.Context) (*x509.CertPool, []string, error) {
	c.Lock()
	defer c.Unlock()
	ca := c.getCAPoolLocked(c.fl.probeRootCAs, prefixed("PROBE_ROOT_CAS"), &c.file.Data.ProbeRootCAs, nil)
	if ca == nil {
		ca = core.NewSystemCAPool()
	}
	return ca.CompileReturnRaw(ctx, core.CAPoolTypeDefaultToSystem)
}

func (c *Config) HostsProbe() proto.TCPAddr {
	tmp := c.getString(c.fl.hosts.probe, prefixed("HOSTS_PROBE"), c.file.Data.Hosts.Probe, string(DefProbeAddr))
	return proto.TCPAddr(tmp)
}

func (c *Config) HostsBeacon() proto.TCPAddr {
	tmp := c.getString(c.fl.hosts.beacon, prefixed("HOSTS_BEACON"), c.file.Data.Hosts.Beacon, "")
	return proto.TCPAddr(tmp)
}

func (c *Config) openConfigFileLocked(ctx context.Context, log core.ThinLogger) error {
	fn, err := c.configFileLocked()
	if err != nil {
		return err
	}

	cfgf := newConfigFile(fn)
	v, err := c.HomeFinder().CacheDir()
	if err != nil {
		log.Errorw("openConfigFile", "err", err)
	} else {
		cfgf.AddExtVar("cache_dir", v)
	}

	v, err = c.HomeFinder().DataDir()
	if err != nil {
		log.Errorw("openConfigFile", "err", err)
	} else {
		cfgf.AddExtVar("data_dir", v)
	}

	v, err = c.HomeFinder().ConfigDir()
	if err != nil {
		log.Errorw("openConfigFile", "err", err)
	} else {
		cfgf.AddExtVar("config_dir", v)
	}

	c.file = cfgf
	if fn != "" {
		err = c.openInner(ctx, log, cfgf)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) openInner(ctx context.Context, log core.ThinLogger, cfgf *ConfigFile) error {
	err := cfgf.Load(ctx)
	if err == nil {
		return nil
	}
	log.Infow("openConfigFile", "err", err)
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !c.getTestingModeLocked() && !c.fl.noConfigCreate {
		log.Infow("openConfigFile", "msg", "creating new empty config file")
		err = cfgf.Create(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) DefaultLocalKeyEncryption() (*proto.SecretKeyStorageType, error) {
	c.Lock()
	defer c.Unlock()
	return c.defaultLocalKeyEncryptionLocked()
}

func (c *Config) defaultLocalKeyEncryptionLocked() (
	*proto.SecretKeyStorageType,
	error,
) {

	if c.tp.localKeyDefaultEncryptionMode != nil {
		return c.tp.localKeyDefaultEncryptionMode, nil
	}

	s := c.getStringLocked(
		c.fl.localKeyring.defaultEncryptionMode,
		prefixed("LOCAL_KEYRING_DEFAULT_ENCRYPTION_STRATEGY"),
		c.file.Data.LocalKeyring.DefaultEncryptionMode,
		"",
	)
	return ParseSecretKeyStorageType(s)
}

func (c *Config) makeConfigDir(ctx context.Context) error {
	// Make our config dir if it didn't already exist, since we'll need it
	// to do things like write private keys in the secret store.
	configDir, err := c.HomeFinder().ConfigDir()
	if err != nil {
		return err
	}
	err = os.MkdirAll(configDir, MkdirAllMode)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) makeLogDir(ctx context.Context) error {
	logDir, err := c.HomeFinder().LogDir()
	if err != nil {
		return err
	}
	err = os.MkdirAll(logDir, MkdirAllMode)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) Configure(ctx context.Context, log core.ThinLogger) error {
	c.Lock()
	defer c.Unlock()

	// keep in mind that config file might dictate where our home directory is!
	err := c.openConfigFileLocked(ctx, log)
	if err != nil {
		return err
	}

	err = c.makeConfigDir(ctx)
	if err != nil {
		return err
	}

	err = c.makeLogDir(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) Standalone() bool {
	c.Lock()
	defer c.Unlock()
	return c.fl.standalone
}

func (c *Config) SimpleUI() bool {
	return c.getBool(c.fl.ui.simple, prefixed("SIMPLE_UI"), c.file.Data.Ui.Simple, false)
}

func (c *Config) DebugSpinners() bool {
	return c.getBool(c.fl.debug.spinners, prefixed("DEBUG_SPINNERS"), c.file.Data.Debug.Spinners, false)
}

func (c *Config) TestingMode() bool {
	c.Lock()
	defer c.Unlock()
	return c.getTestingModeLocked()
}

func (c *Config) getTestingModeLocked() bool {
	return c.getBoolLocked(c.fl.testing, prefixed("TESTING"), c.file.Data.Testing, false)
}

func (c *Config) YubiNoForceUnlock() bool {
	return c.getBool(c.fl.yubi.noForceUnlock, prefixed("YUBI_NO_FORCE_UNLOCK"), c.file.Data.Yubi.NoForceUnlock, false)
}

func (c *Config) JSONOutput() bool {
	return c.getBool(c.fl.json, prefixed("JSON_OUTPUT"), false, false)
}

func (c *Config) RPCLogOptions() (rpc.LogOptions, error) {
	c.Lock()
	defer c.Unlock()
	return rpc.ParseStandardLogOptions(c.fl.rpcLogOpts)
}

type MerkleRaceRetryConfig struct {
	NumRetries int
	Wait       time.Duration
}

type KvConfig struct {
	CacheRace struct {
		NumRetries int
		Wait       time.Duration
	}
	LockTimeout time.Duration
}

type BgConfig struct {
	Tick time.Duration
	User BgTiming
	Clkr BgTiming
}

type BgTiming struct {
	sleep  time.Duration
	pause  time.Duration
	jitter uint16
}

func (c *Config) TestSetTestingMode() {
	c.Lock()
	defer c.Unlock()
	c.fl.testing = true
}

func (c *Config) TestDisableMerkleRaceRetry() {
	c.Lock()
	defer c.Unlock()
	c.fl.merkleRace.numRetries = 0
}

func (c *Config) TestEnableKVRetry() {
	c.Lock()
	defer c.Unlock()
	c.fl.kv.cacheRace.numRetries = 500
}

func (c *Config) TestSetKVListPageSize(i int64) {
	c.Lock()
	defer c.Unlock()
	c.fl.kv.listPageSize = i
}

func (c *Config) TestSetLogTargets(out, err string) {
	c.Lock()
	defer c.Unlock()
	c.fl.log.out = out
	c.fl.log.err = err
}

func (c *Config) TestDisableSecretKeyEncryption() {
	c.Lock()
	defer c.Unlock()
	tmp := proto.SecretKeyStorageType_PLAINTEXT
	c.tp.localKeyDefaultEncryptionMode = &tmp
}

func (c *Config) TestSetMerkleRaceRetryConfig(p MerkleRaceRetryConfig) {
	c.Lock()
	defer c.Unlock()
	c.tp.merkleRaceRetryConfig = &p
}

func (c *Config) MerkleRaceRetryConfig() (*MerkleRaceRetryConfig, error) {
	c.Lock()
	defer c.Unlock()

	if c.tp.merkleRaceRetryConfig != nil {
		return c.tp.merkleRaceRetryConfig, nil
	}

	nRetries := c.getUint(
		c.fl.merkleRace.numRetries,
		prefixed("MERKLE_RACE_NUM_RETRIES"),
		c.file.Data.MerkleRace.NumRetries,
		10,
	)

	wait := c.getMsecDurationLocked(
		c.fl.merkleRace.waitMsec,
		prefixed("MERKLE_RACE_WAIT_MSEC"),
		c.file.Data.MerkleRace.WaitMsec,
		25,
	)

	return &MerkleRaceRetryConfig{
		NumRetries: int(nRetries),
		Wait:       wait,
	}, nil
}

func (c *Config) KvConfig() (*KvConfig, error) {
	c.Lock()
	defer c.Unlock()

	nRetries := c.getUint(
		c.fl.kv.cacheRace.numRetries,
		prefixed("KV_CACHE_RACE_NUM_RETRIES"),
		c.file.Data.Kv.CacheRace.NumRetries,
		500,
	)

	wait := c.getMsecDurationLocked(
		c.fl.kv.cacheRace.waitMsec,
		prefixed("KV_CACHE_RACE_WAIT_MSEC"),
		c.file.Data.Kv.CacheRace.WaitMsec,
		0,
	)

	lto := c.getMsecDurationLocked(
		c.fl.kv.lockTimeoutMsec,
		prefixed("KV_LOCK_TIMEOUT_MSEC"),
		c.file.Data.Kv.LockTimeoutMsec,
		int64(proto.ExportDurationMilli(time.Minute)),
	)

	return &KvConfig{
		CacheRace: struct {
			NumRetries int
			Wait       time.Duration
		}{
			NumRetries: int(nRetries),
			Wait:       wait,
		},
		LockTimeout: lto,
	}, nil

}

type durationParamSet struct {
	cli core.Duration
	env string
	cfg core.Duration
	def time.Duration
}

type jitterParamSet struct {
	cli int32
	env string
	cfg *uint16
	def uint16
}

func (c *Config) getJitterFromParamSetLocked(
	ps jitterParamSet,
) uint16 {
	return c.getUint16(ps.cli, ps.env, ps.cfg, ps.def)
}

func (c *Config) getDurationFromParamSetLocked(
	ps durationParamSet,
) (time.Duration, error) {
	return c.getDuration2Locked(ps.cli, ps.env, ps.cfg, ps.def)
}

func (c *Config) getBgTimingLocked(
	sleep, pause durationParamSet,
	jitter jitterParamSet,
) (*BgTiming, error) {
	s, err := c.getDurationFromParamSetLocked(sleep)
	if err != nil {
		return nil, err
	}

	p, err := c.getDurationFromParamSetLocked(pause)
	if err != nil {
		return nil, err
	}
	jit := c.getJitterFromParamSetLocked(jitter)

	return &BgTiming{
		pause:  p,
		sleep:  s,
		jitter: jit,
	}, nil
}

func (c *Config) BgConfig() (*BgConfig, error) {
	c.Lock()
	defer c.Unlock()

	tick, err := c.getDuration2Locked(
		c.fl.bg.tick,
		prefixed("BG_TICK"),
		c.file.Data.Bg.Tick,
		time.Second*10,
	)
	if err != nil {
		return nil, err
	}

	user, err := c.getBgTimingLocked(
		durationParamSet{
			cli: c.fl.bg.user.sleep,
			env: prefixed("BG_USER_SLEEP"),
			cfg: c.file.Data.Bg.User.Sleep,
			def: time.Minute * 13,
		},
		durationParamSet{
			cli: c.fl.bg.user.pause,
			env: prefixed("BG_USER_PAUSE"),
			cfg: c.file.Data.Bg.User.Pause,
			def: time.Second * 10,
		},
		jitterParamSet{
			cli: c.fl.bg.user.jitter,
			env: prefixed("BG_USER_JITTER"),
			cfg: c.file.Data.Bg.User.Jitter,
			def: 10,
		},
	)
	if err != nil {
		return nil, err
	}

	clkr, err := c.getBgTimingLocked(
		durationParamSet{
			cli: c.fl.bg.clkr.sleep,
			env: prefixed("BG_CLKR_SLEEP"),
			cfg: c.file.Data.Bg.Clkr.Sleep,
			def: time.Minute * 17,
		},
		durationParamSet{
			cli: c.fl.bg.clkr.pause,
			env: prefixed("BG_CLKR_PAUSE"),
			cfg: c.file.Data.Bg.Clkr.Pause,
			def: time.Second * 10,
		},
		jitterParamSet{
			cli: c.fl.bg.clkr.jitter,
			env: prefixed("BG_CLKR_JITTER"),
			cfg: c.file.Data.Bg.Clkr.Jitter,
			def: 10,
		},
	)
	if err != nil {
		return nil, err
	}

	return &BgConfig{
		Tick: tick,
		User: *user,
		Clkr: *clkr,
	}, nil
}

func (c *BgTiming) applyJitter(base time.Duration) time.Duration {
	if c.jitter == 0 {
		return base
	}
	jitFact := time.Duration(rand.Intn(int(2*c.jitter))-int(c.jitter)) / 100
	ret := base * (1 + jitFact)
	return ret
}

func (c *BgTiming) Sleep() time.Duration {
	return c.applyJitter(c.sleep)
}

func (c *BgTiming) Pause() time.Duration {
	return c.applyJitter(c.pause)
}

func NewBgTiming(sleep, pause time.Duration, jitter uint16) BgTiming {
	return BgTiming{
		sleep:  sleep,
		pause:  pause,
		jitter: jitter,
	}
}
