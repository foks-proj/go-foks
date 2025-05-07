// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/foks/cmd"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

var tmpDirs []string
var globalTestEnv *common.TestEnv // server-side test environment
var G *shared.GlobalContext       // server-side global context
var vhostDNSAliases []proto.Hostname

func cleanup() {
	for _, d := range tmpDirs {
		os.RemoveAll(d)
	}
}

func merklePoke(t *testing.T) {
	err := globalTestEnv.DirectMerklePoke()
	require.NoError(t, err)
}

type VHost struct {
	core.HostIDAndName
	Addr proto.TCPAddr
}

func vHost(t *testing.T, i int) *VHost {
	h := globalTestEnv.VHostMakeI(t, i)
	m := globalTestEnv.MetaContext()
	_, ext, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Probe)
	require.NoError(t, err)
	a, err := ext.WithHostname(h.Hostname)
	require.NoError(t, err)
	return &VHost{
		HostIDAndName: *h,
		Addr:          a,
	}
}

func setupReturnErr() error {
	globalTestEnv = common.NewTestEnv()
	domain, err := core.RandomDomain()
	if err != nil {
		return err
	}
	primary := proto.Hostname("pri." + domain)
	vhostDNSAliases = []proto.Hostname{primary}
	hns := []proto.Hostname{
		primary,
		proto.Hostname("127.0.0.1"),
		proto.Hostname("localhost"),
		proto.Hostname("::1"),
	}
	n := 5
	for i := 0; i < n; i++ {
		hn, err := common.VHostnameIReturnErr(i, n, domain)
		if err != nil {
			return err
		}
		hns = append(hns, hn)
		vhostDNSAliases = append(vhostDNSAliases, hn)
	}

	err = globalTestEnv.Setup(
		common.SetupOpts{
			WildcardVhostDomain: domain,
			Hostnames: &common.Hostnames{
				Probe: hns,
			},
			NVHosts: n,
		},
	)
	if err != nil {
		return err
	}
	G = globalTestEnv.G
	err = globalTestEnv.DirectMerklePoke()
	if err != nil {
		return err
	}
	err = globalTestEnv.BeaconRegisterReturnErr()
	if err != nil {
		return err
	}
	libclient.InitMacOSKeychainTest()
	return nil
}

func setup() {
	err := setupReturnErr()
	if err != nil {
		panic(err)
	}
}

func shutdown() {
	_ = globalTestEnv.Shutdown()
	libclient.CleanupMacOSKeychainTest()
	cleanup()
}

func testMetaContext() shared.MetaContext {
	return globalTestEnv.MetaContext()
}

func beaconRegister(t *testing.T) {
	globalTestEnv.BeaconRegister(t)
}

type baseArgsOpts struct {
	yubiSeed libyubi.MockYubiSeed
}

func baseArgs(t *testing.T) []string {
	return baseArgsWithOpts(t, baseArgsOpts{})
}

func baseArgsWithOpts(t *testing.T, opts baseArgsOpts) []string {
	tmp, err := os.MkdirTemp("", "foks_test_")
	require.NoError(t, err)
	tmpDirs = append(tmpDirs, tmp)
	e := globalTestEnv
	var seed libyubi.MockYubiSeed
	if opts.yubiSeed != nil {
		seed = opts.yubiSeed
	} else {
		seed, err = libyubi.NewMockYubiSeed()
		require.NoError(t, err)
	}
	return []string{
		"-s",
		"--testing",
		"--hosts-probe", e.ProbeSrv().ListenerAddr().String(),
		"--hosts-beacon", e.BeaconSrv().ListenerAddr().String(),
		"--probe-root-cas", e.X509Material().ProbeCA.CertFile.String(),
		"--home", tmp,
		"--bg-tick", "1h", // no BG looper running explicitly
		"--mock-yubi-seed", seed.String(),
	}
}

func TestProbe(t *testing.T) {
	args := append(baseArgs(t), "tools", "probe")
	err := cmd.MainInner(args, nil)
	require.NoError(t, err)
}

func TestTwoProbes(t *testing.T) {
	args := append(baseArgs(t), "tools", "probe")
	for i := 0; i < 2; i++ {
		err := cmd.MainInner(args, nil)
		require.NoError(t, err)
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

type testAgent struct {
	home     string
	cfgFlags []string
	yubiSeed libyubi.MockYubiSeed
	opts     agentOpts
	g        *libclient.GlobalContext
}

func (t *testAgent) testEnv() *common.TestEnv {
	if t.opts.env != nil {
		return t.opts.env
	}
	return globalTestEnv
}

type agentOpts struct {
	defaultKeyEncryptionMode string
	noTestingFlag            bool
	dnsAliases               []proto.Hostname
	yubiSeed                 libyubi.MockYubiSeed
	socketFile               string
	killNetwork              bool
	env                      *common.TestEnv
}

func dnsAliasesToString(d []proto.Hostname) string {
	var ret []string
	for _, h := range d {
		ret = append(ret, string(h)+"=localhost")
	}
	return strings.Join(ret, ",")
}

func newTestAgentWithOpts(t *testing.T, opts agentOpts) *testAgent {

	tmp, err := os.MkdirTemp("", "foks_test_")
	require.NoError(t, err)
	tmpDirs = append(tmpDirs, tmp)
	var ret testAgent
	ret.home = tmp
	if opts.yubiSeed != nil {
		ret.yubiSeed = opts.yubiSeed
	} else {
		ret.yubiSeed, err = libyubi.NewMockYubiSeed()
		require.NoError(t, err)
	}
	ret.opts = opts
	ret.setFlags(t)
	return &ret
}

func (a *testAgent) setFlags(t *testing.T) {
	opts := a.opts
	e := a.testEnv()
	flags := []string{
		"--hosts-probe", e.ProbeSrv().ListenerAddr().String(),
		"--hosts-beacon", e.BeaconSrv().ListenerAddr().String(),
		"--probe-root-cas", e.X509Material().ProbeCA.CertFile.String(),
		"--mock-yubi-seed", a.yubiSeed.String(),
		"--home", a.home,
		"--bg-tick", "1h", // no BG looper running explicitly,
		"--kv-list-page-size", "3", // short to test pagination
	}
	if !opts.noTestingFlag {
		flags = append(flags, "--testing")
	} else {
		flags = append(flags, "--no-config-create")
	}
	var encMode = "plaintext"
	if opts.defaultKeyEncryptionMode != "" {
		encMode = opts.defaultKeyEncryptionMode
	}

	dnsa := append([]proto.Hostname{}, vhostDNSAliases...)
	if len(opts.dnsAliases) > 0 {
		dnsa = append(dnsa, opts.dnsAliases...)
	}
	flags = append(flags, "--dns-aliases", dnsAliasesToString(dnsa))

	flags = append(flags,
		"--local-keyring-default-encryption-mode", encMode,
	)
	if opts.socketFile != "" {
		flags = append(flags, "--socket", opts.socketFile)
	}
	if opts.killNetwork {
		flags = append(flags, "--test-kill-network")
	}
	a.cfgFlags = flags
}

func newTestAgent(t *testing.T) *testAgent {
	return newTestAgentWithOpts(t, agentOpts{})
}

func (a *testAgent) cmd(args []string) []string {
	var ret []string
	ret = append(ret, a.cfgFlags...)
	ret = append(ret, args...)
	return ret
}

type bufCloser struct {
	bytes.Buffer
}

func (b *bufCloser) Close() error {
	return nil
}

type terminalUI struct {
	b   bytes.Buffer
	err bufCloser
}

func (t *terminalUI) Write(p []byte) (n int, err error) {
	return t.b.Write(p)
}

func (t *terminalUI) Close() error {
	return nil
}

func (t *terminalUI) Printf(f string, args ...interface{}) {
	fmt.Fprintf(&t.b, f, args...)
}

func (t *terminalUI) OutputStream() io.WriteCloser {
	return t
}

type streamWrapper struct {
	*bufCloser
}

func (s streamWrapper) IsATTY() bool {
	return false
}

func (t *terminalUI) ErrorStream() libclient.IOStreamer { return streamWrapper{bufCloser: &t.err} }

func (t *terminalUI) String() string {
	return t.b.String()
}

func (t *terminalUI) Bytes() []byte {
	return t.b.Bytes()
}

func (t *terminalUI) TrimmedString() string {
	return strings.TrimSpace(t.String())
}

func (t *terminalUI) reset() {
	t.b.Reset()
}

var _ libclient.TerminalUIer = (*terminalUI)(nil)

func (a *testAgent) runCmd(
	t *testing.T,
	hook func(m libclient.MetaContext) error,
	args ...string,
) {
	allArgs := a.cmd(args)
	err := cmd.MainInner(allArgs, hook)
	require.NoError(t, err)
}

func (m *testAgent) runCmdWithUIs(
	t *testing.T,
	uis libclient.UIs,
	args ...string,
) {
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	m.runCmd(t, hook, args...)
}

func (m *testAgent) runCmdErrWithUIs(
	uis libclient.UIs,
	args ...string,
) error {
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	return m.runCmdErr(hook, args...)
}

func (a *testAgent) runCmdErr(
	hook func(m libclient.MetaContext) error,
	args ...string,
) error {
	allArgs := a.cmd(args)
	return cmd.MainInner(allArgs, hook)
}

func (a *testAgent) runCmdToBytes(
	t *testing.T,
	args ...string,
) []byte {
	var term terminalUI
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(libclient.UIs{
			Terminal: &term,
		})
		return nil
	}
	a.runCmd(t, hook, args...)
	return term.Bytes()
}

func (a *testAgent) runCmdToJSON(
	t *testing.T,
	out any,
	args ...string,
) {
	prfx := []string{"--json"}
	args = append(prfx, args...)
	var term terminalUI
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(libclient.UIs{
			Terminal: &term,
		})
		return nil
	}
	a.runCmd(t, hook, args...)
	byts := term.Bytes()
	err := json.Unmarshal(byts, out)
	require.NoError(t, err)
}

func (a *testAgent) runAgent(t *testing.T) {
	// Agent runs in the background; grab its global context though
	// so we can manipulate it (and break it) in tests.
	go a.runCmd(t, func(m libclient.MetaContext) error {
		a.g = m.G()
		return nil
	}, "agent")
	a.waitForSocket(t)
}

func (a *testAgent) runAgentWithHook(
	t *testing.T,
	hook func(libclient.MetaContext) error,
) {
	// Agent runs in the background
	go a.runCmd(t, hook, "agent")
	a.waitForSocket(t)
}

func (a *testAgent) waitForSocket(t *testing.T) {
	var tui terminalUI
	a.runCmd(t, func(m libclient.MetaContext) error {
		uis := m.G().UIs()
		uis.Terminal = &tui
		m.G().SetUIs(uis)
		return nil
	}, "ctl", "socket")
	sock := tui.TrimmedString()

	// Now poll for it, shoudln't take long
	wait := time.Millisecond * 1
	for i := 0; i < 20; i++ {
		_, err := os.Stat(sock)
		if err == nil {
			return
		}
		time.Sleep(wait)
		if wait < time.Millisecond*100 {
			wait *= 2
		}
	}
	t.Fatal("socket not found")
}

func (a *testAgent) stop(t *testing.T) {
	a.runCmd(t, nil, "ctl", "shutdown")
}

func TestAgentStartStop(t *testing.T) {
	agent := newTestAgent(t)
	agent.runAgent(t)
	agent.stop(t)
}

func (a *testAgent) status(t *testing.T) lcl.AgentStatus {
	var st lcl.AgentStatus
	a.runCmdToJSON(t, &st, "status")
	return st
}

func activeUserContext(t *testing.T, s lcl.AgentStatus) proto.UserContext {
	var active *proto.UserContext
	for _, u := range s.Users {
		if u.Info.Active {
			if active != nil {
				require.Fail(t, "more than one active user")
			}
			active = &u
		}
	}
	require.NotNil(t, active)
	return *active
}
