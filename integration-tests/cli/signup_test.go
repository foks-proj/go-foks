// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/foks/cmd"
	"github.com/foks-proj/go-foks/client/foks/cmd/simple_ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

var usedKeySlots = make(map[proto.YubiSlot]bool)

type mockSignupUI struct {
	promptSet        []string
	newUserIdx       int
	noInviteCode     bool
	invite           *rem.InviteCode
	whackyDeviceName bool
	useDeviceKey     bool
	yubiCardPos      int
	testYubiCreate   bool
	em               proto.Email
	waitListID       proto.WaitListID
	username         proto.NameUtf8
	deviceName       proto.DeviceName
	hespInputCh      chan hespAndErr
	hespOutpuCh      chan proto.KexHESP
	passphrase       proto.Passphrase
	homeServer       *proto.TCPAddr
	noYubiReuseCheck bool
	env              *common.TestEnv
	ssoUrl           proto.URLString
	ssoLoginRes      *proto.SSOLoginRes
	ssoUrlCb         func(proto.URLString)
	deviceErr        error
}

func (s *mockSignupUI) Begin(m libclient.MetaContext) error    { return nil }
func (s *mockSignupUI) Rollback(m libclient.MetaContext) error { return nil }
func (s *mockSignupUI) Commit(m libclient.MetaContext) error   { return nil }

func (s *mockSignupUI) PickExistingUser(m libclient.MetaContext, lst []proto.UserInfo) (int, error) {
	var err error
	s.promptSet, s.newUserIdx, err = simple_ui.FormatPickUserItems(lst)
	return -1, err
}

func (s *mockSignupUI) ConfirmActiveUser(m libclient.MetaContext, u proto.UserInfo) error {
	return nil
}

func (s *mockSignupUI) PickServer(
	m libclient.MetaContext,
	def proto.TCPAddr,
	timeout time.Duration,
) (
	*proto.TCPAddr,
	error,
) {
	if s.homeServer != nil {
		return s.homeServer, nil
	}
	return nil, nil
}

func (s *mockSignupUI) CheckedServer(m libclient.MetaContext, addr proto.TCPAddr, e error) error {
	return nil
}

func (s *mockSignupUI) CheckedInviteCode(m libclient.MetaContext, code lcl.InviteCodeString, e error) error {
	return nil
}

func (s *mockSignupUI) GetKexHESP(
	m libclient.MetaContext,
	ourHesp proto.KexHESP,
	lastErr error,
) (
	*proto.KexHESP,
	error,
) {
	if s.hespInputCh == nil || s.hespOutpuCh == nil {
		return nil, core.NotImplementedError{}
	}
	s.hespOutpuCh <- ourHesp
	tmp := <-s.hespInputCh
	return tmp.hesp, tmp.err
}

func newMockSignupUI() *mockSignupUI {
	return &mockSignupUI{
		hespInputCh: make(chan hespAndErr, 1),
		hespOutpuCh: make(chan proto.KexHESP, 1),
	}
}

func (m *mockSignupUI) withDeviceKey() *mockSignupUI {
	m.useDeviceKey = true
	return m
}

func (m *mockSignupUI) withYubiCardPos(p int) *mockSignupUI {
	m.yubiCardPos = p
	return m
}

func (m *mockSignupUI) withInviteCode(i *rem.InviteCode) *mockSignupUI {
	m.invite = i
	return m
}

func (n *mockSignupUI) withDeviceName(d proto.DeviceName) *mockSignupUI {
	n.deviceName = d
	return n
}

func (n *mockSignupUI) withUsername(u proto.NameUtf8) *mockSignupUI {
	n.username = u
	return n
}

func (n *mockSignupUI) withForceYubiReuse() *mockSignupUI {
	n.noYubiReuseCheck = true
	return n
}

func (n *mockSignupUI) withEnv(e *common.TestEnv) *mockSignupUI {
	n.env = e
	return n
}

func (n *mockSignupUI) withSSOUrlCb(cb func(proto.URLString)) *mockSignupUI {
	n.ssoUrlCb = cb
	return n
}

func (n *mockSignupUI) testEnv() *common.TestEnv {
	if n.env != nil {
		return n.env
	}
	return globalTestEnv
}

func (n *mockSignupUI) withServer(s proto.TCPAddr) *mockSignupUI {
	n.homeServer = &s
	return n
}

func (m *mockSignupUI) ShowSSOLoginURL(_ libclient.MetaContext, url proto.URLString) error {
	m.ssoUrl = url
	if m.ssoUrlCb != nil {
		m.ssoUrlCb(url)
	}
	return nil
}
func (m *mockSignupUI) ShowSSOLoginResult(_ libclient.MetaContext, res proto.SSOLoginRes) error {
	m.ssoLoginRes = &res
	return nil
}

func (s *mockSignupUI) PickYubiDevice(m libclient.MetaContext, v []proto.YubiCardID) (int, error) {
	fmt.Printf("Yubi Devices Found:\n")
	for _, d := range v {
		fmt.Printf("  - %v\n", d)
	}
	if s.useDeviceKey {
		fmt.Printf("-> Selecting to use device key..")
		return -1, nil
	}
	return s.yubiCardPos, nil
}

func (s *mockSignupUI) GetEmail(m libclient.MetaContext) (*proto.Email, error) {
	em := proto.Email("a" + core.RandomBase62String(12) + "@gmail.com")
	s.em = em
	return &s.em, nil
}

func (s *mockSignupUI) GetInviteCode(
	m libclient.MetaContext,
	icr proto.InviteCodeRegime,
	attempt int,
) (*lcl.InviteCodeString, error) {
	if s.noInviteCode {
		return nil, core.CancelSignupError{Stage: core.CancelSignupStageWaitList}
	}
	var code rem.InviteCode
	if s.invite != nil {
		code = *s.invite
	} else {
		code = s.testEnv().G.TestMultiUseInviteCode()
	}
	scode, err := core.ExportInviteCode(code)
	if err != nil {
		return nil, err
	}
	tmp := lcl.InviteCodeString(scode)
	return &tmp, nil
}

func (s *mockSignupUI) ShowWaitListID(m libclient.MetaContext, wlid proto.WaitListID) error {
	s.waitListID = wlid
	return nil
}

func (s *mockSignupUI) PickYubiSlot(
	m libclient.MetaContext,
	y proto.YubiCardInfo,
	pri *proto.YubiSlot,
) (
	proto.YubiIndex,
	error,
) {
	var ret proto.YubiIndex
	if !libyubi.GetRealForce() {
		switch {
		case s.testYubiCreate && len(y.EmptySlots) > 0:
			return proto.NewYubiIndexWithEmpty(0), nil
		case !s.testYubiCreate && len(y.Keys) > 0:
			return proto.NewYubiIndexWithReuse(0), nil
		default:
			return ret, core.YubiError("no mock slots available")
		}
	}

	// we won't create any keys if there are 6 or more already
	// created
	maxKeys := 14

	// If we're selecting the PQ key, one of the keys is not
	// included in the list.
	priPlus := core.Sel(pri == nil, 0, 1)
	canCreate := len(y.Keys)+priPlus < maxKeys

	if s.testYubiCreate && !canCreate {
		return ret, core.YubiError("no more room to create any real YubiKeys")
	}

	uks := usedKeySlots
	keys := y.Keys
	found := -1

	if s.noYubiReuseCheck {
		uks = make(map[proto.YubiSlot]bool)
	}

	for i, k := range keys {
		if !uks[k.Slot] {
			found = i
			break
		}
	}

	switch {
	// We need to change this if ever we want to
	// use two yubikeys for one user. Since it will fail
	// if the same user uses the same PQ slot twice.
	case pri != nil && !s.testYubiCreate && len(y.Keys) > 0:
		return proto.NewYubiIndexWithReuse(0), nil
	case found >= 0 && !s.testYubiCreate:
		uks[keys[found].Slot] = true
		return proto.NewYubiIndexWithReuse(uint64(found)), nil
	case canCreate:
		uks[y.EmptySlots[0]] = true
		return proto.NewYubiIndexWithEmpty(0), nil
	default:
		return ret, core.YubiError("no slots available on real key")
	}
}

func (s *mockSignupUI) clear() {
	s.username = ""
	s.deviceName = ""
}

func (s *mockSignupUI) GetUsername(m libclient.MetaContext) (*proto.NameUtf8, error) {
	if s.username != "" {
		return &s.username, nil
	}
	n, err := core.RandomUsername(5)
	if err != nil {
		return nil, err
	}
	weirdAlphabet := core.AllNFDChars()
	n += "_"
	for i := 0; i < 5; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(weirdAlphabet))))
		if err != nil {
			return nil, err
		}
		n += string(weirdAlphabet[r.Uint64()])
	}

	fmt.Printf("Username: %s\n", n)
	s.username = proto.NameUtf8(n)
	return &s.username, nil
}

var dfltDeviceName = proto.DeviceName("Test Device 8.4+ B-C d_e ÿoYô")
var dfltDeviceNameNormalized = proto.DeviceNameNormalized("test device 8.4+ b-c d_e yoyo")

func (s *mockSignupUI) GetDeviceName(m libclient.MetaContext) (*proto.DeviceName, error) {
	if s.deviceErr != nil {
		return nil, s.deviceErr
	}
	if s.deviceName != "" {
		return &s.deviceName, nil
	}
	raw := string(dfltDeviceName)

	if s.whackyDeviceName {
		raw += " Lukáš Kľúčiar"
	}
	dn := proto.DeviceName(raw)
	s.deviceName = dn
	return &s.deviceName, nil
}

func (s *mockSignupUI) GetPassphrase(m libclient.MetaContext, confirm bool, prevErr bool) (*proto.Passphrase, error) {
	if s.passphrase.IsZero() {
		return nil, nil
	}
	return &s.passphrase, nil
}

var _ libclient.SignupUIer = (*mockSignupUI)(nil)

func TestSignup(t *testing.T) {
	testSignup(t, nil)
}

func testSignup(t *testing.T, hook func(u *mockSignupUI)) {
	err := testSignupWithErr(t, hook)
	require.NoError(t, err)
}

func testSignupWithErr(t *testing.T, hook func(u *mockSignupUI)) error {

	var signupUi mockSignupUI
	var terminalUI terminalUI
	uis := libclient.UIs{
		Signup:   &signupUi,
		Terminal: &terminalUI,
	}
	if hook != nil {
		hook(&signupUi)
	}
	args := append(baseArgs(t), "--simple-ui", "signup")
	err := cmd.MainInner(args, func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	})
	if err != nil {
		return err
	}
	require.Len(t, signupUi.promptSet, 1)
	require.Equal(t, signupUi.promptSet[0], "🆕 Go ahead and create a new user.")
	require.Equal(t, 0, signupUi.newUserIdx)

	terminalUI.reset()
	args = append(baseArgs(t), "status", "--json")
	err = cmd.MainInner(args, func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	})
	if err != nil {
		return err
	}
	var st lcl.AgentStatus
	err = json.Unmarshal(terminalUI.Bytes(), &st)
	if err != nil {
		return err
	}

	// We don't have users loaded in because we are in standalone mode,
	// which doesn't ask for users to be loaded. We can reconsider this later.
	require.Equal(t, 0, len(st.Users))

	return nil
}

func TestSignupReuseYubiKeyFail(t *testing.T) {

	seed, err := libyubi.NewMockYubiSeed()
	require.NoError(t, err)

	doOne := func(nyrc bool) error {
		var signupUi mockSignupUI
		signupUi.noYubiReuseCheck = nyrc

		uis := libclient.UIs{
			Signup: &signupUi,
		}
		opts := baseArgsOpts{yubiSeed: seed}
		args := append(baseArgsWithOpts(t, opts), "--simple-ui", "signup")
		err := cmd.MainInner(args, func(m libclient.MetaContext) error {
			m.G().SetUIs(uis)
			return nil
		})
		return err
	}
	err = doOne(false)
	require.NoError(t, err)
	err = doOne(true)
	require.Error(t, err)
	require.Equal(t, err, core.KeyInUseError{})
}

func TestSignupReclaimUsername(t *testing.T) {
	un, err := core.RandomUsername(8)
	require.NoError(t, err)

	a := newTestAgent(t)
	a.runAgent(t)
	defer a.stop(t)

	var signupUi mockSignupUI
	var terminalUI terminalUI
	derr := errors.New("cancelled at device")

	signupUi.username = proto.NameUtf8(un)
	signupUi.deviceErr = derr

	uis := libclient.UIs{
		Signup:   &signupUi,
		Terminal: &terminalUI,
	}
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	err = a.runCmdErr(hook, "--simple-ui", "signup")
	require.Error(t, err)
	require.Equal(t, err, derr)

	terminalUI.reset()
	signupUi.deviceErr = nil
	a.runCmd(t, hook, "--simple-ui", "signup")

	st := a.status(t)
	require.Equal(t, 1, len(st.Users))
	require.Equal(t, un, string(st.Users[0].Info.Username.NameUtf8))
}

func TestSignupWhackyDeviceName(t *testing.T) {
	var signupUi mockSignupUI
	signupUi.whackyDeviceName = true
	uis := libclient.UIs{
		Signup: &signupUi,
	}
	args := append(baseArgs(t), "--simple-ui", "signup")
	err := cmd.MainInner(args, func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, signupUi.promptSet, 1)
	require.Equal(t, signupUi.promptSet[0], "🆕 Go ahead and create a new user.")
	require.Equal(t, 0, signupUi.newUserIdx)
}

func TestSignupNoInviteCode(t *testing.T) {
	var signupUi mockSignupUI
	signupUi.noInviteCode = true
	uis := libclient.UIs{
		Signup: &signupUi,
	}
	args := append(baseArgs(t), "--simple-ui", "signup")
	err := cmd.MainInner(args, func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	})
	require.NoError(t, err)

	m := testMetaContext()
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	var em string
	err = db.QueryRow(m.Ctx(),
		"SELECT email FROM waitlist WHERE wlid=$1 AND status='waiting' AND short_host_id=$2",
		signupUi.waitListID.ExportToDB(),
		int(m.ShortHostID()),
	).Scan(&em)
	require.NoError(t, err)
	require.Equal(t, signupUi.em, proto.Email(em))
}

func TestSignupWithAgent(t *testing.T) {

	a := newTestAgent(t)
	a.runAgent(t)
	defer a.stop(t)

	var signupUi mockSignupUI
	var terminalUI terminalUI
	uis := libclient.UIs{
		Signup:   &signupUi,
		Terminal: &terminalUI,
	}
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	a.runCmd(t, hook, "--simple-ui", "signup")
	require.Len(t, signupUi.promptSet, 1)
	require.Equal(t, signupUi.promptSet[0], "🆕 Go ahead and create a new user.")
	require.Equal(t, 0, signupUi.newUserIdx)

	terminalUI.reset()

	a.runCmd(t, hook, "status", "--json")
	fmt.Printf("%s", terminalUI.String())

	merklePoke(t)
	terminalUI.reset()
	var klres lcl.KeyListRes
	a.runCmdToJSON(t, &klres, "key", "list", "--json")
	require.Equal(t, 1, len(klres.CurrUserAllKeys))
	require.Equal(t, dfltDeviceName, klres.CurrUserAllKeys[0].Di.Dn.Name)
	require.Equal(t, dfltDeviceNameNormalized, klres.CurrUserAllKeys[0].Di.Dn.Label.Name)
}

func getActiveUser(t *testing.T, a *testAgent) *proto.UserContext {
	var terminalUI terminalUI
	uis := libclient.UIs{
		Terminal: &terminalUI,
	}
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	a.runCmd(t, hook, "status", "--json")
	var status lcl.AgentStatus
	data := terminalUI.Bytes()
	err := json.Unmarshal(data, &status)
	require.NoError(t, err)
	for _, uc := range status.Users {
		if uc.Info.Active {
			return &uc
		}
	}
	t.Fatalf("no active user found")
	return nil
}

func fquString(t *testing.T, u proto.UserInfo, strUser bool, strHost bool) string {
	var user string
	if strUser {
		user = string(u.Username.NameUtf8)
	} else {
		var err error
		user, err = u.Fqu.Uid.StringErr()
		require.NoError(t, err)
	}

	var host string

	if strHost {
		require.False(t, u.HostAddr.Hostname().IsZero())
		host = string(u.HostAddr.Hostname())
	} else {
		var err error
		host, err = u.Fqu.HostID.StringErr()
		require.NoError(t, err)
	}
	return strings.Join([]string{user, host}, "@")
}

func userIsUnlocked(u proto.UserContext) bool {
	return len(u.Puks) > 0
}

type userAgentBundle struct {
	agent    *testAgent
	username proto.NameUtf8
}

func (u *userAgentBundle) stop(t *testing.T) {
	u.agent.stop(t)
}

var aliceBundle *userAgentBundle

func (a *userAgentBundle) init(t *testing.T, withYubikey bool) {
	a.initFunc(t, func(u *mockSignupUI) *mockSignupUI {
		if !withYubikey {
			u = u.withDeviceKey()
		}
		return u
	},
	)
}

func (a *userAgentBundle) initFunc(t *testing.T, mockHook func(u *mockSignupUI) *mockSignupUI) {
	a.initFuncAndAgentOpts(t, mockHook, agentOpts{})
}

func (a *userAgentBundle) initFuncAndAgentOpts(
	t *testing.T,
	mockHook func(u *mockSignupUI) *mockSignupUI,
	opts agentOpts,
) {

	a.agent = newTestAgentWithOpts(t, opts)
	a.agent.runAgent(t)

	signupUI := &mockSignupUI{}
	var terminalUI terminalUI
	signupUI = mockHook(signupUI)
	uis := libclient.UIs{
		Signup:   signupUI,
		Terminal: &terminalUI,
	}
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(uis)
		return nil
	}
	a.agent.runCmd(t, hook, "--simple-ui", "signup")
	require.Len(t, signupUI.promptSet, 1)
	require.Equal(t, signupUI.promptSet[0], "🆕 Go ahead and create a new user.")
	require.Equal(t, 0, signupUI.newUserIdx)
	a.username = signupUI.username
}

// Alice is a user that runs with an agent, and signs up via YubiKey.
// We'd like to resuse her since unfortunately YubiKey slots are scarse.
func makeAliceAndHerAgent(t *testing.T) *userAgentBundle {
	if aliceBundle != nil {
		return aliceBundle
	}
	var ret userAgentBundle
	ret.init(t, true)
	aliceBundle = &ret
	return aliceBundle
}

func makeBobAndHisAgent(t *testing.T) *userAgentBundle {
	var ret userAgentBundle
	ret.init(t, false)
	return &ret
}

func makeFreshUserWithAgent(t *testing.T) *userAgentBundle {
	var ret userAgentBundle
	// Use the second mock card here
	ret.initFunc(t, func(u *mockSignupUI) *mockSignupUI {
		return u.withYubiCardPos(1)
	})
	return &ret
}

func TestSignupYubiCreate(t *testing.T) {
	if libyubi.GetRealForce() {
		t.Skip("yubi tests only work with mock bus (we don't want to eat up all your empty slots)")
	}
	testSignup(t, func(u *mockSignupUI) {
		u.testYubiCreate = true
	})
}

func TestSignupAndSwitch(t *testing.T) {

	alice := makeAliceAndHerAgent(t)
	a := alice.agent

	userA := getActiveUser(t, a)

	var signupUi mockSignupUI
	var terminalUI terminalUI
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(libclient.UIs{
			Signup:   &signupUi,
			Terminal: &terminalUI,
		})
		return nil
	}
	// Next signup with device key (user B)
	signupUi.clear()
	signupUi.useDeviceKey = true
	a.runCmd(t, hook, "--simple-ui", "signup")
	require.Len(t, signupUi.promptSet, 2)
	require.Equal(t, signupUi.promptSet[1], "🆕 Go ahead and create a new user.")
	require.Equal(t, 1, signupUi.newUserIdx)

	userB := getActiveUser(t, a)
	require.False(t, userA.Info.Fqu.Eq(userB.Info.Fqu))

	// One more with a device key (user C)
	signupUi.clear()
	a.runCmd(t, hook, "--simple-ui", "signup")
	require.Len(t, signupUi.promptSet, 3)
	require.Equal(t, signupUi.promptSet[2], "🆕 Go ahead and create a new user.")
	require.Equal(t, 2, signupUi.newUserIdx)

	userC := getActiveUser(t, a)
	require.False(t, userC.Info.Fqu.Eq(userB.Info.Fqu))

	sw := func(s string) { a.runCmd(t, nil, "key", "switch", "-u", s) }

	// Test switch via .1a33333@.2eeee form...
	aStr := fquString(t, userA.Info, false, false)
	sw(aStr)
	tmp := getActiveUser(t, a)
	require.True(t, tmp.Info.Fqu.Eq(userA.Info.Fqu))
	require.True(t, userIsUnlocked(*tmp))

	// Test switch via joe@localhost form
	bStr := fquString(t, userB.Info, true, true)
	sw(bStr)
	tmp = getActiveUser(t, a)
	require.True(t, tmp.Info.Fqu.Eq(userB.Info.Fqu))
	require.True(t, userIsUnlocked(*tmp))

	// test that when you unlock what's unlocked, nothing
	// bad happens.
	merklePoke(t) // yubi unlock needs merkle poke
	a.runCmd(t, nil, "yubi", "unlock")
	sw(aStr)
	a.runCmd(t, nil, "yubi", "unlock")

	// now try an agent start and stop. User A should come back up as active,
	// but in the locked state.
	a.stop(t)
	a.runAgent(t)
	tmp = getActiveUser(t, a)
	require.True(t, tmp.Info.Fqu.Eq(userA.Info.Fqu))
	require.False(t, userIsUnlocked(*tmp))

	// Unlock should now work and do something
	a.runCmd(t, nil, "yubi", "unlock")
	tmp = getActiveUser(t, a)
	require.True(t, userIsUnlocked(*tmp))
}

func TestYubiProvision(t *testing.T) {
	alice := makeAliceAndHerAgent(t)
	a := alice.agent
	userA := getActiveUser(t, a)

	b := newTestAgentWithOpts(t, agentOpts{yubiSeed: a.yubiSeed})
	b.runAgent(t)
	defer b.stop(t)

	var terminalUI terminalUI
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(libclient.UIs{Terminal: &terminalUI})
		return nil
	}

	b.runCmd(t, hook, "yubi", "ls")
	var cardList []proto.YubiCardID
	data := terminalUI.Bytes()
	err := json.Unmarshal(data, &cardList)
	require.NoError(t, err)
	require.True(t, len(cardList) > 0)
	serial := cardList[0].Serial

	itoa := func(i any) string { return fmt.Sprintf("%d", i) }

	terminalUI.reset()
	b.runCmd(t, hook, "yubi", "ls", "--serial", itoa(serial))
	var lysRes lcl.ListYubiSlotsRes
	data = terminalUI.Bytes()
	err = json.Unmarshal(data, &lysRes)
	require.NoError(t, err)
	require.Greater(t, len(lysRes.Device.Keys), 0)

	var slot proto.YubiSlot

	// Key is not guaranteed to be the first slot, especially if we've run
	// other tests in this test run. The most general thing to do is to look
	// for it in the array.
	for _, k := range lysRes.Device.Keys {
		if k.Id.EntityID().Eq(userA.Key) {
			slot = k.Slot
			break
		}
	}
	require.NotEqual(t, proto.YubiSlot(0), slot)

	terminalUI.reset()
	b.runCmd(t, hook, "yubi", "ls", "--serial", itoa(serial), "--slot", itoa(slot))
	var lures proto.LookupUserRes
	data = terminalUI.Bytes()
	err = json.Unmarshal(data, &lures)
	require.NoError(t, err)
	require.Equal(t, lures.Fqu, userA.Info.Fqu)

	merklePoke(t) // provision needs a merkle poke

	terminalUI.reset()
	b.runCmd(t, hook, "yubi", "use", "--serial", itoa(serial), "--slot", itoa(slot))

	// yubi provision should yield unlocked PUKs
	aliceOnDevB := getActiveUser(t, b)
	require.True(t, aliceOnDevB.Info.Fqu.Eq(userA.Info.Fqu))
	require.True(t, userIsUnlocked(*aliceOnDevB))

	terminalUI.reset()
	var klres lcl.KeyListRes
	b.runCmdToJSON(t, &klres, "key", "ls", "--json")
	require.Equal(t, 1, len(klres.CurrUserAllKeys))
	require.Equal(t, proto.DeviceType_YubiKey, klres.CurrUserAllKeys[0].Di.Dn.Label.DeviceType)

	// now make B into a bonafide device
	stopper := runMerkleActivePoker(t)
	b.runCmd(t, hook, "key", "dev", "perm", "--name", "zodobomb 3.14+")
	stopper()

	// test device list gives us 2 devices, one of type yubi and one a
	// normal computer
	terminalUI.reset()

	b.runCmdToJSON(t, &klres, "key", "ls", "--json")
	require.Equal(t, 2, len(klres.CurrUserAllKeys))
	types := make(map[proto.DeviceType]bool)
	for _, dev := range klres.CurrUserAllKeys {
		types[dev.Di.Dn.Label.DeviceType] = true
	}
	require.True(t, types[proto.DeviceType_YubiKey])
	require.True(t, types[proto.DeviceType_Computer])
}

// Bob:
//  1. signs up with a device on machine b
//  2. makes a new yubi key on machine b
//  3. goes over to machine c and provisions with the yubikey
func TestYubiNew(t *testing.T) {

	if libyubi.GetRealForce() {
		t.Skip("YubiNew creates a new yubi with fresh slots; we don't want to eat them all up")
	}

	bob := makeBobAndHisAgent(t)
	b := bob.agent

	defer b.stop(t)

	var terminalUI terminalUI
	hook := func(m libclient.MetaContext) error {
		m.G().SetUIs(libclient.UIs{Terminal: &terminalUI})
		return nil
	}

	b.runCmd(t, hook, "yubi", "ls")
	var cardList []proto.YubiCardID
	data := terminalUI.Bytes()
	err := json.Unmarshal(data, &cardList)
	require.NoError(t, err)
	require.True(t, len(cardList) > 0)
	serial := cardList[0].Serial

	itoa := func(i any) string { return fmt.Sprintf("%d", i) }

	terminalUI.reset()
	b.runCmd(t, hook, "yubi", "ls", "--serial", itoa(serial))
	var lysRes lcl.ListYubiSlotsRes
	data = terminalUI.Bytes()
	err = json.Unmarshal(data, &lysRes)
	require.NoError(t, err)
	require.Greater(t, len(lysRes.Device.EmptySlots), 1)

	slots := lysRes.Device.EmptySlots[0:2]
	merklePoke(t)

	b.runCmd(t, hook, "yubi", "new", "--serial", itoa(serial),
		"--slot", itoa(slots[0]), "--pq-slot", itoa(slots[1]), "--name", "zoombomb 3.14+")

	merklePoke(t)

	userOnB := getActiveUser(t, b)
	require.NoError(t, err)
	require.True(t, userIsUnlocked(*userOnB))

	c := newTestAgentWithOpts(t, agentOpts{yubiSeed: b.yubiSeed})
	c.runAgent(t)
	defer c.stop(t)
	c.runCmd(t, hook, "yubi", "use", "--serial", itoa(serial),
		"--slot", itoa(slots[0]))

	userOnC := getActiveUser(t, c)
	require.NoError(t, err)
	require.Equal(t, userOnB.Info.Fqu, userOnC.Info.Fqu)

	// make sure we can unlock the agent after a restart
	c.stop(t)
	c.runAgent(t)
	c.runCmd(t, hook, "yubi", "unlock")
}

func TestYubiNewThenYubiProvision(t *testing.T) {
	if libyubi.GetRealForce() {
		t.Skip("YubiNew creates a new yubi with fresh slots; we don't want to eat them all up")
	}

	bob := makeBobAndHisAgent(t)
	b := bob.agent
	defer b.stop(t)
	var cardList []proto.YubiCardID
	b.runCmdToJSON(t, &cardList, "yubi", "ls")

	require.True(t, len(cardList) > 0)
	serial := cardList[0].Serial

	itoa := func(i any) string { return fmt.Sprintf("%d", i) }

	var lysRes lcl.ListYubiSlotsRes
	b.runCmdToJSON(t, &lysRes, "yubi", "ls", "--serial", itoa(serial))
	require.Greater(t, len(lysRes.Device.EmptySlots), 1)

	slots := lysRes.Device.EmptySlots[0:2]
	merklePoke(t)

	b.runCmd(t, nil, "yubi", "new", "--serial", itoa(serial),
		"--slot", itoa(slots[0]), "--pq-slot", itoa(slots[1]), "--name", "zoombomb 3.14+")

	merklePoke(t)

	// Making a new yubi key doesn't include it as a local user
	var klres lcl.KeyListRes
	b.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 1, len(klres.AllUsers))

	b.stop(t)
	b.runAgent(t)

	b.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 1, len(klres.AllUsers))

	b.runCmd(t, nil, "yubi", "use", "--serial", itoa(serial),
		"--slot", itoa(slots[0]))

	// But provisioning the device with the yubi does add a new
	// user (the initial user under the Yubi key genus)
	b.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 2, len(klres.AllUsers))

	uinfo := getActiveUser(t, b)
	require.True(t, userIsUnlocked(*uinfo))
	require.NotNil(t, uinfo.Info.YubiInfo)

	b.stop(t)
	b.runAgent(t)

	uinfo = getActiveUser(t, b)
	require.False(t, userIsUnlocked(*uinfo))
	require.NotNil(t, uinfo.Info.YubiInfo)

	b.runCmd(t, nil, "yubi", "unlock")
}

func TestSignupInviteCodeOptional(t *testing.T) {
	defer common.DebugEntryAndExit()()

	env := globalTestEnv
	merklePoke(t)
	tvh := env.VHostInit(t, "braves")
	agentOpts := agentOpts{dnsAliases: []proto.Hostname{tvh.Hostname}}

	x := newTestAgentWithOpts(t, agentOpts)
	x.runAgent(t)
	defer x.stop(t)

	m := env.MetaContext().WithHostID(&tvh.HostID)
	err := shared.SetInviteCodeOptional(m)
	require.NoError(t, err)

	eic := rem.NewInviteCodeWithEmpty()
	uis := libclient.UIs{
		Signup: newMockSignupUI().
			withServer(tvh.ProbeAddr).
			withDeviceKey().
			withInviteCode(&eic),
	}
	x.runCmdWithUIs(t, uis, "--simple-ui", "signup")
}
