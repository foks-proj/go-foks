// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/stopwatch"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

const (
	hostCheckTimeout = time.Second * 5
)

type summarySuccessUseYubi struct {
	summarySuccess
}

type summarySuccessCanceler struct {
	msg    string
	cancel func(s summary) bool
}

func (s summarySuccessCanceler) view() string {
	return summarySuccess(s.msg).view()
}

type connectFailure struct {
	host proto.TCPAddr
	def  bool
}

type yubiFailure struct {
	err error
}

type genericFailure struct {
	err error
}

func (g genericFailure) view() string {
	e := ErrorStyle.Render
	return e("✗ ") + g.err.Error()
}

func (f connectFailure) view() string {
	e := ErrorStyle.Render
	def := ""
	if f.def {
		def = "default "
	}
	return e("✗ ") + "Could not connect to " + def + "host: " + e(string(f.host))
}

func (f yubiFailure) view() string {
	e := ErrorStyle.Render
	return e("✗ ") + "Could not use Yubikey: " + e(f.err.Error())
}

type stateHome struct {
	oked     bool
	letsDo   string
	nxt      state
	initHook func(mctx libclient.MetaContext, mdl model) error
}

func newStateHomeSignup() stateHome {
	return stateHome{
		oked:   false,
		letsDo: "Let's signup",
		nxt:    statePickUser{},
	}
}

func newStateHomeProvision() stateHome {
	return stateHome{
		oked:   false,
		letsDo: "Let's provision a new device",
		nxt:    statePickDefaultHost{},
	}
}

func newStateYubiProvision() stateHome {
	return stateHome{
		oked:   false,
		letsDo: "Let's log-in on a new machine with an existing YubiKey",
		nxt:    newStatePickYubiDeviceProvision(),
	}
}

func newStateYubiNew() state {
	return stateHomeYubiNew{}
}

type stateHomeYubiNew struct {
	ui        proto.UserInfo
	confirmed bool
}

func (s stateHomeYubiNew) summary() summary { return nil }
func (s stateHomeYubiNew) failure() failure { return nil }

func (s stateHomeYubiNew) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.confirmed {
		return newStatePickYubiDeviceNew(), nil, nil
	}
	return nil, nil, nil
}

func (s stateHomeYubiNew) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	tmp, err := mdl.cli.LoadStateFromActiveUser(mctx.Ctx(), mdl.sessId)
	if err != nil {
		return nil, nil, err
	}
	s.ui = tmp
	return s, nil, nil
}

func (s stateHomeYubiNew) view() string {
	var b strings.Builder
	u, err := common_ui.FormatUserInfoAsPromptItem(s.ui, &common_ui.FormatUserInfoOpts{})
	if err != nil {
		u = fmt.Sprintf("(error %s)", err)
	}
	fmt.Fprintf(&b, "\n\n")
	fmt.Fprintf(&b, "Provision a new YubiKey for < %s > ?\n\n\n", u)
	okOrCancel(&b)
	return b.String()
}

func (s stateHomeYubiNew) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	if !isEnter(msg) {
		return s, nil, nil
	}
	s.confirmed = true
	return s, nil, nil
}

var _ state = stateHomeYubiNew{}

type stateTODO struct{}

var _ state = stateTODO{}

func (s stateTODO) summary() summary { return nil }
func (s stateTODO) failure() failure { return nil }

func (s stateTODO) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return nil, nil, nil
}

func (s stateTODO) view() string {
	return "\nThat's all ... for now ...\n"
}

func (s stateTODO) update(libclient.MetaContext, model, tea.Msg) (state, tea.Cmd, error) {
	return s, tea.Quit, nil
}

func (s stateTODO) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return s, nil, nil
}

func (s stateHome) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.oked {
		return s.nxt, nil, nil
	}
	return nil, nil, nil
}

func (s stateHome) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.initHook != nil {
		err := s.initHook(mctx, mdl)
		if err != nil {
			return nil, nil, err
		}
	}
	return s, nil, nil
}

func (s stateHome) view() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", h1Style.Render("🔑 Welcome to the Federated Open Key Service -- FOKS! 🔑"))
	fmt.Fprintf(&b, "%s\n\n", s.letsDo)
	fmt.Fprintf(&b, "  🆗 Press %s to get started\n",
		HappyStyle.Render("<Enter>"),
	)
	fmt.Fprintf(&b, "  ☮️  Or %s or %s at any time to quit\n",
		ErrorStyle.Render("<Ctrl+C>"),
		ErrorStyle.Render("<Esc>"),
	)
	fmt.Fprintf(&b, "\n\n\n\n")
	return b.String()
}

func isEnter(msg tea.Msg) bool {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			return true
		}
	}
	return false
}

func (s stateHome) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	if isEnter(msg) {
		s.oked = true
	}
	return s, nil, nil
}

func (m model) cleanup() {
	if m.cleanupFn != nil {
		m.cleanupFn()
	}
}

func (s stateHome) summary() summary { return nil }
func (s stateHome) failure() failure { return nil }

var _ state = stateHome{}

type statePickUser struct {
	picker  list.Model
	users   []proto.UserInfo
	choice  int
	loginAs *proto.UserInfo
	spinner spinner.Model
	loading bool
}

func (s statePickUser) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.loading {
		return nil, nil, nil
	}

	// waiting for user input and there is some user input possible
	if s.choice == -1 && len(s.users) > 0 {
		return nil, nil, nil
	}

	// user actually made a choice of an existing user
	if s.choice > 0 {
		return statePickUserLoginAs{user: s.loginAs}, nil, nil
	}

	switch mdl.typ {
	case proto.UISessionType_NewKeyWizard:
		return statePickDefaultHost{}, nil, nil
	case proto.UISessionType_Signup:
		return newStatePickYubiDeviceSignup(), nil, nil
	default:
		return stateError{err: errors.New("unexpected next state")}, nil, nil
	}
}

func (s statePickUser) view() string {

	switch {
	case s.loading && s.choice == -1:
		return "\n " + s.spinner.View() + " Loading users ..."
	default:
		return "\n" + s.picker.View()
	}
}

type pickUserMsg struct {
	lst []proto.UserInfo
	err error
}

type loginAsMsg struct {
	err error
}

func (s statePickUser) processSelection(mctx libclient.MetaContext, mdl model) (statePickUser, tea.Cmd, error) {
	i, ok := s.picker.SelectedItem().(userInfoItem)
	if !ok {
		return s, nil, nil
	}
	s.choice = i.i
	if i.i == 0 {
		return s, nil, nil
	}
	s.loginAs = i.UserInfo
	s.loading = false
	return s, nil, nil
}

func sortUserList(users []proto.UserInfo) {
	slices.SortFunc(users, func(a, b proto.UserInfo) int {
		if a.Active && !b.Active {
			return -1
		}
		if !a.Active && b.Active {
			return 1
		}
		if a.Username.Name < b.Username.Name {
			return -1
		}
		if a.Username.Name > b.Username.Name {
			return 1
		}
		if a.HostAddr.String() < b.HostAddr.String() {
			return -1
		}
		if a.HostAddr.String() > b.HostAddr.String() {
			return 1
		}
		if a.KeyGenus < b.KeyGenus {
			return -1
		}
		if a.KeyGenus > b.KeyGenus {
			return 1
		}

		return 0
	})
}

func (s statePickUser) loadPickMsg(mdl model, msg pickUserMsg) (statePickUser, error) {
	if msg.err != nil {
		return s, msg.err
	}
	s.users = msg.lst
	s.loading = false

	if len(s.users) == 0 {
		return s, nil
	}

	users := msg.lst
	sortUserList(users)

	items := make([]list.Item, len(s.users)+1)
	items[0] = userInfoItem{i: 0}

	for i, item := range users {
		tmp := item
		items[i+1] = userInfoItem{UserInfo: &tmp, i: i + 1}
	}

	isNewKeyWiz := (mdl.typ == proto.UISessionType_NewKeyWizard)

	opts := common_ui.FormatUserInfoOpts{
		Avatar:    true,
		Active:    true,
		Role:      true,
		NewKeyWiz: isNewKeyWiz,
	}
	l := list.New(items, userInfoItemDelegate{opts: opts}, defaultWidth, listHeight)

	if isNewKeyWiz {
		l.Title = "Who needs a new key?"
	} else {
		l.Title = "Existing users found; login instead?"
	}
	styleList(&l)
	s.picker = l

	return s, nil
}

func (s statePickUser) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case pickUserMsg:
		var err error
		s, err = s.loadPickMsg(mdl, msg)
		return s, nil, err
	case loginAsMsg:
		if msg.err != nil {
			return s, nil, msg.err
		}
		s.loading = false
		return s, nil, nil
	case tea.KeyMsg:
		s.picker, cmd = s.picker.Update(msg)
		var err error
		if isEnter(msg) {
			s, cmd, err = s.processSelection(mctx, mdl)
		}
		return s, cmd, err
	default:
		return s, nil, nil
	}
}

func pushAnyKeyToExit() string {
	return " ✌️  Press any key to exit."
}

func (s statePickUser) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.choice = -1
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.loading = true
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			lst, err := mdl.usercli.GetExistingUsers(mctx.Ctx())
			return pickUserMsg{lst: lst, err: err}
		},
	), nil

}

func (s statePickUser) summary() summary { return nil }
func (s statePickUser) failure() failure { return nil }

var _ state = statePickUser{}

func newStatePickYubiDeviceSignup() state {
	return statePickYubi{
		bypassItem: true,
		needYubi:   false,
		loadListHook: func(ctx context.Context, mdl model) ([]proto.YubiCardID, error) {
			return mdl.ycli.ListAllLocalYubiDevices(ctx, mdl.sessId)
		},
		makeTitleHook: func(n int) string {
			plural := ""
			if n > 0 {
				plural = "s"
			}
			return fmt.Sprintf("Yubikey card%s detected -- use as primary device key?", plural)
		},
		putHook: func(ctx context.Context, mdl model, y proto.YubiCardID, i int) error {
			return mdl.ycli.UseYubi(
				ctx,
				lcl.UseYubiArg{SessionId: mdl.sessId, Idx: uint64(i)},
			)
		},
		nextHook: func(i *proto.YubiCardID) (state, tea.Cmd, error) {
			if i == nil {
				return newStateNewPassphrase(), nil, nil
			}
			return statePickDefaultHost{}, nil, nil
		},
	}
}

func newStateNewPassphrase() state {
	return stateNewPassphrase{
		prompt:       "Enter a passphrase to encrypt your local device key with",
		allowSkip:    true,
		summaryLabel: "Device key locked with passphrase",
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			return mdl.cli.PromptForPassphrase(mctx.Ctx(), mdl.sessId)
		},
		nextHook: func() (state, error) {
			return statePickDefaultHost{}, nil
		},
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			return mdl.cli.PutPassphrase(mctx.Ctx(), lcl.PutPassphraseArg{
				SessionID:  mdl.sessId,
				Passphrase: pp,
			})
		},
	}
}

func newStatePickYubiDeviceProvision() state {
	return statePickYubi{
		bypassItem: false,
		needYubi:   true,
		loadListHook: func(ctx context.Context, mdl model) ([]proto.YubiCardID, error) {
			return mdl.ycli.ListAllLocalYubiDevices(ctx, mdl.sessId)
		},
		makeTitleHook: func(n int) string {
			return "Pick a YubiKey to provision"
		},
		putHook: func(ctx context.Context, mdl model, y proto.YubiCardID, i int) error {
			return mdl.ycli.UseYubi(
				ctx,
				lcl.UseYubiArg{SessionId: mdl.sessId, Idx: uint64(i)},
			)
		},
		nextHook: func(i *proto.YubiCardID) (state, tea.Cmd, error) {
			return statePickDefaultHost{}, nil, nil
		},
	}
}

// newStatePickNewYubiDeviceNew makes a yubi-picking screen to be used with `foks yubi new`;
// recall this is the command to make a new Yubikey keyset, and to countersign it (and box for it)
// into an existing account, with an active local login.
func newStatePickYubiDeviceNew() state {
	return statePickYubi{
		bypassItem: false,
		needYubi:   true,
		loadListHook: func(ctx context.Context, mdl model) ([]proto.YubiCardID, error) {
			return mdl.ycli.ListAllLocalYubiDevices(ctx, mdl.sessId)
		},
		makeTitleHook: func(n int) string {
			return "Pick a YubiKey to make new keys on"
		},
		putHook: func(ctx context.Context, mdl model, y proto.YubiCardID, i int) error {
			return mdl.ycli.UseYubi(
				ctx,
				lcl.UseYubiArg{SessionId: mdl.sessId, Idx: uint64(i)},
			)
		},
		nextHook: func(i *proto.YubiCardID) (state, tea.Cmd, error) {
			return newPickYubiSlotYubiNew(), nil, nil
		},
	}
}

type gotDefaultServerMsg struct {
	err      error
	host     proto.TCPAddr
	mgmtHost proto.TCPAddr
}

type statePickDefaultHostSlots struct {
	def    int
	mgmt   int
	custom int
}

func (s *statePickDefaultHostSlots) init() {
	s.def = -2
	s.mgmt = -2
	s.custom = -2
}

type statePickDefaultHost struct {
	picker     list.Model
	choice     int
	failedHost *proto.TCPAddr
	defFailed  bool
	spinner    spinner.Model
	stopwatch  stopwatch.Model
	loading    bool
	hasPicker  bool
	// nil == no default host is currently set
	// "" == default host is set, but it's set to no host
	defHost  *proto.TCPAddr
	mgmtHost proto.TCPAddr
	slots    statePickDefaultHostSlots
}

func (s statePickDefaultHost) useDef() bool    { return s.choice >= 0 && s.choice == s.slots.def }
func (s statePickDefaultHost) useMgmt() bool   { return s.choice >= 0 && s.choice == s.slots.mgmt }
func (s statePickDefaultHost) useCustom() bool { return s.choice >= 0 && s.choice == s.slots.custom }

func (s statePickDefaultHost) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	switch {
	case s.useDef() && s.defHost != nil && !s.defHost.IsZero():
		return stateTryHost{
			host:     *s.defHost,
			usingDef: true,
			mgmtHost: s.mgmtHost,
			typ:      lcl.RegServerType_Default,
		}, nil, nil
	case s.useMgmt() && !s.mgmtHost.IsZero():
		return stateTryHost{
			host:     s.mgmtHost,
			usingDef: false,
			defHost:  s.defHost,
			mgmtHost: s.mgmtHost,
			typ:      lcl.RegServerType_Mgmt,
		}, nil, nil
	case s.useCustom() || (s.defHost != nil && len(*s.defHost) == 0):
		return statePickCustomHost{defHost: s.defHost, mgmtHost: s.mgmtHost}, nil, nil
	case s.defFailed:
		return statePickCustomHost{failedDefHost: s.failedHost, mgmtHost: s.mgmtHost}, nil, nil
	default:
		return nil, nil, nil
	}
}

func (s statePickDefaultHost) summary() summary {
	return nil
}
func (s statePickDefaultHost) failure() failure {
	if s.failedHost != nil {
		return connectFailure{host: *s.failedHost, def: s.defFailed}
	}
	return nil
}

func (s statePickDefaultHost) view() string {
	var b strings.Builder

	if s.loading {
		b.WriteString("\n")
		fmt.Fprintf(&b,
			"   %s Checking for default FOKS server ... (%s/%s)",
			s.spinner.View(),
			s.stopwatch.View(),
			hostCheckTimeout,
		)
	} else {
		b.WriteString("\n" + s.picker.View())
	}
	return b.String()
}

func (s statePickDefaultHost) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	switch msg := msg.(type) {
	case gotDefaultServerMsg:
		s, err := s.loadResIntoState(msg)
		return s, nil, err
	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case stopwatch.TickMsg, stopwatch.StartStopMsg, stopwatch.ResetMsg:
		var cmd tea.Cmd
		s.stopwatch, cmd = s.stopwatch.Update(msg)
		return s, cmd, nil
	}

	if s.loading || !s.hasPicker {
		return s, nil, nil
	}

	var cmd tea.Cmd
	s.picker, cmd = s.picker.Update(msg)

	if !isEnter(msg) {
		return s, cmd, nil
	}

	i, ok := s.picker.SelectedItem().(simpleItem)
	if !ok {
		return s, nil, nil
	}
	s.choice = i.i

	return s, nil, nil
}

func (s statePickDefaultHost) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {

	// We might be landing here as a result of a retry after a failure, so it's OK then to
	// preload our default host from the last attempt.
	if s.defHost != nil && len(*s.defHost) > 0 {
		s, err := s.loadPicker()
		return s, nil, err
	}

	if s.defHost != nil && len(*s.defHost) == 0 {
		return s, nil, nil
	}

	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.stopwatch = stopwatch.NewWithInterval(time.Millisecond * 10)
	s.loading = true
	s.choice = -1

	return s, tea.Batch(
		s.spinner.Tick,
		s.stopwatch.Reset(),
		s.stopwatch.Start(),
		func() tea.Msg {
			debugSpinners(mctx)
			res, err := mdl.gencli.GetDefaultServer(mctx.Ctx(), lcl.GetDefaultServerArg{
				SessionId: mdl.sessId,
				Timeout:   proto.ExportDurationMilli(hostCheckTimeout),
			})
			err2 := core.StatusToError(res.BigTop.Status)
			if err == nil {
				err = err2
			}
			ret := gotDefaultServerMsg{err: err, host: res.BigTop.Host}

			// We might have gotten down a vhost management host from the server,
			// so include that in the UI too if it's relevant
			if res.Mgmt != nil && !res.Mgmt.Host.IsZero() {
				ret.mgmtHost = res.Mgmt.Host
			}
			return ret
		},
	), nil

}

func (s statePickDefaultHost) loadResIntoState(msg gotDefaultServerMsg) (statePickDefaultHost, error) {

	err := msg.err
	s.loading = false

	var hostp *proto.TCPAddr
	if !msg.host.IsZero() {
		hostp = &msg.host
	}

	if err != nil {
		s.failedHost = hostp
		if hostp == nil {
			tmp := proto.TCPAddr("<unknown>")
			s.failedHost = &tmp
		}
		s.defFailed = true
		return s, nil
	}

	if hostp == nil {
		tmp := proto.TCPAddr("")
		s.defHost = &tmp
		return s, nil
	}

	s.defHost = hostp
	s.mgmtHost = msg.mgmtHost
	return s.loadPicker()

}

func (s statePickDefaultHost) loadPicker() (statePickDefaultHost, error) {

	s.choice = -1
	hn, err := s.defHost.ProbeHostStringErr()
	if err != nil {
		return s, err
	}

	s.slots.init()

	longest := len(hn)

	var mhn string
	if !s.mgmtHost.IsZero() {
		tmp, err := s.mgmtHost.ProbeHostStringErr()
		if err == nil {
			mhn = tmp
			if len(mhn) > longest {
				longest = len(mhn)
			}
		}
	}

	formatChoice := func(emoj, nm, desc string) string {
		nSpaces := longest - len(nm) + 2
		return fmt.Sprintf("%s %s%s%s", emoj, nm, strings.Repeat(" ", nSpaces), desc)
	}

	items := []list.Item{
		simpleItem{
			i: 0,
			s: formatChoice("🏠", hn, "(perfect for individuals and small teams)"),
		},
	}
	s.slots.def = 0

	i := 1

	if mhn != "" {
		items = append(items,
			simpleItem{
				i: i,
				s: formatChoice("🏢", mhn, "(team admins: stand-up a virtual server)"),
			},
		)
		s.slots.mgmt = i
		i++
	}

	s.slots.custom = i

	items = append(items,
		simpleItem{
			i: i,
			s: formatChoice("🏄‍♂️", "-", "(specify a custom server)"),
		},
	)

	l := list.New(items, simpleItemDelegate{}, defaultWidth, listHeight-3)
	l.Title = "Select a home server"
	styleList(&l)
	s.picker = l
	s.hasPicker = true

	return s, nil
}

var _ state = statePickDefaultHost{}

type statePickCustomHost struct {
	input         textinput.Model
	host          proto.TCPAddr
	defHost       *proto.TCPAddr
	failedDefHost *proto.TCPAddr
	failedHost    *proto.TCPAddr
	mgmtHost      proto.TCPAddr
}

func (s statePickCustomHost) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if len(s.host) > 0 {
		return stateTryHost{
			host:          s.host,
			defHost:       s.defHost,
			failedDefHost: s.failedDefHost,
			mgmtHost:      s.mgmtHost,
			typ:           lcl.RegServerType_Custom,
		}, nil, nil
	}
	return nil, nil, nil
}

func (s statePickCustomHost) view() string {
	return drawTextInput(
		s.input,
		"Specify a home server: ",
		func(s string) error { return core.ValidateTCPAddr(proto.TCPAddr(s)) },
	)
}

func (s statePickCustomHost) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)

	if !isEnter(msg) {
		return s, cmd, nil
	}
	i := s.input.Value()
	addr := proto.TCPAddr(i)

	// If the address doesn't validate, keep going, but no need to return an error
	if core.ValidateTCPAddr(addr) != nil {
		return s, nil, nil
	}

	s.host = addr
	return s, nil, nil
}

func (s statePickCustomHost) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {

	ti := textinput.New()
	ti.Placeholder = "<host>[:<port>]"
	ti.Focus()
	ti.Width = defaultWidth
	ti.CharLimit = 140
	ti.Prompt = "> "
	ti.Validate = nil
	s.input = ti

	return s, nil, nil
}

func (s statePickCustomHost) summary() summary { return nil }
func (s statePickCustomHost) failure() failure {
	if s.failedHost != nil {
		return connectFailure{host: *s.failedHost, def: false}
	} else if s.failedDefHost != nil {
		return connectFailure{host: *s.failedDefHost, def: true}
	}
	return nil
}

var _ state = statePickCustomHost{}

type stateTryHost struct {
	host      proto.TCPAddr
	usingDef  bool
	spinner   spinner.Model
	stopwatch stopwatch.Model
	res       *tryHostRes
	typ       lcl.RegServerType

	// nil == no default host supplied
	// "" == default host supplied, but none is known in this configuration
	defHost *proto.TCPAddr

	mgmtHost proto.TCPAddr

	// if non-nil, we previously tried to get the default host and failed, so
	// no need to try again.
	failedDefHost *proto.TCPAddr
}

type tryHostRes struct {
	err    error
	ssoCfg *proto.SSOConfig
}

func (s stateTryHost) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.res == nil {
		return nil, nil, nil
	}
	if s.res.err == nil {
		switch mdl.typ {
		case proto.UISessionType_Signup:
			if s.res.ssoCfg.HasOAuth2() {
				return newStateSsoDoLogin(), nil, nil
			}
			return newStatePickEmail(), nil, nil
		case proto.UISessionType_Provision, proto.UISessionType_NewKeyWizard:
			return newStateSupplyUsername(), nil, nil
		case proto.UISessionType_YubiProvision:
			return newPickYubiSlotYubiProvision(), nil, nil
		}
	}

	if s.failedDefHost != nil {
		return statePickCustomHost{
			failedHost:    &s.host,
			defHost:       s.defHost,
			failedDefHost: s.failedDefHost,
			mgmtHost:      s.mgmtHost,
		}, nil, nil
	}

	return statePickDefaultHost{
		failedHost: &s.host,
		defHost:    s.defHost,
		mgmtHost:   s.mgmtHost,
	}, nil, nil
}

func (s stateTryHost) view() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n   %s Checking %s ... (%s/%s)",
		s.spinner.View(),
		s.host,
		s.stopwatch.View(),
		hostCheckTimeout,
	)
	return b.String()
}

func (s stateTryHost) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
	case stopwatch.TickMsg, stopwatch.StartStopMsg, stopwatch.ResetMsg:
		s.stopwatch, cmd = s.stopwatch.Update(msg)
	case tryHostRes:
		s.res = &msg
	}
	return s, cmd, nil
}

func (s stateTryHost) getHost() *proto.TCPAddr {
	if s.usingDef {
		return nil
	}
	return &s.host
}

func (s stateTryHost) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.stopwatch = stopwatch.NewWithInterval(time.Millisecond * 10)
	return s, tea.Batch(
		s.spinner.Tick,
		s.stopwatch.Reset(),
		s.stopwatch.Start(),
		func() tea.Msg {
			cfg, err := mdl.gencli.PutServer(
				mctx.Ctx(),
				lcl.PutServerArg{
					SessionId: mdl.sessId,
					Server:    s.getHost(),
					Timeout:   proto.ExportDurationMilli(hostCheckTimeout),
					Typ:       s.typ,
				},
			)
			return tryHostRes{err: err, ssoCfg: cfg.Sso}
		},
	), nil
}

func (s stateTryHost) summary() summary {
	if len(s.host) > 0 && s.res != nil && s.res.err == nil {
		hn := s.host.ProbeHostString()
		return summarySuccess("Using FOKS host: " + HappyStyle.Render(hn))
	}
	return nil
}
func (s stateTryHost) failure() failure { return nil }

var _ state = stateTryHost{}

func newStatePickEmail() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "jim.jones.85@gmail.com"
	ti.Focus()
	ti.Width = defaultWidth
	ti.CharLimit = 140
	ti.Prompt = "> "
	s := stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newStateGetInviteCode()
		},
		prompt:           "What's your email address?",
		inputResetCount:  1,
		validate:         func(s string) error { return core.ValidateEmail(proto.Email(s)) },
		badInputMsg:      "Invalid email address",
		goodInputMsg:     "Email accceped",
		checkingInputMsg: "Checking email address",
		post: func(mctx libclient.MetaContext, state stateCheckedInput, mdl model) error {
			err := mdl.cli.PutEmail(mctx.Ctx(), lcl.PutEmailArg{
				SessionId: mdl.sessId,
				Email:     proto.Email(state.acceptedInput),
			})
			return err
		},
		summaryLabel: "Email",
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			em, err := mdl.cli.GetEmailSSO(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			if !em.IsZero() {
				s = s.prePop(em.String())
				s.summarySuffix = "(via SSO)"
			}
			return s, nil
		},
	}
	return s
}

func newStateGetInviteCode() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "hello-foks-2025"
	ti.Focus()
	ti.Width = defaultWidth
	ti.CharLimit = 140
	ti.Prompt = "> "
	return stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newPickYubiSlotSignup()
		},
		validate: func(s string) error {
			return core.ValidateInviteCodeString(lcl.InviteCodeString(s))
		},
		post: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) error {
			err := mdl.cli.PutInviteCode(
				mctx.Ctx(),
				lcl.PutInviteCodeArg{
					SessionId:  mdl.sessId,
					InviteCode: lcl.InviteCodeString(s.acceptedInput),
				},
			)
			return err
		},
		badInputMsg:      "Server rejected invite code",
		checkingInputMsg: "Checking invite code",
		goodInputMsg:     "Invite code confirmed",
		inputResetCount:  2,
		prompt:           "Enter your invite code",
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			ic, err := mdl.cli.GetSkipInviteCodeSSO(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			s.skipped = ic
			return s, nil
		},
	}
}

func newStateConfirmYubiProvision(un proto.Name) state {
	return stateGetConfirmation{
		msg: fmt.Sprintf("Provision YubiKey on this device for %s?",
			italicStyle.Render(string(un))),
		summaryText: "User: " + HappyStyle.Render(string(un)),
		checkingMsg: "Finalizing YubiKey provision",
		nextState: func(s stateGetConfirmation, mdl model) state {
			return newStateFinishYubiProvision()
		},
		post: func(mctx libclient.MetaContext, s stateGetConfirmation, mdl model) error {
			err := mdl.cli.FinishYubiProvision(mctx.Ctx(), mdl.sessId)
			return err
		},
	}
}

func newPickYubiSlotSignup() state {
	return statePickYubiSlot{
		showEmptySlots: true,
		loadingMsg:     "Working....",
		existingTitle:  "Pick an existing key to use instead:",
		putCheckMsg:    "Checking key isn't already in use...",
		loadSlotsHook: func(ctx context.Context, mdl model) (lcl.ListYubiSlotsRes, error) {
			return mdl.cli.ListYubiSlots(ctx, mdl.sessId)
		},
		putSlotHook: func(ctx context.Context, mdl model, ind proto.YubiIndex) (lcl.PutYubiSlotRes, error) {
			return mdl.cli.PutYubiSlot(ctx, lcl.PutYubiSlotArg{
				SessionId: mdl.sessId,
				Index:     ind,
				Typ:       proto.CryptosystemType_Classical,
			})
		},
		nextHook: func(res lcl.PutYubiSlotRes) (state, tea.Cmd, error) {
			return newPickYubiPQSlotSignup(res), nil, nil
		},
	}
}

func newPickYubiPIN(nxt state, doLock bool) state {
	var fatalErr error
	return stateNewPassphrase{
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			if doLock {
				return true, nil
			}
			mks, err := mdl.ycli.ManagementKeyState(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return false, err
			}
			return (mks == proto.ManagementKeyState_ShouldTryPIN), nil
		},
		prompt:       "Enter the PIN for your YubiKey; be careful, you only get 3 tries!",
		summaryLabel: "YubiKey PIN validated",
		validator:    pinValidator,
		noConfirm:    true,
		nextHook: func() (state, error) {
			if fatalErr != nil {
				return stateError{err: fatalErr}, nil
			}
			return nxt, nil
		},
		forceNext: func() bool { return fatalErr != nil },
		what:      "PIN",
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			pin, err := pp.ToYubiPIN()
			if err != nil {
				return err
			}
			if libyubi.IsDefaultPIN(pin) && doLock {
				err = core.YubiDefaultPINError{}
				fatalErr = err
				return err
			}
			return mdl.ycli.ValidateCurrentPIN(mctx.Ctx(),
				lcl.ValidateCurrentPINArg{
					SessionId: mdl.sessId,
					Pin:       pin,
					DoUnlock:  true,
				},
			)
		},
	}
}

func newPickPINPRotection(nxt state) state {
	NO := menuVal(0)
	YES := menuVal(1)
	return statePickFromMenu{
		title: "Protect your key with a short PIN?",
		initHook: func(mctx libclient.MetaContext, mdl model) ([]menuOpt, error) {
			return []menuOpt{
				{label: "👎 No", val: NO},
				{label: "👍 Yes", val: YES},
			}, nil
		},
		postHook: func(mctx libclient.MetaContext, s statePickFromMenu, mdl model) error {
			if s.choice == NO {
				return nil
			}
			return mdl.ycli.ProtectKeyWithPIN(mctx.Ctx(), mdl.sessId)
		},
		nextHook: func(s statePickFromMenu, mdl model) state {
			return newPickYubiPIN(nxt, s.choice == YES)
		},
		succHook: func(s statePickFromMenu) summary {
			if s.choice == YES {
				return summarySuccess("PIN protection: 👍 enabled")
			}
			return nil
		},
	}
}

func newPickYubiPQSlotSignup(pri lcl.PutYubiSlotRes) state {
	return newPickYubiPQSlot(pri, newPickPINPRotection(newStatePickUsername()), false)
}

func newPickYubiPQSlotYubiNew(pri lcl.PutYubiSlotRes) state {
	return newPickYubiPQSlot(pri, newPickPINPRotection(newStatePickDeviceName()), true)
}

func newPickYubiPQSlot(pri lcl.PutYubiSlotRes, nxt state, noDeviceKey bool) state {
	if pri.IdxType == proto.YubiIndexType_None {
		return newStatePickUsername()
	}

	return statePickYubiSlot{
		noDeviceKey:    noDeviceKey,
		showEmptySlots: true,
		pqKey:          true,
		hideReuseSlots: (pri.IdxType == proto.YubiIndexType_Empty),
		existingTitle: "Pick an existing slot to use for PQ seed instead -- " +
			BoldStyle.Render("STRONGLY DISCOURAGED") + ":",
		putCheckMsg: "Checking slot isn't already in use...",
		nextHook: func(lcl.PutYubiSlotRes) (state, tea.Cmd, error) {
			return nxt, nil, nil
		},
		loadSlotsHook: func(ctx context.Context, mdl model) (lcl.ListYubiSlotsRes, error) {
			return lcl.ListYubiSlotsRes{Device: &pri.Device}, nil
		},
		putSlotHook: func(ctx context.Context, mdl model, ind proto.YubiIndex) (lcl.PutYubiSlotRes, error) {
			return mdl.cli.PutYubiSlot(ctx, lcl.PutYubiSlotArg{
				SessionId: mdl.sessId,
				Index:     ind,
				Typ:       proto.CryptosystemType_PQKEM,
			})
		},
	}
}

// newPickYubiSlotYubiNew makes screens for picking a slot, as called from `foks yubi new`;
func newPickYubiSlotYubiNew() statePickYubiSlot {
	return statePickYubiSlot{
		showEmptySlots: true,
		noDeviceKey:    true,
		existingTitle:  "Pick a slot for your new key",
		putCheckMsg:    "Checking that key isn't already registered...",
		loadSlotsHook: func(ctx context.Context, mdl model) (lcl.ListYubiSlotsRes, error) {
			return mdl.cli.ListYubiSlots(ctx, mdl.sessId)
		},
		putSlotHook: func(ctx context.Context, mdl model, ind proto.YubiIndex) (lcl.PutYubiSlotRes, error) {
			return mdl.cli.PutYubiSlot(ctx, lcl.PutYubiSlotArg{
				SessionId: mdl.sessId,
				Index:     ind,
			})
		},
		nextHook: func(res lcl.PutYubiSlotRes) (state, tea.Cmd, error) {
			return newPickYubiPQSlotYubiNew(res), nil, nil
		},
	}
}

func newPickYubiSlotYubiProvision() statePickYubiSlot {
	return statePickYubiSlot{
		showEmptySlots: false,
		existingTitle:  "Pick an key slot for your previously registered key:",
		putCheckMsg:    "Checking that key is registered...",
		loadSlotsHook: func(ctx context.Context, mdl model) (lcl.ListYubiSlotsRes, error) {
			return mdl.cli.ListYubiSlots(ctx, mdl.sessId)
		},
		putSlotHook: func(ctx context.Context, mdl model, ind proto.YubiIndex) (lcl.PutYubiSlotRes, error) {
			return mdl.cli.PutYubiSlot(ctx, lcl.PutYubiSlotArg{
				SessionId: mdl.sessId,
				Index:     ind,
			})
		},
		nextHook: func(res lcl.PutYubiSlotRes) (state, tea.Cmd, error) {
			unp := res.Username
			if unp == nil {
				return nil, nil, errors.New("no username provided")
			}
			return newStateConfirmYubiProvision(*unp), nil, nil
		},
	}
}

func newStateSupplyUsername() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "steve.jones.30"
	ti.Focus()
	ti.Width = defaultWidth
	ti.CharLimit = core.UsernameMaxLen
	ti.Prompt = "> "
	s := stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newStatePickDeviceName()
		},
		prompt: "What is your username?",
		validate: func(i string) error {
			_, err := core.NormalizeName(proto.NameUtf8(i))
			return err
		},
		inputResetCount:  0,
		badInputMsg:      "Username unknown to service",
		goodInputMsg:     "Username found",
		checkingInputMsg: "Checking that user exists...",
		post: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) error {
			err := mdl.cli.PutUsername(mctx.Ctx(), lcl.PutUsernameArg{
				SessionId: mdl.sessId,
				Username:  proto.NameUtf8(s.acceptedInput),
			})
			return err
		},
		isBadInputError: func(err error) bool {
			return errors.Is(err, core.UserNotFoundError{})
		},
		summaryLabel: "Username",
	}
	return s
}

func newStatePickUsername() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "steve.jones.30"
	ti.Focus()
	ti.Width = defaultWidth
	ti.CharLimit = core.UsernameMaxLen
	ti.Prompt = "> "
	s := stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newStatePickDeviceName()
		},
		prompt: "Pick a username (3-25 characters, with some Latin Unicode, hypens, periods, and underscores)",
		validate: func(i string) error {
			_, err := core.NormalizeName(proto.NameUtf8(i))
			return err
		},
		inputResetCount:  0,
		badInputMsg:      "Username unavailable",
		goodInputMsg:     "Username available",
		checkingInputMsg: "Checking username availability",
		post: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) error {
			err := mdl.cli.PutUsername(mctx.Ctx(), lcl.PutUsernameArg{
				SessionId: mdl.sessId,
				Username:  proto.NameUtf8(s.acceptedInput),
			})
			return err
		},
		summaryLabel: "Username",
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			un, err := mdl.cli.GetUsernameSSO(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			if !un.IsZero() {
				s = s.prePop(un.String())
				s.summarySuffix = "(via SSO)"
			}
			return s, nil
		},
	}
	return s
}

func newStatePickDeviceName() stateCheckedInput {
	makeInput := func(placeholder string) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.Focus()
		ti.Width = defaultWidth
		ti.CharLimit = 100
		ti.Prompt = "> "
		return ti
	}
	s := stateCheckedInput{
		input: makeInput("iPhone 12+ Pro Max"),
		nextState: func(s stateCheckedInput, mdl model) state {
			switch mdl.typ {
			case proto.UISessionType_Provision:
				return newStateStartKex()
			case proto.UISessionType_YubiNew:
				return newStateFinishYubiNew()
			case proto.UISessionType_NewKeyWizard:
				switch mdl.nkw.mode {
				case newYubiKey:
					return newStateFinishYubiNew()
				case newDeviceKey:
					return newStateFinishNKWNewDeviceKey()
				default:
					return newStateStartKex()
				}
			default:
				return newStateFinishSignup()
			}
		},
		prompt: "Pick a device name:",
		validate: func(i string) error {
			err := core.CheckDeviceName(i)
			return err
		},
		inputResetCount:  1,
		badInputMsg:      "Invalid device name",
		goodInputMsg:     "Device name acccepted",
		checkingInputMsg: "Checking device name",
		post: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) error {
			dn := core.FixDeviceName(s.acceptedInput)
			err := mdl.cli.PutDeviceName(mctx.Ctx(), lcl.PutDeviceNameArg{
				SessionId:  mdl.sessId,
				DeviceName: dn,
			})
			return err
		},
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			typ, err := mdl.cli.GetDeviceType(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			if typ == proto.DeviceType_YubiKey {
				s.input = makeInput("YubiKey 5 NFC")
				s.prompt = "Pick a name for this YubiKey:"
				s.badInputMsg = "Invalid YubiKey name"
				s.goodInputMsg = "YubiKey name accepted"
				s.checkingInputMsg = "Checking YubiKey name"
				s.summaryLabel = "YubiKey name"
			}
			return s, nil
		},
		summaryLabel: "Device name",
	}
	return s
}

type finishRes struct {
	err  error
	res  *lcl.FinishRes
	hesp *lcl.BackupHESP
}

type stateFinishSub interface {
	view(b stateFinishBase) string
	init(mctx libclient.MetaContext, mdl model) tea.Msg
}

type stateError struct {
	err error
}

func (s stateError) view() string {

	return fmt.Sprintf("   %s\n  %s (%T)\n\n %s\n\n",
		h2Style.Render("Fatal Error"),
		RenderError(s.err),
		s.err,
		pushAnyKeyToExit(),
	)
}

func (s stateError) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return s, nil, nil
}

func (s stateError) failure() failure { return nil }
func (s stateError) summary() summary { return nil }
func (s stateError) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return nil, nil, nil
}

func (s stateError) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	switch msg.(type) {
	case tea.KeyMsg:
		return s, tea.Quit, nil
	}
	return s, nil, nil
}

var _ state = stateError{}

type stateFinishBase struct {
	spinner spinner.Model
	loading bool
	res     *finishRes
	sub     stateFinishSub
}

type stateFinishSignup struct{}
type stateFinishYubiNew struct{}
type stateFinishNKWNewDeviceKey struct{}
type stateFinishNKWNewBackupKey struct{}

var _ stateFinishSub = stateFinishSignup{}

func newStateFinishNKWNewDeviceKey() stateFinishBase {
	return stateFinishBase{sub: stateFinishNKWNewDeviceKey{}}
}

func newStateFinishSignup() stateFinishBase    { return stateFinishBase{sub: stateFinishSignup{}} }
func newStateFinishProvision() stateFinishBase { return stateFinishBase{sub: stateFinishProvision{}} }
func newStateFinishYubiProvision() stateFinishBase {
	return stateFinishBase{sub: stateFinishYubiProvision{}}
}
func newStateFinishYubiNew() stateFinishBase { return stateFinishBase{sub: stateFinishYubiNew{}} }
func newStateFinishNKWNewBackupKey() stateFinishBase {
	return stateFinishBase{sub: stateFinishNKWNewBackupKey{}}
}

type stateFinishProvision struct{}
type stateFinishYubiProvision struct{}

var _ stateFinishSub = stateFinishProvision{}
var _ stateFinishSub = stateFinishYubiProvision{}
var _ stateFinishSub = stateFinishNKWNewDeviceKey{}

func (s stateFinishBase) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.loading = true
	return s,
		tea.Batch(
			s.spinner.Tick,
			func() tea.Msg {
				debugSpinners(mctx)
				return s.sub.init(mctx, mdl)
			},
		), nil
}

func (s stateFinishNKWNewDeviceKey) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	err := mdl.cli.FinishNKWNewDeviceKey(mctx.Ctx(), mdl.sessId)
	return finishRes{err: err}
}

func (s stateFinishNKWNewBackupKey) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	hesp, err := mdl.cli.FinishNKWNewBackupKey(mctx.Ctx(), mdl.sessId)
	res := finishRes{err: err}
	if err == nil {
		res.hesp = &hesp
	}
	return res
}

func (s stateFinishNKWNewDeviceKey) view(b stateFinishBase) string {
	return finishProvisionView(b)
}

func (s stateFinishNKWNewBackupKey) view(sfb stateFinishBase) string {
	common := sfb.viewCommon("Provisioning backup key")
	if common != "" {
		return common
	}
	var hesp *lcl.BackupHESP
	if sfb.res != nil && sfb.res.hesp != nil {
		hesp = sfb.res.hesp
	}
	if hesp == nil {
		return fmt.Sprintf("\n %s\n", ErrorStyle.Render("Unexpected state: no backup key"))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", h2Style.Render("💾 New Backup Key Activated 💾"))
	fmt.Fprintf(&b, " Here is your key. Please write it down and keep it in a safe place:\n")
	fmt.Fprintf(&b, "\n   %s\n\n", strings.Join(*hesp, " "))
	fmt.Fprintf(&b, "\n%s\n\n", pushAnyKeyToExit())
	return b.String()
}

func (f stateFinishYubiProvision) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	return finishRes{err: nil}
}

func (s stateFinishBase) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return nil, nil, nil
}

func (s stateFinishBase) view() string {
	return s.sub.view(s)
}

func (f stateFinishYubiNew) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	err := mdl.cli.FinishYubiNew(mctx.Ctx(), mdl.sessId)
	return finishRes{err: err}
}

func (f stateFinishYubiNew) view(s stateFinishBase) string {
	if s.loading {
		return fmt.Sprintf("\n\n  %s Finalizing registration with server", s.spinner.View())
	}

	var b strings.Builder
	if s.res == nil {
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Unexpeted state: no result"))

	} else if s.res.err != nil {
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Provision failed: "+s.res.err.Error()))
	} else {

		fmt.Fprintf(&b, "%s\n", h2Style.Render("🔑 Success 🔑"))
		fmt.Fprintf(&b, "  Your new Yubikey is now ready to use. Have fun, and remember,\n")
		nyknyd(&b)
	}
	fmt.Fprintf(&b, "\n %s\n\n", pushAnyKeyToExit())
	return b.String()
}

func (f stateFinishSignup) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	res, err := mdl.cli.Finish(mctx.Ctx(), mdl.sessId)
	return finishRes{err: err, res: &res}
}

func (f stateFinishProvision) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	err := mdl.cli.WaitForKexComplete(mctx.Ctx(), mdl.sessId)
	return finishRes{err: err}
}

func (f stateFinishProvision) view(s stateFinishBase) string {
	return finishProvisionView(s)
}

func nyknyd(b *strings.Builder) {
	fmt.Fprintf(b, "  %s\n", italicStyle.Render("not your keys, not your data!\n"))

}

func (s stateFinishBase) viewCommon(op string) string {
	if s.loading {
		return fmt.Sprintf("\n\n  %s Waiting for provisioning to complete", s.spinner.View())
	}
	var b strings.Builder
	if s.res == nil {
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Unexpected state: no result"))

	} else if s.res.err != nil {
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Provisioning failed: "+s.res.err.Error()))
	} else {
		return ""
	}
	fmt.Fprintf(&b, "\n %s\n\n", pushAnyKeyToExit())
	return b.String()

}

func finishProvisionView(s stateFinishBase) string {
	common := s.viewCommon("Provisioning")
	if common != "" {
		return common
	}
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", h2Style.Render("🖥️  New Device Activated 🖥️"))
	fmt.Fprintf(&b, "  Your new device is now ready to use. Have fun, and remember,\n")
	nyknyd(&b)
	fmt.Fprintf(&b, "\n %s\n\n", pushAnyKeyToExit())

	return b.String()
}

type NextStepsTableOpts struct {
	BackupOnly bool
	Header     bool
	NoWeb      bool
	OnlyWeb    bool
	NoBilling  bool
}

func NextStepsTable(t NextStepsTableOpts) string {
	var b strings.Builder
	if t.Header {
		fmt.Fprintf(&b, BoldStyle.Render(" Next Steps You Might Consider️:")+"\n\n")
	}

	type nextStep struct {
		emoji     string
		desc      string
		cmd       string
		isBkp     bool
		isWeb     bool
		isBilling bool
	}

	items := []nextStep{
		{"🔑", "Create a backup key", "key new", true, false, false},
		{"📄", "Store files and string data", "kv put", false, false, false},
		{"🔀", "Host a git repository", "git create", false, false, false},
		{"🤝", "Create a team", "team create", false, false, false},
		{"🌐", "Setup billing via web", "admin web", false, true, true},
	}

	doSkip := func(item nextStep) bool {
		if t.BackupOnly && !item.isBkp {
			return true
		}
		if t.NoWeb && item.isWeb {
			return true
		}
		if t.OnlyWeb && !item.isWeb {
			return true
		}
		if t.NoBilling && item.isBilling {
			return true
		}
		return false
	}

	var longDescLen int
	for _, item := range items {
		if !doSkip(item) && len(item.desc) > longDescLen {
			longDescLen = len(item.desc)
		}
	}

	for _, item := range items {
		if !doSkip(item) {
			fmt.Fprintf(&b, "    %s %s%s%s\n",
				item.emoji,
				item.desc,
				strings.Repeat(" ", longDescLen-len(item.desc)+2),
				HappyStyle.Render("foks "+item.cmd))
		}
	}
	return b.String()
}

func (f stateFinishSignup) view(s stateFinishBase) string {
	if s.loading {
		return fmt.Sprintf("\n\n  %s Finalizing signup with server", s.spinner.View())
	}
	var noBilling bool
	if s.res != nil && s.res.res != nil && !s.res.res.HostType.SupportBilling() {
		noBilling = true
	}

	var b strings.Builder
	switch {

	case s.res == nil:
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Unexpeted state: no result"))

	case s.res.err != nil:
		fmt.Fprintf(&b, "\n %s\n", ErrorStyle.Render("Signup failed: "+s.res.err.Error()))

	case s.res.res != nil && s.res.res.RegServerType == lcl.RegServerType_Mgmt:

		fmt.Fprintf(&b, "%s\n", h2Style.Render("🔑 Welcome to FOKS 🔑"))
		fmt.Fprintf(&b, "  You have signed up for a %s account.\n",
			italicStyle.Render("Virtual Host Management"))
		fmt.Fprintf(&b, "  The next step is to access the web management portal:\n\n")
		fmt.Fprintf(&b, "      %s\n\n", HappyStyle.Render("foks admin web"))
		fmt.Fprintf(&b, "  Also, consider securing your account with backup keys:\n")
		s := NextStepsTable(NextStepsTableOpts{Header: false, BackupOnly: true, NoBilling: noBilling})
		fmt.Fprintf(&b, "\n%s\n\n", s)

	default:

		fmt.Fprintf(&b, "%s\n", h2Style.Render("🔑 Welcome to FOKS 🔑"))
		fmt.Fprintf(&b, "  Your account is now ready to use. Have fun, and remember,\n")
		nyknyd(&b)
		s := NextStepsTable(NextStepsTableOpts{Header: true, NoBilling: noBilling})
		fmt.Fprintf(&b, "\n%s\n\n", s)
	}
	fmt.Fprintf(&b, "\n%s\n\n", pushAnyKeyToExit())
	return b.String()
}

func (f stateFinishYubiProvision) view(s stateFinishBase) string {

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", h2Style.Render("🔑 YubiKey Provisioned 🔑"))
	fmt.Fprintf(&b, "  Your YubiKey is now ready to use on this device. Have fun, and remember,\n")
	nyknyd(&b)

	fmt.Fprintf(&b, "\n%s\n\n", pushAnyKeyToExit())
	return b.String()
}

func (s stateFinishBase) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	var cmd tea.Cmd
	if s.loading {
		s.spinner, cmd = s.spinner.Update(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if s.res != nil {
			cmd = tea.Quit
		}
	case finishRes:
		s.res = &msg
		s.loading = false
	}

	return s, cmd, nil
}

func (s stateFinishBase) summary() summary { return nil }
func (s stateFinishBase) failure() failure { return nil }

var _ state = stateFinishBase{}

func cancelSession(m libclient.MetaContext, mdl model) error {
	if mdl.sessId.IsZero() {
		return nil
	}
	err := mdl.gencli.FinishSession(m.Ctx(), mdl.sessId)
	if err != nil {
		m.Warnw("cancelSession", "err", err)
		return err
	}
	return nil
}

func newStateStartKex() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "air 424 bee ..."
	ti.Focus()
	ti.Width = 100
	ti.CharLimit = 250
	ti.Prompt = "> "
	s := stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newStateFinishProvision()
		},
		prompt:           "Loading...",
		inputResetCount:  1,
		validate:         func(s string) error { return core.KexSeedHESPConfig.ValidateInput(s) },
		badInputMsg:      "Invalid KEX secret phrase",
		goodInputMsg:     "KEX accepted",
		checkingInputMsg: "Checking KEX secret phrase",
		post: func(mctx libclient.MetaContext, state stateCheckedInput, mdl model) error {
			err := mdl.cli.GotKexInput(mctx.Ctx(), lcl.KexSessionAndHESP{
				SessionId: mdl.sessId,
				Hesp:      proto.NewKexHESP(state.acceptedInput),
			})
			return err
		},
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			hesp, err := mdl.cli.StartKex(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			s.prompt = fmt.Sprintf(
				"Run `foks key assist` on your existing device, and input that phrase here,\n"+
					"or enter the below phrase on that computer:\n\n"+
					"\t%s",
				hesp.String(),
			)
			return s, nil
		},
		cancelInput: func(mctx libclient.MetaContext, mdl model) tea.Cmd {
			return func() tea.Msg {
				err := mdl.cli.KexCancelInput(mctx.Ctx(), mdl.sessId)
				if err != nil {
					return nil
				}
				return cancelMsg{}
			}
		},
	}
	return s

}

type statePickUserLoginAs struct {
	user    *proto.UserInfo
	loading bool
	spinner spinner.Model
}

func (s statePickUserLoginAs) view() string {
	user := func() string {
		u, err := common_ui.FormatUserInfoAsPromptItem(
			*s.user,
			&common_ui.FormatUserInfoOpts{
				Active: false,
				Avatar: true,
			},
		)
		if err != nil {
			u = "(error formatting user info)"
		}
		return "[" + u + "]"
	}
	if s.loading {
		return "\n " + s.spinner.View() + " Logging in as " + user() + " ..."
	}
	return "\n\nLogged in as " + user() + "\n\n" + pushAnyKeyToExit() + "\n\n"
}

func (s statePickUserLoginAs) failure() failure { return nil }

func (s statePickUserLoginAs) summary() summary { return nil }

func (s statePickUserLoginAs) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.loading {
		return nil, nil, nil
	}
	switch mdl.typ {
	case proto.UISessionType_NewKeyWizard:
		return newStateNKWPickKeyGenus(), nil, nil
	default:
		return nil, nil, nil
	}
}

func (s statePickUserLoginAs) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {

	if s.user.Active {
		return s, nil, nil
	}

	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.loading = true

	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			err := mdl.cli.LoginAs(
				mctx.Ctx(),
				lcl.LoginAsArg{
					SessionId: mdl.sessId,
					User:      *s.user,
				})
			return loginAsMsg{err: err}
		},
	), nil
}

func (s statePickUserLoginAs) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case loginAsMsg:
		s.loading = false
		return s, cmd, msg.err
	case tea.KeyMsg:
		if !s.loading && mdl.typ != proto.UISessionType_NewKeyWizard {
			cmd = tea.Quit
		}
		return s, cmd, nil
	default:
		return s, nil, nil
	}
}

func RunModelForSessionType(m libclient.MetaContext, typ proto.UISessionType) error {

	var s state
	switch typ {
	case proto.UISessionType_Signup:
		s = newStateHomeSignup()
	case proto.UISessionType_NewKeyWizard:
		s = newStateNKWHome()
	case proto.UISessionType_Provision:
		s = newStateHomeProvision()
	case proto.UISessionType_YubiProvision:
		s = newStateYubiProvision()
	case proto.UISessionType_YubiNew:
		s = newStateYubiNew()
	default:
		return core.InternalError(fmt.Sprintf("unknown signup session type: %d", int(typ)))
	}

	return RunNewModelForStateAndSessionType(m, s, typ)
}

var _ state = statePickUserLoginAs{}
