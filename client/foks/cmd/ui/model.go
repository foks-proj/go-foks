// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type summary interface {
	view() string
}

type summarySuccess string

func (g summarySuccess) view() string { return happyStyle.Render("✓ ") + string(g) }

type failure interface {
	view() string
}

type state interface {
	next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error)
	view() string
	update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error)
	init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error)
	summary() summary
	failure() failure
}

type model struct {
	g           *libclient.GlobalContext
	s           state
	breadcrumbs []state
	err         error
	typ         proto.UISessionType
	firstCmd    tea.Cmd

	cli       lcl.SignupClient
	gencli    lcl.GeneralClient
	devcli    lcl.DeviceAssistClient
	usercli   lcl.UserClient
	ycli      lcl.YubiClient
	gcli      *rpc.Client
	cleanupFn func()
	sessId    proto.UISessionID
	nkw       *nkwState
}

func (m model) advance(mctx libclient.MetaContext) (model, tea.Cmd, error) {
	var cmds []tea.Cmd

	collect := func(cmd tea.Cmd) {
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	for {
		next, cmd, err := m.s.next(mctx, m)
		if err != nil {
			return m, nil, err
		}
		if next == nil {
			break
		}
		collect(cmd)
		next, cmd, err = next.init(mctx, m)
		if err != nil {
			return m, nil, err
		}
		collect(cmd)
		m.breadcrumbs = append(m.breadcrumbs, m.s)
		m.s = next
	}
	return m, tea.Batch(cmds...), nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	mctx := libclient.NewMetaContextBackground(m.g)

	// We might have a first command buffered up from when we initialized
	if m.firstCmd != nil {
		tmp := m.firstCmd
		m.firstCmd = nil
		return m, tmp
	}

	var cmds []tea.Cmd
	var err error
	var cmd tea.Cmd

	collect := func() bool {
		if err != nil {
			m.err = err
			m.s = stateError{err: err}
			return false
		}
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return true
	}

	m, cmd, err = m.advance(mctx)
	if !collect() {
		return m, nil
	}

	m, cmd, err = m.updateMsg(mctx, msg)
	if !collect() {
		return m, nil
	}

	m, cmd, err = m.advance(mctx)
	if !collect() {
		return m, nil
	}

	return m, tea.Batch(cmds...)
}

func (m model) updateMsg(mctx libclient.MetaContext, msg tea.Msg) (model, tea.Cmd, error) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "esc":
			return m, tea.Quit, nil
		}
	}
	var cmd tea.Cmd
	var s state
	var err error
	s, cmd, err = m.s.update(mctx, m, msg)
	if err != nil {
		return m, nil, err
	}
	m.s = s
	return m, cmd, nil
}

func (m model) history() string {
	var lines []string
	var cancelers []summarySuccessCanceler

	// First get all the cancelers in an initial pass
	for _, s := range m.breadcrumbs {
		sum := s.summary()
		if sum == nil {
			continue
		}
		if canceler, ok := sum.(summarySuccessCanceler); ok {
			cancelers = append(cancelers, canceler)
		}
	}

	// Now iterate over the breadcrumbs again and skip any canceled steps
	for _, s := range m.breadcrumbs {
		sum := s.summary()
		if sum == nil {
			continue
		}
		skip := false
		for _, canceler := range cancelers {
			if canceler.cancel(sum) {
				skip = true
			}
		}
		if skip {
			continue
		}

		msg := sum.view()
		lines = append(lines, msg)
	}

	// Should only have one line of failure, at the current step
	fail := m.s.failure()
	if fail != nil {
		msg := fail.view()
		lines = append(lines, msg)
	}

	var ret string
	if len(lines) > 0 {
		ret = historyStyle.Render(strings.Join(lines, "\n")) + "\n"
	}
	return ret
}

func (m model) View() string {
	m1 := m.history()
	m2 := m.s.view()
	return m1 + m2
}

func (m model) Init() tea.Cmd { return nil }

var _ tea.Model = model{}

func (m model) connect(mctx libclient.MetaContext) (model, error) {
	gcli, fn, err := mctx.G().ConnectToAgentCli(mctx.Ctx())
	if err != nil {
		return m, err
	}
	m.cleanupFn = fn
	m.gcli = gcli
	m.cli = lcl.SignupClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	m.gencli = lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	m.devcli = lcl.DeviceAssistClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	m.ycli = lcl.YubiClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	m.usercli = libclient.NewRpcTypedClient[lcl.UserClient](mctx, gcli)
	return m, nil
}

func (m model) startSession(mctx libclient.MetaContext) (model, error) {
	sess, err := m.gencli.NewSession(mctx.Ctx(), m.typ)
	if err != nil {
		return m, err
	}
	m.sessId = sess
	return m, nil
}

func (m model) initNetwork(mctx libclient.MetaContext) (model, error) {
	var err error
	m, err = m.connect(mctx)
	if err != nil {
		return m, err
	}
	m, err = m.startSession(mctx)
	if err != nil {
		return m, err
	}
	return m, nil
}

func runModel(mctx libclient.MetaContext, mdl model) error {

	var err error
	mdl, err = mdl.initNetwork(mctx)
	if err != nil {
		return err
	}
	defer mdl.cleanup()

	mdl.s, mdl.firstCmd, err = mdl.s.init(mctx, mdl)
	if err != nil {
		return err
	}

	_, err = tea.NewProgram(mdl).Run()
	return err
}

func newModel(g *libclient.GlobalContext, s state, typ proto.UISessionType) model {
	return model{
		g:   g,
		s:   s,
		typ: typ,
	}
}

func RunNewModelForStateAndSessionType(m libclient.MetaContext, s state, typ proto.UISessionType) (err error) {

	mdl := newModel(m.G(), s, typ)

	defer func() {
		tmp := cancelSession(m, mdl)
		if err == nil && tmp != nil {
			err = tmp
		}
	}()

	// In general, the model is passed by value across the different states, with
	// mutable state living in the agent process. But the NewKeyWizard needs a little
	// bit more control over the state transitions, depending on the user
	// input. So break that paradigm here. Potentially rethink all of this!
	if typ == proto.UISessionType_NewKeyWizard {
		mdl.nkw = &nkwState{}
	}

	return runModel(m, mdl)
}
