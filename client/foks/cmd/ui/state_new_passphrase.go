// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

const (
	subStateCollectRetype subState = 100
)

type stateNewPassphraseInitRes struct {
	err      error
	doPrompt bool
}

type stateNewPassphrasePostRes struct {
	err error
}

type stateNewPassphrase struct {
	//state
	subState subState
	spinner  spinner.Model
	pp       proto.Passphrase
	ti       textinput.Model
	mismatch bool
	isEmpty  bool
	didLock  bool
	inputErr error
	fail     failure

	// input
	prompt        string
	promptCanSkip string
	allowSkip     bool
	postEmpty     bool
	summaryLabel  string
	initHook      func(mctx libclient.MetaContext, mdl model) (bool, error)
	nextHook      func() (state, error)
	postHook      func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error
	validator     func(s string) error
	forceNext     func() bool
	noConfirm     bool
	what          string
}

func (s stateNewPassphrase) summary() summary {
	if s.summaryLabel == "" || !s.didLock {
		return nil
	}
	return summarySuccess(s.summaryLabel)
}

func (s stateNewPassphrase) failure() failure {
	if s.fail != nil {
		return s.fail
	}
	return nil
}

func (s stateNewPassphrase) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.subState = subStateLoading

	ti := textinput.New()
	ti.Width = 10
	ti.EchoMode = textinput.EchoPassword
	ti.Prompt = "> "
	ti.CharLimit = 1024
	ti.Focus()
	s.ti = ti

	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			doPrompt, err := s.initHook(mctx, mdl)
			return stateNewPassphraseInitRes{
				err:      err,
				doPrompt: doPrompt,
			}
		},
	), nil
}

func (s stateNewPassphrase) renderPrompt() string {

	var b strings.Builder
	fmt.Fprintf(&b, "\n%s", s.prompt)
	switch s.subState {
	case subStateCollectRetype:
		fmt.Fprintf(&b, " (retype to confirm)")
	case subStatePicking:
		if s.allowSkip {
			ope := "or press enter for no passphrase"
			if s.promptCanSkip != "" {
				ope = s.promptCanSkip
			}
			fmt.Fprintf(&b, " (%s)", ope)
		}
	}
	fmt.Fprintf(&b, ":\n\n%s\n\n",
		textInputStyle.Render(s.ti.View()),
	)
	what := s.what
	if what == "" {
		what = "passphrase"
	}
	if s.subState == subStatePicking || s.subState == subStateCollectRetype {
		switch {
		case s.mismatch:
			fmt.Fprintf(&b, " ❌ %s\n\n",
				ErrorStyle.Render(fmt.Sprintf("%ss do not match", what)),
			)
		case s.isEmpty && !s.allowSkip:
			fmt.Fprintf(&b, " ❌ %s\n\n",
				ErrorStyle.Render(fmt.Sprintf("%s cannot be empty", what)),
			)
		case s.inputErr != nil:
			fmt.Fprintf(&b, " ❌ %s\n\n", ErrorStyle.Render(s.inputErr.Error()))
		}
	}
	return b.String()
}

func (s stateNewPassphrase) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.forceNext != nil && s.forceNext() {
		s.subState = subStateDone
	}
	if s.subState != subStateDone {
		return nil, nil, nil
	}
	res, err := s.nextHook()
	return res, nil, err
}

func (s stateNewPassphrase) submit(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) (state, tea.Cmd, error) {
	s.subState = subStatePutting
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			err := s.postHook(mctx, mdl, pp)
			return stateNewPassphrasePostRes{err: err}
		},
	), nil
}

func (s stateNewPassphrase) val() string {
	return strings.TrimSpace(s.ti.Value())
}

func (s stateNewPassphrase) handleEnter(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	i := s.val()
	trimmedLen := len(i)
	ppNew := proto.Passphrase(i)
	doConfirm := !s.noConfirm
	hasInput := trimmedLen > 0

	switch {
	case s.subState == subStatePicking && s.allowSkip && !hasInput && !s.postEmpty:
		s.subState = subStateDone
		return s, nil, nil
	case s.subState == subStatePicking && !s.allowSkip && !hasInput:
		s.isEmpty = true
		return s, nil, nil
	case s.subState == subStatePicking && hasInput && doConfirm:
		s.pp = ppNew
		s.subState = subStateCollectRetype
		s.ti.SetValue("")
		return s, nil, nil
	case (s.subState == subStatePicking && (hasInput || s.postEmpty) && !doConfirm) ||
		(s.subState == subStateCollectRetype && s.pp == ppNew):
		s.pp = ppNew
		return s.submit(mctx, mdl, ppNew)
	case s.subState == subStateCollectRetype && s.pp != ppNew:
		s.mismatch = true
		s.ti.SetValue("")
		s.subState = subStatePicking
		s.pp = ""
		return s, nil, nil
	default:
		return s, nil, core.InternalError("unhandled case after enter")
	}
}

func (s stateNewPassphrase) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case stateNewPassphraseInitRes:
		if msg.err == nil && !msg.doPrompt {
			s.subState = subStateDone
		} else {
			s.subState = subStatePicking
		}
		return s, nil, msg.err
	case tea.KeyMsg:
		var cmd tea.Cmd
		if s.inputErr == nil && isEnter(msg) {
			return s.handleEnter(mctx, mdl)
		}
		s.ti, cmd = s.ti.Update(msg)
		if s.subState == subStateCollectRetype {
			inp := s.val()
			s.mismatch = (len(inp) > 0 && s.pp != proto.Passphrase(inp))
		} else if s.validator != nil {
			s.inputErr = s.validator(s.val())
		}
		return s, cmd, nil
	case stateNewPassphrasePostRes:
		if msg.err != nil {
			s.fail = genericFailure(msg)
			s.inputErr = msg.err
			s.subState = subStatePicking
			s.ti.SetValue("")
			return s, nil, nil
		}
		s.didLock = true
		s.subState = subStateDone
		return s, nil, nil
	}

	return s, nil, nil
}

func (s stateNewPassphrase) view() string {
	switch s.subState {
	case subStateLoading, subStatePutting:
		return "\n\n   " + s.spinner.View() + " Loading..."
	case subStatePicking, subStateCollectRetype:
		return s.renderPrompt()
	default:
		return "<nothing to show; internal error>"
	}
}

var _ state = stateNewPassphrase{}
