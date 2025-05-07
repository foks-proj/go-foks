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
)

type checkedInputRes struct {
	err error
}

type stateCheckedInput struct {
	// state local to this state
	input         textinput.Model
	acceptedInput string
	spinner       spinner.Model
	checking      bool
	res           *checkedInputRes
	confirmed     bool
	canceled      bool
	inputCount    int
	skipped       bool

	// to be filled in by "subclasses"
	//  - cancelInput potentially interrupts the input, say in Kex if the
	//    other side does the input.
	nextState        func(s stateCheckedInput, mdl model) state
	initHook         func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error)
	post             func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) error
	cancelInput      func(mctx libclient.MetaContext, mdl model) tea.Cmd
	isBadInputError  func(e error) bool
	badInputMsg      string
	checkingInputMsg string
	goodInputMsg     string
	inputResetCount  int
	prompt           string
	validate         func(s string) error
	summaryLabel     string
	summarySuffix    string
}

func (s stateCheckedInput) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if (!s.checking && s.confirmed && len(s.acceptedInput) > 0) || s.canceled || s.skipped {
		return s.nextState(s, mdl), nil, nil
	}
	return nil, nil, nil
}

func pushReturnToContinue(b *strings.Builder, s string) {
	fmt.Fprintf(b, "   ✅ %s; %s", HappyStyle.Render(s), "push <return> to continue")
}

func (s stateCheckedInput) view() string {
	var b strings.Builder
	msg := drawTextInput(
		s.input,
		s.prompt,
		s.validate,
	)
	b.WriteString(msg)
	if s.checking {
		fmt.Fprintf(&b, "   %s %s...", s.spinner.View(), s.checkingInputMsg)
	} else if s.res != nil && s.res.err != nil {
		if s.isBadInputError == nil || s.isBadInputError(s.res.err) {
			fmt.Fprintf(&b, "   ❌ %s", ErrorStyle.Render(s.badInputMsg))
		} else {
			fmt.Fprintf(&b, "   ❌ %s", ErrorStyle.Render(s.res.err.Error()))
		}
	} else if s.res != nil && s.res.err == nil {
		pushReturnToContinue(&b, s.goodInputMsg)
	}
	return b.String()
}

type cancelMsg struct{}

func (s stateCheckedInput) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	var cmd tea.Cmd
	frozen := s.checking || (s.res != nil && s.res.err == nil)

	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case checkedInputRes:
		s.res = &msg
		s.checking = false
		return s, cmd, nil
	case cancelMsg:
		s.canceled = true
		return s, nil, nil
	case tea.KeyMsg:
		s.inputCount += 1
		if !frozen {
			s.input, cmd = s.input.Update(msg)
		}
	}

	// Remove the error message after a while
	if s.inputCount > s.inputResetCount && s.res != nil && s.res.err != nil {
		s.res = nil
	}

	if !isEnter(msg) {
		return s, cmd, nil
	}

	if s.res != nil && s.res.err == nil {
		s.confirmed = true
		return s, nil, nil
	}

	i := s.input.Value()
	err := s.validate(i)
	if err != nil {
		return s, nil, nil
	}
	s.acceptedInput = i

	s.checking = true
	s.res = nil
	s.inputCount = 0
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			err := s.post(mctx, s, mdl)
			return checkedInputRes{err: err}
		},
	), nil
}

func (s stateCheckedInput) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.initHook != nil {
		tmp, err := s.initHook(mctx, s, mdl)
		if err != nil {
			return s, nil, err
		}
		s = tmp
	}
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	var cmd tea.Cmd
	if s.cancelInput != nil {
		cmd = s.cancelInput(mctx, mdl)
	}
	return s, cmd, nil
}

func (s stateCheckedInput) summary() summary {
	if s.summaryLabel == "" {
		return nil
	}
	if len(s.acceptedInput) == 0 {
		return nil
	}
	display := fmt.Sprintf("%s: %s", s.summaryLabel, HappyStyle.Render(s.acceptedInput))
	if s.summarySuffix != "" {
		display += " " + s.summarySuffix
	}
	return summarySuccess(display)
}

func (s stateCheckedInput) failure() failure { return nil }

func (s stateCheckedInput) prePop(v string) stateCheckedInput {
	s.acceptedInput = v
	s.confirmed = true
	return s
}
