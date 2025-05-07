// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
)

type stateGetConfirmation struct {
	msg         string
	summaryText string
	checkingMsg string
	confirmed   bool
	checking    bool
	res         *getConfirmationRes
	spinner     spinner.Model
	nextState   func(s stateGetConfirmation, mdl model) state
	post        func(mctx libclient.MetaContext, s stateGetConfirmation, mdl model) error
}

type getConfirmationRes struct {
	err error
}

func (s stateGetConfirmation) summary() summary {
	if !s.confirmed || len(s.summaryText) == 0 {
		return nil
	}
	return summarySuccess(s.summaryText)
}

func (s stateGetConfirmation) failure() failure { return nil }

func (s stateGetConfirmation) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	return s, nil, nil
}

func (s stateGetConfirmation) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	switch {
	case s.res != nil && s.res.err != nil:
		return stateError{err: s.res.err}, nil, nil
	case s.res != nil && s.res.err == nil:
		return s.nextState(s, mdl), nil, nil
	default:
		return nil, nil, nil
	}
}

func okOrCancel(b *strings.Builder) {
	fmt.Fprintf(b, "  🆗 Press %s to accept\n",
		HappyStyle.Render("<Return>"),
	)
	fmt.Fprintf(b, "  ☮️  Or %s or %s to cancel\n",
		ErrorStyle.Render("<Ctrl+C>"),
		ErrorStyle.Render("<Esc>"),
	)
}

func (s stateGetConfirmation) view() string {

	var b strings.Builder
	fmt.Fprintf(&b, "\n\n")

	switch {
	case !s.checking:
		fmt.Fprintf(&b, "   %s\n\n", s.msg)
		okOrCancel(&b)
	case s.checking:
		fmt.Fprintf(&b, "   %s %s...", s.spinner.View(), s.checkingMsg)
	}
	return b.String()
}

func (s stateGetConfirmation) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case getConfirmationRes:
		s.res = &msg
		s.checking = false
		return s, cmd, nil
	}

	if !isEnter(msg) {
		return s, cmd, nil
	}

	s.checking = true
	s.confirmed = true
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			err := s.post(mctx, s, mdl)
			return getConfirmationRes{err: err}
		},
	), nil
}

var _ state = stateGetConfirmation{}
