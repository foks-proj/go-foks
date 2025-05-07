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

type stateShowKey struct {
	// internal state
	spinner   spinner.Model
	initRes   *stateShowKeyInitRes
	confirmed bool

	// inputs
	nextState func(s stateShowKey, mdl model) state
	initHook  func(mctx libclient.MetaContext, mdl model) (string, string, error)
}

func (s stateShowKey) summary() summary {
	if s.initRes == nil || len(s.initRes.succ) == 0 {
		return nil
	}
	return summarySuccess(s.initRes.succ)
}

func (s stateShowKey) failure() failure {
	if s.initRes != nil && s.initRes.err != nil {
		return genericFailure{
			err: s.initRes.err,
		}
	}
	return nil
}

type stateShowKeyInitRes struct {
	msg  string
	succ string
	err  error
}

func (s stateShowKey) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot

	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			msg, succ, err := s.initHook(mctx, mdl)
			return stateShowKeyInitRes{
				msg:  msg,
				succ: succ,
				err:  err,
			}
		},
	), nil
}

func (s stateShowKey) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	switch {
	case s.initRes != nil && s.initRes.err == nil && s.confirmed:
		return s.nextState(s, mdl), nil, nil
	case s.initRes != nil && s.initRes.err != nil:
		return stateError{err: s.initRes.err}, nil, nil
	default:
		return nil, nil, nil
	}
}

func anyKey(b *strings.Builder) {
	fmt.Fprintf(b, "  🆗 Press %s to continue\n",
		HappyStyle.Render("<Return>"),
	)
}

func (s stateShowKey) view() string {

	var b strings.Builder
	fmt.Fprintf(&b, "\n")

	switch {
	case s.initRes == nil:
		fmt.Fprintf(&b, "\n   %s Loading...\n", s.spinner.View())
	case s.initRes.err == nil:
		b.WriteString(s.initRes.msg)
		anyKey(&b)
	default:
		fmt.Fprintf(&b, "   ❌ %s\n", s.initRes.err.Error())
	}

	return b.String()
}

func (s stateShowKey) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case stateShowKeyInitRes:
		s.initRes = &msg
		return s, cmd, nil
	case tea.KeyMsg:
		if isEnter(msg) && s.initRes != nil {
			s.confirmed = true
		}
		return s, cmd, nil
	default:
		return s, cmd, nil
	}

}

var _ state = stateShowKey{}
