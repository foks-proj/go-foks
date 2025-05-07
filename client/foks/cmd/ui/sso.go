// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type stateDoSsoLogin struct {
	url      proto.URLString
	spinner  spinner.Model
	loading  bool
	res      *ssoRes
	loginMsg *ssoLoginMsg
}

type ssoLoginMsg struct {
	li  lcl.SsoLoginFlow
	err error
}

type ssoRes struct {
	res proto.SSOLoginRes
	err error
}

var _ state = stateDoSsoLogin{}

func newStateSsoDoLogin() stateDoSsoLogin {
	return stateDoSsoLogin{}
}

func (s stateDoSsoLogin) summary() summary {
	if s.res != nil && s.res.err == nil {
		return summarySuccess("SSO Issuer: " + HappyStyle.Render(s.res.res.Issuer.String()))
	}
	return nil
}
func (s stateDoSsoLogin) failure() failure {
	if s.res != nil && s.res.err != nil {
		return ssoFailure{err: s.res.err}
	}
	return nil
}

func (s stateDoSsoLogin) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.loading = true
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			li, err := mdl.cli.SignupStartSsoLoginFlow(mctx.Ctx(), mdl.sessId)
			return ssoLoginMsg{li: li, err: err}
		},
	), nil
}

func (s stateDoSsoLogin) view() string {
	if s.loading {
		return "\n" + s.spinner.View() + " Generating SSO Login session...."
	}
	if !s.url.IsZero() {
		return "\n" + s.spinner.View() + " Please login via SSO: " + HappyStyle.Render(s.url.String())
	}
	return ""
}

type ssoFailure struct {
	err error
}

func (f ssoFailure) view() string {
	e := ErrorStyle.Render
	return e("✗ ") + "SSO login failure: " + e(f.err.Error())
}

func (s stateDoSsoLogin) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		s.spinner, cmd = s.spinner.Update(msg)
	case ssoLoginMsg:
		s.loginMsg = &msg
		if msg.err == nil {
			s.loading = false
			s.url = msg.li.Url
			cmd = func() tea.Msg {
				res, err := mdl.cli.SignupWaitForSsoLogin(mctx.Ctx(), mdl.sessId)
				return ssoRes{err: err, res: res}
			}
		}
	case ssoRes:
		s.loading = false
		s.res = &msg
	}
	return s, cmd, nil
}

func newStateConfirmSSODetails(res proto.SSOLoginRes) state {
	var b strings.Builder
	b.WriteString(h2Style.Render("Confirm SSO Details") + "\n")
	fmt.Fprintf(&b, "  Username : %s\n", res.Username)
	fmt.Fprintf(&b, "  Email    : %s\n", res.Email)
	fmt.Fprintf(&b, "  Issuer   : %s\n", res.Issuer.String())

	return stateGetConfirmation{
		msg:         b.String(),
		checkingMsg: "Finalizing SSO Login",
		nextState: func(s stateGetConfirmation, mdl model) state {
			return newStatePickEmail()
		},
		post: func(mctx libclient.MetaContext, s stateGetConfirmation, mdl model) error {
			// noop
			return nil
		},
	}
}

func (s stateDoSsoLogin) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	switch {
	case s.res != nil && s.res.err == nil:
		return newStateConfirmSSODetails(s.res.res), nil, nil
	case s.res != nil && s.res.err != nil:
		return stateError{err: s.res.err}, nil, nil
	case s.loginMsg != nil && s.loginMsg.err != nil:
		return stateError{err: s.loginMsg.err}, nil, nil
	default:
		return nil, nil, nil
	}
}
