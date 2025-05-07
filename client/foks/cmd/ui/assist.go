// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type stateAssistHome struct {
	oked bool
}

var _ state = stateAssistHome{}

func (s stateAssistHome) summary() summary { return nil }
func (s stateAssistHome) failure() failure { return nil }
func (s stateAssistHome) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.oked {
		return stateAssistConfirmUser{}, nil, nil
	}
	return nil, nil, nil
}
func (s stateAssistHome) view() string {
	tmpl := template.Must(template.New("assistHome").Parse(`
{{.Title}}

   • This command assists key creation on {{.Another}} device

   • Run {{.Tick}}foks key new{{.Tick}} on your new device
       and this command on an existing device
   
	
  🆗 Press {{.Enter}} to get started
  ☮️  Or {{.ControlC}} or {{.Esc}} at any time to quit

`))
	data := struct {
		Title    string
		Another  string
		Tick     string
		Enter    string
		ControlC string
		Esc      string
	}{
		Title:    h1Style.Render("📱 FOKS Key Assist 📱"),
		Another:  italicStyle.Render("another"),
		Tick:     "`",
		Enter:    HappyStyle.Render("<Return>"),
		Esc:      ErrorStyle.Render("<Esc>"),
		ControlC: ErrorStyle.Render("<Ctrl+C>"),
	}
	var b strings.Builder
	err := tmpl.Execute(&b, data)
	if err != nil {
		panic(err)
	}
	return b.String()
}

func (s stateAssistHome) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	if isEnter(msg) {
		s.oked = true
	}
	return s, nil, nil
}
func (s stateAssistHome) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	return s, nil, nil
}

type confirmMsg struct {
	uinfo proto.UserInfo
	err   error
}

type stateAssistConfirmUser struct {
	spinner   spinner.Model
	uinfo     *proto.UserInfo
	confirmed bool
}

func (s stateAssistConfirmUser) summary() summary { return nil }
func (s stateAssistConfirmUser) failure() failure { return nil }
func (s stateAssistConfirmUser) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.confirmed && s.uinfo != nil {
		return newStateAssistStartKex(), nil, nil
	}
	return nil, nil, nil
}

type stateFinishAssist struct{}

func (f stateFinishAssist) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	err := mdl.devcli.AssistWaitForKexComplete(mctx.Ctx(), mdl.sessId)
	return finishRes{err: err}
}

func (f stateFinishAssist) view(s stateFinishBase) string {
	return finishProvisionView(s)
}

var _ stateFinishSub = stateFinishAssist{}

func newStateFinishAssist() stateFinishBase { return stateFinishBase{sub: stateFinishAssist{}} }

func newStateAssistStartKex() stateCheckedInput {
	ti := textinput.New()
	ti.Placeholder = "air 424 bee ..."
	ti.Focus()
	ti.Width = 100
	ti.CharLimit = 250
	ti.Prompt = "> "
	s := stateCheckedInput{
		input: ti,
		nextState: func(s stateCheckedInput, mdl model) state {
			return newStateFinishAssist()
		},
		prompt:           "Loading...",
		inputResetCount:  1,
		validate:         func(s string) error { return core.KexSeedHESPConfig.ValidateInput(s) },
		badInputMsg:      "Invalid KEX secret phrase",
		goodInputMsg:     "KEX accepted",
		checkingInputMsg: "Checking KEX secret phrase",
		post: func(mctx libclient.MetaContext, state stateCheckedInput, mdl model) error {
			err := mdl.devcli.AssistGotKexInput(mctx.Ctx(), lcl.KexSessionAndHESP{
				SessionId: mdl.sessId,
				Hesp:      proto.NewKexHESP(state.acceptedInput),
			})
			return err
		},
		initHook: func(mctx libclient.MetaContext, s stateCheckedInput, mdl model) (stateCheckedInput, error) {
			hesp, err := mdl.devcli.AssistStartKex(mctx.Ctx(), mdl.sessId)
			if err != nil {
				return s, err
			}
			s.prompt = fmt.Sprintf(
				"Run `foks key dev new` (or `foks key new`) "+
					"on your new device, and input that phrase here,\n"+
					"or enter the below phrase on that computer:\n\n"+
					"\t%s",
				hesp.String(),
			)
			return s, nil
		},
		cancelInput: func(mctx libclient.MetaContext, mdl model) tea.Cmd {
			return func() tea.Msg {
				err := mdl.devcli.AssistKexCancelInput(mctx.Ctx(), mdl.sessId)
				if err != nil {
					return nil
				}
				return cancelMsg{}
			}
		},
	}
	return s

}
func (s stateAssistConfirmUser) view() string {
	if s.uinfo == nil {
		return fmt.Sprintf("\n\n  %s Loading...", s.spinner.View())
	}
	pi, err := common_ui.FormatUserInfoAsPromptItem(
		*s.uinfo,
		&common_ui.FormatUserInfoOpts{Avatar: false, Active: false},
	)
	if err != nil {
		pi = "<ERROR>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "  Provision new user as %s ?\n\n", HappyStyle.Render(pi))
	fmt.Fprintf(&b, "  🆗 Press %s to confirm\n", HappyStyle.Render("<Return>"))
	fmt.Fprintf(&b, "  ☮️  Or %s or %s at any time to quit\n",
		ErrorStyle.Render("<Ctrl+C>"),
		ErrorStyle.Render("<Esc>"),
	)
	fmt.Fprintf(&b, "\n\n")
	return b.String()
}
func (s stateAssistConfirmUser) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {
	switch msg := msg.(type) {
	case confirmMsg:
		if msg.err != nil {
			return s, nil, msg.err
		}
		s.uinfo = &msg.uinfo
		return s, nil, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case tea.KeyMsg:
		if isEnter(msg) {
			s.confirmed = true
			return s, nil, nil
		}
	}
	return s, nil, nil
}
func (s stateAssistConfirmUser) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinnerStyle
	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			uinfo, err := mdl.devcli.AssistInit(mctx.Ctx(), mdl.sessId)
			return confirmMsg{err: err, uinfo: uinfo}
		},
	), nil
}

var _ state = stateAssistConfirmUser{}

func RunAssist(m libclient.MetaContext) error {
	model := model{
		g:   m.G(),
		s:   stateAssistHome{},
		typ: proto.UISessionType_Assist,
	}
	return runModel(m, model)
}
