// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type switchState int

const (
	switchStateLoading   switchState = iota
	switchStateUIGo      switchState = iota
	switchStateSwitching switchState = iota
	switchStateDone      switchState = iota
)

type switchModality int

const (
	switchModalitySwitch switchModality = iota
	switchModalityRemove
)

type switchModel struct {
	g         *libclient.GlobalContext
	usercli   lcl.UserClient
	spinner   spinner.Model
	state     switchState
	users     []proto.UserInfo
	active    *proto.UserInfo
	err       error
	picker    list.Model
	choice    int
	choiceStr string
	modality  switchModality
}

type switchGetExistingMsg struct {
	err   error
	users []proto.UserInfo
}

type switchSwitchMsg struct {
	err error
}

func (m switchModel) Init() tea.Cmd {
	mctx := libclient.NewMetaContextBackground(m.g)
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			users, err := m.usercli.GetExistingUsers(mctx.Ctx())
			return switchGetExistingMsg{err: err, users: users}
		},
	)
}

func (m switchModel) View() string {

	var b strings.Builder
	switch m.state {
	case switchStateLoading:
		fmt.Fprintf(&b, "\n\n %s Loading users...\n", m.spinner.View())
	case switchStateSwitching:
		if m.modality == switchModalitySwitch {
			fmt.Fprintf(&b, "\n\n %s Switching to %s\n", m.spinner.View(), m.choiceStr)
		} else {
			fmt.Fprintf(&b, "\n\n %s Removing %s\n", m.spinner.View(), m.choiceStr)
		}
	case switchStateDone:
		switch {
		case m.err != nil:
			fmt.Fprintf(&b, "\n\n  %s\n\n", ErrorStyle.Render("Error"))
			fmt.Fprintf(&b, "  %s\n\n", RenderError(m.err))
		case len(m.users) == 0:
			if m.modality == switchModalityRemove {
				fmt.Fprintf(&b, "\n\n  %s\n\n", ErrorStyle.Render("No eligible keys found"))
			} else {
				fmt.Fprintf(&b, "\n\n  %s\n\n", ErrorStyle.Render("No inactive users found"))
			}
		default:
			if m.modality == switchModalityRemove {
				fmt.Fprintf(&b, "\n\n ✅ %s Removed %s\n\n", HappyStyle.Render("Success!"), m.choiceStr)
			} else {
				fmt.Fprintf(&b, "\n\n ✅ %s Switched to %s\n\n", HappyStyle.Render("Success!"), m.choiceStr)
			}
		}
		fmt.Fprint(&b, " ✌  Press any key to exit\n")
	case switchStateUIGo:
		if m.active != nil {
			u, err := common_ui.FormatUserInfoAsPromptItem(*m.active,
				&common_ui.FormatUserInfoOpts{
					Active: false,
					Role:   true,
				})
			if err == nil {
				fmt.Fprintf(&b, "\n   Currently [%s] is active.\n", u)
			}
		}
		fmt.Fprintf(&b, "\n%s", m.picker.View())
	default:
	}
	return b.String()
}

func filterOutDevices(users []proto.UserInfo) (*proto.UserInfo, []proto.UserInfo) {
	var active *proto.UserInfo
	ret := make([]proto.UserInfo, 0, len(users))
	sortUserList(users)
	for _, u := range users {
		if u.KeyGenus == proto.KeyGenus_Device {
			continue
		}
		if u.Active {
			tmp := u
			active = &tmp
		} else {
			ret = append(ret, u)
		}
	}
	if active == nil {
		return nil, ret
	}
	return active, ret

}

func filterActive(users []proto.UserInfo) (*proto.UserInfo, []proto.UserInfo) {
	var active *proto.UserInfo
	ret := make([]proto.UserInfo, 0, len(users))
	sortUserList(users)
	for _, u := range users {
		if u.Active {
			tmp := u
			active = &tmp
		} else {
			ret = append(ret, u)
		}
	}
	return active, ret
}

func (m switchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	mctx := libclient.NewMetaContextBackground(m.g)
	var ret tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}
		switch m.state {
		case switchStateUIGo:
			if !isEnter(msg) {
				var cmd tea.Cmd
				m.picker, cmd = m.picker.Update(msg)
				return m, cmd
			}
			m.state = switchStateSwitching
			i, ok := m.picker.SelectedItem().(userInfoItem)
			if !ok {
				return m, tea.Quit
			}
			m.choice = i.i
			u, err := common_ui.FormatUserInfoAsPromptItem(m.users[m.choice], nil)
			if err != nil {
				m.choiceStr = fmt.Sprintf("user errored (%s)", err.Error())
			} else {
				m.choiceStr = u
			}
			ret = tea.Batch(
				m.spinner.Tick,
				func() tea.Msg {
					debugSpinners(mctx)
					var err error
					if m.modality == switchModalitySwitch {
						err = m.usercli.SwitchUserByInfo(mctx.Ctx(), m.users[m.choice])
					} else {
						err = m.usercli.RemoveKeyByInfo(mctx.Ctx(), m.users[m.choice])
					}
					return switchSwitchMsg{err: err}
				},
			)
		case switchStateDone:
			ret = tea.Quit
		}
	case spinner.TickMsg:
		m.spinner, ret = m.spinner.Update(msg)
	case switchSwitchMsg:
		m.err = msg.err
		m.state = switchStateDone
	case switchGetExistingMsg:
		if m.modality == switchModalitySwitch {
			m.active, m.users = filterActive(msg.users)
		} else {
			m.active, m.users = filterOutDevices(msg.users)
		}
		m.err = msg.err
		if m.err != nil || len(m.users) == 0 {
			m.state = switchStateDone
		} else {
			m.state = switchStateUIGo
			items := make([]list.Item, len(m.users))
			for i, item := range m.users {
				tmp := item
				items[i] = userInfoItem{UserInfo: &tmp, i: i}
			}
			dlg := userInfoItemDelegate{
				opts: common_ui.FormatUserInfoOpts{
					Role:   true,
					Avatar: true,
				},
			}
			l := list.New(items, dlg, defaultWidth, listHeight)
			styleList(&l)
			var prompt string
			if m.modality == switchModalitySwitch {
				prompt = "Select user to switch to: "
			} else {
				prompt = "Select key to remove: "
			}
			l.Title = prompt
			m.picker = l
		}
	}

	return m, ret
}

func (m switchModel) init(mctx libclient.MetaContext) (switchModel, error) {
	m.spinner = spinner.New()
	m.spinner.Spinner = spinner.Dot
	m.state = switchStateLoading
	m.choice = -1
	return m, nil
}

func (m switchModel) run(mctx libclient.MetaContext) error {
	m, err := m.init(mctx)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m).Run()
	return err
}

func RunSwitch(m libclient.MetaContext, cli lcl.UserClient) error {
	model := switchModel{
		g:        m.G(),
		usercli:  cli,
		modality: switchModalitySwitch,
	}
	return model.run(m)
}

func RunRemove(m libclient.MetaContext, cli lcl.UserClient) error {
	model := switchModel{
		g:        m.G(),
		usercli:  cli,
		modality: switchModalityRemove,
	}
	return model.run(m)
}

var _ tea.Model = &switchModel{}
