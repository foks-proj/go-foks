// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type baseItemDelegate struct{}

func (baseItemDelegate) Height() int                               { return 1 }
func (baseItemDelegate) Spacing() int                              { return 0 }
func (baseItemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }

type userInfoItem struct {
	*proto.UserInfo
	i int
}

func (s userInfoItem) FilterValue() string { return "" }

type userInfoItemDelegate struct {
	baseItemDelegate
	opts common_ui.FormatUserInfoOpts
}

func (baseItemDelegate) renderString(w io.Writer, m list.Model, index int, s string) {
	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render(" > " + strings.Join(s, ""))
		}
	}
	_, _ = w.Write([]byte(fn(s)))
}

func (u userInfoItemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(userInfoItem)
	if !ok {
		return
	}
	var s string
	if i.UserInfo != nil {
		var err error
		s, err = common_ui.FormatUserInfoAsPromptItem(*i.UserInfo, &u.opts)
		if err != nil {
			s = fmt.Sprintf("<ERROR: %s>", err)
		}
	} else if u.opts.NewKeyWiz {
		s = "🆕 A new user on this device"
	} else {
		s = "🆕 Go ahead and create a new user."
	}
	u.renderString(w, m, index, s)
}

type yubiDeviceItem struct {
	*proto.YubiCardID
	i int
}

func (s yubiDeviceItem) FilterValue() string { return "" }

func (y yubiDeviceItemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(yubiDeviceItem)
	if !ok {
		return
	}
	var s string
	if i.YubiCardID != nil {
		s = fmt.Sprintf("🔑 %s 0x%x", string(i.YubiCardID.Name), uint(i.YubiCardID.Serial))
	} else {
		s = "🖥️  Use local device keys instead"
	}
	y.renderString(w, m, index, s)
}

type yubiDeviceItemDelegate struct {
	baseItemDelegate
}

type simpleItem struct {
	i int
	s string
}

func (s simpleItem) FilterValue() string { return "" }

type simpleItemDelegate struct {
	baseItemDelegate
}

func (d simpleItemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(simpleItem)
	if !ok {
		return
	}
	d.renderString(w, m, index, i.s)
}

type yubiSlotItem struct {
	i      int
	s      string
	slot   proto.YubiSlot
	devkey bool
	other  bool
	reuse  bool
}

func (s yubiSlotItem) FilterValue() string { return "" }

type yubiSlotItemDelegate struct {
	baseItemDelegate
}

func (d yubiSlotItemDelegate) Render(w io.Writer, m list.Model, index int, listITem list.Item) {
	i, ok := listITem.(yubiSlotItem)
	if !ok {
		return
	}
	d.renderString(w, m, index, i.s)
}
