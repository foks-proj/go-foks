// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type statePickYubiState int

const (
	statePickYubiLoading statePickYubiState = 0
	statePickYubiPicking statePickYubiState = 1
	statePickYubiPutting statePickYubiState = 2
	statePickYubiDone    statePickYubiState = 3
)

type statePickYubi struct {

	// callers should initialize these fields...
	bypassItem    bool
	needYubi      bool
	loadListHook  func(ctx context.Context, mdl model) ([]proto.YubiCardID, error)
	makeTitleHook func(n int) string
	putHook       func(ctx context.Context, mdl model, yd proto.YubiCardID, i int) error
	nextHook      func(i *proto.YubiCardID) (state, tea.Cmd, error)
	loadingMsg    string

	choice      int
	yubiDevices []proto.YubiCardID
	spinner     spinner.Model
	state       statePickYubiState
	picker      list.Model
	fail        failure
	pickedYubi  *proto.YubiCardID
}

type statePickYubiInitRes struct {
	err error
	lst []proto.YubiCardID
}

type statePickYubiPutRes struct {
	err error
}

func (s statePickYubi) offset() int {
	if s.bypassItem {
		return 1
	}
	return 0
}

func (s statePickYubi) summary() summary {
	switch {
	case s.pickedYubi != nil:
		msg := fmt.Sprintf("%s: %s",
			"Using YubiKey device",
			HappyStyle.Render(string(s.pickedYubi.Name)))
		return summarySuccessUseYubi{
			summarySuccess: summarySuccess(msg),
		}
	case s.pickedYubi == nil && !s.needYubi:
		return summarySuccess(
			"Using a local device key (" + italicStyle.Render("not a yubikey") + ")",
		)
	default:
		return nil
	}
}

func (s statePickYubi) failure() failure { return s.fail }

func (s statePickYubi) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.state = statePickYubiLoading

	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			lst, err := s.loadListHook(mctx.Ctx(), mdl)
			return statePickYubiInitRes{err: err, lst: lst}
		},
	), nil
}

func (s statePickYubi) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.state != statePickYubiDone {
		return nil, nil, nil
	}
	return s.nextHook(s.pickedYubi)
}

func (s statePickYubi) loadListIntoState(lst []proto.YubiCardID) statePickYubi {
	s.yubiDevices = lst
	s.choice = -1

	items := make([]list.Item, len(lst)+s.offset())
	if s.bypassItem {
		items[0] = yubiDeviceItem{i: 0}
	}
	for i, yd := range lst {
		tmp := yd
		items[i+s.offset()] = yubiDeviceItem{YubiCardID: &tmp, i: i + s.offset()}
	}

	l := list.New(items, yubiDeviceItemDelegate{}, defaultWidth, listHeight)
	l.Title = s.makeTitleHook(len(lst))
	styleList(&l)
	s.picker = l
	s.state = statePickYubiPicking

	return s
}

func (s statePickYubi) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil

	case statePickYubiInitRes:
		if msg.err != nil {
			return s, nil, msg.err
		}
		s = s.loadListIntoState(msg.lst)
		if len(msg.lst) == 0 {
			if s.needYubi {
				return s, nil, errors.New("no YubiKey devices found")
			}
			s.state = statePickYubiDone
		} else {
			s.state = statePickYubiPicking
		}
		return s, nil, nil

	case statePickYubiPutRes:
		if msg.err != nil {
			s.state = statePickYubiPicking
			s.choice = -1
			s.fail = yubiFailure(msg)
			return s, nil, nil
		}
		s.state = statePickYubiDone
		return s, nil, nil
	}

	var cmd tea.Cmd
	s.picker, cmd = s.picker.Update(msg)

	if !isEnter(msg) {
		return s, cmd, nil
	}

	i, ok := s.picker.SelectedItem().(yubiDeviceItem)
	if !ok {
		s.fail = nil
		return s, cmd, nil
	}
	s.choice = i.i
	s.pickedYubi = i.YubiCardID

	if s.choice == 0 && s.bypassItem {
		s.fail = nil
		s.state = statePickYubiDone
		return s, cmd, nil
	}

	s.state = statePickYubiPutting
	return s,
		tea.Batch(
			cmd,
			func() tea.Msg {
				debugSpinners(mctx)
				err := s.putHook(mctx.Ctx(), mdl, *i.YubiCardID, i.i-s.offset())
				return statePickYubiPutRes{err: err}
			},
		), nil
}

func (s statePickYubi) view() string {
	switch s.state {
	case statePickYubiLoading:
		msg := s.loadingMsg
		if msg == "" {
			msg = "Loading YubiKey devices..."
		}
		return "\n\n  " + s.spinner.View() + " " + msg
	case statePickYubiPutting:
		return "\n\n  " + s.spinner.View() + " Selecting YubiKey device..."
	case statePickYubiPicking:
		return "\n" + s.picker.View()
	default:
		return "<internal error>"
	}
}

var _ state = statePickYubi{}
