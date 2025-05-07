// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type subState int

const (
	subStateLoading subState = 0
	subStatePicking subState = 1
	subStatePutting subState = 2
	subStateDone    subState = 3
)

type statePickYubiSlot struct {
	showEmptySlots bool
	hideReuseSlots bool
	noDeviceKey    bool
	pqKey          bool
	existingTitle  string
	putCheckMsg    string
	loadSlotsHook  func(ctx context.Context, mdl model) (lcl.ListYubiSlotsRes, error)
	putSlotHook    func(ctx context.Context, mdl model, ind proto.YubiIndex) (lcl.PutYubiSlotRes, error)
	nextHook       func(lcl.PutYubiSlotRes) (state, tea.Cmd, error)
	loadingMsg     string

	subState       subState
	spinner        spinner.Model
	emptyPicker    list.Model
	existingPicker list.Model
	activePicker   *list.Model
	inactivePicker *list.Model
	badSlots       []proto.YubiSlot
	putRes         *statePickYubiSlotPutRes
	prevFailure    failure
	yubiInfo       *proto.YubiCardInfo
	index          *proto.YubiIndex
}

type statePickYubiSlotInitRes struct {
	err error
	res lcl.ListYubiSlotsRes
}

type statePickYubiSlotPutRes struct {
	err  error
	slot proto.YubiSlot
	res  lcl.PutYubiSlotRes
}

func (s statePickYubiSlot) summary() summary {
	if s.subState != subStateDone || s.index == nil || s.yubiInfo == nil {
		return nil
	}
	typ, err := s.index.GetT()
	if err != nil {
		return nil
	}
	sty := HappyStyle.Render
	var pq string
	if s.pqKey {
		pq = " for ML-KEM key seed"
	}
	switch typ {
	case proto.YubiIndexType_None:
		return summarySuccessCanceler{
			msg: "Using a local device key",
			cancel: func(s summary) bool {
				_, ok := s.(summarySuccessUseYubi)
				return ok
			},
		}
	case proto.YubiIndexType_Empty:
		slot := s.yubiInfo.EmptySlots[s.index.Empty()]
		return summarySuccess(
			"Using empty YubiKey slot" + pq + ": " + sty(fmt.Sprintf("%d", slot)),
		)
	case proto.YubiIndexType_Reuse:
		key := s.yubiInfo.Keys[s.index.Reuse()]
		skey, err := proto.EntityID(key.Id).StringErr()
		if err != nil {
			return nil
		}
		return summarySuccess(
			"Using existing YubiKey slot" + pq + ": " + sty(skey),
		)
	default:
		return nil
	}

}

func (s statePickYubiSlot) failure() failure { return s.prevFailure }

func (s statePickYubiSlot) init(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	s.spinner = spinner.New()
	s.spinner.Spinner = spinner.Dot
	s.subState = subStateLoading

	return s, tea.Batch(
		s.spinner.Tick,
		func() tea.Msg {
			debugSpinners(mctx)
			res, err := s.loadSlotsHook(mctx.Ctx(), mdl)
			return statePickYubiSlotInitRes{err: err, res: res}
		},
	), nil
}

func (s statePickYubiSlot) loadFromYubiInfo() (statePickYubiSlot, error) {
	y := s.yubiInfo

	badSlotSet := make(map[proto.YubiSlot]bool)
	for _, slot := range s.badSlots {
		badSlotSet[slot] = true
	}

	hasEmptySlots := false
	for _, slot := range y.EmptySlots {
		if !badSlotSet[slot] {
			hasEmptySlots = true
			break
		}
	}

	hasExistingKeys := false
	if !s.hideReuseSlots {
		for _, key := range y.Keys {
			if !badSlotSet[key.Slot] {
				hasExistingKeys = true
				break
			}
		}
	}
	showEmptySlots := hasEmptySlots && s.showEmptySlots

	deviceKey := "🖥️  Use a local device key instead"

	if showEmptySlots {
		var slots []list.Item
		for i, slot := range y.EmptySlots {
			if badSlotSet[slot] {
				continue
			}

			slots = append(slots, yubiSlotItem{
				s:    fmt.Sprintf("🎰 Slot %d", slot),
				i:    i,
				slot: slot,
			})
		}
		if hasExistingKeys {
			lbl := "♻️  Pick an existing key instead"
			if s.pqKey {
				lbl += BoldStyle.Render(" -- STRONGLY DISCOURAGED FOR ML-KEM KEY SEEDS")
			}
			slots = append(slots, yubiSlotItem{
				s:     lbl,
				i:     -1,
				other: true,
			})
		}

		if !s.noDeviceKey {
			slots = append(slots, yubiSlotItem{
				s:      deviceKey,
				i:      -1,
				devkey: true,
			})
		}

		ep := list.New(slots, yubiSlotItemDelegate{}, defaultWidth, listHeight)
		tit := "Pick an empty slot on your Yubikey"
		if s.pqKey {
			tit += " as an ML-KEM Key seed"
		}
		tit += ":"
		ep.Title = tit
		styleList(&ep)
		s.emptyPicker = ep
	}

	if hasExistingKeys {
		var keyItems []list.Item

		for i, key := range y.Keys {

			if badSlotSet[key.Slot] {
				continue
			}

			skey, err := proto.EntityID(key.Id).StringErr()
			if err != nil {
				return s, err
			}
			keyItems = append(keyItems, yubiSlotItem{
				s:     fmt.Sprintf("🔑 Slot %d: %s", key.Slot, skey),
				i:     i,
				slot:  key.Slot,
				reuse: true,
			})
		}
		if showEmptySlots {
			keyItems = append(keyItems, yubiSlotItem{
				s:     "🆕 Generate a new key instead",
				i:     -1,
				other: true,
			})
		}

		if !s.noDeviceKey {

			keyItems = append(keyItems, yubiSlotItem{
				s:      deviceKey,
				i:      -1,
				devkey: true,
			})
		}

		rp := list.New(keyItems, yubiSlotItemDelegate{}, defaultWidth, listHeight)
		rp.Title = s.existingTitle
		styleList(&rp)
		s.existingPicker = rp
	}

	if showEmptySlots {
		s.activePicker = &s.emptyPicker
		s.inactivePicker = &s.existingPicker
	} else {
		s.activePicker = &s.existingPicker
		s.inactivePicker = &s.emptyPicker
	}

	return s, nil
}

func (s statePickYubiSlot) loadInitResIntoState(msg statePickYubiSlotInitRes) (statePickYubiSlot, error) {
	if msg.err != nil {
		return s, msg.err
	}
	y := msg.res.Device
	if y == nil {
		s.subState = subStateDone
		return s, nil
	}
	s.yubiInfo = y
	s.subState = subStatePicking

	// Reload the list of slots every time from the agent
	s.yubiInfo = msg.res.Device

	return s.loadFromYubiInfo()
}

func (s statePickYubiSlot) swapPickers() statePickYubiSlot {
	s.activePicker, s.inactivePicker = s.inactivePicker, s.activePicker
	return s
}

func (s statePickYubiSlot) next(mctx libclient.MetaContext, mdl model) (state, tea.Cmd, error) {
	if s.subState != subStateDone {
		return nil, nil, nil
	}
	var arg lcl.PutYubiSlotRes
	if s.putRes != nil {
		arg = s.putRes.res
	}
	return s.nextHook(arg)
}

func (s statePickYubiSlot) view() string {
	switch s.subState {
	case subStateLoading:
		msg := s.loadingMsg
		if msg == "" {
			msg = "Reading YubiKey..."
		}
		return "\n\n   " + s.spinner.View() + " " + msg
	case subStatePicking:
		return "\n" + s.activePicker.View()
	case subStatePutting:
		return "\n\n   " + s.spinner.View() + " " + s.putCheckMsg
	default:
		return "<nothing to show; internal error>"
	}
}

func (s statePickYubiSlot) loadPutResIntoState(msg statePickYubiSlotPutRes) (statePickYubiSlot, tea.Cmd, error) {
	s.putRes = &msg
	if msg.err == nil {
		s.subState = subStateDone
		return s, nil, nil
	}
	var err error
	s.badSlots = append(s.badSlots, msg.slot)
	s.prevFailure = yubiFailure{err: msg.err}
	s, err = s.loadFromYubiInfo()
	if err != nil {
		return s, nil, err
	}
	s.subState = subStatePicking
	return s, nil, nil
}

func (s statePickYubiSlot) update(mctx libclient.MetaContext, mdl model, msg tea.Msg) (state, tea.Cmd, error) {

	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spinner, cmd = s.spinner.Update(msg)
		return s, cmd, nil
	case statePickYubiSlotInitRes:
		var err error
		s, err = s.loadInitResIntoState(msg)
		return s, nil, err
	case statePickYubiSlotPutRes:
		return s.loadPutResIntoState(msg)
	}

	if s.activePicker == nil {
		return s, nil, nil
	}

	p, cmd := s.activePicker.Update(msg)
	*s.activePicker = p

	if !isEnter(msg) {
		return s, cmd, nil
	}

	i, ok := s.activePicker.SelectedItem().(yubiSlotItem)
	if !ok {
		return s, nil, nil
	}

	if i.other {
		s = s.swapPickers()
		return s, cmd, nil
	}

	var tmp proto.YubiIndex
	switch {
	case i.devkey:
		tmp = proto.NewYubiIndexDefault(proto.YubiIndexType_None)
	case i.reuse:
		tmp = proto.NewYubiIndexWithReuse(uint64(i.i))
	default:
		tmp = proto.NewYubiIndexWithEmpty(uint64(i.i))
	}
	s.index = &tmp
	s.subState = subStatePutting

	return s, tea.Batch(
		cmd,
		func() tea.Msg {
			debugSpinners(mctx)
			res, err := s.putSlotHook(mctx.Ctx(), mdl, tmp)
			return statePickYubiSlotPutRes{
				res:  res,
				err:  err,
				slot: i.slot,
			}
		},
	), nil

}

var _ state = statePickYubiSlot{}
