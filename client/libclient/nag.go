// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import "time"

type NagState struct {
	Device DeviceNagState
}

type NagTimes struct {
	Shown     time.Time
	Refreshed time.Time
}

type DeviceNagState struct {
	Times      NagTimes
	NumDevices uint64
}

func (g *GlobalContext) NagState() GlobalNagState {
	g.Lock()
	defer g.Unlock()
	if g.nagState == nil {
		return GlobalNagState{}
	}
	return *g.nagState
}

func (g *GlobalContext) SetNagState(n GlobalNagState) {
	g.Lock()
	defer g.Unlock()
	g.nagState = &n
}

func (u *UserContext) NagState() NagState {
	u.Lock()
	defer u.Unlock()
	return u.nagState
}

func (u *UserContext) SetNagState(n NagState) {
	u.Lock()
	defer u.Unlock()
	u.nagState = n
}

func (u *UserContext) ShowDeviceNag(m MetaContext) {
	u.Lock()
	defer u.Unlock()
	u.nagState.Device.Times.Shown = m.G().Now()
}

type ClientVersionNagState struct {
	Times NagTimes
}

type GlobalNagState struct {
	ClientVersion ClientVersionNagState
}
