// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import "time"

type NagState struct {
	Device DeviceNagState
}

type DeviceNagState struct {
	Shown      time.Time
	Refreshed  time.Time
	NumDevices uint64
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
	u.nagState.Device.Shown = m.G().Now()
}
