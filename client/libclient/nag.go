// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

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
	Scvi  *proto.ServerClientVersionInfo
}

type GlobalNagState struct {
	ClientVersion ClientVersionNagState
}

func (g *GlobalContext) GetGlobalNagState() GlobalNagState {
	g.Lock()
	defer g.Unlock()
	if g.nagState == nil {
		return GlobalNagState{}
	}
	return *g.nagState
}

func (g *GlobalContext) SetGlobalNagState(n GlobalNagState) {
	g.Lock()
	defer g.Unlock()
	g.nagState = &n
}

type NagMinder struct {

	// Args in from caller
	WithRateLimit bool
	CliVersion    proto.ClientVersionExt

	// internal state
	scv *proto.ServerClientVersionInfo

	// result
	res []lcl.UnifiedNag
}

const nagRefreshInterval = 30 * time.Second
const nagVersionClashSnoozeInterval = 30 * time.Second
const nagUpgradeAvailableSnoozeInterval = 1 * time.Hour

func (n *NagMinder) getServerClientVersionInfo(m MetaContext) error {

	au, err := m.ActiveConnectedUser(&ACUOpts{})
	// it's ok if there is no active user, we will skip this particular nag if so
	if err != nil && errors.Is(err, core.NoActiveUserError{}) {
		return nil
	}
	if err != nil {
		return err
	}

	gns := m.G().GetGlobalNagState()
	refr := gns.ClientVersion.Times.Refreshed
	now := m.G().Now()
	diff := now.Sub(refr)

	if diff < nagRefreshInterval && gns.ClientVersion.Scvi != nil && n.WithRateLimit {
		tmp := *gns.ClientVersion.Scvi
		n.scv = &tmp
		return nil
	}

	reg, err := au.RegClient(m)
	if err != nil {
		return err
	}

	scv, err := reg.GetClientVersionInfo(m.Ctx(), proto.ClientVersionExt{
		Vers:            core.CurrentClientVersion,
		LinkerVersion:   LinkerVersion,
		LinkerPackaging: LinkerPackaging,
	})

	if err != nil {
		return err
	}
	n.scv = &scv

	gns.ClientVersion.Scvi = n.scv
	gns.ClientVersion.Times.Refreshed = now
	m.G().SetGlobalNagState(gns)

	return nil
}

func (n *NagMinder) checkClientCriticallyOutdated(m MetaContext) (bool, error) {
	if n.scv == nil {
		return false, nil
	}
	if n.scv.Min == nil {
		return false, nil
	}
	diff := n.scv.Min.Cmp(core.CurrentClientVersion)
	if diff > 0 {
		n.res = append(n.res, lcl.NewUnifiedNagWithClientversioncritical(
			lcl.UpgradeNagInfo{
				Agent:  core.CurrentClientVersion,
				Server: *n.scv,
			},
		),
		)
		return true, nil
	}
	return false, nil
}

func (n *NagMinder) checkAgentVersionClash(m MetaContext) (bool, error) {

	diff := core.CurrentClientVersion.Cmp(n.CliVersion.Vers)
	if diff == 0 {
		return false, nil
	}
	gns := m.G().GetGlobalNagState()
	now := m.G().Now()
	shown := gns.ClientVersion.Times.Shown
	if !shown.IsZero() &&
		now.Sub(shown) < nagVersionClashSnoozeInterval &&
		n.WithRateLimit {
		return false, nil
	}

	gns.ClientVersion.Times.Shown = now
	m.G().SetGlobalNagState(gns)

	n.res = append(n.res, lcl.NewUnifiedNagWithClientversionclash(
		lcl.CliVersionPair{
			Agent: core.CurrentClientVersion,
			Cli:   n.CliVersion.Vers,
		},
	),
	)
	return true, nil
}

func (n *NagMinder) getDeviceNag(m MetaContext) (bool, error) {
	au, err := m.ActiveConnectedUser(&ACUOpts{})
	if err != nil && errors.Is(err, core.NoActiveUserError{}) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	ns := au.NagState()
	dns := &ns.Device

	var ret lcl.DeviceNagInfo

	ret.NumDevices = uint64(dns.NumDevices)
	now := m.G().Now()
	last := now.Sub(dns.Times.Refreshed)
	if last < nagRefreshInterval && n.WithRateLimit {
		return false, nil
	}

	ucli, err := au.UserClient(m)
	if err != nil {
		return false, err
	}
	info, err := ucli.GetDeviceNag(m.Ctx())
	if err != nil {
		return false, err
	}
	now = m.G().Now()
	dns.NumDevices = info.NumDevices
	ret.NumDevices = dns.NumDevices
	dns.Times.Refreshed = now
	au.SetNagState(ns)

	if info.Cleared || info.NumDevices > 1 {
		return false, nil
	}

	dns.Times.Shown = now
	au.SetNagState(ns)

	ret.DoNag = true
	n.res = append(n.res, lcl.NewUnifiedNagWithToofewdevices(ret))

	return true, nil
}

func nagIgnoreVersionDbKey(v proto.SemVer) core.KVKey {
	return core.KVKey("ignore-upgrade:" + v.String())
}

func (n *NagMinder) checkUpgradeAvailable(m MetaContext) (bool, error) {

	if n.scv == nil || n.scv.Newest == nil {
		return false, nil
	}

	diff := n.scv.Newest.Cmp(core.CurrentClientVersion)

	// Ignore the case of the client being newer than what the server
	// says is possible. Maybe the client is trying a test build.
	if diff <= 0 {
		return false, nil
	}

	gns := m.G().GetGlobalNagState()
	now := m.G().Now()
	shown := gns.ClientVersion.Times.Shown

	if !shown.IsZero() && n.WithRateLimit &&
		now.Sub(shown) < nagUpgradeAvailableSnoozeInterval {
		return false, nil
	}

	// can also have dismissed the advice via snoozer
	var until proto.Time
	dbKey := nagIgnoreVersionDbKey(*n.scv.Newest)

	_, err := m.DbGetGlobalKV(&until, DbTypeHard, dbKey)

	if err != nil && errors.Is(err, core.RowNotFoundError{}) {
		// noop
	} else if err != nil {
		return false, err
	} else if !until.IsZero() && until.Import().After(now) {
		// snoozed
		return false, nil
	}

	gns.ClientVersion.Times.Shown = now
	m.G().SetGlobalNagState(gns)

	n.res = append(n.res,
		lcl.NewUnifiedNagWithClientversionupgradeavailable(
			lcl.UpgradeNagInfo{
				Agent:  core.CurrentClientVersion,
				Server: *n.scv,
			},
		),
	)
	return true, nil

}

func (n *NagMinder) Run(m MetaContext) error {

	err := n.getServerClientVersionInfo(m)
	if err != nil {
		return err
	}

	done, err := n.checkClientCriticallyOutdated(m)
	if err != nil || done {
		return err
	}

	done, err = n.checkAgentVersionClash(m)
	if err != nil || done {
		return err
	}

	done, err = n.getDeviceNag(m)
	if err != nil || done {
		return err
	}

	done, err = n.checkUpgradeAvailable(m)
	if err != nil || done {
		return err
	}

	return nil
}

func (n *NagMinder) GetResult() []lcl.UnifiedNag {
	return n.res
}

func SnoozeVersionUpgrade(
	m MetaContext,
	dur time.Duration,
	onOff bool,
) error {

	nm := NagMinder{}
	err := nm.getServerClientVersionInfo(m)
	if err != nil {
		return err
	}
	if nm.scv == nil {
		return core.NoActiveUserError{}
	}
	if nm.scv.Newest == nil {
		return core.NotFoundError("newest advertised server version")
	}

	ver := *nm.scv.Newest
	until := m.G().Now().Add(dur)

	untilExp := proto.ExportTime(until)
	dbKey := nagIgnoreVersionDbKey(ver)

	if !onOff {
		err = m.DbDeleteGlobalKV(DbTypeHard, dbKey)
	} else {
		err = m.DbPutTx(
			DbTypeHard,
			[]PutArg{{Key: dbKey, Val: &untilExp}},
		)
	}
	if err != nil {
		return err
	}

	return nil
}
