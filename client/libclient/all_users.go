// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type deviceNameCacheEntry struct {
	val proto.DeviceLabelAndName
	tm  time.Time
}

type DeviceNameCache struct {
	sync.Mutex
	m map[proto.FixedEntityID]*deviceNameCacheEntry
}

func (d *DeviceNameCache) Get(
	m MetaContext,
	id proto.FixedEntityID,
) *proto.DeviceLabelAndName {
	d.Lock()
	defer d.Unlock()
	if d.m == nil {
		return nil
	}
	ent := d.m[id]
	if ent == nil {
		return nil
	}
	if m.G().Now().Sub(ent.tm) > time.Minute {
		delete(d.m, id)
		return nil
	}
	return &ent.val
}

func (d *DeviceNameCache) Set(
	m MetaContext,
	id proto.FixedEntityID,
	name proto.DeviceLabelAndName,
) {
	d.Lock()
	defer d.Unlock()
	if d.m == nil {
		d.m = make(map[proto.FixedEntityID]*deviceNameCacheEntry)
	}
	d.m[id] = &deviceNameCacheEntry{
		val: name,
		tm:  m.G().Now(),
	}
}

func lookupDeviceName(
	m MetaContext,
	fqu proto.FQUser,
	e proto.EntityID,
) (
	*proto.DeviceLabelAndName,
	error,
) {
	fxid, err := e.Fixed()
	if err != nil {
		return nil, err
	}
	dc := m.G().DeviceNameCache()
	name := dc.Get(m, fxid)
	if name != nil {
		return name, nil
	}

	var state lcl.UserSigchainState

	_, err = m.DbGet(
		&state,
		DbTypeHard,
		&fqu,
		lcl.DataType_UserSigchainState,
		core.EmptyKey{},
	)
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ret *proto.DeviceLabelAndName
	for _, d := range state.Devices {
		if d.Dn != nil && d.Key.Member.Id.Entity.Eq(e) {
			ret = d.Dn
			break
		}
	}
	if ret == nil {
		return nil, nil
	}
	dc.Set(m, fxid, *ret)
	return ret, nil
}

// Manage the loading of all users who have accounts on this machine, as required by some
// CLI tools. This might get slightly tricky if the user has blown away their SQLite local
// DB, a case that we should try to handle as gracefully as possible. In this case, we
// still can recover the users from the secret store file, and we try to do that here.

type AllUserReader struct {
	all        map[core.LocalUserIndex]proto.UserInfo
	db         map[core.LocalUserIndex]proto.UserInfo
	secrets    map[core.LocalUserIndex]proto.UserInfo
	repairList []proto.UserInfo
	order      []core.LocalUserIndex
	active     *core.LocalUserIndex
}

func NewAllUserLoader() *AllUserReader {
	return &AllUserReader{
		all:     make(map[core.LocalUserIndex]proto.UserInfo),
		db:      make(map[core.LocalUserIndex]proto.UserInfo),
		secrets: make(map[core.LocalUserIndex]proto.UserInfo),
	}
}

func (a *AllUserReader) Users() []proto.UserInfo {
	ret := make([]proto.UserInfo, len(a.order))
	for i, u := range a.order {
		ret[i] = a.all[u]
	}
	return ret
}

func (a *AllUserReader) loadFromDb(m MetaContext) error {

	v, err := LoadAllUsersFromDB(m)
	if err != nil {
		return err
	}

	for _, u := range v {
		k, err := core.ImportLocalUserIndexFromInfo(u)
		if err != nil {
			return err
		}

		if a.active != nil && a.active.Eq(*k) {
			u.Active = true
		}

		if _, ok := a.all[*k]; !ok {
			a.order = append(a.order, *k)
			a.all[*k] = u
		}

		a.db[*k] = u

	}
	return nil
}

func fillHostInfo(m MetaContext, u *proto.UserInfo) error {

	var probe proto.HostchainState
	tm, err := m.DbGet(&probe, DbTypeHard, &u.Fqu.HostID, lcl.DataType_Hostchain, core.EmptyKey{})
	nf := errors.Is(err, core.RowNotFoundError{})
	if err != nil && !nf {
		return err
	}

	age := time.Since(tm.Import())
	if !nf && age <= 24*time.Hour {
		u.HostAddr = probe.Addr
		return nil
	}

	res, err := m.ResolveHostID(u.Fqu.HostID, &chains.ResolveOpts{Timeout: 5 * time.Second})
	if err == nil {
		u.HostAddr = res.Addr
		return nil
	}

	m.Warnw("fillHostInfo", "hostid", u.Fqu.HostID, "cachedAddr", probe.Addr, "err", err)
	if core.IsConnectError(err) && !nf {
		u.HostAddr = probe.Addr
		m.Infow("fillHostInfo", "hostid", u.Fqu.HostID, "cachedAddr", probe.Addr,
			"outcome", "overriding failure; using cached address")
		return nil
	}

	return err
}

func (a *AllUserReader) loadBackupKeys(m MetaContext) error {
	users := m.G().AllUsers()
	for _, u := range users {
		ui := u.Info
		if ui.KeyGenus != proto.KeyGenus_Backup {
			continue
		}
		lui, err := core.ImportLocalUserIndexFromInfo(ui)
		if err != nil {
			return err
		}
		// should not happen
		if _, ok := a.all[*lui]; ok {
			continue
		}

		// This field is not set to true even if we pull it off of
		// live global context, so we still need to set it here.
		if a.active != nil && a.active.Eq(*lui) {
			ui.Active = true
		}

		ui.Devname = u.Devname
		a.order = append(a.order, *lui)
		a.all[*lui] = ui
	}
	return nil
}

func (a *AllUserReader) loadFromSecrets(m MetaContext) error {
	fquList, err := m.G().SecretStore().ListAll()
	if err != nil {
		return err
	}

	for _, fqu := range fquList {
		k, err := core.NewLocalUserIndex(fqu.Fqur.Fqu, fqu.KeyID.EntityID())
		if err != nil {
			return err
		}

		if _, ok := a.all[*k]; ok {
			continue
		}

		tmp := proto.UserInfo{
			Fqu:      fqu.Fqur.Fqu,
			Role:     fqu.Fqur.Role,
			KeyGenus: proto.KeyGenus_Device,
			Key:      fqu.KeyID.EntityID(),
		}

		err = fillHostInfo(m, &tmp)
		if err != nil {
			m.Warnw("AllUserLoader::loadFromSecrets", "fqu", fqu, "err", err)
			continue
		}

		if a.active != nil && a.active.Eq(*k) {
			tmp.Active = true
		}

		a.order = append(a.order, *k)
		a.all[*k] = tmp
		a.secrets[*k] = tmp
		a.repairList = append(a.repairList, tmp)
	}
	return nil
}

func (a *AllUserReader) repair(m MetaContext) error {

	if len(a.repairList) == 0 {
		return nil
	}

	m.Warnw("AllUserLoader::repair", "repairList", a.repairList)

	var ltx LocalDbTx

	for _, r := range a.repairList {
		err := ltx.PutUser(r, false)
		if err != nil {
			return err
		}
	}
	err := ltx.Exec(m)
	if err != nil {
		return err
	}
	return nil
}

func (a *AllUserReader) getActiveUser(m MetaContext) error {
	uc := m.G().ActiveUser()
	if uc == nil {
		return nil
	}
	au := uc.Info
	key, err := core.ImportLocalUserIndexFromInfo(au)
	if err != nil {
		return err
	}
	a.active = key

	return nil
}

func (a *AllUserReader) loadDeviceNames(m MetaContext) error {

	for k, u := range a.all {
		if u.Devname != "" {
			continue
		}
		nm, err := lookupDeviceName(m, u.Fqu, u.Key)
		if err != nil {
			return err
		}
		if nm != nil {
			u.Devname = nm.Name
			a.all[k] = u
		}
	}
	return nil
}

func (a *AllUserReader) Run(m MetaContext) error {

	err := a.getActiveUser(m)
	if err != nil {
		return err
	}

	err = a.loadFromDb(m)
	if err != nil {
		return err
	}

	err = a.loadFromSecrets(m)
	if err != nil {
		return err
	}

	err = a.loadBackupKeys(m)
	if err != nil {
		return err
	}

	err = a.loadDeviceNames(m)
	if err != nil {
		return err
	}

	err = a.repair(m)
	if err != nil {
		return err
	}
	return nil
}

func ReadAllUsers(m MetaContext) ([]proto.UserInfo, error) {
	aul := NewAllUserLoader()
	err := aul.Run(m)
	if err != nil {

		return nil, err
	}
	return aul.Users(), nil
}

func ReadAllUsersAndStatus(m MetaContext) ([]proto.UserInfoAndStatus, error) {
	tmp, err := ReadAllUsers(m)
	if err != nil {
		return nil, err
	}
	res := core.Map(tmp, func(i proto.UserInfo) proto.UserInfoAndStatus {
		return proto.UserInfoAndStatus{
			Info: i,
		}
	})
	return res, nil
}

func LookupSimpleInAllUsers(
	m MetaContext,
	u proto.FQUserAndRole,
) (
	*proto.UserInfo,
	error,
) {

	users, err := ReadAllUsers(m)
	if err != nil {
		return nil, err
	}

	match := func(i proto.UserInfo) (bool, error) {
		req, err := i.Role.Eq(u.Role)
		if err != nil {
			return false, nil
		}
		return (i.Fqu.Eq(u.Fqu) && req), nil
	}
	for _, u := range users {
		ok, err := match(u)
		if err != nil {
			return nil, err
		}
		if ok {
			return &u, nil
		}
	}
	return nil, core.UserNotFoundError{}
}

func LookupUserInAllUsers(
	m MetaContext,
	u lcl.LocalUserIndexParsed,
	getDefaultHostID func(MetaContext) (proto.HostID, error),
) (*proto.UserInfo, error) {
	users, err := ReadAllUsers(m)
	if err != nil {
		return nil, err
	}

	var defHostID proto.HostID

	getDefHost := func() (proto.HostID, error) {
		if !defHostID.IsZero() {
			return defHostID, nil
		}
		tmp, err := getDefaultHostID(m)
		if err != nil {
			return defHostID, err
		}
		defHostID = tmp
		return defHostID, nil
	}

	matchHostname := func(u *proto.ParsedHostname, i proto.UserInfo) (bool, error) {
		if u == nil {
			def, err := getDefHost()
			if err != nil {
				return false, err
			}
			match := !i.Fqu.HostID.IsZero() && def.Eq(i.Fqu.HostID)
			return match, nil
		}

		isName, err := u.GetS()
		if err != nil {
			return false, err
		}
		if isName {
			match := !i.HostAddr.Hostname().IsZero() &&
				u.True().NormEqIgnorePort(i.HostAddr)
			return match, nil
		}
		match := !i.Fqu.HostID.IsZero() && u.False().Eq(i.Fqu.HostID)
		return match, nil
	}

	matchUsername := func(u proto.ParsedUser, i proto.UserInfo) (bool, error) {
		isName, err := u.GetS()
		if err != nil {
			return false, err
		}
		if isName {
			nun, err := core.NormalizeName(u.True())
			if err != nil {
				return false, err
			}
			match := i.Username.EqUsername(nun)
			return match, nil
		}
		match := !i.Fqu.Uid.IsZero() && u.False().Eq(i.Fqu.Uid)
		return match, nil
	}

	match := func(u lcl.LocalUserIndexParsed, i proto.UserInfo) (bool, error) {
		ok, err := matchHostname(u.Fqu.Host, i)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		ok, err = matchUsername(u.Fqu.User, i)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		ok, err = u.Role.Eq(i.Role)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		return true, nil
	}

	var matches []proto.UserInfo

	for _, e := range users {

		ok, err := match(u, e)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		if u.KeyGenus != nil && e.KeyGenus != *u.KeyGenus {
			continue
		}
		if u.KeyID != nil && !e.Key.Eq(u.KeyID) {
			continue
		}
		matches = append(matches, e)
	}

	switch {
	case len(matches) == 0:
		return nil, core.UserNotFoundError{}
	case len(matches) > 1:
		return nil, core.AmbiguousError("two or more users match query; must specify key genus or key ID to disambiguate")
	default:
		return &matches[0], nil
	}
}
