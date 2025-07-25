// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type ActiveUserLoader struct {
	opts      LoadActiveUserOpts
	db        *DB
	uinfo     *proto.UserInfo
	uc        *UserContext
	setCurr   bool
	lockState proto.UserLockState
}

type LoadActiveUserOpts struct {
	Standalone      bool
	NeedUnlocked    bool
	ForceYubiUnlock bool // we'll try unlock PUKs via yubi with this flag on
	Timeout         time.Duration
}

func NewActiveUserLoader(o LoadActiveUserOpts) *ActiveUserLoader {
	return &ActiveUserLoader{
		opts: o,
		uc:   &UserContext{},
	}
}

func (a *ActiveUserLoader) WithUser(u *proto.UserInfo) *ActiveUserLoader {
	a.uinfo = u
	return a
}

func (a *ActiveUserLoader) init(m MetaContext) error {
	db, err := m.G().Db(m.Ctx(), DbTypeHard)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *ActiveUserLoader) loadUInfoFromDB(m MetaContext) error {
	if a.uinfo == nil {
		tmp, err := LoadCurrentUserFromDB(m)
		if err != nil {
			return err
		}
		a.uinfo = tmp
		a.setCurr = true
	}
	a.uc.Info = *a.uinfo
	return nil
}

func (a *ActiveUserLoader) updateUserContext(m MetaContext) error {
	k, err := core.ImportLocalUserIndexFromInfo(*a.uinfo)
	if err != nil {
		return err
	}

	// Note -- don't grab g.userMu since we already grabbed it when
	// the activeUserLoader started running.
	g := m.G()

	if a.setCurr {
		g.curr = a.uc
	}
	g.users[*k] = a.uc
	return nil
}

func (a *ActiveUserLoader) probe(m MetaContext) error {
	to := a.opts.Timeout
	if to == 0 {
		to = m.G().Cfg().ProbeTimeout()
	}
	pr, err := m.G().Probe(m.Ctx(), a.uinfo.Fqu.HostID, to)
	if pr != nil && (err == nil || core.IsConnectError(err)) {
		a.uc.SetHomeServer(pr)
	}
	if err != nil {
		return err
	}
	return nil
}

func (a *ActiveUserLoader) Run(m MetaContext) error {

	err := a.init(m)
	if err != nil {
		return err
	}

	g := m.G()
	g.userMu.Lock()
	defer g.userMu.Unlock()

	err = a.loadUInfoFromDB(m)

	// It's ok to have no active user loaded, so return without error.
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil
	}

	if err != nil {
		return err
	}

	err = a.probe(m)

	switch {
	case err == nil:
		err = a.uc.UnlockKeys(m, a.opts)
	case core.IsConnectError(err):
		m.Warnw("ActiveUserLoader::Run", "stage", "probe", "err", err)
		err = nil
	}

	if err != nil {
		return err
	}

	err = a.updateUserContext(m)
	if err != nil {
		return err
	}

	return nil
}

func (a *ActiveUserLoader) GenerateLockError() error {
	switch a.lockState {
	case proto.UserLockState_Passphrase:
		return core.PassphraseLockedError{}
	case proto.UserLockState_Yubi:
		return core.YubiLockedError{Info: *a.uinfo.YubiInfo}
	case proto.UserLockState_Unset:
		return core.InternalError("unset lock state")
	default:
		return nil
	}
}

func (g *GlobalContext) LoadActiveUser(ctx context.Context, opts LoadActiveUserOpts) error {
	m := NewMetaContext(ctx, g)
	aul := NewActiveUserLoader(opts)
	err := aul.Run(m)
	if err != nil {
		return err
	}
	if opts.NeedUnlocked {
		err = aul.GenerateLockError()
		if err != nil {
			return err
		}
	}
	return nil
}

func SwitchActiveUserFallbackToLoad(m MetaContext, ui proto.UserInfo) error {

	_, err := SwitchActiveUser(m, ui)
	if err == nil {
		return nil
	}
	if !errors.Is(err, core.UserNotFoundError{}) {
		return err
	}

	// now try to load via the active user loader
	aul := NewActiveUserLoader(LoadActiveUserOpts{}).WithUser(&ui)
	err = aul.Run(m)
	if err != nil {
		return err
	}

	_, err = SwitchActiveUser(m, ui)
	if err != nil {
		return err
	}

	return nil
}

func LookupAndSwitchUserWithFallback(
	m MetaContext,
	u lcl.LocalUserIndexParsed,
	getDefaultHostID func(m MetaContext) (proto.HostID, error),
) error {

	found, err := LookupUserInAllUsers(m, u, getDefaultHostID)
	if err != nil {
		return err
	}

	err = SwitchActiveUserFallbackToLoad(m, *found)
	if err != nil {
		return err
	}

	return nil
}

func RemoveKey(
	m MetaContext,
	u lcl.LocalUserIndexParsed,
	getDefaultHostID func(m MetaContext) (proto.HostID, error),
) error {
	found, err := LookupUserInAllUsers(m, u, getDefaultHostID)
	if err != nil {
		return err
	}
	if found == nil {
		return core.KeyNotFoundError{Which: "yubikey or backup"}
	}
	return RemoveKeyByInfo(m, *found)
}

func RemoveKeyByInfo(m MetaContext, found proto.UserInfo) error {

	if found.KeyGenus == proto.KeyGenus_Device {
		return core.BadArgsError("cannot remove device key")
	}
	lui, err := core.ImportLocalUserIndexFromInfo(found)
	if err != nil {
		return err
	}
	err = cleanKeyDeleteError(
		m.DeleteUserWithLocalUserIndex(*lui, found.Key),
	)
	if err != nil {
		return err
	}
	err = cleanKeyDeleteError(
		DeleteUserFromDB(m, lui.Export(), found.Key),
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserContext) maybeYubiUnlock(
	m MetaContext,
	opts LoadActiveUserOpts,
) error {
	if !opts.ForceYubiUnlock && u.lockState != proto.UserLockState_Unlocked {
		u.lockState = proto.UserLockState_Yubi
		return nil
	}
	err := u.yubiUnlockUserLocked(m)
	if err != nil {
		return err
	}
	u.lockState = proto.UserLockState_Unlocked // now can be unlocked with the yubi
	return nil
}

func (u *UserContext) maybeClearProvisionalBit(
	m MetaContext,
	skkm *SecretKeyMaterialManager,
) error {
	m.Infow("maybeClearProvisionalBit", "fqu", u.Info.Fqu, "stage", "enter")
	ss := m.G().SecretStore()
	cli, err := u.regClientLocked(m)
	if err != nil {
		return err
	}
	tok := skkm.SelfViewToken()
	if tok == nil {
		return core.InternalError("no self view token in maybeClearProvisionalBit")
	}
	err = cli.ProbeKeyExists(m.Ctx(), rem.ProbeKeyExistsArg{
		Uid:     u.Info.Fqu.Uid,
		SelfTok: *tok,
		DevID:   skkm.DeviceID(),
	})

	// The key wasn't found on the DB, so let's delete it from our keychain since it's no longer useful
	// and potentially dangerous to keep around.
	if _, ok := err.(core.KeyNotFoundError); ok {
		// We previously considered deleting the row from the secret file here, but this makes
		// me nervous, since we'd have to rule out the case of the cleanup racing an ongoing
		// provisioning operation. Revisit this in the future (2025.03.06)
		return nil
	}

	if err != nil {
		return err
	}

	m.Warnw("maybeClearProvisionalBit", "fqu", u.Info.Fqu, "action", "clearing provisional bit from prior crashed run")
	err = skkm.ClearProvisionalBit(m.Ctx(), ss)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserContext) unlockDevOrYubiKey(
	m MetaContext,
	opts LoadActiveUserOpts,
) error {
	u.Lock()
	defer u.Unlock()

	if u.Info.YubiInfo != nil {
		return u.maybeYubiUnlock(m, opts)
	}

	skkm := NewSecretKeyMaterialManager(u.Info.Fqu, u.Info.Role)

	err := skkm.Load(m.Ctx(), m.G().SecretStore(), SecretStoreGetOpts{})

	// It's ok if we can't load a secret key for the current user;
	// this means likely that the user was revoked but we crashed
	// during the clean-up process
	if _, ok := err.(core.KeyNotFoundError); ok {
		return nil
	}

	if err != nil {
		return err
	}

	if skkm.IsProvisional() {
		err = u.maybeClearProvisionalBit(m, skkm)
		if err != nil {
			return err
		}
		// If we failed to clear the provisional bit, then we can't use this key.
		if skkm.IsProvisional() {
			return nil
		}
	}

	u.skmm = skkm
	err = skkm.ReadySeed(m.Ctx())

	// If we have a locked key, we'll hit this error when trying to load ourself.
	// Short-circuit and return the user context.
	if errors.Is(err, core.PassphraseLockedError{}) {
		u.lockState = proto.UserLockState_Passphrase
		return nil
	}

	if err != nil {
		return err
	}

	u.lockState = proto.UserLockState_Unlocked

	return nil
}

func (u *UserContext) pingForSSO(m MetaContext) error {
	cli, err := u.UserClient(m)
	if err != nil {
		return err
	}
	_, err = cli.Ping(m.Ctx())
	if err == nil {
		return nil
	}
	if core.IsSSOAuthError(err) {
		u.lockState = proto.UserLockState_SSO
		return nil
	}
	return err
}

func (u *UserContext) MarkSSOUnlocked() error {
	u.unlockKeysMu.Lock()
	defer u.unlockKeysMu.Unlock()
	if u.lockState == proto.UserLockState_SSO {
		u.lockState = proto.UserLockState_Unlocked
	}
	return nil
}

func (u *UserContext) UnlockKeys(m MetaContext, opts LoadActiveUserOpts) error {

	u.unlockKeysMu.Lock()
	defer u.unlockKeysMu.Unlock()

	err := u.unlockDevOrYubiKey(m, opts)
	if err != nil {
		return err
	}

	if u.lockState != proto.UserLockState_Unlocked {
		return nil
	}

	err = u.pingForSSO(m)
	if err != nil {
		return err
	}

	// might transition to UserLockStateSSO if our ping of the user server failed with
	// an SSO-related error.
	if u.lockState != proto.UserLockState_Unlocked {
		return nil
	}

	err = u.PopulateWithDevkey(m)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserContext) IsConnected() bool {
	hs := u.HomeServer()
	return hs != nil && hs.IsConnected()
}

func (u *UserContext) Reconnect(m MetaContext) error {
	hs := u.HomeServer()

	// Should always be set, even if we failed to connect
	if hs == nil {
		return core.InternalError("no home server")
	}

	if hs.IsConnected() {
		return nil
	}

	err := hs.Reconnect(m)
	if err != nil {
		return err
	}

	to, err := m.G().Cfg().UserTimeout()
	if err != nil {
		return err
	}
	opts := LoadActiveUserOpts{
		Timeout: to,
	}

	return u.UnlockKeys(m, opts)
}

type ACUOpts struct {
	AssertUnlocked bool
	SSOLogin       bool
}

func (m MetaContext) ActiveConnectedUser(
	opts *ACUOpts,
) (
	*UserContext,
	error,
) {
	g := m.G()
	au := g.ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	err := au.Reconnect(m)
	if err != nil {
		return nil, err
	}
	if opts == nil || !opts.AssertUnlocked {
		return au, nil
	}

	err = au.AssertUnlocked(m.Ctx())
	if err == nil {
		return au, nil
	}
	if opts.SSOLogin && errors.Is(err, core.SSOIdPLockedError{}) {
		return au, nil
	}
	return nil, err
}
