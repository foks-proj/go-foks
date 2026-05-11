// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"errors"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (c *AgentConn) keyList(m libclient.MetaContext) ([]lcl.ActiveDeviceInfo, error) {
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{
		ProbeUnlocked: true,
	})

	// With ProbeUnlocked, we might get back an error in addition to
	// a workable object. So we need to check both conditions here.
	if err != nil {
		if au == nil {
			return nil, err
		}
		if errors.Is(err, core.BotTokenLockedError{}) {
			return nil, err
		}
		// there might be other cases we want to short-cirtcuit,
		// but we are going to be defensive for now and just limit
		// it to the bot token locked case for the benefit of #263.
		// But with the core.BotTokenLockedError, LoadMe() will fail.
		// So in other words, we are NOT exiting here, we are going to let
		// err be stomped by LoadMe(), even if non-zero.
	}

	user, err := libclient.LoadMe(m, au)
	if err != nil {
		return nil, err
	}

	devices := user.Prot().Devices
	var ret []lcl.ActiveDeviceInfo

	dk, err := au.Devkey(m.Ctx())

	if errors.Is(err, core.PassphraseLockedError{}) || errors.Is(err, core.KeyNotFoundError{}) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	var pub proto.EntityID
	if dk != nil {
		pub, err = dk.EntityID()
		if err != nil {
			return nil, err
		}
	}

	for _, d := range devices {
		elem := lcl.ActiveDeviceInfo{Di: d}
		if pub != nil && d.Key.Member.Id.Entity.Eq(pub) {
			elem.Active = true
			if au.ArePUKsUnlocked() {
				elem.Unlocked = true
			}
		}
		ret = append(ret, elem)
	}

	return ret, nil
}

func (c *AgentConn) KeyRevoke(ctx context.Context, arg proto.EntityID) error {
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return err
	}
	return libclient.Revoke(m, au, arg)
}

func (c *AgentConn) KeyList(ctx context.Context, includeHidden bool) (lcl.KeyListRes, error) {

	var ret lcl.KeyListRes
	tmp, err := c.g.ActiveUserExport()

	m := c.MetaContext(ctx)

	if err == nil {
		ret.CurrUser = tmp
	} else if !errors.Is(err, core.UserNotFoundError{}) {
		return ret, err
	}

	klst, err := c.keyList(m)
	if err == nil {
		ret.CurrUserAllKeys = klst
	} else if !errors.Is(err, core.NoActiveUserError{}) {
		return ret, err
	}

	allu, err := libclient.ReadAllUsersAndStatus(m, &libclient.ReadAllUsersOpts{
		IncludeHidden: includeHidden,
	})
	if err != nil {
		return ret, err
	}

	ret.AllUsers = allu

	return ret, nil

}

var _ lcl.KeyInterface = (*AgentConn)(nil)
