// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

func (c *AgentConn) DeleteMacOSKeychainItem(ctx context.Context) error {

	m := c.MetaContext(ctx)
	if !m.G().Cfg().TestingMode() {
		return core.TestingOnlyError{}
	}

	if !libclient.HasMacOSKeychain {
		return core.PlatformError{}
	}
	ac, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return err
	}
	skkm := ac.Skmm()
	if skkm == nil {
		return core.PassphraseError("no skkm for user")
	}
	ss := m.G().SecretStore()
	err = ss.Load(m.Ctx())
	if err != nil {
		return err
	}
	liid, err := ss.LocalInstanceID()
	if err != nil {
		return err
	}
	return skkm.TestingOnlyDeleteMacOSKeychainItem(ctx, *liid)
}

func (c *AgentConn) GetNoiseFile(ctx context.Context) (string, error) {
	return "", core.NoActiveUserError{}
}

func (c *AgentConn) ClearUserState(ctx context.Context) error {
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return err
	}
	au.ClearConnections()
	return nil
}

func (c *AgentConn) TestTriggerBgUserJob(ctx context.Context) error {
	m := c.MetaContext(ctx)
	job := libclient.NewBgUserRefresh(libclient.NewBgTiming(0, 0, 0))
	return job.Perform(m)
}

func (c *AgentConn) LoadSecretStore(ctx context.Context) (lcl.SecretStore, error) {
	var ret lcl.SecretStore
	m := c.MetaContext(ctx)
	ss := m.G().SecretStore()
	err := ss.Load(m.Ctx())
	if err != nil {
		return ret, err
	}
	tmp := ss.Export()
	if tmp == nil {
		return ret, core.NotFoundError("secret store")
	}
	return *tmp, nil
}

func (c *AgentConn) SetFakeTeamIndexRange(ctx context.Context, arg lcl.SetFakeTeamIndexRangeArg) error {
	m := c.MetaContext(ctx)
	return m.G().Cfg().TestSetFakeRationalRange(arg.Team, core.NewRationalRange(arg.Tir))
}

func (c *AgentConn) SetNetworkConditions(
	ctx context.Context,
	nc lcl.NetworkConditions,
) error {
	m := c.MetaContext(ctx)
	typ, err := nc.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case lcl.NetworkConditionsType_Catastrophic:
		m.G().SetNetworkConditioner(core.CatastrophicNetworkConditions{On: true})
	default:
		m.G().SetNetworkConditioner(nil)
	}
	return nil
}

func (c *AgentConn) GetUnlockedSKMWK(ctx context.Context) (lcl.UnlockedSKMWK, error) {
	var zed lcl.UnlockedSKMWK
	m := c.MetaContext(ctx)
	au := m.G().ActiveUser()
	if au == nil {
		return zed, core.NoActiveUserError{}
	}
	tmp, err := au.GetUnlockedSKMWK(m)
	if err != nil {
		return zed, err
	}
	return *tmp, nil
}

var _ lcl.TestInterface = (*AgentConn)(nil)

func OtherProtocols(
	c *AgentConn,
) []rpc.ProtocolV2 {
	return []rpc.ProtocolV2{
		lcl.TestProtocol(c),
	}
}
