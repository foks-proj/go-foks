// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type AutocertServer struct {
	shared.BaseRPCServer
	cfg    shared.AutocertServiceConfigger
	looper *shared.AutocertLooper
	pokeCh chan chan<- error
	lock   *shared.Lock
}

type AutocertClientConn struct {
	shared.BaseClientConn
	srv *AutocertServer
	xp  rpc.Transporter
}

func (s *AutocertServer) ToRPCServer() shared.RPCServer { return s }

func (q *AutocertServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &AutocertClientConn{
		srv:            q,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(q.G(), uhc),
	}
}

func (q *AutocertServer) ServerType() proto.ServerType {
	return proto.ServerType_Autocert
}

func (q *AutocertServer) RequireAuth() shared.AuthType { return shared.AuthTypeInternal }
func (q *AutocertServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return nil, shared.CheckKeyValidInternal(m, uhc, key)
}

func (q *AutocertServer) Setup(m shared.MetaContext) error {
	var err error
	q.cfg, err = m.G().Config().AutocertServiceConfig(m.Ctx())
	if err != nil {
		return err
	}
	q.lock, err = shared.NewLock(q.GetHostID().Short, q.ServerType())
	if err != nil {
		return err
	}
	vhc, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}
	doer, err := m.G().AutocertDoerAtAddr(m.Ctx(), 0)
	if err != nil {
		return err
	}
	q.looper = shared.NewAutocertLooper(
		q.cfg,
		vhc,
		doer,
	)
	err = q.looper.Start(m)
	if err != nil {
		return err
	}
	q.pokeCh = make(chan chan<- error)
	return nil
}

func (q *AutocertServer) IsInternal() bool { return true }

func (c *AutocertClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(infra.AutocertProtocol(c))
}

func (s *AutocertServer) RunBackgroundLoops(m shared.MetaContext, shutdownCh chan<- error) error {
	return s.RunBackgroundLoopsWithLooper(m, shutdownCh, s)
}

func (c *AutocertClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *AutocertServer) DoOnePollForHost(m shared.MetaContext) error {
	err := c.looper.DoSome(m)
	return err
}

func (c *AutocertClientConn) DoAutocert(
	ctx context.Context,
	arg infra.DoAutocertArg,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	err := c.srv.looper.DoHost(m, arg)
	return err
}

func (c *AutocertServer) Poke() error {
	retCh := make(chan error)
	c.pokeCh <- retCh
	return <-retCh
}

func (c *AutocertClientConn) Poke(
	ctx context.Context,
) error {
	return c.srv.Poke()
}

func (c *AutocertServer) GetName() string                         { return "AutocertServer" }
func (c *AutocertServer) GetPokeCh() chan chan<- error            { return c.pokeCh }
func (c *AutocertServer) InitLoop(m shared.MetaContext) error     { return nil }
func (c *AutocertServer) GetLock() *shared.Lock                   { return c.lock }
func (c *AutocertServer) GetConfig() shared.ServerLooperConfigger { return c.cfg.GetLooperConfigger() }

func (c *AutocertServer) PollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error) {
	return c.looper.PollReadyHosts(m)
}

var _ shared.ClientConn = (*AutocertClientConn)(nil)
var _ shared.RPCServer = (*AutocertServer)(nil)
var _ infra.AutocertInterface = (*AutocertClientConn)(nil)
var _ shared.Looper = (*AutocertServer)(nil)
