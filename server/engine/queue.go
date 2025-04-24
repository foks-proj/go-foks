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

type QueueServer struct {
	shared.BaseRPCServer
	sw *shared.Switchboard
}

func (b *QueueServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &QueueClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

func (s *QueueServer) ServerType() proto.ServerType {
	return proto.ServerType_Queue
}

func (s *QueueServer) RequireAuth() shared.AuthType { return shared.AuthTypeInternal }
func (s *QueueServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return nil, shared.CheckKeyValidInternal(m, uhc, key)
}

func (s *QueueServer) Setup(m shared.MetaContext) error {
	s.sw = shared.NewSwitchboard()
	return nil
}

func (s *QueueServer) IsInternal() bool { return true }

type QueueClientConn struct {
	shared.BaseClientConn
	srv *QueueServer
	xp  rpc.Transporter
}

func (c *QueueClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(infra.QueueProtocol(c))
}

func (c *QueueClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *QueueClientConn) Enqueue(ctx context.Context, arg infra.EnqueueArg) error {
	c.srv.sw.Enqueue(arg.QueueId, arg.LaneId, arg.Msg)
	return nil
}

func (c *QueueClientConn) Dequeue(ctx context.Context, arg infra.DequeueArg) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, arg.Wait.Duration())
	defer cancel()
	ret, err := c.srv.sw.Dequeue(ctx, arg.QueueId, arg.LaneId)
	return ret, err
}

func (s *QueueServer) ToRPCServer() shared.RPCServer { return s }

var _ shared.ClientConn = (*QueueClientConn)(nil)
var _ shared.RPCServer = (*QueueServer)(nil)
var _ infra.QueueInterface = (*QueueClientConn)(nil)
