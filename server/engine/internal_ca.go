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

type InternalCAServer struct {
	shared.BaseRPCServer
}

func (b *InternalCAServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &InternalCAClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

func (s *InternalCAServer) ServerType() proto.ServerType {
	return proto.ServerType_InternalCA
}

func (s *InternalCAServer) RequireAuth() shared.AuthType { return shared.AuthTypeNone }
func (s *InternalCAServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return nil, nil
}

type InternalCAClientConn struct {
	shared.BaseClientConn
	srv *InternalCAServer
	xp  rpc.Transporter
}

func (c *InternalCAClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(infra.InternalCAProtocol(c))
}

func (c *InternalCAClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *InternalCAClientConn) GetClientCertChainForService(ctx context.Context, arg infra.GetClientCertChainForServiceArg) ([][]byte, error) {
	g := c.srv.G()
	m := shared.NewMetaContext(ctx, g)
	tmp := g.HostID()
	uhc := shared.UserHostContext{
		Uid:    arg.Service,
		HostID: &tmp,
	}
	certChain, err := shared.IssueCertChainInternal(m, uhc, arg.Key)
	if err != nil {
		return nil, err
	}
	return certChain, nil
}

func (s *InternalCAServer) ToRPCServer() shared.RPCServer { return s }

var _ shared.ClientConn = (*InternalCAClientConn)(nil)
var _ shared.RPCServer = (*InternalCAServer)(nil)
var _ infra.InternalCAInterface = (*InternalCAClientConn)(nil)
