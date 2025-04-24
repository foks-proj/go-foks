// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"flag"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type ProbeServer struct {
	shared.BaseRPCServer
}

var _ shared.RPCServer = (*ProbeServer)(nil)

func (s *ProbeServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (s *ProbeServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &ProbeClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}

func (s *ProbeServer) Setup(m shared.MetaContext) error {
	return nil
}

func (s *ProbeServer) ServerType() proto.ServerType {
	return proto.ServerType_Probe
}

func (s *ProbeServer) RequireAuth() shared.AuthType { return shared.AuthTypeNone }

func (s *ProbeServer) CheckDeviceKey(shared.MetaContext, shared.UserHostContext, proto.EntityID) (*proto.Role, error) {
	return nil, nil
}

type ProbeClientConn struct {
	shared.BaseClientConn
	srv *ProbeServer
	xp  rpc.Transporter
}

var _ shared.ClientConn = (*ProbeClientConn)(nil)

func (c *ProbeClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(rem.ProbeProtocol(c))
}

func (c *ProbeClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *ProbeClientConn) Probe(ctx context.Context, arg rem.ProbeArg) (rem.ProbeRes, error) {
	mctx := shared.NewMetaContext(ctx, c.srv.G())
	return shared.LoadProbe(mctx, arg)
}

func (s *ProbeServer) ToRPCServer() shared.RPCServer { return s }

var _ rem.ProbeInterface = (*ProbeClientConn)(nil)
