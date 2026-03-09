// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"flag"
	"net"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type BeaconServer struct {
	shared.BaseRPCServer
}

var _ shared.RPCServer = (*BeaconServer)(nil)

func (s *BeaconServer) ToRPCServer() shared.RPCServer        { return s }
func (s *BeaconServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (s *BeaconServer) Setup(m shared.MetaContext) error     { return nil }
func (s *BeaconServer) ServerType() proto.ServerType         { return proto.ServerType_Beacon }
func (s *BeaconServer) RequireAuth() shared.AuthType         { return shared.AuthTypeNone }
func (s *BeaconServer) CheckDeviceKey(shared.MetaContext, shared.UserHostContext, proto.EntityID) (*proto.Role, error) {
	return nil, nil
}

func (s *BeaconServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &BeaconClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}

type BeaconClientConn struct {
	shared.BaseClientConn
	srv *BeaconServer
	xp  rpc.Transporter
}

var _ shared.ClientConn = (*BeaconClientConn)(nil)

func (c *BeaconClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(rem.BeaconProtocol(c))
}

func (c *BeaconClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
}

// checkDialAddr checks that the resolves DNS name doesn't point to an internal
// IP address, to avoid SSRF attacks.
func checkDialAddr(m shared.MetaContext, host proto.Hostname, port proto.Port) (proto.TCPAddr, error) {
	var ret proto.TCPAddr
	bcfg, err := m.G().Config().BeaconServerConfig(m.Ctx())
	if err != nil {
		return ret, err
	}
	if bcfg.AllowPrivateIPs() {
		return ret, nil
	}
	ips, err := net.LookupIP(host.String())
	if err != nil {
		return ret, core.BadArgsError("cannot resolve hostname")
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return ret, core.BadArgsError("cannot register a hostname that resolves to a private IP address")
		}
	}
	if len(ips) > 0 {
		ret = proto.NewTCPAddr(proto.Hostname(ips[0].String()), port)
	}
	return ret, nil
}

func (c *BeaconClientConn) BeaconRegister(ctx context.Context, arg rem.BeaconRegisterArg) error {
	m := shared.NewMetaContext(ctx, c.srv.G())
	timeout := 3 * time.Minute
	if arg.Host.IsIPAddr() {
		return core.BadArgsError("cannot register an IP address")
	}
	dialAddr, err := checkDialAddr(m, arg.Host, arg.Port)
	if err != nil {
		return err
	}
	return shared.BeaconRegisterSrv(m, arg.Host, arg.Port, arg.HostID, timeout, dialAddr)
}

func (c *BeaconClientConn) BeaconLookup(ctx context.Context, arg proto.HostID) (proto.TCPAddr, error) {
	m := shared.NewMetaContext(ctx, c.srv.G())
	return shared.BeaconLookup(m, arg)
}

var _ rem.BeaconInterface = (*BeaconClientConn)(nil)
