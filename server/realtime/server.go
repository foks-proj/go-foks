package realtime

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type Server struct {
	shared.BaseRPCServer
}

func (s *Server) ToRPCServer() shared.RPCServer { return s }
func (s *Server) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValid(m, uhc, key)
}
func (s *Server) RequireAuth() shared.AuthType { return shared.AuthTypeExternal }

func (s *Server) ServerType() proto.ServerType {
	return proto.ServerType_RealTime
}

func (s *Server) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &ClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}
func (c *ClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(rem.RealTimeProtocol(c))
}

func (c *ClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

type ClientConn struct {
	shared.BaseClientConn
	srv *Server
	xp  rpc.Transporter
}

func (s *Server) Setup(m shared.MetaContext) error {
	return nil
}

func (c *ClientConn) RtNewChannel(ctx context.Context, arg rem.RtNewChannelArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	err := MakeChannel(m, arg.Md, arg.SetVers)
	return err
}
func (c *ClientConn) RtGetChannel(ctx context.Context, arg proto.RTChannelID) (res rem.RTChannelMetadata, err error) {
	return res, core.NotImplementedError{}
}

func (c *ClientConn) RtListAllChannelsForTeam(
	ctx context.Context,
	arg rem.RtListAllChannelsForTeamArg,
) (
	rem.RTChannelSet,
	error,
) {
	var ret rem.RTChannelSet
	m := shared.NewMetaContextConn(ctx, c)
	p, err := ListAllChannels(m, arg.Team, arg.AppID, arg.Last)
	if err != nil {
		return ret, err
	}
	return *p, nil
}

func (c *ClientConn) RtSend(ctx context.Context, arg rem.RTSendArg) (res rem.RTSendRes, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := SendMessage(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtGetThread(ctx context.Context, arg rem.RTThreadQuery) (res rem.RTThreadPage, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := GetThread(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtGetInboxVersion(ctx context.Context, arg rem.RTInboxKey) (res proto.RTInboxVersion, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtGetChangedThreads(ctx context.Context, arg rem.RTGetChangedThreadsArg) (res rem.RTInboxDelta, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtReadThrough(ctx context.Context, arg rem.RTReadThroughArg) error {
	return core.NotImplementedError{}
}
func (c *ClientConn) RtPollInbox(ctx context.Context, arg rem.RTPollInboxArg) (res proto.RTInboxPollRes, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtSelectVHost(ctx context.Context, arg proto.HostID) error {
	return core.NotImplementedError{}
}
func (c *ClientConn) RtGetThreadRecents(
	ctx context.Context,
	arg rem.RtGetThreadRecentsArg,
) (
	res rem.RTMsgList,
	err error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := GetThreadRecents(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}

var _ shared.RPCServer = (*Server)(nil)

var _ rem.RealTimeInterface = (*ClientConn)(nil)
