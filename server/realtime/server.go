package realtime

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
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
	return core.NotImplementedError{}
}

func (c *ClientConn) RtNewChannel(ctx context.Context, arg rem.RtNewChannelArg) (res proto.RTChannelMetadata, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtGetChannel(ctx context.Context, arg proto.RTChannelID) (res proto.RTChannelMetadata, err error) {
	return res, core.NotImplementedError{}
}

func readChannelSet(
	m shared.MetaContext,
	db shared.Querier,
	teamID proto.TeamID,
	appID proto.RTAppID,
) (
	proto.RTChannelSetVersion,
	proto.Time,
	error,
) {
	var vers int
	var mtime time.Time

	var retVers proto.RTChannelSetVersion
	var retTime proto.Time

	err := db.QueryRow(
		m.Ctx(),
		`SELECT vers, mtime FROM channel_sets
		 WHERE short_host_id=$1 AND parent_team_id=$2 AND app_id=$3`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
		appID.ExportToDB(),
	).Scan(&vers, &mtime)
	if err == pgx.ErrNoRows {
		return retVers, retTime, nil
	}
	if err != nil {
		return retVers, retTime, nil
	}
	return proto.RTChannelSetVersion(vers), proto.ExportTime(mtime), nil
}

func readAllChannels(
	m shared.MetaContext,
	db shared.Querier,
	team proto.TeamID,
	app proto.RTAppID,
) (
	[]proto.RTChannelMetadata,
	error,
) {
	return nil, core.NotImplementedError{}
}

func (c *ClientConn) RtListAllChannels(
	ctx context.Context,
	arg rem.RtListAllChannelsArg,
) (
	proto.RTChannelSet,
	error,
) {
	var ret proto.RTChannelSet

	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeRealTime)

	if err != nil {
		return ret, err
	}
	defer db.Release()

	vers, mtime, err := readChannelSet(m, db, arg.Team, arg.AppID)
	if err != nil {
		return ret, err

	}
	ret.Mtime = mtime
	ret.Vers = vers

	lst, err := readAllChannels(m, db, arg.Team, arg.AppID)
	if err != nil {
		return ret, err
	}
	ret.Lst = lst
	return ret, nil
}
func (c *ClientConn) RtSend(ctx context.Context, arg rem.RTSendArg) (res rem.RTSendRes, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtGetThread(ctx context.Context, arg proto.RTThreadQuery) (res proto.RTThreadPage, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtGetInboxVersion(ctx context.Context, arg rem.RTInboxKey) (res proto.RTInboxVersion, err error) {
	return res, core.NotImplementedError{}
}
func (c *ClientConn) RtGetChangedThreads(ctx context.Context, arg rem.RTGetChangedThreadsArg) (res proto.RTInboxDelta, err error) {
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

var _ shared.RPCServer = (*Server)(nil)

var _ rem.RealTimeInterface = (*ClientConn)(nil)
