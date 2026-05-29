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
	rows, err := db.Query(
		m.Ctx(),
		`SELECT c.channel_id_full, c.seqno, c.name_box, c.desc_box,
		        c.read_role_type, c.read_role_viz_level,
		        c.write_role_type, c.write_role_viz_level,
		        c.last_msg_type, c.last_msg_seq, c.last_send_time,
		        cp.party_id, cp.uid,
		        c.ctime, c.mtime, c.updated_at_set_vers
		 FROM channels c
		 LEFT JOIN channel_parties cp ON
		     cp.short_host_id = c.short_host_id
		     AND cp.channel_id = c.channel_id
		     AND cp.party_no = c.last_sender_no
		 WHERE c.short_host_id=$1 AND c.parent_team_id=$2 AND c.app_id=$3
		 ORDER BY c.channel_id ASC`,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		app.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []proto.RTChannelMetadata
	for rows.Next() {
		var (
			idRaw, nameBoxRaw, descBoxRaw []byte
			partyIDRaw, uidRaw            []byte
			seqno                         int
			rrt, rvl, wrt, wvl            int
			lastMsgType                   *string
			lastMsgSeq                    *int64
			lastSendTime                  *time.Time
			ctime, mtime                  time.Time
			updatedAtSetVers              int
		)
		err := rows.Scan(
			&idRaw, &seqno, &nameBoxRaw, &descBoxRaw,
			&rrt, &rvl, &wrt, &wvl,
			&lastMsgType, &lastMsgSeq, &lastSendTime,
			&partyIDRaw, &uidRaw,
			&ctime, &mtime, &updatedAtSetVers,
		)
		if err != nil {
			return nil, err
		}

		md := proto.RTChannelMetadata{
			ParentTeam:          team,
			AppID:               app,
			Seqno:               proto.RTChannelSeqno(seqno),
			Ctime:               proto.ExportTime(ctime),
			Mtime:               proto.ExportTime(mtime),
			UpdatedAtSetVersion: proto.RTChannelSetVersion(updatedAtSetVers),
		}
		if len(idRaw) != len(md.Id) {
			return nil, core.BadServerDataError("bad channel_id_full length")
		}
		copy(md.Id[:], idRaw)

		err = core.DecodeFromBytes(&md.NameBox, nameBoxRaw)
		if err != nil {
			return nil, err
		}
		if len(descBoxRaw) > 0 {
			var box proto.RTChannelDescBox
			err = core.DecodeFromBytes(&box, descBoxRaw)
			if err != nil {
				return nil, err
			}
			md.DescBox = &box
		}
		err = md.Roles.Read.ImportFromDB(rrt, rvl)
		if err != nil {
			return nil, err
		}
		err = md.Roles.Write.ImportFromDB(wrt, wvl)
		if err != nil {
			return nil, err
		}
		if lastMsgType != nil {
			err = md.LastMsgType.ImportFromDB(*lastMsgType)
			if err != nil {
				return nil, err
			}
		}
		if lastMsgSeq != nil {
			md.LastMsgSeq = proto.RTMsgSeq(*lastMsgSeq)
		}
		if lastSendTime != nil {
			t := proto.ExportTime(*lastSendTime)
			md.LastSendTime = &t
		}
		if partyIDRaw != nil {
			var pid proto.PartyID
			err = pid.ImportFromDB(partyIDRaw)
			if err != nil {
				return nil, err
			}
			md.LastSenderPartyID = &pid
		}
		if uidRaw != nil {
			var uid proto.UID
			err = uid.ImportFromDB(uidRaw)
			if err != nil {
				return nil, err
			}
			md.LastSenderUid = &uid
		}

		ret = append(ret, md)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
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
