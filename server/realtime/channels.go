package realtime

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

func ListAllChannels(
	m shared.MetaContext,
	team proto.TeamID,
	app proto.RTAppID,
) (
	*proto.RTChannelSet,
	error,
) {
	db, err := m.Db(shared.DbTypeRealTime)

	if err != nil {
		return nil, err
	}
	defer db.Release()

	vers, mtime, err := readChannelSet(m, db, team, app)
	if err != nil {
		return nil, err

	}
	var ret proto.RTChannelSet
	ret.Mtime = mtime
	ret.Vers = vers

	lst, err := readAllChannels(m, db, team, app)
	if err != nil {
		return nil, err
	}
	ret.Lst = lst
	// return &ret, nil
	return nil, core.PermissionError("forgot to check permissions, so no data yet")
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

	importLastMessage := func(
		msgType *string,
		msgSeq *int64,
		sendTime *time.Time,
		partyIDRaw []byte,
		uidRaw []byte,
	) (
		*proto.RTMessageMetadata,
		error,
	) {
		var ret proto.RTMessageMetadata
		if msgType == nil &&
			msgSeq == nil &&
			sendTime == nil &&
			len(partyIDRaw) == 0 &&
			len(uidRaw) == 0 {
			return nil, nil
		}
		if msgType == nil {
			return nil, core.BadServerDataError("nil last msgType unexpected")
		}
		err = ret.MsgType.ImportFromDB(*msgType)
		if err != nil {
			return nil, err
		}
		if msgSeq == nil {
			return nil, core.BadServerDataError("nil last msgSeq unexpected")
		}
		ret.MsgSeq = proto.RTMsgSeq(*msgSeq)
		if sendTime == nil {
			return nil, core.BadServerDataError("nil last sendtime unexpected")
		}

		t := proto.ExportTime(*sendTime)
		ret.SendTime = t
		if len(partyIDRaw) == 0 {
			return nil, core.BadServerDataError("nil last sender unexpected")
		}

		var pid proto.PartyID
		err = pid.ImportFromDB(partyIDRaw)
		if err != nil {
			return nil, err
		}
		ret.SenderPartyID = pid

		if uidRaw != nil {
			var uid proto.UID
			err = uid.ImportFromDB(uidRaw)
			if err != nil {
				return nil, err
			}
			ret.FurtherUserAttribution = &uid
		}

		return &ret, nil
	}

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

		lm, err := importLastMessage(
			lastMsgType,
			lastMsgSeq,
			lastSendTime,
			partyIDRaw,
			uidRaw,
		)
		if err != nil {
			return nil, err
		}
		if lm != nil {
			md.LastMsg = lm
		}

		ret = append(ret, md)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}
