// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5/pgxpool"
)

func paginate(args []any, q string, pg *rem.InboxPagination) ([]any, string) {
	i := len(args)
	nxtPos := func() string {
		i++
		ret := fmt.Sprintf("$%d", i)
		return ret
	}
	if pg != nil && pg.End > 0 {
		args = append(args, pg.End.Import().UTC())
		q += " AND ctime <= " + nxtPos() + " "
	}
	if pg != nil && pg.Start > 0 {
		args = append(args, pg.Start.Import().UTC())
		q += " AND ctime >=  " + nxtPos() + " "
	}
	q += " ORDER BY ctime DESC "
	if pg != nil && pg.Limit > 0 {
		args = append(args, pg.Limit)
		q += " LIMIT " + nxtPos() + " "
	}
	return args, q
}

const (
	JoinStatePending = "pending"
)

func loadTeamInboxLocal(
	m MetaContext,
	db *pgxpool.Conn,
	tid proto.TeamID,
	pg *rem.InboxPagination,
) (
	[]rem.TeamRawInboxRow,
	error,
) {
	args := []any{m.ShortHostID().ExportToDB(), tid.ExportToDB(), JoinStatePending}
	q := `SELECT token, joiner_party_id, joiner_src_role_type, joiner_src_viz_level, 
	    ctime, permission_token
		FROM local_joinreqs
		WHERE short_host_id=$1 AND team_id=$2 AND state=$3`
	args, q = paginate(args, q, pg)
	rows, err := db.Query(m.Ctx(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []rem.TeamRawInboxRow
	for rows.Next() {
		var tokRaw, pidRaw, ptokRaw []byte
		var srcRol, srcViz int
		var ctime time.Time
		err = rows.Scan(&tokRaw, &pidRaw, &srcRol, &srcViz, &ctime, &ptokRaw)
		if err != nil {
			return nil, err
		}
		var tok proto.TeamRSVPLocal
		err = tok.ImportFromDB(tokRaw)
		if err != nil {
			return nil, err
		}
		var pid proto.PartyID
		err = pid.ImportFromDB(pidRaw)
		if err != nil {
			return nil, err
		}
		var ptok proto.PermissionToken
		err = ptok.ImportFromDB(ptokRaw)
		if err != nil {
			return nil, err
		}
		role, err := core.ImportRoleKeyFromDB(srcRol, srcViz)
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			rem.TeamRawInboxRow{
				Time:  proto.ExportTime(ctime),
				State: rem.JoinreqState_Pending,
				Row: rem.NewTeamRawInboxRowVarWithLocal(
					rem.TeamRawInboxRowLocal{
						Tok:     tok,
						Joiner:  pid,
						SrcRole: role.Export(),
						Perm:    ptok,
					},
				),
			},
		)
	}
	return ret, nil
}

func loadTeamInboxRemote(
	m MetaContext,
	db *pgxpool.Conn,
	tid proto.TeamID,
	pg *rem.InboxPagination,
) (
	[]rem.TeamRawInboxRow,
	error,
) {
	args := []any{m.ShortHostID().ExportToDB(), tid.ExportToDB(), JoinStatePending}
	q := `SELECT token, req, ctime
 	 FROM remote_joinreqs
	 WHERE short_host_id=$1 AND team_id=$2 AND state=$3`
	args, q = paginate(args, q, pg)
	rows, err := db.Query(m.Ctx(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []rem.TeamRawInboxRow
	for rows.Next() {
		var tokRaw, reqRaw []byte
		var ctime time.Time
		err = rows.Scan(&tokRaw, &reqRaw, &ctime)
		if err != nil {
			return nil, err
		}
		var tok proto.TeamRSVPRemote
		err = tok.ImportFromDB(tokRaw)
		if err != nil {
			return nil, err
		}
		var req rem.TeamRemoteJoinReq
		err = core.DecodeFromBytes(&req, reqRaw)
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			rem.TeamRawInboxRow{
				Time:  proto.ExportTime(ctime),
				State: rem.JoinreqState_Pending,
				Row: rem.NewTeamRawInboxRowVarWithRemote(
					rem.TeamRawInboxRowRemote{
						Tok: tok,
						Req: req,
					},
				),
			},
		)

	}
	return ret, nil
}

func mergeRows(
	a []rem.TeamRawInboxRow,
	b []rem.TeamRawInboxRow,
	pg *rem.InboxPagination,
) []rem.TeamRawInboxRow {
	tot := len(a) + len(b)
	if pg != nil && pg.Limit > 0 && tot > int(pg.Limit) {
		tot = int(pg.Limit)
	}
	ret := make([]rem.TeamRawInboxRow, 0, tot)
	var i, j int
	for i < len(a) && j < len(b) && len(ret) < tot {
		if a[i].Time > b[j].Time {
			ret = append(ret, a[i])
			i++
		} else {
			ret = append(ret, b[j])
			j++
		}
	}
	for i < len(a) && len(ret) < tot {
		ret = append(ret, a[i])
		i++
	}
	for j < len(b) && len(ret) < tot {
		ret = append(ret, b[j])
		j++
	}
	return ret
}

func LoadTeamInbox(
	m MetaContext,
	tid proto.TeamID,
	pg *rem.InboxPagination,
) (
	*rem.TeamRawInbox,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	remote, err := loadTeamInboxRemote(m, db, tid, pg)
	if err != nil {
		return nil, err
	}
	loc, err := loadTeamInboxLocal(m, db, tid, pg)
	if err != nil {
		return nil, err
	}
	rows := mergeRows(remote, loc, pg)

	ret := rem.TeamRawInbox{
		Rows: rows,
	}

	return &ret, nil
}
