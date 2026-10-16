package realtime

// Push holds: a team admin delegates the release of a team's pushes to one
// member, the holder. For example, a bot that knows which members want to be
// notified about which messages.
//
// While the holder is an active team member, a send into a channel of the team
// whose read role the holder's role clears writes its push_outbox rows as
// 'held' instead of 'queued'. The relay never claims a held row. The holder
// decides held rows with ReleasePushes (queue or delete), and may queue
// content-free pushes of its own with NotifyMembers. When the hold is cleared,
// or a send finds that the holder has left the team, every row it held is
// queued as is.
//
// The server stores only who holds. Why the holder keeps a member's push back
// is never sent to it.

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

const (
	pushStatusQueued = "queued"
	pushStatusHeld   = "held"

	// maxPushHandleLen bounds the opaque handle of a notify push. It is
	// handed to the push provider as is, so it stays small.
	maxPushHandleLen = 32

	// maxPushNotifyEntries bounds the entries of one rtNotifyMembers call.
	maxPushNotifyEntries = 10000
)

// readPushHolder returns the holder of the push hold on the channel's team and
// app, or nil if there is no hold.
func readPushHolder(
	m shared.MetaContext,
	db shared.Querier,
	channelID int64,
) (
	*proto.UID,
	error,
) {
	var raw []byte
	err := db.QueryRow(
		m.Ctx(),
		`SELECT h.holder_uid
		 FROM push_holds h
		 JOIN channels c ON (c.short_host_id=h.short_host_id
		                     AND c.parent_team_id=h.team_id
		                     AND c.app_id=h.app_id)
		 WHERE c.short_host_id=$1 AND c.channel_id=$2`,
		m.ShortHostID(),
		channelID,
	).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var uid proto.UID
	err = uid.ImportFromDB(raw)
	if err != nil {
		return nil, err
	}
	return &uid, nil
}

// endPushHold deletes the (team, app) push hold, if any, and queues every row
// it held in the team's channels.
func endPushHold(
	m shared.MetaContext,
	tx pgx.Tx,
	team proto.TeamID,
	app proto.RTAppID,
) error {
	appDB, err := app.ExportToDB()
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		m.Ctx(),
		`DELETE FROM push_holds WHERE short_host_id=$1 AND team_id=$2 AND app_id=$3`,
		m.ShortHostID(),
		team.ExportToDB(),
		appDB,
	)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		m.Ctx(),
		`UPDATE push_outbox SET status='queued', mtime=NOW()
		 WHERE short_host_id=$1 AND status='held'
		   AND channel_id IN (
		     SELECT channel_id FROM channels
		     WHERE short_host_id=$1 AND parent_team_id=$2 AND app_id=$3)`,
		m.ShortHostID(),
		team.ExportToDB(),
		appDB,
	)
	return err
}

// roleCanRead reports whether a team role clears a channel's read role.
func roleCanRead(role core.RoleKey, readRole proto.Role) (bool, error) {
	rr, err := core.ImportRole(readRole)
	if err != nil {
		return false, err
	}
	return !role.LessThan(*rr), nil
}

// pushStatusForSend returns the status for a send's push rows. It runs in the
// send transaction, before the push fan-out. If the holder has left the team,
// the hold ends here and the send's rows are queued.
func (s *messageSender) pushStatusForSend(m shared.MetaContext) (string, error) {
	holder, err := readPushHolder(m, s.tx, s.channelID())
	if err != nil {
		return "", err
	}
	if holder == nil {
		return pushStatusQueued, nil
	}
	live, err := activeTeamMembers(m, s.userdb, s.parentTeam, []proto.UID{*holder})
	if err != nil {
		return "", err
	}
	role, ok := live[*holder]
	if !ok {
		err = endPushHold(m, s.tx, s.parentTeam, s.appID)
		if err != nil {
			return "", err
		}
		return pushStatusQueued, nil
	}
	readable, err := roleCanRead(role, s.readRole)
	if err != nil {
		return "", err
	}
	if !readable {
		return pushStatusQueued, nil
	}
	return pushStatusHeld, nil
}

// adminTx runs fn in a realtime transaction, after checking that the caller
// is a team admin or above.
func adminTx(
	m shared.MetaContext,
	team proto.TeamID,
	which string,
	fn func(m shared.MetaContext, tx pgx.Tx) error,
) error {
	userdb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer userdb.Release()
	role, err := AuthorizeUserForTeam(m, userdb, team)
	if err != nil {
		return err
	}
	if !role.IsAdminOrAbove() {
		return core.PermissionError("only team admins may set or clear a push hold")
	}
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return err
	}
	defer rtdb.Release()
	return shared.RetryTx(m, rtdb, which, fn)
}

// SetPushHold places the (team, app) push hold with the caller as holder, or
// replaces the holder of an existing one.
func SetPushHold(m shared.MetaContext, arg rem.RtSetPushHoldArg) error {
	appDB, err := arg.AppID.ExportToDB()
	if err != nil {
		return err
	}
	return adminTx(m, arg.Team, "realtime.SetPushHold",
		func(m shared.MetaContext, tx pgx.Tx) error {
			_, err := tx.Exec(
				m.Ctx(),
				`INSERT INTO push_holds (short_host_id, team_id, app_id, holder_uid, ctime)
				 VALUES ($1, $2, $3, $4, NOW())
				 ON CONFLICT (short_host_id, team_id, app_id)
				 DO UPDATE SET holder_uid=EXCLUDED.holder_uid, ctime=NOW()`,
				m.ShortHostID(),
				arg.Team.ExportToDB(),
				appDB,
				m.UID().ExportToDB(),
			)
			return err
		})
}

// ClearPushHold removes the (team, app) push hold and queues what it held.
func ClearPushHold(m shared.MetaContext, arg rem.RtClearPushHoldArg) error {
	return adminTx(m, arg.Team, "realtime.ClearPushHold",
		func(m shared.MetaContext, tx pgx.Tx) error {
			return endPushHold(m, tx, arg.Team, arg.AppID)
		})
}

// holderChannel is what holderTx loads about the channel.
type holderChannel struct {
	team     proto.TeamID
	readRole proto.Role
}

// holderTx runs fn in a realtime transaction, after checking that the caller
// can read the channel, as rtGetThread does, and holds the push hold on the
// channel's team and app.
func holderTx(
	m shared.MetaContext,
	chid proto.RTChannelID,
	which string,
	fn func(m shared.MetaContext, tx pgx.Tx, ch holderChannel, userdb shared.Querier) error,
) error {
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return err
	}
	defer rtdb.Release()
	userdb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer userdb.Release()

	return shared.RetryTx(m, rtdb, which, func(m shared.MetaContext, tx pgx.Tx) error {
		team, readRole, err := loadChannelForRead(m, tx, chid.Short().Int64())
		if err != nil {
			return err
		}
		role, err := AuthorizeUserForTeam(m, userdb, team)
		if err != nil {
			return err
		}
		readable, err := roleCanRead(*role, readRole)
		if err != nil {
			return err
		}
		if !readable {
			return core.PermissionError("user role too low to read channel")
		}
		holder, err := readPushHolder(m, tx, chid.Short().Int64())
		if err != nil {
			return err
		}
		if holder == nil || !holder.Eq(m.UID()) {
			return core.PermissionError("only the holder of the push hold may release or notify")
		}
		return fn(m, tx, holderChannel{team: team, readRole: readRole}, userdb)
	})
}

// ReleasePushes decides the channel's held rows with seq <= arg.ThroughSeq.
// Rows of members in arg.Keep stay held, rows named in arg.Drop are deleted,
// and for every other member the row with the highest seq is queued and the
// others deleted, so each member gets at most one push per call. Only held
// rows change, so repeating a call is a no-op.
func ReleasePushes(m shared.MetaContext, arg rem.RtReleasePushesArg) error {
	return holderTx(m, arg.ChannelID, "realtime.ReleasePushes",
		func(m shared.MetaContext, tx pgx.Tx, _ holderChannel, _ shared.Querier) error {
			chid := arg.ChannelID.Short().Int64()
			if len(arg.Drop) > 0 {
				uids := make([][]byte, len(arg.Drop))
				seqs := make([]int64, len(arg.Drop))
				for i, d := range arg.Drop {
					uids[i] = d.Uid.ExportToDB()
					seqs[i] = d.Seq.Int64()
				}
				_, err := tx.Exec(
					m.Ctx(),
					`DELETE FROM push_outbox p
					 USING unnest($3::bytea[], $4::bigint[]) AS d(uid, seq)
					 WHERE p.short_host_id=$1 AND p.channel_id=$2 AND p.status='held'
					   AND p.uid=d.uid AND p.seq=d.seq`,
					m.ShortHostID(), chid, uids, seqs,
				)
				if err != nil {
					return err
				}
			}
			keep := make([][]byte, len(arg.Keep))
			for i, u := range arg.Keep {
				keep[i] = u.ExportToDB()
			}
			through := arg.ThroughSeq.Int64()
			_, err := tx.Exec(
				m.Ctx(),
				`UPDATE push_outbox p SET status='queued', mtime=NOW()
				 FROM (SELECT uid, MAX(seq) AS seq FROM push_outbox
				       WHERE short_host_id=$1 AND channel_id=$2 AND status='held'
				         AND seq <= $3 AND NOT (uid = ANY($4::bytea[]))
				       GROUP BY uid) top
				 WHERE p.short_host_id=$1 AND p.channel_id=$2 AND p.status='held'
				   AND p.uid=top.uid AND p.seq=top.seq`,
				m.ShortHostID(), chid, through, keep,
			)
			if err != nil {
				return err
			}
			_, err = tx.Exec(
				m.Ctx(),
				`DELETE FROM push_outbox
				 WHERE short_host_id=$1 AND channel_id=$2 AND status='held'
				   AND seq <= $3 AND NOT (uid = ANY($4::bytea[]))`,
				m.ShortHostID(), chid, through, keep,
			)
			return err
		})
}

// NotifyMembers queues one content-free 'system' push for each listed member
// who can read the channel, carrying the entry's handle in push_outbox.data.
// Members who cannot read the channel are skipped without error. A member
// listed more than once gets one push.
func NotifyMembers(m shared.MetaContext, arg rem.RtNotifyMembersArg) error {
	if len(arg.Entries) > maxPushNotifyEntries {
		return core.BadArgsError("too many push notify entries")
	}
	seen := make(map[proto.UID]bool, len(arg.Entries))
	var entries []rem.RTPushNotify
	var uids []proto.UID
	for _, e := range arg.Entries {
		if len(e.Handle) > maxPushHandleLen {
			return core.BadArgsError("push handle too long")
		}
		if seen[e.Uid] {
			continue
		}
		seen[e.Uid] = true
		entries = append(entries, e)
		uids = append(uids, e.Uid)
	}
	return holderTx(m, arg.ChannelID, "realtime.NotifyMembers",
		func(m shared.MetaContext, tx pgx.Tx, ch holderChannel, userdb shared.Querier) error {
			live, err := activeTeamMembers(m, userdb, ch.team, uids)
			if err != nil {
				return err
			}
			for _, e := range entries {
				role, ok := live[e.Uid]
				if !ok {
					continue
				}
				readable, err := roleCanRead(role, ch.readRole)
				if err != nil {
					return err
				}
				if !readable {
					continue
				}
				var data []byte
				if len(e.Handle) > 0 {
					data = e.Handle
				}
				// Only members with a user_channels row, the same set the
				// send fan-out pushes to.
				_, err = tx.Exec(
					m.Ctx(),
					`INSERT INTO push_outbox
					   (short_host_id, uid, channel_id, kind, seq, data, status, ctime, mtime)
					 SELECT uc.short_host_id, uc.uid, uc.channel_id, 'system', NULL, $4, 'queued', NOW(), NOW()
					   FROM user_channels uc
					  WHERE uc.short_host_id=$1 AND uc.channel_id=$2 AND uc.uid=$3`,
					m.ShortHostID(), arg.ChannelID.Short().Int64(), e.Uid.ExportToDB(), data,
				)
				if err != nil {
					return err
				}
			}
			return nil
		})
}
