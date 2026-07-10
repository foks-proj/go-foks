package realtime

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

// reconcileUserChannels implements the late-join fan-in (issue #301): a user
// added to a team -- or promoted past a channel's read role -- after a channel
// was created never got a user_channels membership row from the creation
// fanout, leaving them without delivery bumps, invisible threads in
// rtGetChangedThreads, and a failing rtReadThrough. This pass diffs the
// channels of the user's current teams against their membership rows and fans
// them into anything missing, one inbox-version bump per stamped row (the
// UNIQUE user_channels_inbox_idx forbids batch-stamping). The fresh bumps make
// the discovered channels surface in the very sync (or poll) that triggered
// the reconcile.
//
// It runs at the top of rtGetChangedThreads and rtPollInbox, but its work is
// gated on an exact change signal: user_membership_vers (users DB) is bumped
// in the same transaction as every team_members change for the user, so an
// unchanged version proves an unchanged membership set. The steady-state cost
// per call is therefore a single point read; the team-list/anti-join work runs
// only after an actual membership change (or once per process per user, to
// bootstrap and self-heal). Teams the user has left don't appear in the team
// list, so their lingering rows are never re-created (and the sync's per-team
// re-authorization keeps skipping them).
func reconcileUserChannels(m shared.MetaContext, app proto.RTAppID) error {
	uid := m.UID()
	hub := m.G().RTInboxHub()
	key := shared.RTInboxHubKey{
		HostID: m.ShortHostID(),
		Uid:    uid,
		App:    app,
	}
	appDB, err := app.ExportToDB()
	if err != nil {
		return err
	}

	// Read the membership version BEFORE the team list below: if a change
	// commits in between, we reconcile against the newer memberships but
	// record the older version, so the next call harmlessly re-triggers.
	// The converse -- recording a version whose changes we didn't see --
	// can't happen.
	markerVers, err := readUserMembershipVers(m, uid)
	if err != nil {
		return err
	}
	if seen, ok := hub.ReconciledThrough(key); ok && seen >= markerVers {
		return nil
	}

	// The memory tier missed: process restart, or the marker moved. Consult
	// the persistent tier (fanin_cursors): another process -- or a prior life
	// of this one -- may already have reconciled through markerVers. If so,
	// re-warm the memory tier and skip the heavy pass.
	sqlVers, err := readFaninCursor(m, uid, appDB)
	if err != nil {
		return err
	}
	if sqlVers >= markerVers {
		hub.SetReconciledThrough(key, sqlVers)
		return nil
	}

	// The user's current teams, with their role in each -- one users-DB query.
	// A user can hold memberships at multiple source roles; keep the highest
	// destination role per team.
	teams, err := shared.GetTeamListForUser(m)
	if err != nil {
		return err
	}
	roles := make(map[proto.TeamID]core.RoleKey)
	for _, te := range teams {
		rk, err := core.ImportRole(te.DstRole)
		if err != nil {
			return err
		}
		if prev, ok := roles[te.Id]; !ok || prev.LessThan(*rk) {
			roles[te.Id] = *rk
		}
	}

	var candidates []proto.RTChannelIDShort
	if len(roles) > 0 {
		candidates, err = findMissingChannels(m, app, uid, roles)
		if err != nil {
			return err
		}
	}

	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return err
	}
	defer rtdb.Release()

	// A successful reconcile with nothing to fan still advances both cursor
	// tiers, so neither re-runs the pass until the next real change.
	if len(candidates) == 0 {
		err = upsertFaninCursor(m, rtdb, uid, appDB, markerVers)
		if err != nil {
			return err
		}
		hub.SetReconciledThrough(key, markerVers)
		return nil
	}

	return shared.RetryTx2(m,
		rtdb,
		"realtime.reconcileUserChannels",
		func(m shared.MetaContext, tx pgx.Tx) (func(shared.MetaContext), error) {
			fanned := false
			for _, chid := range candidates {
				inserted, err := fanUserIntoChannel(m, tx, uid, appDB, chid)
				if err != nil {
					return nil, err
				}
				// !inserted = a concurrent device of this user fanned the
				// row in first; the bump is a harmless version gap.
				fanned = fanned || inserted
			}
			// The persistent cursor advances in the same transaction as the
			// backfill it describes: recording success is inseparable from
			// the writes themselves.
			err := upsertFaninCursor(m, tx, uid, appDB, markerVers)
			if err != nil {
				return nil, err
			}
			// Once the writes commit, warm the memory tier, and wake the
			// user's own parked pollers (their other devices) if this call
			// did the fanning.
			return func(m shared.MetaContext) {
				hub.SetReconciledThrough(key, markerVers)
				if fanned {
					wakeInboxPollers(m, app, []proto.UID{uid})
				}
			}, nil
		},
	)
}

// readFaninCursor reads the persistent reconciled-through cursor; a user with
// no row is at 0 (never reconciled, or the soft state was wiped).
func readFaninCursor(
	m shared.MetaContext,
	uid proto.UID,
	appDB string,
) (
	int64,
	error,
) {
	db, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return 0, err
	}
	defer db.Release()
	var v int64
	err = db.QueryRow(
		m.Ctx(),
		`SELECT vers FROM fanin_cursors
		 WHERE short_host_id=$1 AND uid=$2 AND app_id=$3`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		appDB,
	).Scan(&v)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

// upsertFaninCursor advances the persistent reconciled-through cursor,
// monotonically (GREATEST guards against a stale writer racing a fresher
// one). q is either the backfill's transaction -- making the advance atomic
// with the writes it describes -- or a plain connection for the
// nothing-to-fan paths.
func upsertFaninCursor(
	m shared.MetaContext,
	q shared.DbExecer,
	uid proto.UID,
	appDB string,
	vers int64,
) error {
	_, err := q.Exec(
		m.Ctx(),
		`INSERT INTO fanin_cursors (short_host_id, uid, app_id, vers, mtime)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (short_host_id, uid, app_id)
		 DO UPDATE SET vers = GREATEST(fanin_cursors.vers, EXCLUDED.vers),
		               mtime = NOW()`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		appDB,
		vers,
	)
	return err
}

// readUserMembershipVers point-reads the user's membership-change version
// from the users DB; a user with no row (no membership change since the table
// was introduced) is at version 0.
func readUserMembershipVers(
	m shared.MetaContext,
	uid proto.UID,
) (
	int64,
	error,
) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return 0, err
	}
	defer db.Release()
	var v int64
	err = db.QueryRow(
		m.Ctx(),
		`SELECT vers FROM user_membership_vers
		 WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
	).Scan(&v)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

// findMissingChannels returns the IDs of channels in the user's teams that
// their role can read but that have no user_channels membership row, ordered
// by channel ID for deterministic version allocation.
func findMissingChannels(
	m shared.MetaContext,
	app proto.RTAppID,
	uid proto.UID,
	roles map[proto.TeamID]core.RoleKey,
) (
	[]proto.RTChannelIDShort,
	error,
) {
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return nil, err
	}
	defer rtdb.Release()

	appDB, err := app.ExportToDB()
	if err != nil {
		return nil, err
	}
	teamIDs := make([][]byte, 0, len(roles))
	for tid := range roles {
		teamIDs = append(teamIDs, tid.ExportToDB())
	}

	rows, err := rtdb.Query(
		m.Ctx(),
		`SELECT c.channel_id, c.parent_team_id,
		        c.read_role_type, c.read_role_viz_level
		 FROM channels c
		 WHERE c.short_host_id=$1
		 AND c.app_id=$2
		 AND c.parent_team_id = ANY($3)
		 AND NOT EXISTS (
		    SELECT 1 FROM user_channels uc
		    WHERE uc.short_host_id = c.short_host_id
		    AND uc.channel_id = c.channel_id
		    AND uc.uid = $4
		 )
		 ORDER BY c.channel_id ASC`,
		m.ShortHostID().ExportToDB(),
		appDB,
		teamIDs,
		uid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []proto.RTChannelIDShort
	for rows.Next() {
		var chid int64
		var teamRaw []byte
		var rrt, rvl int
		err = rows.Scan(&chid, &teamRaw, &rrt, &rvl)
		if err != nil {
			return nil, err
		}
		var team proto.TeamID
		err = team.ImportFromDB(teamRaw)
		if err != nil {
			return nil, err
		}
		// Same membership rule as the creation fanout: the user's team role
		// must be at or above the channel's read role.
		readRole, err := core.ImportRoleKeyFromDB(rrt, rvl)
		if err != nil {
			return nil, err
		}
		role, ok := roles[team]
		if !ok || role.LessThan(*readRole) {
			continue
		}
		ret = append(ret, proto.RTChannelIDShort(chid))
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}
