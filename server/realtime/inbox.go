package realtime

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

// defaultInboxPage bounds a single rtGetChangedThreads page when the client
// doesn't ask for a specific size (max=0).
const defaultInboxPage = 100
const maxInboxPage = 1000

const (
	// Timeout default (when the client passes 0) and cap: keep well under
	// typical LB idle timeouts. The client immediately re-issues on return.
	defaultPollInboxTimeout = 25 * time.Second
	maxPollInboxTimeout     = 55 * time.Second
)

func cappedPollTimeout(d proto.DurationMilli) time.Duration {
	ret := d.Duration()
	if ret == 0 {
		return defaultPollInboxTimeout
	}
	if ret > maxPollInboxTimeout {
		return maxPollInboxTimeout
	}
	return ret
}

func cappedInboxPage(max uint64) uint64 {
	if max == 0 {
		return defaultInboxPage
	}
	if max > maxInboxPage {
		return maxInboxPage
	}
	return max
}

// GetInboxVersion returns the authenticated user's current global inbox
// version for the app -- the head that rtGetChangedThreads pages toward. A
// user with no inbox yet is at version 0, which is also what a client passes
// as `since` for a full sync.
func GetInboxVersion(
	m shared.MetaContext,
	arg rem.RTInboxKey,
) (
	proto.RTInboxVersion,
	error,
) {
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return 0, err
	}
	defer rtdb.Release()
	return readInboxVersion(m, rtdb, m.UID(), arg.AppID)
}

func readInboxVersion(
	m shared.MetaContext,
	db shared.Querier,
	uid proto.UID,
	app proto.RTAppID,
) (
	proto.RTInboxVersion,
	error,
) {
	appDB, err := app.ExportToDB()
	if err != nil {
		return 0, err
	}
	var v int64
	err = db.QueryRow(
		m.Ctx(),
		`SELECT inbox_version FROM user_inbox
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
	return proto.RTInboxVersion(v), nil
}

// inboxChannelRaw is one scanned row of the changed-threads query: the shared
// channel-metadata columns plus this user's per-channel state.
type inboxChannelRaw struct {
	md          channelMetadataRaw
	teamRaw     []byte
	inboxVers   int64
	readThrough int64
	hidden      bool
	muted       bool
}

// scanDests matches the changed-threads SELECT: the shared channel-metadata
// columns followed by the parent team and the caller's per-channel state.
func (r *inboxChannelRaw) scanDests() []any {
	return append(r.md.scanDests(),
		&r.teamRaw, &r.inboxVers, &r.readThrough, &r.hidden, &r.muted)
}

// GetChangedThreads implements the inbox sync (see "Inbox View" in
// chat-server-design.md): return metadata for every channel whose
// user_channels row bumped past arg.Since, up to a page, plus the current
// head. The client paginates by re-issuing with since = the highest
// inboxVersion it has received, until it reaches the head.
func GetChangedThreads(
	m shared.MetaContext,
	arg rem.RTGetChangedThreadsArg,
) (
	*rem.RTInboxDelta,
	error,
) {
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return nil, err
	}
	defer rtdb.Release()
	udb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer udb.Release()

	ret := rem.RTInboxDelta{
		AppID:    arg.AppID,
		Channels: []rem.RTInboxChannel{},
	}

	// Late-join fan-in (issue #301): backfill membership rows for channels the
	// user gained access to after creation; the fresh bumps make them surface
	// in this very sync. Best-effort -- a transient failure just defers
	// discovery to the next call.
	err = reconcileUserChannels(m, arg.AppID)
	if err != nil {
		m.Warnw("GetChangedThreads", "stage", "reconcile", "err", err)
	}

	head, err := readInboxVersion(m, rtdb, m.UID(), arg.AppID)
	if err != nil {
		return nil, err
	}
	ret.InboxVersion = head

	// Caught up (or the client is somehow ahead of us; it will full-sync with
	// since=0 if the head it gets back confuses it).
	if head <= arg.Since {
		return &ret, nil
	}

	raws, err := readChangedChannels(m, rtdb, arg, head)
	if err != nil {
		return nil, err
	}

	// Authorize per parent team against the *current* team roster: a
	// user_channels row is written at channel-creation/fan-in time and lingers
	// if the user has since been removed from (or demoted in) the team, so
	// membership rows alone must not leak channel activity. One check per
	// distinct team in the page, memoized.
	roles := make(map[proto.TeamID]*core.RoleKey)
	for _, raw := range raws {
		var team proto.TeamID
		err = team.ImportFromDB(raw.teamRaw)
		if err != nil {
			return nil, err
		}
		role, seen := roles[team]
		if !seen {
			role, err = AuthorizeUserForTeam(m, udb, team)
			if err != nil && !core.IsPermissionError(err) {
				return nil, err
			}
			// nil role (permission error) = no longer a team member; the
			// stale membership rows are skipped, but the sync proceeds for
			// the user's other teams.
			roles[team] = role
		}
		if role == nil {
			continue
		}

		md, err := raw.md.export(team, arg.AppID)
		if err != nil {
			return nil, err
		}
		// Same visibility rules as the channel list: admin-tier channels
		// disappear entirely for callers below admin, and the read-role gate
		// withholds desc/last-message from callers below the read role.
		if md.Tier == proto.RTChannelTier_Admin && !role.IsAdminOrAbove() {
			continue
		}
		err = applyReadRoleGate(md, *role)
		if err != nil {
			return nil, err
		}

		ret.Channels = append(ret.Channels, rem.RTInboxChannel{
			Md:           *md,
			InboxVersion: proto.RTInboxVersion(raw.inboxVers),
			ReadThrough:  proto.RTMsgSeq(raw.readThrough),
			Hidden:       raw.hidden,
			Muted:        raw.muted,
		})
	}
	return &ret, nil
}

// readChangedChannels pages this user's user_channels rows in (since, head],
// oldest bump first, joined against the channel metadata. The upper bound
// keeps the page consistent with the head we already read: a bump that lands
// between the two queries belongs to the next sync round. Driven by the
// user_channels_inbox_idx hot index.
//
// The cursor (client re-issues with since = highest version received) is only
// sound because no two of a user's rows can share an inbox version -- each
// version is a serialized +1 bump of user_inbox stamping exactly one row --
// so a LIMIT boundary can never split a version group. The UNIQUE
// user_channels_inbox_idx enforces this; see its comment in foks_realtime.sql.
func readChangedChannels(
	m shared.MetaContext,
	db shared.Querier,
	arg rem.RTGetChangedThreadsArg,
	head proto.RTInboxVersion,
) (
	[]inboxChannelRaw,
	error,
) {
	appDB, err := arg.AppID.ExportToDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(
		m.Ctx(),
		`SELECT `+channelMetadataCols+`,
		        c.parent_team_id,
		        uc.inbox_version, uc.read_through, uc.hidden, uc.muted
		 FROM user_channels uc
		 JOIN channels c ON
		     c.short_host_id = uc.short_host_id
		     AND c.channel_id = uc.channel_id
		 `+lastSenderJoin+`
		 WHERE uc.short_host_id=$1
		 AND uc.uid=$2
		 AND uc.app_id=$3
		 AND uc.inbox_version > $4
		 AND uc.inbox_version <= $5
		 ORDER BY uc.inbox_version ASC
		 LIMIT $6`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		appDB,
		int64(arg.Since),
		int64(head),
		cappedInboxPage(arg.Max),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []inboxChannelRaw
	for rows.Next() {
		var raw inboxChannelRaw
		err := rows.Scan(raw.scanDests()...)
		if err != nil {
			return nil, err
		}
		ret = append(ret, raw)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

// PollInbox blocks until the caller's inbox version for the app advances past
// arg.Since, the (capped) timeout elapses, or the caller disconnects. It
// returns the current head either way, with Bumped saying which happened; a
// stale Since (head already past it) returns immediately. The client is
// expected to re-issue the poll as soon as it returns (after running a
// rtGetChangedThreads sync on a bump).
//
// Parked pollers are woken by the in-process RTInboxHub, which writers signal
// after their transactions commit. The subscribe-BEFORE-read order below is
// what makes the park race-free: a bump landing between our version read and
// the select still closes the channel we already hold. Wakes carry no data,
// so we always re-read the version after one -- a spurious wake just loops.
func PollInbox(
	m shared.MetaContext,
	arg rem.RTPollInboxArg,
) (
	*proto.RTInboxPollRes,
	error,
) {
	hub := m.G().RTInboxHub()
	key := shared.RTInboxHubKey{
		HostID: m.ShortHostID(),
		Uid:    m.UID(),
		App:    arg.AppID,
	}
	// Late-join fan-in (issue #301), best-effort: if it backfills anything,
	// the caller's version bumps, so the first read below returns Bumped
	// immediately and the client runs the sync that discovers the channels.
	err := reconcileUserChannels(m, arg.AppID)
	if err != nil {
		m.Warnw("PollInbox", "stage", "reconcile", "err", err)
	}

	deadline := time.Now().Add(cappedPollTimeout(arg.Timeout))

	// oneRound runs a single subscribe/read/park round, with the subscription
	// (and the park timer) released via defer on every exit path. A nil, nil
	// return means "go around again" -- after a wake or the final deadline
	// tick -- and the next round re-subscribes before re-reading.
	oneRound := func() (*proto.RTInboxPollRes, error) {
		ch := hub.Subscribe(key)
		defer hub.Unsubscribe(key, ch)

		vers, err := pollInboxOnce(m, arg.AppID)
		if err != nil {
			return nil, err
		}
		if vers > arg.Since {
			return &proto.RTInboxPollRes{Bumped: true, InboxVersion: vers}, nil
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return &proto.RTInboxPollRes{Bumped: false, InboxVersion: vers}, nil
		}
		timer := time.NewTimer(remain)
		defer timer.Stop()
		select {
		case <-ch:
			// Woken; the next round re-reads.
		case <-m.Ctx().Done():
			return nil, m.Ctx().Err()
		case <-timer.C:
			// Deadline; the next round's read returns not-bumped.
		}
		return nil, nil
	}

	for {
		res, err := oneRound()
		if res != nil || err != nil {
			return res, err
		}
	}
}

// pollInboxOnce reads the caller's current head, acquiring and releasing the
// pooled connection around the single query: a parked poller must not pin a
// connection for its whole (potentially ~minute-long) wait.
func pollInboxOnce(
	m shared.MetaContext,
	app proto.RTAppID,
) (
	proto.RTInboxVersion,
	error,
) {
	db, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return 0, err
	}
	defer db.Release()
	return readInboxVersion(m, db, m.UID(), app)
}
