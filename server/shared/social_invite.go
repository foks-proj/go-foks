// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

// Social invites (docs/social_signup_spec.md). All DB and state-machine work
// lives here so the engine handlers, the sweeper and tests share one
// implementation. Readers treat a row past its etime as absent, with one
// exception: the guest fetch keeps serving accepted and declined rows until
// the sweeper takes them, so a decision made just before expiry still
// reaches the invitee.

func exportSocialInviteState(s proto.SocialInviteState) (string, error) {
	switch s {
	case proto.SocialInviteState_Open:
		return "open", nil
	case proto.SocialInviteState_Replied:
		return "replied", nil
	case proto.SocialInviteState_AskAgain:
		return "ask_again", nil
	case proto.SocialInviteState_Accepted:
		return "accepted", nil
	case proto.SocialInviteState_Declined:
		return "declined", nil
	case proto.SocialInviteState_Canceled:
		return "canceled", nil
	default:
		return "", core.BadArgsError("bad social invite state")
	}
}

func importSocialInviteState(s string) (proto.SocialInviteState, error) {
	switch s {
	case "open":
		return proto.SocialInviteState_Open, nil
	case "replied":
		return proto.SocialInviteState_Replied, nil
	case "ask_again":
		return proto.SocialInviteState_AskAgain, nil
	case "accepted":
		return proto.SocialInviteState_Accepted, nil
	case "declined":
		return proto.SocialInviteState_Declined, nil
	case "canceled":
		return proto.SocialInviteState_Canceled, nil
	default:
		return proto.SocialInviteState_None, core.InternalError("bad social invite state in DB")
	}
}

func importSocialInviteParty(s string) (proto.SocialInviteParty, error) {
	switch s {
	case "inviter":
		return proto.SocialInviteParty_Inviter, nil
	case "invitee":
		return proto.SocialInviteParty_Invitee, nil
	default:
		return proto.SocialInviteParty_Inviter, core.InternalError("bad social invite party in DB")
	}
}

func socialInviteSettings(m MetaContext) (Settings, error) {
	return m.G().Config().Settings(m.Ctx())
}

// socialInviteInviterLockID keys a Postgres transaction-scoped advisory lock
// on (host, inviter). Taking it serializes the transactions that count a
// user's rows before inserting one, so a per-user cap cannot be exceeded by
// concurrent inserts: the count and the insert of two racing calls no longer
// interleave.
func socialInviteInviterLockID(shid int, uid proto.UID) int64 {
	h := sha256.New()
	h.Write([]byte("social-invite-inviter"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(shid))
	h.Write(buf[:])
	h.Write(uid[:])
	sum := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func lockSocialInviteInviter(m MetaContext, tx pgx.Tx, shid int, uid proto.UID) error {
	_, err := tx.Exec(m.Ctx(), `SELECT pg_advisory_xact_lock($1)`,
		socialInviteInviterLockID(shid, uid))
	return err
}

// InsertSocialInvite creates a row in state open with the opening message at
// seq 1. If a standard invite code is attached, it must be the caller's and
// unused; the column exists so the sweeper and terminal transitions can
// reclaim it. The code the invitee redeems travels inside the message box.
func InsertSocialInvite(m MetaContext, arg rem.CreateArg, inviter proto.UID) error {
	settings, err := socialInviteSettings(m)
	if err != nil {
		return err
	}

	var code []byte
	if arg.InviteCode != nil {
		typ, err := arg.InviteCode.GetT()
		if err != nil {
			return err
		}
		if typ != rem.InviteCodeType_Standard {
			// Only standard single-use codes attach to a row; a host-wide
			// multiuse code is not per-invitation and is never stored here.
			return core.BadInviteCodeError{}
		}
		code = arg.InviteCode.Standard()
	}

	seedBox, err := core.EncodeToBytes(&arg.SeedBox)
	if err != nil {
		return err
	}
	msgBox, err := core.EncodeToBytes(&arg.Msg)
	if err != nil {
		return err
	}

	// Cap the expiry by host config; a zero etime means "the max". A nonzero
	// etime already in the past is a client bug: the insert would succeed
	// but every reader would treat the row as absent, so the inviter would
	// hand out a link that can never work.
	now := m.Now()
	maxEtime := now.Add(settings.SocialInviteMaxLifespan())
	etime := arg.Etime.Import()
	if arg.Etime != 0 && !etime.After(now) {
		return core.BadArgsError("etime is in the past")
	}
	if arg.Etime == 0 || etime.After(maxEtime) {
		etime = maxEtime
	}

	shid := m.ShortHostID().ExportToDB()

	return RetryTxUserDB(m, "InsertSocialInvite", func(m MetaContext, tx pgx.Tx) error {

		err := lockSocialInviteInviter(m, tx, shid, inviter)
		if err != nil {
			return err
		}

		var nOpen int
		err = tx.QueryRow(m.Ctx(),
			`SELECT COUNT(*) FROM social_invites
			 WHERE short_host_id=$1 AND inviter=$2
			 AND state IN ('open', 'replied', 'ask_again')
			 AND etime > NOW()`,
			shid, inviter.ExportToDB(),
		).Scan(&nOpen)
		if err != nil {
			return err
		}
		if nOpen >= settings.SocialInviteMaxOpen() {
			return core.RateLimitError{}
		}

		var tmp int
		err = tx.QueryRow(m.Ctx(),
			`SELECT 1 FROM teams WHERE short_host_id=$1 AND team_id=$2`,
			shid, arg.Team.ExportToDB(),
		).Scan(&tmp)
		if err == pgx.ErrNoRows {
			return core.TeamNotFoundError{}
		}
		if err != nil {
			return err
		}

		if code != nil {
			// The NOT EXISTS refuses a code already attached to another
			// invitation: canceling that one deletes the code, which would
			// silently revoke this one too.
			err = tx.QueryRow(m.Ctx(),
				`SELECT 1 FROM invite_codes
				 WHERE short_host_id=$1 AND code=$2 AND creator=$3
				 AND used_by IS NULL
				 AND NOT EXISTS (
					SELECT 1 FROM social_invites si
					WHERE si.short_host_id=$1 AND si.invite_code=$2)`,
				shid, code, inviter.ExportToDB(),
			).Scan(&tmp)
			if err == pgx.ErrNoRows {
				return core.BadInviteCodeError{}
			}
			if err != nil {
				return err
			}
		}

		tags, err := tx.Exec(m.Ctx(),
			`INSERT INTO social_invites(
				short_host_id, id, inviter, team_id, state, last_seq,
				invite_code, wk_commit, seed_box, seed_box_gen, invitee,
				ctime, mtime, etime)
			 VALUES($1, $2, $3, $4, 'open', 1, $5, $6, $7, $8, NULL,
			 	NOW(), NOW(), $9)`,
			shid, arg.Id[:], inviter.ExportToDB(), arg.Team.ExportToDB(),
			code, arg.WkCommit[:], seedBox, int(arg.SeedBox.Gen), etime,
		)
		if err != nil {
			if IsDuplicateKeyError(err, "social_invites_pkey") {
				return core.DuplicateError("social invite")
			}
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.InsertError("social_invites")
		}

		tags, err = tx.Exec(m.Ctx(),
			`INSERT INTO social_invite_msgs(
				short_host_id, id, seq, sender, box, ctime)
			 VALUES($1, $2, 1, 'inviter', $3, NOW())`,
			shid, arg.Id[:], msgBox,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.InsertError("social_invite_msgs")
		}
		return nil
	})
}

func importSocialInviteMsg(
	seq uint64,
	sender string,
	box []byte,
) (
	rem.SocialInviteMsg,
	error,
) {
	party, err := importSocialInviteParty(sender)
	if err != nil {
		return rem.SocialInviteMsg{}, err
	}
	var sb proto.SecretBox
	err = core.DecodeFromBytes(&sb, box)
	if err != nil {
		return rem.SocialInviteMsg{}, err
	}
	return rem.SocialInviteMsg{
		Seq:    seq,
		Sender: party,
		Box:    sb,
	}, nil
}

func loadSocialInviteMsgs(
	m MetaContext,
	q Querier,
	id proto.SocialInviteID,
) (
	[]rem.SocialInviteMsg,
	error,
) {
	rows, err := q.Query(m.Ctx(),
		`SELECT seq, sender, box FROM social_invite_msgs
		 WHERE short_host_id=$1 AND id=$2
		 ORDER BY seq ASC`,
		m.ShortHostID().ExportToDB(), id[:],
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []rem.SocialInviteMsg
	for rows.Next() {
		var seq uint64
		var sender string
		var box []byte
		err = rows.Scan(&seq, &sender, &box)
		if err != nil {
			return nil, err
		}
		msg, err := importSocialInviteMsg(seq, sender, box)
		if err != nil {
			return nil, err
		}
		ret = append(ret, msg)
	}
	return ret, rows.Err()
}

// LoadSocialInviteGuestView is the unauthenticated fetch. Unknown, expired
// and canceled rows all answer SocialInviteNotFoundError, so the fetch tells
// a scanner nothing; accepted and declined stay fetchable until the sweeper
// takes them, even past etime, since the invitee is waiting on that answer
// and a decision made just before expiry must survive it. The view carries
// ciphertext and state only: an unauthenticated fetch must not hand the team,
// the inviter or the code to anyone who observed an id in transit.
func LoadSocialInviteGuestView(
	m MetaContext,
	id proto.SocialInviteID,
) (
	*rem.SocialInviteGuestView,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	// State and transcript are two queries; a repeatable-read transaction
	// makes them read one snapshot, so a write committing between them
	// cannot produce a state that disagrees with the messages.
	tx, err := db.BeginTx(m.Ctx(), pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(m.Ctx()) }()

	var stateRaw string
	err = tx.QueryRow(m.Ctx(),
		`SELECT state FROM social_invites
		 WHERE short_host_id=$1 AND id=$2 AND state != 'canceled'
		 AND (etime > NOW() OR state IN ('accepted', 'declined'))`,
		m.ShortHostID().ExportToDB(), id[:],
	).Scan(&stateRaw)
	if err == pgx.ErrNoRows {
		return nil, core.SocialInviteNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	state, err := importSocialInviteState(stateRaw)
	if err != nil {
		return nil, err
	}
	msgs, err := loadSocialInviteMsgs(m, tx, id)
	if err != nil {
		return nil, err
	}
	err = tx.Commit(m.Ctx())
	if err != nil {
		return nil, err
	}
	return &rem.SocialInviteGuestView{
		State: state,
		Msgs:  msgs,
	}, nil
}

// ListSocialInvites returns the caller's non-expired rows in creation order,
// terminal states included: those stay listed until the sweeper's grace
// elapses, and the row is the inviter's only record of the exchange.
func ListSocialInvites(m MetaContext, inviter proto.UID) ([]rem.SocialInviteRow, error) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	// Rows and transcripts are two queries; a repeatable-read transaction
	// makes them read one snapshot (see LoadSocialInviteGuestView).
	tx, err := db.BeginTx(m.Ctx(), pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(m.Ctx()) }()

	rows, err := tx.Query(m.Ctx(),
		`SELECT id, team_id, state, seed_box, invitee, ctime, mtime, etime
		 FROM social_invites
		 WHERE short_host_id=$1 AND inviter=$2 AND etime > NOW()
		 ORDER BY ctime ASC`,
		m.ShortHostID().ExportToDB(), inviter.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []rem.SocialInviteRow
	for rows.Next() {
		var idRaw, teamRaw, seedBoxRaw []byte
		var stateRaw string
		var inviteeRaw []byte
		var ctime, mtime, etime time.Time
		err = rows.Scan(&idRaw, &teamRaw, &stateRaw, &seedBoxRaw,
			&inviteeRaw, &ctime, &mtime, &etime)
		if err != nil {
			return nil, err
		}
		var row rem.SocialInviteRow
		copy(row.Id[:], idRaw)
		team, err := proto.ImportTeamIDFromBytes(teamRaw)
		if err != nil {
			return nil, err
		}
		row.Team = *team
		row.State, err = importSocialInviteState(stateRaw)
		if err != nil {
			return nil, err
		}
		err = core.DecodeFromBytes(&row.SeedBox, seedBoxRaw)
		if err != nil {
			return nil, err
		}
		if inviteeRaw != nil {
			uid, err := proto.ImportUIDFromBytes(inviteeRaw)
			if err != nil {
				return nil, err
			}
			row.Invitee = uid
		}
		row.Ctime = proto.ExportTime(ctime)
		row.Mtime = proto.ExportTime(mtime)
		row.Etime = proto.ExportTime(etime)
		ret = append(ret, row)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	if len(ret) == 0 {
		return ret, nil
	}

	// One query loads every transcript, rather than one query per row.
	idx := make(map[proto.SocialInviteID]int, len(ret))
	for i := range ret {
		idx[ret[i].Id] = i
	}
	mrows, err := tx.Query(m.Ctx(),
		`SELECT m.id, m.seq, m.sender, m.box
		 FROM social_invite_msgs m
		 JOIN social_invites si
		   ON si.short_host_id=m.short_host_id AND si.id=m.id
		 WHERE m.short_host_id=$1 AND si.inviter=$2
		 ORDER BY m.seq ASC`,
		m.ShortHostID().ExportToDB(), inviter.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var idRaw, box []byte
		var seq uint64
		var sender string
		err = mrows.Scan(&idRaw, &seq, &sender, &box)
		if err != nil {
			return nil, err
		}
		var id proto.SocialInviteID
		copy(id[:], idRaw)
		i, found := idx[id]
		if !found {
			// A transcript of an expired row: the join above does not
			// repeat the listing's etime filter.
			continue
		}
		msg, err := importSocialInviteMsg(seq, sender, box)
		if err != nil {
			return nil, err
		}
		ret[i].Msgs = append(ret[i].Msgs, msg)
	}
	err = mrows.Err()
	if err != nil {
		return nil, err
	}
	err = tx.Commit(m.Ctx())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// ReplySocialInvite is the one write made by the invitee. The write key, not
// authentication, is what protects the slot: the caller presents wk and it
// is checked in constant time against the commitment published at create
// time. InReplyTo must name the inviter turn being answered; a reply to a
// turn that is no longer current fails with SocialInviteStaleTurnError, and
// a second reply to the same turn is a lost-ack retry that replaces the
// invitee's message rather than appending.
func ReplySocialInvite(m MetaContext, arg rem.ReplyArg, invitee proto.UID) error {
	msgBox, err := core.EncodeToBytes(&arg.Msg)
	if err != nil {
		return err
	}
	shid := m.ShortHostID().ExportToDB()

	return RetryTxUserDB(m, "ReplySocialInvite", func(m MetaContext, tx pgx.Tx) error {
		var stateRaw string
		var lastSeq uint64
		var wkCommitRaw []byte
		err := tx.QueryRow(m.Ctx(),
			`SELECT state, last_seq, wk_commit FROM social_invites
			 WHERE short_host_id=$1 AND id=$2
			 AND etime > NOW() AND state != 'canceled'
			 FOR UPDATE`,
			shid, arg.Id[:],
		).Scan(&stateRaw, &lastSeq, &wkCommitRaw)
		if err == pgx.ErrNoRows {
			return core.SocialInviteNotFoundError{}
		}
		if err != nil {
			return err
		}
		state, err := importSocialInviteState(stateRaw)
		if err != nil {
			return err
		}

		var wkCommit proto.SocialInviteWriteKeyCommitment
		copy(wkCommit[:], wkCommitRaw)
		err = core.CheckSocialInviteWriteKey(arg.Wk, wkCommit)
		if err != nil {
			return err
		}

		switch state {
		case proto.SocialInviteState_Open, proto.SocialInviteState_AskAgain:
			// last_seq is an inviter turn; the reply appends after it.
			if arg.InReplyTo != lastSeq {
				return core.SocialInviteStaleTurnError{}
			}
			tags, err := tx.Exec(m.Ctx(),
				`INSERT INTO social_invite_msgs(
					short_host_id, id, seq, sender, box, ctime)
				 VALUES($1, $2, $3, 'invitee', $4, NOW())`,
				shid, arg.Id[:], lastSeq+1, msgBox,
			)
			if err != nil {
				return err
			}
			if tags.RowsAffected() != 1 {
				return core.InsertError("social_invite_msgs")
			}
			tags, err = tx.Exec(m.Ctx(),
				`UPDATE social_invites
				 SET state='replied', last_seq=$3, invitee=$4, mtime=NOW()
				 WHERE short_host_id=$1 AND id=$2`,
				shid, arg.Id[:], lastSeq+1, invitee.ExportToDB(),
			)
			if err != nil {
				return err
			}
			if tags.RowsAffected() != 1 {
				return core.UpdateError("social_invites")
			}
			return nil

		case proto.SocialInviteState_Replied:
			// last_seq is the invitee's own turn; a repeat of the same
			// inReplyTo replaces it, since the wk check already proved the
			// same writer.
			if arg.InReplyTo != lastSeq-1 {
				return core.SocialInviteStaleTurnError{}
			}
			tags, err := tx.Exec(m.Ctx(),
				`UPDATE social_invite_msgs SET box=$4, ctime=NOW()
				 WHERE short_host_id=$1 AND id=$2 AND seq=$3`,
				shid, arg.Id[:], lastSeq, msgBox,
			)
			if err != nil {
				return err
			}
			if tags.RowsAffected() != 1 {
				return core.UpdateError("social_invite_msgs")
			}
			tags, err = tx.Exec(m.Ctx(),
				`UPDATE social_invites SET invitee=$3, mtime=NOW()
				 WHERE short_host_id=$1 AND id=$2`,
				shid, arg.Id[:], invitee.ExportToDB(),
			)
			if err != nil {
				return err
			}
			if tags.RowsAffected() != 1 {
				return core.UpdateError("social_invites")
			}
			return nil

		default:
			// accepted or declined; both are visible to the invitee anyway.
			return core.SocialInviteWrongStateError{}
		}
	})
}

// AskAgainSocialInvite appends an inviter turn to a replied row. Rows the
// caller doesn't own read as absent.
func AskAgainSocialInvite(m MetaContext, arg rem.AskAgainArg, inviter proto.UID) error {
	msgBox, err := core.EncodeToBytes(&arg.Msg)
	if err != nil {
		return err
	}
	shid := m.ShortHostID().ExportToDB()

	return RetryTxUserDB(m, "AskAgainSocialInvite", func(m MetaContext, tx pgx.Tx) error {
		var stateRaw string
		var lastSeq uint64
		err := tx.QueryRow(m.Ctx(),
			`SELECT state, last_seq FROM social_invites
			 WHERE short_host_id=$1 AND id=$2 AND inviter=$3
			 AND etime > NOW() AND state != 'canceled'
			 FOR UPDATE`,
			shid, arg.Id[:], inviter.ExportToDB(),
		).Scan(&stateRaw, &lastSeq)
		if err == pgx.ErrNoRows {
			return core.SocialInviteNotFoundError{}
		}
		if err != nil {
			return err
		}
		state, err := importSocialInviteState(stateRaw)
		if err != nil {
			return err
		}
		if state != proto.SocialInviteState_Replied {
			return core.SocialInviteWrongStateError{}
		}
		tags, err := tx.Exec(m.Ctx(),
			`INSERT INTO social_invite_msgs(
				short_host_id, id, seq, sender, box, ctime)
			 VALUES($1, $2, $3, 'inviter', $4, NOW())`,
			shid, arg.Id[:], lastSeq+1, msgBox,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.InsertError("social_invite_msgs")
		}
		tags, err = tx.Exec(m.Ctx(),
			`UPDATE social_invites
			 SET state='ask_again', last_seq=$3, mtime=NOW()
			 WHERE short_host_id=$1 AND id=$2`,
			shid, arg.Id[:], lastSeq+1,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.UpdateError("social_invites")
		}
		return nil
	})
}

// CloseSocialInvite moves a row to a terminal state. It is bookkeeping, not
// the membership change: an accepted close follows the team edit made
// through the existing team machinery. A canceled or declined close deletes
// a still-unused attached code in the same transaction: the code was handed
// out inside the opening message, and deleting it is the revocation. An
// accepted close leaves the code alone; the consumed row is the audit trail.
func CloseSocialInvite(m MetaContext, arg rem.CloseArg, inviter proto.UID) error {
	switch arg.St {
	case proto.SocialInviteState_Accepted,
		proto.SocialInviteState_Declined,
		proto.SocialInviteState_Canceled:
	default:
		return core.BadArgsError("close takes accepted, declined or canceled")
	}
	shid := m.ShortHostID().ExportToDB()

	return RetryTxUserDB(m, "CloseSocialInvite", func(m MetaContext, tx pgx.Tx) error {
		var stateRaw string
		var code []byte
		err := tx.QueryRow(m.Ctx(),
			`SELECT state, invite_code FROM social_invites
			 WHERE short_host_id=$1 AND id=$2 AND inviter=$3
			 AND etime > NOW()
			 FOR UPDATE`,
			shid, arg.Id[:], inviter.ExportToDB(),
		).Scan(&stateRaw, &code)
		if err == pgx.ErrNoRows {
			return core.SocialInviteNotFoundError{}
		}
		if err != nil {
			return err
		}
		state, err := importSocialInviteState(stateRaw)
		if err != nil {
			return err
		}

		// A close whose response was lost gets retried; the same terminal
		// state again is that retry, not a new transition, and succeeds
		// without touching the row. Any other operation on a canceled row
		// reads it as never-existed, matching every other reader.
		if state == arg.St {
			return nil
		}
		if state == proto.SocialInviteState_Canceled {
			return core.SocialInviteNotFoundError{}
		}

		ok := false
		switch state {
		case proto.SocialInviteState_Open, proto.SocialInviteState_AskAgain:
			ok = (arg.St == proto.SocialInviteState_Canceled)
		case proto.SocialInviteState_Replied:
			ok = (arg.St == proto.SocialInviteState_Accepted ||
				arg.St == proto.SocialInviteState_Declined)
		}
		if !ok {
			return core.SocialInviteWrongStateError{}
		}

		if arg.St != proto.SocialInviteState_Accepted && code != nil {
			// Deleting the code is the revocation; the FK's ON DELETE SET
			// NULL clears the row's reference. It has to happen in this
			// transaction rather than waiting for the sweeper: a gap
			// between cancel and sweep would be a window where the revoked
			// invitation's code still signs people up.
			_, err = tx.Exec(m.Ctx(),
				`DELETE FROM invite_codes
				 WHERE short_host_id=$1 AND code=$2 AND used_by IS NULL`,
				shid, code,
			)
			if err != nil {
				return err
			}
		}

		newState, err := exportSocialInviteState(arg.St)
		if err != nil {
			return err
		}
		tags, err := tx.Exec(m.Ctx(),
			`UPDATE social_invites SET state=$3, mtime=NOW()
			 WHERE short_host_id=$1 AND id=$2`,
			shid, arg.Id[:], newState,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.UpdateError("social_invites")
		}
		return nil
	})
}

// SweepSocialInvites deletes expired and terminal rows once the grace period
// has elapsed, reclaiming any still-unused attached codes in the same
// transaction. Row deletion is tidiness, not correctness: every reader
// already treats a row past its etime as absent. Code reclamation is not:
// an expired invitation's unused code is deleted on the first sweep after
// etime, because the grace period keeps the row readable but must not keep
// an expired invitation's signup code redeemable.
func SweepSocialInvites(m MetaContext) error {
	settings, err := socialInviteSettings(m)
	if err != nil {
		return err
	}
	now := m.Now()
	cutoff := now.Add(-settings.SocialInviteGrace())
	shid := m.ShortHostID().ExportToDB()

	return RetryTxUserDB(m, "SweepSocialInvites", func(m MetaContext, tx pgx.Tx) error {
		// Codes first: this join needs the parent rows still present.
		_, err := tx.Exec(m.Ctx(),
			`DELETE FROM invite_codes ic
			 USING social_invites si
			 WHERE ic.short_host_id=$1 AND si.short_host_id=$1
			 AND si.invite_code=ic.code AND ic.used_by IS NULL
			 AND (si.etime < $2
			      OR (si.state IN ('accepted', 'declined', 'canceled')
			          AND si.mtime < $3))`,
			shid, now, cutoff,
		)
		if err != nil {
			return err
		}
		// ON DELETE CASCADE takes the msgs.
		_, err = tx.Exec(m.Ctx(),
			`DELETE FROM social_invites
			 WHERE short_host_id=$1
			 AND (etime < $2
			      OR (state IN ('accepted', 'declined', 'canceled')
			          AND mtime < $2))`,
			shid, cutoff,
		)
		return err
	})
}
