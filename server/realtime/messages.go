package realtime

import (
	"errors"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultThreadPage bounds a single rtGetThread page when the client doesn't
// ask for a specific size (max=0).
const defaultThreadPage = 100
const maxThreadPage = 1000

// messageSender sends one message into a channel. All work happens inside a
// single realtime-DB transaction; we lock the channels row up front with
// SELECT ... FOR UPDATE so that per-channel seq assignment and sender interning
// are serialized, without needing a CAS/retry loop.
type messageSender struct {
	arg    rem.RTSendArg
	sender proto.UID
	userdb shared.Querier
	tx     pgx.Tx

	// loaded from the locked channels row
	parentTeam proto.TeamID
	writeRole  proto.Role
	readRole   proto.Role
	prevSeq    proto.RTMsgSeq
	appID      proto.RTAppID
	private    bool
	noPush     bool

	// members whose inbox versions the fanout bumped; the caller wakes their
	// parked long-pollers after the transaction commits.
	wakeUIDs []proto.UID
}

func (s *messageSender) channelID() int64 { return int64(s.arg.Chid) }

// typeWakesPhone reports whether a send of this type queues push rows. Edits
// and deletes never notify (fork, queued for upstream in SECO-UPSTREAM.md):
// the app's rule is that changing or removing a message is not news. The app
// deletes by editing to an empty body, so Edit covers both in practice;
// Delete is listed for what the type means.
//
// The type is the sender's plaintext claim. Mislabelling a new message as an
// edit gains nothing: readers reject a message whose type does not match its
// sealed body. A real edit does deliver its new text without a push, which is
// the point.
func typeWakesPhone(t proto.RTMsgType) bool {
	switch t {
	case proto.RTMsgType_Edit, proto.RTMsgType_Delete:
		return false
	default:
		return true
	}
}

// lockChannel reads (and row-locks) the channel being sent into, and
// authorizes the sender. The FOR UPDATE serializes concurrent sends to the
// same channel, so seq assignment below is race-free.
//
// Inventory row 3 (rtSend sender auth): the load and the authorization are one
// call through the chokepoint, so a private channel can never be sent into by
// someone without an ACL row -- and a non-member cannot learn it exists,
// because they get the same RowNotFound a missing channel gives.
func (s *messageSender) lockChannel(m shared.MetaContext) error {
	ca, err := authorizeChannel(m, s.tx, s.userdb, s.channelID(), accessWrite, true)
	if _, ok := err.(core.RTChannelArchivedError); ok {
		// A retry of a send that already landed is not new activity, so the
		// idempotency contract comes first: if this msg_id is in the thread,
		// the caller lost an ack, and gets the original result back as it
		// would from a live channel. Otherwise the client's outbox would mark
		// as failed a message every member can already read. The archived
		// gate runs last in authorizeChannel, so a caller who gets here may
		// send, and the row lock is held. The lookup runs only for an
		// archived channel, so a live send pays nothing for it (upstream
		// #392, which checks after its own authorize step instead).
		exists, xerr := s.msgIDExists(m)
		if xerr != nil {
			return xerr
		}
		if exists {
			return errMsgIDReplay
		}
		return err
	}
	if err != nil {
		return err
	}
	s.parentTeam = ca.team
	s.writeRole = ca.writeRole
	s.readRole = ca.readRole
	s.appID = ca.appID
	s.private = ca.private
	s.noPush = ca.noPush
	if ca.lastMsgSeq != nil {
		s.prevSeq = proto.RTMsgSeq(*ca.lastMsgSeq)
	}
	return nil
}

// checkEncryptionRole verifies the client encrypted the message at exactly the
// channel's read role. Encrypting higher would lock out authorized readers;
// encrypting lower would hand the plaintext to a key below the channel's read
// threshold. Either way the box is malformed, so we reject it rather than
// persist an undecryptable/over-shared message.
func (s *messageSender) checkEncryptionRole(rg proto.RoleAndGen) error {
	msgRole, err := core.ImportRole(rg.Role)
	if err != nil {
		return err
	}
	readRole, err := core.ImportRole(s.readRole)
	if err != nil {
		return err
	}
	if !msgRole.Eq(*readRole) {
		return core.BadArgsError("message must be encrypted at the channel's read role")
	}
	return nil
}

// checkEncryptionGen verifies the client sealed the message under the team's
// newest key generation for its role. After a rekey (a member removed) a
// sender whose team cache predates it would otherwise keep sealing under the
// generation the removed member holds, until the cache expires. Such a send is
// refused with RTRaceError{RTRaceKeyGeneration}, so the sender reloads the team
// and re-seals -- unless this msg_id already landed (a lost ack from before
// the rekey), which is answered as a replay like any other.
func (s *messageSender) checkEncryptionGen(m shared.MetaContext, rg proto.RoleAndGen) error {
	roleType, vizLevel, err := rg.Role.ExportToDB()
	if err != nil {
		return err
	}
	var gen int
	err = s.userdb.QueryRow(m.Ctx(),
		`SELECT gen FROM shared_key_generations
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 AND viz_level=$4`,
		m.ShortHostID().ExportToDB(),
		s.parentTeam.EntityID().ExportToDB(),
		roleType,
		vizLevel,
	).Scan(&gen)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.BadArgsError("team has no key at the message's role")
	}
	if err != nil {
		return err
	}
	switch {
	case int(rg.Gen) > gen:
		return core.BadArgsError("message sealed under a key generation the team does not have")
	case int(rg.Gen) < gen:
		exists, err := s.msgIDExists(m)
		if err != nil {
			return err
		}
		if exists {
			return errMsgIDReplay
		}
		return core.RTRaceError{Which: core.RTRaceKeyGeneration}
	}
	return nil
}

// internSender maps the sending user to a small per-channel ordinal (party_no),
// inserting a new channel_parties row the first time the user posts. Safe under
// the channels row lock held by the caller.
func (s *messageSender) internSender(m shared.MetaContext) (int, error) {
	pid := s.sender.ToPartyID()
	var partyNo int
	err := s.tx.QueryRow(
		m.Ctx(),
		`INSERT INTO channel_parties
			(short_host_id, channel_id, party_no, party_id, uid, ctime)
		 SELECT $1, $2, COALESCE(MAX(cp.party_no), 0) + 1, $3, $4, NOW()
		   FROM channel_parties cp
		   WHERE cp.short_host_id=$1 AND cp.channel_id=$2
		 ON CONFLICT (short_host_id, channel_id, party_id)
		 DO UPDATE SET uid = EXCLUDED.uid
		 RETURNING party_no`,
		m.ShortHostID(),
		s.channelID(),
		pid.ExportToDB(),
		s.sender.ExportToDB(),
	).Scan(&partyNo)
	if err != nil {
		return 0, err
	}
	return partyNo, nil
}

// insertMessage writes the row to messages_enc at the freshly-assigned seq and
// updates the denormalized last_* fields on the channel for inbox snippets.
func (s *messageSender) insertMessage(
	m shared.MetaContext,
	senderNo int,
	seq proto.RTMsgSeq,
) (
	proto.Time,
	error,
) {
	var zed proto.Time

	bodyType, err := s.arg.Mw.GetT()
	if err != nil {
		return zed, err
	}
	// Stage 1a clients always send end-to-end encrypted bodies; server-authored
	// plaintext (join/leave/system) lands in messages_clear and is deferred.
	if bodyType != proto.MsgBodyType_Encrypted {
		return zed, core.BadArgsError("only encrypted message bodies are supported")
	}
	ebody := s.arg.Mw.Encrypted()

	ctxtTyp, err := ebody.Ctext.GetT()
	if err != nil {
		return zed, err
	}
	if ctxtTyp != proto.BoxType_NACL {
		return zed, core.BadArgsError("only nacl boxes accepted")
	}
	naclctxt := ebody.Ctext.Nacl()
	err = s.checkEncryptionRole(ebody.Rg)
	if err != nil {
		return zed, err
	}
	err = s.checkEncryptionGen(m, ebody.Rg)
	if err != nil {
		return zed, err
	}
	roleType, vizLevel, err := ebody.Rg.Role.ExportToDB()
	if err != nil {
		return zed, err
	}
	typ, err := s.arg.Md.Typ.ExportToDB()
	if err != nil {
		return zed, err
	}

	var insertTime time.Time
	err = s.tx.QueryRow(
		m.Ctx(),
		`INSERT INTO messages_enc
			(short_host_id, channel_id, seq, msg_id, typ, msg_box, ptk_gen,
			 role_type, viz_level, sender_no, sent_at_time, insert_time,
			 prev_msg_id, prev_seq)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), $12, $13)
		 RETURNING insert_time`,
		m.ShortHostID(),
		s.channelID(),
		seq.Int64(),
		s.arg.Md.MsgID.Bytes(),
		typ,
		naclctxt,
		int(ebody.Rg.Gen),
		roleType,
		vizLevel,
		senderNo,
		s.arg.Md.SendTime.Import(),
		s.arg.Md.PrevID.Bytes(),
		s.arg.Md.PrevSeq.Int64(),
	).Scan(&insertTime)
	if shared.IsDuplicateKeyError(err, "messages_enc_pkey") {
		// Shouldn't happen: we hold the channels row lock, so seq is ours.
		return zed, core.RTRaceError{Which: "messages"}
	}
	if shared.IsDuplicateKeyError(err, "messages_enc_msg_id_key") {
		// This msg_id was already delivered -- a client retrying a send whose
		// ack it lost. The violation aborts the transaction, so the caller
		// (SendMessage) resolves the replay with a fresh read after rollback.
		return zed, errMsgIDReplay
	}
	if err != nil {
		return zed, err
	}

	_, err = s.tx.Exec(
		m.Ctx(),
		`UPDATE channels
		 SET last_msg_type=$3, last_msg_seq=$4, last_sender_no=$5,
		     last_send_time=$6, mtime=NOW()
		 WHERE short_host_id=$1 AND channel_id=$2`,
		m.ShortHostID(),
		s.channelID(),
		typ,
		seq,
		senderNo,
		s.arg.Md.SendTime.Import(),
	)
	if err != nil {
		return zed, err
	}

	return proto.ExportTime(insertTime), nil
}

// fanoutInboxVersions bumps each channel member's per-(user, app) global inbox
// version and stamps their user_channels membership row at that new version --
// the fan-out-on-write described for user_channels/user_inbox in
// foks_realtime.sql. The stamped row is what the (uid, app_id, inbox_version)
// index scans to answer "which threads changed since version X" on the
// member's next inbox sync. Membership is the set of user_channels rows for
// this channel (written by the channel-creation fanout); both statements are
// set-based and run in the send transaction, so the fanout commits or rolls
// back atomically with the message itself.
func (s *messageSender) fanoutInboxVersions(
	m shared.MetaContext,
	insertTime time.Time,
	seq proto.RTMsgSeq,
) error {
	// Bump each member's (uid, app) global inbox version. The insert arm is
	// paranoia -- the channel-creation fanout writes user_inbox before
	// user_channels -- but keeps a missing row self-healing. The ORDER BY
	// makes concurrent sends into different channels with overlapping
	// membership acquire user_inbox row locks in a consistent order, avoiding
	// deadlocks. RETURNING collects the bumped members so the caller can wake
	// their parked long-pollers once this transaction commits.
	rows, err := s.tx.Query(
		m.Ctx(),
		`INSERT INTO user_inbox (short_host_id, uid, app_id, inbox_version, mtime)
		 SELECT uc.short_host_id, uc.uid, uc.app_id, 1, NOW()
		   FROM user_channels uc
		  WHERE uc.short_host_id=$1 AND uc.channel_id=$2
		  ORDER BY uc.uid
		 ON CONFLICT (short_host_id, uid, app_id)
		 DO UPDATE SET inbox_version = user_inbox.inbox_version + 1, mtime = NOW()
		 RETURNING uid`,
		m.ShortHostID(),
		s.channelID(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var uidRaw []byte
		err = rows.Scan(&uidRaw)
		if err != nil {
			return err
		}
		var uid proto.UID
		err = uid.ImportFromDB(uidRaw)
		if err != nil {
			return err
		}
		s.wakeUIDs = append(s.wakeUIDs, uid)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()

	// Stamp each membership row at its owner's just-bumped global version, and
	// refresh the denormalized last-message time for inbox ordering. Reads the
	// user_inbox rows written above in the same transaction. Sending implies
	// reading: the sender's own read pointer advances to the new message in the
	// same stamp (GREATEST keeps it monotonic), so a member's own messages never
	// count against their unread badge. No extra version is consumed -- the row
	// was bumping for the delivery anyway, so other devices pick the read state
	// up along with the message.
	//
	// The sender's explicit pointer (fork-only, cross-device-read-sync) moves
	// with it -- sending is the clearest sign of having read -- and settles
	// the sender's own pushes in this channel, below. Its old value is read
	// first.
	var senderExplicit int64
	err = s.tx.QueryRow(
		m.Ctx(),
		`SELECT explicit_read_through FROM user_channels
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
		m.ShortHostID(),
		s.channelID(),
		s.sender.ExportToDB(),
	).Scan(&senderExplicit)
	senderRow := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	_, err = s.tx.Exec(
		m.Ctx(),
		`UPDATE user_channels uc
		 SET inbox_version = ui.inbox_version, last_msg_time = $3, mtime = NOW(),
		     read_through = CASE WHEN uc.uid = $4
		                         THEN GREATEST(uc.read_through, $5)
		                         ELSE uc.read_through END,
		     explicit_read_through = CASE WHEN uc.uid = $4
		                                  THEN GREATEST(uc.explicit_read_through, $5)
		                                  ELSE uc.explicit_read_through END
		 FROM user_inbox ui
		 WHERE ui.short_host_id = uc.short_host_id
		   AND ui.uid = uc.uid AND ui.app_id = uc.app_id
		   AND uc.short_host_id=$1 AND uc.channel_id=$2`,
		m.ShortHostID(),
		s.channelID(),
		insertTime,
		s.sender.ExportToDB(),
		seq.Int64(),
	)
	if err != nil {
		return err
	}
	if senderRow && seq.Int64() > senderExplicit {
		err = settleReadPushes(m, s.tx, s.sender, s.channelID(), senderExplicit, seq.Int64())
		if err != nil {
			return err
		}
	}

	// Queue one content-free push row per recipient (not the sender, and not
	// a member who muted the channel -- fork-only, follow-scoped-push) in
	// the same transaction as the send, so a row exists iff the message
	// does. push_outbox is already in the schema; this is the writer.
	// kind='msg', data=NULL — a pure wake: no message content, sender or
	// channel name leaves the E2EE boundary for a push provider.
	//
	// A no-push channel (fork-only, dm-handshake-over-rt) skips ONLY this
	// fan-out: the inbox-version bump above already woke every member's
	// parked long-poller, so online delivery is untouched — what a no-push
	// channel never does is buzz a phone about machine-to-machine traffic.
	// Channel names are PTK-encrypted at rest, so this per-channel flag is
	// the only way the server can tell a control channel from conversation.
	if s.noPush {
		return nil
	}
	// An edit or a delete (fork, typeWakesPhone) skips the fan-out the same
	// way: the message is stored and every member's inbox is bumped and
	// stamped above, but no phone is woken. The server can tell because the
	// message type travels in the clear. This return comes before
	// pushStatusForSend, so an edit does not end a hold whose holder has left
	// the team; the next ordinary send does.
	if !typeWakesPhone(s.arg.Md.Typ) {
		return nil
	}
	// A send the sender flagged noPush (fork-only, silent-system-notices) skips
	// it the same way, and for the same reason sits before pushStatusForSend.
	// The app sets it on its in-app system notices, whose kind is sealed in the
	// body, so the type above cannot tell them from a message.
	if s.arg.NoPush {
		return nil
	}
	// Under a push hold (fork-only, pushhold.go) the rows are 'held' until
	// the holder decides them.
	status, err := s.pushStatusForSend(m)
	if err != nil {
		return err
	}
	_, err = s.tx.Exec(
		m.Ctx(),
		`INSERT INTO push_outbox (short_host_id, uid, channel_id, kind, seq, status, ctime, mtime)
		 SELECT uc.short_host_id, uc.uid, uc.channel_id, 'msg', $3, $5::push_status, NOW(), NOW()
		   FROM user_channels uc
		  WHERE uc.short_host_id=$1 AND uc.channel_id=$2 AND uc.uid <> $4
		    AND NOT uc.muted`,
		m.ShortHostID(),
		s.channelID(),
		seq.Int64(),
		s.sender.ExportToDB(),
		status,
	)
	return err
}

// msgIDExists reports whether this send's msg_id is already in messages_enc,
// which means the caller is retrying a send whose ack it lost. The caller
// then returns errMsgIDReplay so SendMessage resolves the replay.
func (s *messageSender) msgIDExists(m shared.MetaContext) (bool, error) {
	var exists bool
	err := s.tx.QueryRow(
		m.Ctx(),
		`SELECT EXISTS(SELECT 1 FROM messages_enc WHERE msg_id=$1)`,
		s.arg.Md.MsgID.Bytes(),
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (s *messageSender) run(m shared.MetaContext) (*rem.RTSendRes, error) {
	err := s.lockChannel(m)
	if err != nil {
		return nil, err
	}
	// Inventory row 4, team-leave cascade (§6.3): for a private channel,
	// re-validate the recipient set against the team roster and drop anyone
	// who has left, BEFORE the fan-out below selects its recipients from the
	// same rows. We hold the channels row lock, so no concurrent send can be
	// fanning out while we prune.
	if s.private {
		appDB, err := s.appID.ExportToDB()
		if err != nil {
			return nil, err
		}
		err = pruneStaleChannelMembers(m, s.tx, s.userdb, s.parentTeam, s.channelID(), appDB)
		if err != nil {
			return nil, err
		}
	}
	seq := s.prevSeq + 1
	// Optional optimistic-concurrency check from the client.
	// A failed CAS must still honor the idempotency contract: if this msg_id
	// already landed, the caller's own committed insert is what advanced
	// prevSeq, and every retry would otherwise loop on RTRaceError -- exactly
	// the lost-ack ambiguity the replay path exists to remove.
	if s.arg.ExpectedPrevSeq.IsValid() &&
		s.arg.ExpectedPrevSeq != s.prevSeq {
		exists, err := s.msgIDExists(m)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errMsgIDReplay
		}
		return nil, core.RTRaceError{Which: "messages"}
	}
	senderNo, err := s.internSender(m)
	if err != nil {
		return nil, err
	}
	insertTime, err := s.insertMessage(m, senderNo, seq)
	if err != nil {
		return nil, err
	}
	err = s.fanoutInboxVersions(m, insertTime.Import(), seq)
	if err != nil {
		return nil, err
	}
	return &rem.RTSendRes{
		Seq:        proto.RTMsgSeq(seq),
		InsertTime: insertTime,
	}, nil
}

// SendMessage sends a message into an existing channel on behalf of the
// authenticated user (m.UID()).
func SendMessage(
	m shared.MetaContext,
	arg rem.RTSendArg,
) (
	*rem.RTSendRes,
	error,
) {
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return nil, err
	}
	defer rtdb.Release()
	userdb, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer userdb.Release()

	var res *rem.RTSendRes
	err = shared.RetryTx2(m,
		rtdb,
		"realtime.SendMessage",
		func(m shared.MetaContext, tx pgx.Tx) (func(shared.MetaContext), error) {
			s := messageSender{
				arg:    arg,
				sender: m.UID(),
				userdb: userdb,
				tx:     tx,
			}
			tmp, err := s.run(m)
			if err != nil {
				return nil, err
			}
			res = tmp
			// Once the fanout's bumps commit, wake the members' parked
			// long-pollers.
			return func(m shared.MetaContext) {
				wakeInboxPollers(m, s.appID, s.wakeUIDs)
			}, nil
		},
	)
	if err == errMsgIDReplay {
		// The msg_id unique violation aborted the insert transaction; resolve
		// the replay with a fresh read. rtSend is idempotent on msgID: a
		// retry of a send whose ack was lost gets the original result back.
		return loadReplay(m, rtdb, arg)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// errMsgIDReplay is an internal sentinel: the messages_enc insert hit the
// msg_id unique constraint. Never returned to a client.
var errMsgIDReplay = errors.New("realtime: duplicate msg_id")

// loadReplay resolves an rtSend whose msg_id already exists. If the existing
// row was sent by this caller, into this channel, on this host, the send is a
// replay -- return the original seq and insert time, making rtSend idempotent
// on msgID. Any mismatch (or a message ID collision, vanishingly unlikely in
// a random 16-byte space) is refused with a payload-free error: the existing
// row's location must not leak to a caller who doesn't already know it.
//
// Runs outside the (aborted) insert transaction; that is safe without a lock
// because messages_enc rows are immutable once committed.
func loadReplay(
	m shared.MetaContext,
	rtdb *pgxpool.Conn,
	arg rem.RTSendArg,
) (
	*rem.RTSendRes,
	error,
) {
	var shid int
	var chid, seq int64
	var insertTime time.Time
	var partyRaw []byte
	err := rtdb.QueryRow(
		m.Ctx(),
		`SELECT me.short_host_id, me.channel_id, me.seq, me.insert_time, cp.party_id
		 FROM messages_enc AS me
		 JOIN channel_parties AS cp
		   ON (cp.short_host_id=me.short_host_id
		       AND cp.channel_id=me.channel_id
		       AND cp.party_no=me.sender_no)
		 WHERE me.msg_id=$1`,
		arg.Md.MsgID.Bytes(),
	).Scan(&shid, &chid, &seq, &insertTime, &partyRaw)
	if err == pgx.ErrNoRows {
		// The row that made the insert collide is gone. Nothing deletes
		// messages, so treat as an internal race and let the client retry.
		return nil, core.RTRaceError{Which: "messages"}
	}
	if err != nil {
		return nil, err
	}
	var party proto.PartyID
	err = party.ImportFromDB(partyRaw)
	if err != nil {
		return nil, err
	}
	if shid != int(m.ShortHostID()) ||
		chid != int64(arg.Chid) ||
		!party.Eq(m.UID().ToPartyID()) {
		return nil, core.RTMsgReplayMismatchError{}
	}
	return &rem.RTSendRes{
		Seq:        proto.RTMsgSeq(seq),
		InsertTime: proto.ExportTime(insertTime),
		WasReplay:  true,
	}, nil
}

// wakeInboxPollers wakes the given users' parked rtPollInbox calls. Call only
// after the transaction that bumped their inbox versions has committed; see
// shared.RTInboxHub.
func wakeInboxPollers(m shared.MetaContext, app proto.RTAppID, uids []proto.UID) {
	hub := m.G().RTInboxHub()
	for _, uid := range uids {
		hub.Wake(shared.RTInboxHubKey{
			HostID: m.ShortHostID(),
			Uid:    uid,
			App:    app,
		})
	}
}

// readThroughMarker advances the calling user's read pointer in one channel
// and, if the pointer actually moved, bumps the caller's global inbox version
// and stamps their user_channels row at it -- exactly as a delivery would (see
// "read_through" in chat-server-design.md). That's how the caller's *other*
// devices learn the read state on their next inbox sync.
//
// Fork-only (dm-read-receipts): with arg.Dm it also marks the caller's row as
// a 1:1 DM, and in a channel that then qualifies for read receipts (see
// receipts.go) a moved explicit pointer, or the mark itself, also bumps the
// OTHER member's inbox and stamps their row, so their sync returns the new
// peerReadThrough.
type readThroughMarker struct {
	arg    rem.RTReadThroughArg
	reader proto.UID
	userdb shared.Querier
	tx     pgx.Tx

	// loaded from the channels row
	parentTeam proto.TeamID
	readRole   proto.Role
	lastSeq    *int64
	appID      string
	app        proto.RTAppID

	// bumped records whether the caller's inbox version was bumped; a stale
	// mark leaves it false and must not wake any pollers.
	bumped bool
	// peerBumped is the other member, when their inbox was bumped too.
	peerBumped *proto.UID
}

func (r *readThroughMarker) channelID() int64 { return r.arg.ChannelID.Short().Int64() }

// loadChannel loads and authorizes the channel in one chokepoint call. No row
// lock: an honest client only marks messages it has already received, which
// are committed and thus visible to our snapshot, so last_msg_seq can't race
// backwards under us.
//
// Inventory row 10 (rtReadThrough). The UPDATE below is already gated by the
// user_channels row -- which revoke deletes -- but the read gate applies here
// too, so a revoked member's mark fails at the ACL rather than falling through
// to a "no membership row" answer that would confirm the channel exists.
func (r *readThroughMarker) loadChannel(m shared.MetaContext) error {
	ca, err := authorizeChannel(m, r.tx, r.userdb, r.channelID(), accessRead, false)
	if err != nil {
		return err
	}
	r.parentTeam = ca.team
	r.readRole = ca.readRole
	r.lastSeq = ca.lastMsgSeq
	r.app = ca.appID
	appDB, err := ca.appID.ExportToDB()
	if err != nil {
		return err
	}
	r.appID = appDB
	return nil
}

func (r *readThroughMarker) run(m shared.MetaContext) error {
	err := r.loadChannel(m)
	if err != nil {
		return err
	}

	seq := r.arg.Seq.Int64()
	if seq <= 0 {
		return core.BadArgsError("read-through seq must be positive")
	}
	if r.lastSeq == nil || seq > *r.lastSeq {
		return core.BadArgsError("read-through seq exceeds last message")
	}

	// Read receipts: a channel that can qualify is a two-row one whose other
	// row is marked, with the caller's row marked or about to be. Then both
	// members' user_inbox rows are locked in one ascending-uid statement --
	// the order sends use -- so two members reading their DM at once, or a
	// read racing a send to both, cannot deadlock.
	pair, err := loadDmPair(m, r.tx, r.channelID(), r.reader)
	if err != nil {
		return err
	}
	if pair != nil && !(pair.peerMarked && (pair.callerMarked || r.arg.Dm)) {
		pair = nil
	}

	// Take the user_inbox row lock(s) BEFORE touching user_channels, without
	// bumping. Every other writer in this package locks user_inbox first
	// (fanoutInboxVersions says so explicitly; so do the channel-creation
	// fanout, the metadata mutations and the revoke path). The bump must stay
	// conditional -- see the monotonicity note below. Anyone with a
	// user_channels row has a user_inbox row (fanUserIntoChannel writes the
	// inbox row first), so this finds one whenever the update below can
	// succeed; when it finds none, the update below fails anyway.
	locked := []proto.UID{r.reader}
	if pair != nil {
		locked = append(locked, pair.peer)
		sortUIDs(locked)
	}
	off, err := lockInboxes(m, r.tx, r.appID, locked)
	if err != nil {
		return err
	}
	receiptsOn := pair != nil &&
		!off[string(r.reader.ExportToDB())] && !off[string(pair.peer.ExportToDB())]

	// Both pointers, under the row lock: a missing row means the user was never
	// fanned into this channel.
	var readThrough, explicitThrough int64
	var marked bool
	err = r.tx.QueryRow(
		m.Ctx(),
		`SELECT read_through, explicit_read_through, receipts FROM user_channels
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3
		 FOR UPDATE`,
		m.ShortHostID(),
		r.channelID(),
		r.reader.ExportToDB(),
	).Scan(&readThrough, &explicitThrough, &marked)
	if err == pgx.ErrNoRows {
		return core.RowNotFoundError{}
	}
	if err != nil {
		return err
	}

	// Advance monotonically. A stale or repeated mark (seq at or below the
	// current pointer) is a no-op and must NOT bump the inbox version, or
	// out-of-order marks from racing devices would churn every device's sync.
	// An explicit mark (fork-only, cross-device-read-sync) moves both
	// pointers; any other moves only read_through. Marking the row as a DM is
	// a change of its own: the first dm read after an update usually carries
	// a seq the pointer has already reached.
	explicitMoved := r.arg.Explicit && seq > explicitThrough
	newlyMarked := r.arg.Dm && !marked
	if seq <= readThrough && !explicitMoved && !newlyMarked {
		return nil
	}

	// Something moved: bump the caller's global inbox version and stamp this
	// row at it, "like a send would do" (chat-server-design.md), so the
	// caller's other devices pick the read state up on their next sync.
	//
	// ONE update of the row, with the stamp folded in. A second UPDATE of a
	// row this transaction already updated re-runs its foreign-key check
	// (Postgres skips it only for a row another transaction wrote), which
	// takes a KEY SHARE lock on the channels row -- and a send holds that row
	// FOR UPDATE while it waits for this reader's user_inbox row: a deadlock
	// on every read racing a send in the same channel.
	r.bumped = true
	vers, err := bumpInbox(m, r.tx, r.reader, r.appID)
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(
		m.Ctx(),
		`UPDATE user_channels
		 SET read_through=GREATEST(read_through, $4),
		     explicit_read_through=CASE WHEN $5 THEN GREATEST(explicit_read_through, $4)
		                                ELSE explicit_read_through END,
		     receipts = receipts OR $6,
		     inbox_version=$7,
		     mtime=NOW()
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
		m.ShortHostID(),
		r.channelID(),
		r.reader.ExportToDB(),
		seq,
		explicitMoved,
		newlyMarked,
		vers,
	)
	if err != nil {
		return err
	}
	if explicitMoved {
		err = settleReadPushes(m, r.tx, r.reader, r.channelID(), explicitThrough, seq)
		if err != nil {
			return err
		}
	}

	// The other member sees this read, or the receipts the mark just turned
	// on, only through their own row's peerReadThrough.
	if receiptsOn && (explicitMoved || newlyMarked) {
		err = bumpAndStamp(m, r.tx, pair.peer, r.appID, r.channelID())
		if err != nil {
			return err
		}
		r.peerBumped = &pair.peer
	}
	return nil
}

// MarkReadThrough advances the authenticated user's (m.UID()) read pointer in
// a channel.
func MarkReadThrough(
	m shared.MetaContext,
	arg rem.RTReadThroughArg,
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

	return shared.RetryTx2(m,
		rtdb,
		"realtime.MarkReadThrough",
		func(m shared.MetaContext, tx pgx.Tx) (func(shared.MetaContext), error) {
			r := readThroughMarker{
				arg:    arg,
				reader: m.UID(),
				userdb: userdb,
				tx:     tx,
			}
			if err := r.run(m); err != nil {
				return nil, err
			}
			// A stale mark advances nothing and must wake nobody.
			if !r.bumped {
				return nil, nil
			}
			// Once the bump commits, wake the caller's own parked pollers
			// (their other devices), and the other member's when their row
			// was stamped too (dm-read-receipts).
			woken := []proto.UID{r.reader}
			if r.peerBumped != nil {
				woken = append(woken, *r.peerBumped)
			}
			return func(m shared.MetaContext) {
				wakeInboxPollers(m, r.app, woken)
			}, nil
		},
	)
}

// threadMsgSelect is the column list + sender-attribution join shared by every
// message read (range fetch and by-seq fetch). Callers append their own WHERE /
// ORDER BY / LIMIT clause; $1/$2 are reserved for short_host_id/channel_id.
const threadMsgSelect = `SELECT me.seq, me.msg_id, me.typ, me.msg_box, me.ptk_gen,
              me.role_type, me.viz_level, me.sent_at_time, me.insert_time,
              me.prev_msg_id, me.prev_seq,
              cp.party_id, cp.uid
       FROM messages_enc me
       JOIN channel_parties cp ON
           cp.short_host_id = me.short_host_id
           AND cp.channel_id = me.channel_id
           AND cp.party_no = me.sender_no`

// scanThreadMsgs decodes rows produced by a threadMsgSelect query into RTMsgs.
func scanThreadMsgs(rows pgx.Rows) ([]rem.RTMsg, error) {
	var ret []rem.RTMsg
	for rows.Next() {
		var (
			seq                  int64
			msgIDRaw             []byte
			typRaw               string
			msgBoxRaw            []byte
			ptkGen               int
			roleType, vizLevel   int
			sentAtTime, insertTm time.Time
			prevMsgIDRaw         []byte
			prevSeq              int64
			partyIDRaw, uidRaw   []byte
		)
		err := rows.Scan(
			&seq, &msgIDRaw, &typRaw, &msgBoxRaw, &ptkGen,
			&roleType, &vizLevel, &sentAtTime, &insertTm,
			&prevMsgIDRaw, &prevSeq,
			&partyIDRaw, &uidRaw,
		)
		if err != nil {
			return nil, err
		}

		var typ proto.RTMsgType
		err = typ.ImportFromDB(typRaw)
		if err != nil {
			return nil, err
		}

		var msgID, prevMsgID proto.RTMsgID
		err = msgID.ImportFromBytes(msgIDRaw)
		if err != nil {
			return nil, err
		}
		err = prevMsgID.ImportFromBytes(prevMsgIDRaw)
		if err != nil {
			return nil, err
		}

		box := proto.RTMsgBox{
			Ctext: proto.NewRTMsgCiphertextWithNacl(
				msgBoxRaw,
			),
		}
		box.Rg.Gen = proto.Generation(ptkGen)
		err = box.Rg.Role.ImportFromDB(roleType, vizLevel)
		if err != nil {
			return nil, err
		}

		var pid proto.PartyID
		err = pid.ImportFromDB(partyIDRaw)
		if err != nil {
			return nil, err
		}

		msg := rem.RTMsg{
			Md: proto.RTMsgMetadata{
				MsgID:    msgID,
				PrevID:   prevMsgID,
				PrevSeq:  proto.RTMsgSeq(prevSeq),
				Typ:      typ,
				SendTime: proto.ExportTime(sentAtTime),
			},
			Seq:    proto.RTMsgSeq(seq),
			Sender: &pid,
			Mw: proto.NewRTMsgWrapperWithEncrypted(
				box,
			),
			InsertTime: proto.ExportTime(insertTm),
		}
		if uidRaw != nil {
			var uid proto.UID
			err = uid.ImportFromDB(uidRaw)
			if err != nil {
				return nil, err
			}
			tmp := uid.ToPartyID()
			msg.Sender = &tmp
		}
		ret = append(ret, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

// cappedThreadMax clamps a client-requested range size to defaultThreadPage,
// treating 0 (unspecified) as "use the default".
func cappedThreadMax(max uint64) uint64 {
	if max == 0 || max > defaultThreadPage {
		return defaultThreadPage
	}
	return max
}

func readThreadRecents(
	m shared.MetaContext,
	db shared.Querier,
	channelID proto.RTChannelID,
	stopAt proto.RTMsgSeq,
	lim uint64,
) (
	[]rem.RTMsg,
	error,
) {
	lim = cappedThreadMax(lim)
	q := threadMsgSelect +
		` WHERE me.short_host_id=$1 AND me.channel_id=$2
	  AND me.seq > $3
	  ORDER BY me.seq DESC LIMIT $4`
	args := []any{m.ShortHostID(), channelID.Short().Int64(),
		stopAt.Int64(),
		lim,
	}
	rows, err := db.Query(
		m.Ctx(),
		q,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreadMsgs(rows)
}

// readThread pulls one contiguous page of messages from messages_enc, joining
// channel_parties to recover sender attribution.
func readThreadBookends(
	m shared.MetaContext,
	db shared.Querier,
	channelID proto.RTChannelID,
	bookends rem.RTThreadRangeBookends,
) (
	[]rem.RTMsg,
	error,
) {

	q := threadMsgSelect + " WHERE me.short_host_id=$1 AND me.channel_id=$2 "
	args := []any{m.ShortHostID(), channelID.Short().Int64()}

	var order string
	var bottom, top proto.RTMsgSeq
	if bookends.Start < bookends.End {
		bottom = bookends.Start
		top = bookends.End
		order = "ASC"
	} else {
		bottom = bookends.End
		top = bookends.Start
		order = "DESC"
	}
	if top-bottom > maxThreadPage {
		return nil, core.BadArgsError("message fetch range too wide")
	}
	args = append(args, bottom.Int64(), top.Int64())
	q += fmt.Sprintf(" AND me.seq >= $3 AND me.seq <= $4 ORDER BY me.seq %s", order)

	rows, err := db.Query(
		m.Ctx(),
		q,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreadMsgs(rows)
}

// readMsgsBySeq fetches the messages whose seq is in `seqs`. Seqs with no
// matching message are simply absent from the result; order is unspecified
// (each RTMsg carries its own seq, so the caller can slot it back into place).
func readMsgsBySeq(
	m shared.MetaContext,
	db shared.Querier,
	channelID proto.RTChannelID,
	seqs []proto.RTMsgSeq,
) (
	[]rem.RTMsg,
	error,
) {
	if len(seqs) == 0 {
		return nil, nil
	}
	v := make([]int64, len(seqs))
	for i, s := range seqs {
		v[i] = int64(s)
	}
	rows, err := db.Query(
		m.Ctx(),
		threadMsgSelect+`
		       WHERE me.short_host_id=$1 AND me.channel_id=$2
		         AND me.seq = ANY($3)`,
		m.ShortHostID(),
		channelID.Short().Int64(),
		v,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreadMsgs(rows)
}

// maxMsgsBySeq bounds the seq-list portion of a single rtGetThread request, so
// a client can't ask for an unbounded set of seqs in one round trip.
const maxMsgsBySeq = 4096

func GetThreadRecents(
	m shared.MetaContext,
	arg rem.RtGetThreadRecentsArg,
) (
	*rem.RTMsgList,
	error,
) {
	channelID := arg.Ch
	var retp *rem.RTMsgList
	err := getThreadGeneric(
		m,
		channelID,
		func(
			rtdb *pgxpool.Conn,
		) error {
			msgs, err := readThreadRecents(m, rtdb, channelID, arg.StopAt, arg.Lim)
			if err != nil {
				return err
			}
			ret := rem.RTMsgList{
				Lst: msgs,
			}
			retp = &ret
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return retp, nil
}

// GetThread answers a thread query after checking that the authenticated user
// (m.UID()) is authorized to read the channel. A query may carry a contiguous
// range, an explicit set of seqs (to fill holes between cached and
// remote-fetched ranges), or both; the two are answered into separate result
// lists. Seq lookups are found-only: missing seqs are silently omitted.
func GetThread(
	m shared.MetaContext,
	q rem.RTThreadQuery,
) (
	*rem.RTThreadPage,
	error,
) {
	channelID := q.ChannelID
	var retp *rem.RTThreadPage

	err := getThreadGeneric(
		m,
		channelID,
		func(
			rtdb *pgxpool.Conn,
		) error {
			if len(q.Seqs) > maxMsgsBySeq {
				return core.BadArgsError("too many seqs requested")
			}

			ret := rem.RTThreadPage{}

			for _, rng := range q.Bookends {
				msgs, err := readThreadBookends(m, rtdb, channelID, rng)
				if err != nil {
					return err
				}
				ret.RangeMsgs = append(ret.RangeMsgs, rem.RTMsgList{Lst: msgs})
			}

			if len(q.Seqs) > 0 {
				msgs, err := readMsgsBySeq(m, rtdb, channelID, q.Seqs)
				if err != nil {
					return err
				}
				ret.SeqMsgs = msgs
			}
			retp = &ret
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return retp, nil
}

func getThreadGeneric(
	m shared.MetaContext,
	chid proto.RTChannelID,
	fn func(rtdb *pgxpool.Conn) error,
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

	// Inventory rows 1 and 2 (rtGetThread, rtGetThreadRecents): the chokepoint
	// applies the team, tier, read-role and private-ACL gates, and hides a
	// private channel's existence from a non-member behind RowNotFound.
	_, err = authorizeChannel(m, rtdb, userdb, chid.Short().Int64(), accessRead, false)
	if err != nil {
		return err
	}

	err = fn(rtdb)
	if err != nil {
		return err
	}
	return nil
}
