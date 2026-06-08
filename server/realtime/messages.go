package realtime

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

// defaultThreadPage bounds a single rtGetThread page when the client doesn't
// ask for a specific size (max=0).
const defaultThreadPage = 100

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
	prevSeq    int64
}

func (s *messageSender) channelID() int64 { return int64(s.arg.Chid) }

// lockChannel reads (and row-locks) the channel being sent into. The FOR UPDATE
// serializes concurrent sends to the same channel, so seq assignment below is
// race-free.
func (s *messageSender) lockChannel(m shared.MetaContext) error {
	var teamRaw []byte
	var wrt, wvl, rrt, rvl int
	var prevSeq *int64
	err := s.tx.QueryRow(
		m.Ctx(),
		`SELECT parent_team_id, write_role_type, write_role_viz_level,
		        read_role_type, read_role_viz_level, last_msg_seq
		 FROM channels
		 WHERE short_host_id=$1 AND channel_id=$2
		 FOR UPDATE`,
		m.ShortHostID(),
		s.channelID(),
	).Scan(&teamRaw, &wrt, &wvl, &rrt, &rvl, &prevSeq)
	if err == pgx.ErrNoRows {
		return core.RowNotFoundError{}
	}
	if err != nil {
		return err
	}
	err = s.parentTeam.ImportFromDB(teamRaw)
	if err != nil {
		return err
	}
	err = s.writeRole.ImportFromDB(wrt, wvl)
	if err != nil {
		return err
	}
	err = s.readRole.ImportFromDB(rrt, rvl)
	if err != nil {
		return err
	}
	if prevSeq != nil {
		s.prevSeq = *prevSeq
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

func (s *messageSender) authorize(m shared.MetaContext) error {
	role, err := AuthorizeUserForTeam(m, s.userdb, s.parentTeam)
	if err != nil {
		return err
	}
	writeRole, err := core.ImportRole(s.writeRole)
	if err != nil {
		return err
	}
	if role.LessThan(*writeRole) {
		return core.PermissionError("user role too low to send into channel")
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
	seq int64,
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
		seq,
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

func (s *messageSender) run(m shared.MetaContext) (*rem.RTSendRes, error) {
	err := s.lockChannel(m)
	if err != nil {
		return nil, err
	}
	err = s.authorize(m)
	if err != nil {
		return nil, err
	}
	seq := s.prevSeq + 1
	// Optional optimistic-concurrency check from the client.
	if s.arg.ExpectedPrevSeq.IsValid() &&
		s.arg.ExpectedPrevSeq.Int64() != s.prevSeq {
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
	err = shared.RetryTx(m,
		rtdb,
		"realtime.SendMessage",
		func(m shared.MetaContext, tx pgx.Tx) error {
			s := messageSender{
				arg:    arg,
				sender: m.UID(),
				userdb: userdb,
				tx:     tx,
			}
			tmp, err := s.run(m)
			if err != nil {
				return err
			}
			res = tmp
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// loadChannelForRead returns the channel's parent team and read role, for
// authorizing a thread fetch.
func loadChannelForRead(
	m shared.MetaContext,
	db shared.Querier,
	channelID int64,
) (
	proto.TeamID,
	proto.Role,
	error,
) {
	var team proto.TeamID
	var readRole proto.Role
	var teamRaw []byte
	var rrt, rvl int
	err := db.QueryRow(
		m.Ctx(),
		`SELECT parent_team_id, read_role_type, read_role_viz_level
		 FROM channels
		 WHERE short_host_id=$1 AND channel_id=$2`,
		m.ShortHostID(),
		channelID,
	).Scan(&teamRaw, &rrt, &rvl)
	if err == pgx.ErrNoRows {
		return team, readRole, core.RowNotFoundError{}
	}
	if err != nil {
		return team, readRole, err
	}
	err = team.ImportFromDB(teamRaw)
	if err != nil {
		return team, readRole, err
	}
	err = readRole.ImportFromDB(rrt, rvl)
	if err != nil {
		return team, readRole, err
	}
	return team, readRole, nil
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

// readThread pulls one page of messages from messages_enc, joining
// channel_parties to recover sender attribution.
func readThread(
	m shared.MetaContext,
	db shared.Querier,
	q proto.RTThreadQuery,
) (
	[]rem.RTMsg,
	error,
) {
	max := q.Max
	if max == 0 || max > defaultThreadPage {
		max = defaultThreadPage
	}
	channelID := int64(q.ChannelID.Short())

	// Forward = ascending seq from `start` (inclusive); Backward = descending
	// seq from `start` (or the head when start==0).
	var sql string
	switch q.Dir {
	case proto.RTThreadDir_Backward:
		sql = threadMsgSelect + `
		       WHERE me.short_host_id=$1 AND me.channel_id=$2
		         AND ($3 = 0 OR me.seq <= $3)
		       ORDER BY me.seq DESC
		       LIMIT $4`
	default:
		sql = threadMsgSelect + `
		       WHERE me.short_host_id=$1 AND me.channel_id=$2
		         AND me.seq >= $3
		       ORDER BY me.seq ASC
		       LIMIT $4`
	}

	rows, err := db.Query(
		m.Ctx(),
		sql,
		m.ShortHostID(),
		channelID,
		int64(q.Start),
		int64(max),
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
	channelID int64,
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
		channelID,
		v,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreadMsgs(rows)
}

// GetThread fetches a page of messages from a channel, after checking that the
// authenticated user (m.UID()) is authorized to read it.
func GetThread(
	m shared.MetaContext,
	q proto.RTThreadQuery,
) (
	*rem.RTThreadPage,
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

	team, readRole, err := loadChannelForRead(m, rtdb, int64(q.ChannelID.Short()))
	if err != nil {
		return nil, err
	}
	role, err := AuthorizeUserForTeam(m, userdb, team)
	if err != nil {
		return nil, err
	}
	readRoleKey, err := core.ImportRole(readRole)
	if err != nil {
		return nil, err
	}
	if role.LessThan(*readRoleKey) {
		return nil, core.PermissionError("user role too low to read channel")
	}

	max := q.Max
	if max == 0 || max > defaultThreadPage {
		max = defaultThreadPage
	}
	msgs, err := readThread(m, rtdb, q)
	if err != nil {
		return nil, err
	}
	ret := rem.RTThreadPage{
		Msgs: msgs,
		// A short page means we reached the end of the requested range.
		Final: uint64(len(msgs)) < max,
	}
	return &ret, nil
}

// maxMsgsBySeq bounds a single rtGetMsgs request, so a client can't ask for an
// unbounded set of seqs in one round trip.
const maxMsgsBySeq = 512

// GetMsgs fetches an arbitrary set of messages by seq, after checking that the
// authenticated user (m.UID()) is authorized to read the channel. Used to fill
// holes between locally-cached messages and a paged remote fetch. Only found
// messages are returned; missing seqs are silently omitted.
func GetMsgs(
	m shared.MetaContext,
	arg rem.RTGetMsgsArg,
) (
	*rem.RTGetMsgsRes,
	error,
) {
	if len(arg.Seqs) > maxMsgsBySeq {
		return nil, core.BadArgsError("too many seqs requested")
	}

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

	team, readRole, err := loadChannelForRead(m, rtdb, int64(arg.ChannelID.Short()))
	if err != nil {
		return nil, err
	}
	role, err := AuthorizeUserForTeam(m, userdb, team)
	if err != nil {
		return nil, err
	}
	readRoleKey, err := core.ImportRole(readRole)
	if err != nil {
		return nil, err
	}
	if role.LessThan(*readRoleKey) {
		return nil, core.PermissionError("user role too low to read channel")
	}

	msgs, err := readMsgsBySeq(m, rtdb, int64(arg.ChannelID.Short()), arg.Seqs)
	if err != nil {
		return nil, err
	}
	return &rem.RTGetMsgsRes{Msgs: msgs}, nil
}
