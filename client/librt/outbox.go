// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package librt

import (
	"cmp"
	"errors"
	"slices"
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// The client-side durable outbox (docs/rt_offline.md, D2). A send is written
// here, sealed, before its first network attempt, and deleted only after the
// server's ack is reflected into the thread cache. Between those two points
// the message survives transport failures, process restarts, and crashes at
// any step: re-attempting is always safe because rtSend is idempotent on
// msgID (D1), so a retry of a send that actually landed converges to the
// original seq.
//
// Storage layout, all soft state under the party scope (the same scope as the
// thread cache):
//   - DataType_RTOutboxEntry, key = msgID: one lcl.RTOutboxEntry per queued or
//     failed message, holding the sealed proto.RTMsgCached exactly as it will
//     be sent. Plaintext never hits the local DB.
//   - DataType_RTOutboxIndex, key = EmptyKey: the index of entries plus the
//     monotonic queue-order allocator, since the KV layer can't enumerate keys
//     in a scope (the RTInboxSyncState pattern).
//
// Enqueue writes the entry row and the index in one DbPutTx. Removal deletes
// the row first and rewrites the index second, so a crash between the two
// leaves an index entry whose row is missing -- dropped, self-healing,
// whenever the drain or a listing next touches it, regardless of the entry's
// recorded state. The reverse order would leave an unreachable orphan row.
//
// Ordering is per-channel FIFO by ord. The drain sends one message per
// channel at a time and does not advance past a still-queued row; a failed
// row (semantic rejection) steps aside so it doesn't hold the channel
// hostage, and is retried only explicitly. Distinct channels drain
// concurrently.
//
// Locking: the outbox and pending read-mark singletons are PER-USER state,
// but Minder instances are not one-per-user -- librt.App keeps one Minder per
// team plus a user-scoped Minder. A mutex on the Minder therefore cannot
// serialize these read-modify-write cycles. outboxLocks hands out one
// process-wide mutex per party scope, shared by every Minder for that user.
var outboxLocks sync.Map // party-scope key (string) -> *sync.Mutex

func (d *Minder) outboxLock() *sync.Mutex {
	// FQParty holds slice-backed IDs, so it can't key a map directly; a
	// byte-string of party+host is an equivalent, hashable identity.
	fqp := d.au.FQParty()
	key := string(fqp.Party) + "@" + string(fqp.Host[:])
	v, _ := outboxLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// maxOutboxPerChannel bounds outbox rows per channel -- queued and failed
// alike, so a stream of rejections cannot grow state unboundedly. At
// capacity, sends fail fast with RTOutboxFullError rather than silently
// shedding a row.
const maxOutboxPerChannel = 256

// dbGetSingleton loads a singleton soft-DB row under the party scope,
// treating a missing row as the zero value. On any error the zero value is
// returned alongside it, so best-effort callers never consume a partially
// decoded struct.
func dbGetSingleton[T any, PT interface {
	*T
	core.Codecable
}](
	d *Minder,
	m MetaContext,
	typ lcl.DataType,
) (
	T,
	error,
) {
	var zero, ret T
	scope := d.au.FQParty()
	_, err := m.DbGet(PT(&ret), libclient.DbTypeSoft, &scope, typ, core.EmptyKey{})
	if errors.Is(err, core.RowNotFoundError{}) {
		return zero, nil
	}
	if err != nil {
		return zero, err
	}
	return ret, nil
}

func (d *Minder) dbPutSingleton(
	m MetaContext,
	typ lcl.DataType,
	val core.Codecable,
) error {
	scope := d.au.FQParty()
	return m.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scope,
		Typ:   typ,
		Key:   core.EmptyKey{},
		Val:   val,
	})
}

// dbGetOutboxIndex loads the outbox index; a missing row is an empty outbox.
// Callers mutating outbox state must hold d.outboxLock().
func (d *Minder) dbGetOutboxIndex(m MetaContext) (lcl.RTOutboxIndex, error) {
	return dbGetSingleton[lcl.RTOutboxIndex](d, m, lcl.DataType_RTOutboxIndex)
}

func (d *Minder) dbGetOutboxEntry(
	m MetaContext,
	msgID proto.RTMsgID,
) (
	*lcl.RTOutboxEntry,
	error,
) {
	var ret lcl.RTOutboxEntry
	scope := d.au.FQParty()
	_, err := m.DbGet(&ret, libclient.DbTypeSoft, &scope,
		lcl.DataType_RTOutboxEntry, msgID)
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// dbPutOutbox writes an entry row and the index atomically.
func (d *Minder) dbPutOutbox(
	m MetaContext,
	entry *lcl.RTOutboxEntry,
	idx *lcl.RTOutboxIndex,
) error {
	scope := d.au.FQParty()
	args := []libclient.PutArg{
		{
			Scope: &scope,
			Typ:   lcl.DataType_RTOutboxEntry,
			Key:   entry.Msg.Md.Md.MsgID,
			Val:   entry,
		},
		{
			Scope: &scope,
			Typ:   lcl.DataType_RTOutboxIndex,
			Key:   core.EmptyKey{},
			Val:   idx,
		},
	}
	return m.DbPutTx(libclient.DbTypeSoft, args)
}

func (d *Minder) dbPutOutboxEntry(m MetaContext, entry *lcl.RTOutboxEntry) error {
	scope := d.au.FQParty()
	return m.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scope,
		Typ:   lcl.DataType_RTOutboxEntry,
		Key:   entry.Msg.Md.Md.MsgID,
		Val:   entry,
	})
}

func (d *Minder) dbPutOutboxIndex(m MetaContext, idx *lcl.RTOutboxIndex) error {
	return d.dbPutSingleton(m, lcl.DataType_RTOutboxIndex, idx)
}

// enqueueOutbox durably queues a sealed message. It reports whether earlier
// rows are already queued for the same channel (in which case the caller must
// not race past them to the server -- no queue-jumping, D2). Fails fast with
// RTOutboxFullError at the per-channel cap, which counts queued and failed
// rows alike.
func (d *Minder) enqueueOutbox(
	m MetaContext,
	msgCached proto.RTMsgCached,
) (
	hasEarlier bool,
	err error,
) {
	lk := d.outboxLock()
	lk.Lock()
	defer lk.Unlock()

	chid := msgCached.Md.Chid
	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return false, err
	}
	nQueued, nAll := 0, 0
	for _, e := range idx.Entries {
		if e.Chid != chid {
			continue
		}
		nAll++
		if e.State == lcl.RTOutboxState_Queued {
			nQueued++
		}
	}
	if nAll >= maxOutboxPerChannel {
		return false, core.RTOutboxFullError{}
	}
	hasEarlier = nQueued > 0

	entry := lcl.RTOutboxEntry{
		Msg:   msgCached,
		State: lcl.RTOutboxState_Queued,
		Ord:   idx.NextOrd,
	}
	idx.Entries = append(idx.Entries, lcl.RTOutboxIndexEntry{
		MsgID: msgCached.Md.Md.MsgID,
		Chid:  chid,
		Ord:   idx.NextOrd,
		State: lcl.RTOutboxState_Queued,
	})
	idx.NextOrd++

	err = d.dbPutOutbox(m, &entry, &idx)
	if err != nil {
		return false, err
	}
	return hasEarlier, nil
}

// removeOutbox deletes a delivered or discarded entry: row first, index
// second, so a crash in between self-heals (see the layout comment above).
// Reports whether an index entry was actually removed.
func (d *Minder) removeOutbox(m MetaContext, msgID proto.RTMsgID) (bool, error) {
	lk := d.outboxLock()
	lk.Lock()
	defer lk.Unlock()
	return d.removeOutboxLocked(m, msgID)
}

func (d *Minder) removeOutboxLocked(m MetaContext, msgID proto.RTMsgID) (bool, error) {
	scope := d.au.FQParty()
	err := m.G().DbDelete(m.Ctx(), libclient.DbTypeSoft, &scope,
		lcl.DataType_RTOutboxEntry, msgID)
	if err != nil && !errors.Is(err, core.RowNotFoundError{}) {
		return false, err
	}
	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return false, err
	}
	removed := false
	kept := idx.Entries[:0]
	for _, e := range idx.Entries {
		if e.MsgID == msgID {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return false, nil
	}
	idx.Entries = kept
	return true, d.dbPutOutboxIndex(m, &idx)
}

// setOutboxState updates an entry after an attempt: attempts++, the error
// recorded, and the state mirrored into the index -- but the index (a
// singleton every reader scans) is rewritten only when the state actually
// changed.
func (d *Minder) setOutboxState(
	m MetaContext,
	msgID proto.RTMsgID,
	state lcl.RTOutboxState,
	attemptErr error,
) error {
	lk := d.outboxLock()
	lk.Lock()
	defer lk.Unlock()

	entry, err := d.dbGetOutboxEntry(m, msgID)
	if err != nil {
		return err
	}
	if entry == nil {
		return core.RowNotFoundError{}
	}
	stateChanged := entry.State != state
	entry.State = state
	entry.Attempts++
	if attemptErr != nil {
		entry.LastError = attemptErr.Error()
	} else {
		entry.LastError = ""
	}
	if !stateChanged {
		return d.dbPutOutboxEntry(m, entry)
	}
	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return err
	}
	for i := range idx.Entries {
		if idx.Entries[i].MsgID == msgID {
			idx.Entries[i].State = state
		}
	}
	return d.dbPutOutbox(m, entry, &idx)
}

// attemptSend issues the rtSend RPC for a sealed message. Everything the wire
// call needs travels inside the stored RTMsgCached, so the drain never has to
// re-resolve teams or channels.
func (d *Minder) attemptSend(
	m MetaContext,
	msgCached *proto.RTMsgCached,
) (
	*rem.RTSendRes,
	error,
) {
	arg := rem.RTSendArg{
		Md:   msgCached.Md.Md,
		Mw:   msgCached.Mw,
		Chid: msgCached.Md.Chid.Short(),
	}
	if d.testHooks != nil && d.testHooks.SendRPC != nil {
		return d.testHooks.SendRPC(m, arg)
	}
	_, cli, err := d.clientLocal(m.Base(), d.au)
	if err != nil {
		return nil, err
	}
	res, err := cli.RtSend(m.Ctx(), arg)
	if d.testHooks != nil && d.testHooks.MutateSendOutcome != nil {
		resp, err := d.testHooks.MutateSendOutcome(&res, err)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// finalizeAck reflects a server ack into the thread cache and removes the
// outbox row -- strictly in that order, so a crash in between re-sends and
// converges via the replay path rather than losing the message.
//
// prevSeq, when valid (nonzero), enables the fresh-send ordering check: an
// acked seq at or below the last locally-seen one is server misbehavior
// unless the cache proves it is a replay of this very msgID. The drain passes
// zero -- a drained message's prev pointers were frozen at queue time and the
// protocol explicitly permits them to be stale (D3). Either way, cache
// occupancy is validated BEFORE the msgID->seq LRU is touched, so a rejected
// ack cannot poison the mapping that later prev-pointer validations consult.
func (d *Minder) finalizeAck(
	m MetaContext,
	msgCached proto.RTMsgCached,
	res *rem.RTSendRes,
	prevSeq proto.RTMsgSeq,
) error {
	msgID := msgCached.Md.Md.MsgID
	chid := msgCached.Md.Chid

	cached, err := dbGetMsgs(m, d.au, chid, res.Seq, res.Seq)
	if err != nil {
		return err
	}
	isReplay := len(cached) == 1 && cached[0].Cm.Md.Md.MsgID == msgID
	if len(cached) == 1 && !isReplay {
		return core.RTMsgOrderError(
			"server acked a sequence already held by a different message",
		)
	}
	if prevSeq.IsValid() && res.Seq <= prevSeq && !isReplay {
		return core.RTMsgOrderError(
			"sent message has sequence at or below the last seen",
		)
	}

	err = d.cacheMsgID(res.Seq, msgID)
	if err != nil {
		return err
	}
	if !isReplay {
		// A replay's cached copy is the delivered original, validated on
		// ingest; keep it rather than overwriting with this attempt's re-seal.
		msgCached.Sit = res.InsertTime
		err = d.dbPutMsgs(m, []proto.RTMsgCachedWithSeq{{
			Cm:  msgCached,
			Seq: res.Seq,
		}})
		if err != nil {
			return err
		}
	}

	_, err = d.removeOutbox(m, msgID)
	return err
}

// DrainResult reports what a drain pass did.
type DrainResult struct {
	// Acked maps each delivered msgID to its server result (fresh or replay).
	Acked map[proto.RTMsgID]*rem.RTSendRes
	// Failed lists msgIDs marked Failed this pass; FailedErrs carries the
	// error each one failed with.
	Failed     []proto.RTMsgID
	FailedErrs map[proto.RTMsgID]error
	// TransportErr is the first transport-level failure, if the pass ended
	// early because the server was unreachable; the remaining rows stay
	// queued.
	TransportErr error
}

func (r *DrainResult) noteFailed(mu *sync.Mutex, msgID proto.RTMsgID, err error) {
	mu.Lock()
	defer mu.Unlock()
	r.Failed = append(r.Failed, msgID)
	r.FailedErrs[msgID] = err
}

func (r *DrainResult) noteTransport(mu *sync.Mutex, err error) {
	mu.Lock()
	defer mu.Unlock()
	if r.TransportErr == nil {
		r.TransportErr = err
	}
}

// snapshotQueue groups the current index's queued entries by channel, in ord
// (FIFO) order. Only the small index rows are copied under the lock; the
// sealed message rows are fetched lazily by the drain, right before each
// attempt.
func (d *Minder) snapshotQueue(
	m MetaContext,
	only *proto.RTChannelID,
) (
	map[proto.RTChannelID][]lcl.RTOutboxIndexEntry,
	error,
) {
	lk := d.outboxLock()
	lk.Lock()
	defer lk.Unlock()

	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return nil, err
	}
	ret := make(map[proto.RTChannelID][]lcl.RTOutboxIndexEntry)
	for _, e := range idx.Entries {
		if only != nil && e.Chid != *only {
			continue
		}
		if e.State != lcl.RTOutboxState_Queued {
			continue
		}
		ret[e.Chid] = append(ret[e.Chid], e)
	}
	for _, entries := range ret {
		slices.SortFunc(entries, func(a, b lcl.RTOutboxIndexEntry) int {
			return cmp.Compare(a.Ord, b.Ord)
		})
	}
	return ret, nil
}

// drainChannelRows walks one channel's queued rows in FIFO order. A transport
// error stops the channel (everything behind stays queued for the next
// trigger); a semantic rejection -- from the server, or from a deterministic
// finalize failure like a seq/msgID conflict -- marks the row Failed and
// steps past it, so one poisoned message doesn't hold the channel hostage.
//
// Each row is re-read just before its attempt: an entry discarded or retried
// concurrently since the snapshot is skipped, and a snapshot entry whose row
// is missing (a crash between an ack's row delete and its index rewrite) is
// self-healed out of the index.
func (d *Minder) drainChannelRows(
	m MetaContext,
	rows []lcl.RTOutboxIndexEntry,
	res *DrainResult,
	mu *sync.Mutex,
) {
	for _, ie := range rows {
		msgID := ie.MsgID
		entry, err := d.dbGetOutboxEntry(m, msgID)
		if err != nil {
			// An unreadable row must not brick the drain for every healthy
			// message behind and beside it; skip it and keep going.
			m.Warnw("drainChannelRows", "stage", "load", "err", err)
			continue
		}
		if entry == nil {
			_, err = d.removeOutbox(m, msgID)
			if err != nil {
				m.Warnw("drainChannelRows", "stage", "selfHeal", "err", err)
			}
			continue
		}
		if entry.State != lcl.RTOutboxState_Queued {
			continue
		}

		ack, err := d.attemptSend(m, &entry.Msg)
		if err != nil {
			if core.IsTransportError(err) {
				_ = d.setOutboxState(m, msgID, lcl.RTOutboxState_Queued, err)
				res.noteTransport(mu, err)
				return
			}
			_ = d.setOutboxState(m, msgID, lcl.RTOutboxState_Failed, err)
			res.noteFailed(mu, msgID, err)
			continue
		}
		err = d.finalizeAck(m, entry.Msg, ack, 0)
		if err != nil {
			if core.IsTransportError(err) {
				// Local bookkeeping hiccup; the ack landed server-side. Leave
				// the row queued -- the next drain replays and converges.
				res.noteTransport(mu, err)
				return
			}
			// Deterministic finalize failure (e.g. the ack conflicts with the
			// validated cache). Re-attempting can only repeat it, so step
			// aside as Failed rather than wedging the channel forever.
			_ = d.setOutboxState(m, msgID, lcl.RTOutboxState_Failed, err)
			res.noteFailed(mu, msgID, err)
			continue
		}
		mu.Lock()
		res.Acked[msgID] = ack
		mu.Unlock()
	}
}

// Drain attempts every queued outbox row, distinct channels concurrently,
// each channel strictly FIFO, then replays any pending read-marks. Safe to
// call at any time and from any trigger (an inbox sync, an explicit CLI
// drain, a send): a row whose earlier attempt actually landed resolves as a
// replay. Concurrent drains of the same row are likewise convergent, if
// wasteful.
func (d *Minder) Drain(m MetaContext) (*DrainResult, error) {
	return d.drain(m, nil)
}

// DrainChannel is Drain for a single channel.
func (d *Minder) DrainChannel(
	m MetaContext,
	chid proto.RTChannelID,
) (
	*DrainResult,
	error,
) {
	return d.drain(m, &chid)
}

func (d *Minder) drain(
	m MetaContext,
	only *proto.RTChannelID,
) (
	*DrainResult,
	error,
) {
	snapshot, err := d.snapshotQueue(m, only)
	if err != nil {
		return nil, err
	}
	res := &DrainResult{
		Acked:      make(map[proto.RTMsgID]*rem.RTSendRes),
		FailedErrs: make(map[proto.RTMsgID]error),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, rows := range snapshot {
		wg.Add(1)
		go func(rows []lcl.RTOutboxIndexEntry) {
			defer wg.Done()
			d.drainChannelRows(m, rows, res, &mu)
		}(rows)
	}
	wg.Wait()

	// Read-marks queued while offline replay on the same triggers (D5).
	err = d.drainPendingMarks(m, only)
	if err != nil {
		if core.IsTransportError(err) {
			res.noteTransport(&mu, err)
		} else {
			m.Warnw("drain", "stage", "pendingMarks", "err", err)
		}
	}
	return res, nil
}

// hasOutboxWork reports whether a drain has anything to do: queued rows or
// pending read-marks. Used by drain triggers to skip the pass cheaply.
func (d *Minder) hasOutboxWork(m MetaContext) bool {
	idx, err := d.dbGetOutboxIndex(m)
	if err == nil {
		for _, e := range idx.Entries {
			if e.State == lcl.RTOutboxState_Queued {
				return true
			}
		}
	}
	marks, err := d.dbGetPendingMarks(m)
	return err == nil && len(marks.Entries) > 0
}

// loadOutboxRowsLocked resolves the index to its live entry rows in queue
// order, applying the shared enumeration policy: self-heal index entries
// whose row is missing (any state), and skip -- with a warning, without
// aborting -- rows that fail to load. Callers must hold d.outboxLock().
func (d *Minder) loadOutboxRowsLocked(
	m MetaContext,
	only *proto.RTChannelID,
) (
	[]lcl.RTOutboxEntry,
	error,
) {
	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return nil, err
	}
	var ret []lcl.RTOutboxEntry
	for _, e := range idx.Entries {
		if only != nil && e.Chid != *only {
			continue
		}
		entry, err := d.dbGetOutboxEntry(m, e.MsgID)
		if err != nil {
			m.Warnw("loadOutboxRows", "stage", "load", "err", err)
			continue
		}
		if entry == nil {
			_, err = d.removeOutboxLocked(m, e.MsgID)
			if err != nil {
				return nil, err
			}
			continue
		}
		ret = append(ret, *entry)
	}
	slices.SortFunc(ret, func(a, b lcl.RTOutboxEntry) int {
		return cmp.Compare(a.Ord, b.Ord)
	})
	return ret, nil
}

// ListOutbox returns every outbox entry, queued and failed, in queue order.
func (d *Minder) ListOutbox(m MetaContext) ([]lcl.RTOutboxRowView, error) {
	lk := d.outboxLock()
	lk.Lock()
	defer lk.Unlock()

	entries, err := d.loadOutboxRowsLocked(m, nil)
	if err != nil {
		return nil, err
	}
	var ret []lcl.RTOutboxRowView
	for _, e := range entries {
		ret = append(ret, lcl.RTOutboxRowView{
			MsgID:     e.Msg.Md.Md.MsgID,
			Chid:      e.Msg.Md.Chid,
			Ord:       e.Ord,
			State:     e.State,
			Attempts:  e.Attempts,
			LastError: e.LastError,
			SendTime:  e.Msg.Md.Md.SendTime,
		})
	}
	return ret, nil
}

// RetryOutbox re-queues a Failed entry (the manual escape hatch for a
// misclassified or transient rejection) and drains its channel. A retried
// message delivers after anything younger that already went out -- knowingly
// out of order.
func (d *Minder) RetryOutbox(
	m MetaContext,
	msgID proto.RTMsgID,
) (
	*DrainResult,
	error,
) {
	entry, err := d.dbGetOutboxEntry(m, msgID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, core.RowNotFoundError{}
	}
	err = d.setOutboxState(m, msgID, lcl.RTOutboxState_Queued, nil)
	if err != nil {
		return nil, err
	}
	return d.DrainChannel(m, entry.Msg.Md.Chid)
}

// DiscardOutbox drops an entry without sending it. A msgID that names no
// entry is an error, so a typo never reports success. Note the narrow race
// this cannot close: a drain that already passed its pre-attempt state check
// may have the row's RPC in flight (the window is one in-flight call, not a
// whole pass).
func (d *Minder) DiscardOutbox(m MetaContext, msgID proto.RTMsgID) error {
	// Ask whether the row exists before removing it. The index is the wrong
	// thing to judge by on its own: a crash between an earlier ack's row
	// delete and its index rewrite leaves a row the index has lost, and
	// discarding that row is real work that must not report "not found".
	// The delete itself cannot answer -- it is a plain DELETE, silent about
	// whether it matched -- so the read has to come first. It costs one
	// lookup on a rare, user-initiated path.
	entry, err := d.dbGetOutboxEntry(m, msgID)
	if err != nil {
		return err
	}
	removed, err := d.removeOutbox(m, msgID)
	if err != nil {
		return err
	}
	if !removed && entry == nil {
		return core.RowNotFoundError{}
	}
	return nil
}

// pendingMsgViews decrypts the viewer's own undelivered outbox messages for
// one channel into app-layer views, in queue order, with seq 0 (unassigned)
// and the entry's state attached so the UI can distinguish awaiting-delivery
// from rejected. The sender's own name is attached directly; no team-mediated
// resolution is needed for one's own messages.
func (d *Minder) pendingMsgViews(
	m MetaContext,
	rtp *RTParty,
	appID proto.RTAppID,
	chid proto.RTChannelID,
) (
	[]lcl.RTPendingMsgView,
	error,
) {
	entries, err := func() ([]lcl.RTOutboxEntry, error) {
		lk := d.outboxLock()
		lk.Lock()
		defer lk.Unlock()
		return d.loadOutboxRowsLocked(m, &chid)
	}()
	if err != nil {
		return nil, err
	}

	selfName := d.au.Info.Username.NameUtf8
	var ret []lcl.RTPendingMsgView
	for _, e := range entries {
		body, _, err := d.openMessage(m, rtp, appID,
			e.Msg.Md.Md, e.Msg.Mw, e.Msg.Md.Sender, e.Msg.Sit, chid)
		if err != nil {
			m.Warnw("pendingMsgViews", "stage", "open", "err", err)
			continue
		}
		mv := lcl.RTMsgView{
			MsgID:      e.Msg.Md.Md.MsgID,
			PrevID:     e.Msg.Md.Md.PrevID,
			PrevSeq:    e.Msg.Md.Md.PrevSeq,
			Typ:        e.Msg.Md.Md.Typ,
			SentAtTime: e.Msg.Md.Md.SendTime,
			Body:       body,
			SenderName: &selfName,
		}
		if e.Msg.Md.Sender != nil {
			mv.Sender = &e.Msg.Md.Sender.Party
		}
		ret = append(ret, lcl.RTPendingMsgView{Msg: mv, State: e.State})
	}
	return ret, nil
}

// outboxCounts tallies the viewer's queued and failed outbox messages per
// channel, for inbox badging.
func (d *Minder) outboxCounts(m MetaContext) (
	queued map[proto.RTChannelID]uint64,
	failed map[proto.RTChannelID]uint64,
	err error,
) {
	idx, err := d.dbGetOutboxIndex(m)
	if err != nil {
		return nil, nil, err
	}
	queued = make(map[proto.RTChannelID]uint64)
	failed = make(map[proto.RTChannelID]uint64)
	for _, e := range idx.Entries {
		if e.State == lcl.RTOutboxState_Failed {
			failed[e.Chid]++
		} else {
			queued[e.Chid]++
		}
	}
	return queued, failed, nil
}
