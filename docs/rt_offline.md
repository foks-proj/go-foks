# RT Offline Mode

Design and implementation plan for offline support in the realtime (RT) chat
system: reading cached state with no connectivity, and queueing sends that
drain when connectivity returns.

This builds directly on the architecture in `chat-server-design.md`. The
inbox-versioning design there already anticipates the offline *read* case
("mainly used when the app is coming into the foreground, or when it's started
up after a period of being offline"), and much of it is built. This document
specifies the remaining read-side behavior and the entire write side, which is
currently a stub.

**Scope.** This plan began RT-only — thread reads, inbox sync, message
sends, and read-marks — and the design sections below keep that scope. The
"Cold-start bootstrap" section then extends the same verified-on-write
doctrine to the layers RT sits on (user, team, and host-identity loading),
strictly for *reads from verified local snapshots*. Offline *writes* outside
RT (team creation, membership changes, KV puts) remain out of scope: sigchain
links commit to current server state and cannot be sealed ahead of time and
drained later.

## Goals

- **Offline reads**: a client with no connectivity renders its inbox and any
  cached thread content, clearly distinguishable from fresh state. Partial
  cache coverage degrades to "what we have, flagged stale" rather than an
  error.
- **Offline writes**: a send attempted without connectivity is queued durably
  and drained on reconnect, exactly once, in per-channel order, surviving app
  restarts and crashes at any point in the pipeline.
- **Offline read-marks**: read-through positions advance locally offline and
  replay on reconnect.
- **Ad-hoc team compatibility**: the design accounts for ad-hoc teams' lazy
  PTK rotation (`chat-server-design.md`, Team Topology), even though Stage 1
  servers don't serve them yet.

## Non-Goals

- Offline *write* support outside RT. Reads of verified local snapshots are
  in scope (see "Cold-start bootstrap"); queueing non-RT writes is not.
- Conflict resolution beyond ordering. RT messages are append-only; there is
  nothing to merge.
- Offline channel *creation*. `MakeChannel` requires the server; queueing
  channel creation pulls in name-reservation races for marginal benefit.
- Attachment queueing (attachments are Stage 2b and live in the KV store).

## Current State

What exists today, verified against the code:

**Read side — largely built.**

- Inbox sync state (cursor + channel index) persists to local soft SQLite,
  pages applied atomically, crash-safe resume (`client/librt/inbox.go`).
  Ciphertext stays boxed at rest; decryption happens at render.
- Thread messages cache locally (`DataType_RTThreadMsgData`), and
  `GetThreadBookended` is cache-first: it computes holes and asks the server
  only for the bookends and gaps. A fully-cached range costs zero RPCs.
- `since=0` means full sync, inbox versions are monotonic, and the server
  never prunes `messages_enc`/`user_channels`/`user_inbox` — so a stored
  cursor cannot go stale today (see "Retention guard" below).

**Write side — a stub.**

- `Send` writes the sealed message to a local outbox row
  (`DataType_RTOutboxMsg`) *before* issuing `RtSend` — but nothing ever reads
  or deletes that row. There is no drain loop, no retry, and successful sends
  leave the row behind as an orphan. If `RtSend` fails, the error propagates
  to the caller and the queued row is dead weight.
- The outbox row is mis-keyed: `Key` is the channel ID with the send time
  (millisecond resolution) as the index, and the local DB upserts on
  `(scope, type, key, idx)`. Two sends into one channel in the same
  millisecond silently overwrite each other, and rows are not addressable
  individually for deletion. Any real outbox must key rows by `msgID`.
- `ReadThrough` is a bare RPC with no local persistence. Worse, the
  read-mark advance that `GetThreadView` issues after rendering a page is
  best-effort — on failure it logs a warning and drops the mark, so offline
  reading currently loses read state entirely.

**Server side — idempotency is half-built.**

- `messages_enc` has `UNIQUE(msg_id)` on the client-assigned 16-byte random
  message ID, so a retried send carrying the same `msgID` cannot double-insert.
  But `insertMessage` only special-cases the `messages_enc_pkey` conflict; a
  `msg_id` conflict surfaces as a generic database error the client cannot
  distinguish from failure — and the response does not carry the seq the
  message actually got.
- Prev-pointers are stored, never validated. The protocol comment on
  `RTMsgMetadata` already blesses `prevSeq`/`prevID` disagreeing ("the user is
  typing two messages rapidly"), which is exactly the queued-send situation.
  The only optimistic check is the client-opt-in `expectedPrevSeq`.

## Relation to the original design

This plan is a continuation of `chat-server-design.md`, not a fork of it: the
offline-read behavior implements that document's stated use case for inbox
versioning, client retries are anticipated there (`insertTime` "might be
later than sentAtTime if retries were needed"), D3 leans on its own
prev-pointer comment, and D6 executes its ad-hoc presend rule at drain time.
Two things here are genuinely new rather than derived:

1. **A client-side durable outbox.** The only outbox in the original design
   is the server's `push_outbox` for notifications; a persistent client-side
   send queue appears nowhere in it. Nothing there argues against one — it is
   this document's addition.
2. **Defined duplicate-send semantics.** `UNIQUE(msg_id)` exists in the
   schema, but the behavior on conflict is unspecified (today: a raw
   database error). D1 defines it as idempotent replay — filling a hole in
   the original design rather than overriding a choice it made.

## Design

### D1 — Idempotent replay on the server: duplicate `msg_id` returns the original result

`RtSend` becomes idempotent on `msgID`. When the insert hits the
`UNIQUE(msg_id)` constraint, the server loads the existing row and — after
verifying it matches the caller (same host, channel, and sender) — returns a
normal `RTSendRes` carrying the original seq and insert time, **unchanged in
shape**. No new response field: the caller that needs to know "was this a
replay?" is the drain loop, and it already knows it is retrying; nothing else
needs the distinction on the wire.

Avoiding the wire change is deliberate. Snowpack structs encode as
positional msgpack arrays (`codec:",toarray"` with per-field pointers), which
makes decoding a *shorter* old array safe (missing fields import as zero) but
leaves an *old* client decoding a server's *grown* array unproven. `RtSend`
responses flow server→client, the risky direction, and a chat server should
not require flag-day client upgrades. If a replay indicator ever becomes
worth having (metrics, CLI), it ships as an `rtSendV2` method rather than a
mutation of this response.

If the existing row does *not* match the caller (different host, channel, or
sender — either a client bug or a stray collision in a 16-byte random space),
the server returns a new status code `RT_MSG_REPLAY_MISMATCH` rather than
silently acking, wired through `status.snowp` and `lib/core/errors.go` in the
usual pattern.

Rationale for returning success rather than an error on a clean replay: the
client's question during a drain is "did my earlier attempt land?"; making the
common answer an error forces every drain implementation to catch and rewrite
it. True idempotency — same call, same result — is the simpler contract.

Implementation notes:

- A unique violation **aborts the enclosing Postgres transaction**, and
  `RetryTx2` correctly won't retry it (`pgconn.SafeToRetry` is false for
  constraint violations). The replay lookup therefore runs *after* the failed
  transaction rolls back, as a fresh read — it cannot be handled inline in
  `insertMessage`'s transaction. The lookup-then-return is safe without a
  lock: `messages_enc` rows are immutable once committed.
- The match check compares **host, channel, and sender** against the existing
  row. `UNIQUE(msg_id)` is global — it spans channels and virtual hosts — so
  without the host/channel comparison, a replay ack could be minted against a
  row the caller has no relationship to, and without the sender comparison, a
  channel member could "successfully replay" another member's message ID and
  treat the forged ack as their own delivery.
- Because the constraint is global, a mismatch necessarily reveals that the
  16-byte ID exists *somewhere*. That existence oracle is unavoidable given
  the schema, and unexploitable in practice (IDs are random in a 2^128
  space; an attacker can only learn IDs from channels they can already
  read). The mismatch error must still be a bare status — no channel, host,
  or sender detail from the existing row leaks in the response.

### D2 — Outbox lifecycle: queue → drain → ack → delete

The existing `dbPutMsgToOutbox` write becomes the head of a real pipeline:

1. **Queue.** `Send` seals the message, assigns `msgID`, and writes the
   outbox row (as today), keyed by channel with the send time as index.
   State advances to *queued*.
2. **Attempt.** The drain loop issues `RtSend`. Three outcomes:
   - **Ack** (fresh or replayed): write the message into the thread
     cache (as `Send` does today), then delete the outbox row. Delete strictly
     after the thread-cache put, so a crash between the two re-sends and hits
     the replay path — at-least-once attempts, exactly-once delivery.
   - **Transport error** (connection refused, timeout, TLS, DNS): leave the
     row queued; back off and retry. This is the offline case.
   - **Semantic rejection** (auth failure, channel gone, permanent server
     error): mark the row *failed* with the error, stop retrying it, surface
     to the caller/UI. Failed rows block nothing behind them (see ordering
     below) but are retained for the user to inspect/discard.
3. **Drain triggers.** Implemented: a send into a channel with queued rows
   (the no-queue-jumping flush), a successful inbox sync (proof of
   connectivity — this covers app-start and foreground cadence, since apps
   sync on both), and the explicit CLI drain/retry. Still future, at the app
   layer: a periodic backoff timer and a real connectivity signal. There is
   no standing inbox poll loop today (`PollInbox` is a single long-poll
   call); when one lands, its first success after a gap is another drain
   trigger.

**Ordering.** Per-channel FIFO by queue time. The drain sends one message per
channel at a time and does not advance past a row still in *queued* state —
otherwise a flaky link reorders a conversation. Distinct channels drain
concurrently. A *failed* row is the exception: it steps aside so one rejected
message doesn't block the rest of the channel (a manual retry of a
failed row after later messages have delivered is knowingly out of order).

**No queue-jumping.** The same rule binds the synchronous path: when a
channel has queued rows, a fresh `Send` into it must not race past them to
the server. It enqueues behind them, returns `RTMsgQueuedError`, and kicks
the drain — which, with connectivity restored, typically flushes the whole
channel including the new message within the same trigger.

**Caps.** When a channel's outbox is at capacity, `Send` fails fast with a
distinct error rather than dropping the oldest or newest row silently; the
caller decides what to shed.

**Restart recovery.** On start, every outbox row is either queued (drain will
retry) or failed (left for the user). No reconciliation against the thread
cache is needed — or practical, since the cache is keyed by seq, not `msgID`:
D1's replay protection means blindly re-draining a row whose original attempt
actually landed converges to the same seq via the replay path, at the cost of
one RPC. Rows written by pre-drain versions of the client (today's orphans)
are re-sent the same way and resolve as replays.

**`Send` return semantics.** Today `Send` is synchronous: RPC result or
error. It stays synchronous when connectivity is up. When the RPC fails with
a transport error, `Send` returns a new `RTMsgQueuedError` (status code
`RT_MSG_QUEUED`) carrying the `msgID` — not success, because the message has
no seq yet and callers must not assume ordering; not a plain failure, because
the message *will* be delivered. Callers that don't care can treat it as
soft-success; interactive clients use the `msgID` to render the pending
message and reconcile when the drain acks it.

### D3 — Prev-pointers on drained sends: already answered, one client fix

A message queued offline carries `prevSeq`/`prevID` frozen at queue time,
stale by the time it drains. No protocol change needed: the server stores
these unvalidated, and the `RTMsgMetadata` comment explicitly allows them to
disagree with reality. Queued sends never set `expectedPrevSeq` (it exists
for callers that *want* CAS semantics; a drain wants the opposite).

One client change: `SendWithTestHooks` currently errors (`RTMsgOrderError`)
if the acked seq is ≤ the last locally-seen seq. For a drained message that
check compares against a prev captured at queue time, which is exactly the
case the protocol permits — the drain path skips it. (The check remains for
the synchronous path, where it still catches genuine server misbehavior.)

### D4 — Read-side degradation: serve what we have, say that we did

`GetThreadBookended`, `GetThreadRecentMsgs`, and the inbox load each get a
uniform degraded mode: when the server RPC fails with a transport error *and*
the local cache has any relevant rows, return the cached subset with a
staleness indicator instead of the error.

Concretely, thread reads return a result carrying:

- the messages found in cache (holes and truncated bookends included),
- `stale: bool` — true when the server was needed and unreachable,
- the underlying transport error, for callers that want to distinguish
  "offline" from "healthy but empty".

An empty cache plus an unreachable server still returns the error — an empty
result would be indistinguishable from a genuinely empty thread. Pending outbox messages for the
channel are appended to thread reads (flagged as unacked) so the sender sees
their own queued messages, and inbox rows for channels with queued or failed
messages carry a pending count so list views can badge them.

The current signatures can't express this — `GetThreadBookended`'s boolean
already means "final in the paging direction" — so the thread-read family
moves to a small result struct (messages, final, stale, transport error)
rather than growing more positional returns.

The inbox path needs no protocol work — a failed `RtGetChangedThreads` leaves
the persisted snapshot in place; the change is to return that snapshot with
`stale=true` rather than propagating the error.

### D5 — Offline read-marks: last-writer-wins replay

`ReadThrough` gets the same treatment as sends, but simpler because
read-marks are idempotent and monotonic server-side (a stale mark is ignored,
never an error):

- The client persists the highest locally-read seq per channel
  (`DataType_RTReadThroughPending`, soft state).
- On transport failure the mark is queued; the drain replays only the
  highest pending seq per channel (intermediate marks are subsumed).
- On ack the pending row is deleted.

The natural insertion point already exists: `GetThreadView` advances the
read pointer after rendering a page and today drops the mark with a warning
on failure — that fallback becomes "persist as pending" instead of a log
line. Local unread computation must consult pending marks too, so a channel
read offline doesn't keep showing as unread on the same device until the
drain runs.

No ordering interaction with the message outbox; the two queues are
independent.

### D6 — Sealing time and ad-hoc teams

A queued message is sealed at *queue* time with the then-current PTK (that is
what the outbox stores today — the boxed wrapper, consistent with the rule
that plaintext never hits the local DB). Two cases:

**Regular teams.** PTK rotation happens on membership change. A message
sealed to gen N and drained after a rotation to N+1 is accepted (the server
stores `ptk_gen` per row and never validates it) and remains readable by
current members, who hold all prior gens. The one wrinkle: a member removed
during the offline window can still read a message sealed before their
removal. This matches the security semantics of a message *sent* before the
removal — which, from the sender's point of view, it was. Documented as
accepted behavior.

**Ad-hoc teams.** These rotate lazily *before message send* precisely so that
removals take effect at the next send. A drained message sealed pre-rotation
would silently skip that guarantee. So the drain performs the
rotate-if-needed check at *drain* time, exactly as a live send would, and if
the PTK has advanced past the sealed gen, the client **re-seals** before
sending: unbox with the stored gen (the sender holds it), re-box with the
current gen, regenerate the box under the same `msgID` and metadata. `msgID`
is assigned at queue time and never changes across re-seals, so replay
protection is unaffected.

The crypto mechanics check out for this: the message key is derived
per-(PTK seed, app, key-type) via `KeyMgr`, so a member re-derives any
generation they hold, and the secretbox nonce is domain-separated from the
noncer payload — re-boxing the same metadata under the new generation's key
reuses the nonce only across *different* keys, which is sound.

Re-sealing is the only part of this design that touches message crypto, and
it is confined to the ad-hoc drain path. Stage 1 servers don't serve ad-hoc
teams, so it can land as a later phase — but the outbox row format carries the
sealed gen from day one so no migration is needed.

### D7 — Connectivity classification, not a connectivity service

The design deliberately avoids a reachability oracle. "Offline" is defined
operationally: an RPC failed with a transport-class error. A helper
(`core.IsTransportError` or similar, shared with the drain loop) classifies
errors into transport vs. semantic; everything else in this document keys off
that classification plus the drain triggers in D2. If the platform later
grows a real connectivity signal, it becomes one more drain trigger — nothing
else changes.

This classifier is the main feasibility risk in the plan: the RPC stack
surfaces failures as a mix of net-level errors, TLS errors, and RPC-layer
timeouts, and misclassifying a semantic error as transport means an
undeliverable message retried forever (bounded by the attempt cap), while the reverse
means a deliverable message marked failed. The classifier must default to
**semantic** (fail fast, surface to the user) for anything unrecognized, and
its table should be built by enumerating the error paths in the client
transport code rather than by pattern-matching strings.

### Cold-start bootstrap (closed)

Everything above assumes the client can load its active user, which
originally required the network even from a warm disk. The user half of that
gap is now closed, by the same verified-on-write doctrine used everywhere
else in this design -- nothing is served from cache that was not fully
verified when it was written, and nothing new enters without verification:

- the host's public zone is cached after signature verification, and the
  probe rehydrates chain + zone when a network probe fails on transport;
- the reg-issued client-cert chain (public material only) is cached per key,
  so mTLS clients construct offline -- an expired chain just fails the
  handshake, which reads as offline;
- `PopulateWithDevkey` falls back to the merkle-verified local sigchain
  snapshot, and PUK parcels already decrypt from their local cache with the
  device key;
- the chain loader no longer retries transport failures on the merkle-race
  backoff schedule, so offline fallbacks engage immediately;
- a user whose device lacks these caches (never completed an online load)
  stays loaded-but-locked with the outage reported, exactly as before; and
  the CLI's parting nag check no longer fails an otherwise-successful
  command when the server is unreachable.

With that, a cold agent starts offline, unlocks its user, and serves
user-scoped state -- the outbox included. `TestRTOfflineCLIWalkthrough`
(integration-tests/cli) pins it end-to-end through the real CLI and agent.

**Team-scoped state from a cold start is closed too**, on two design
decisions confirmed with upstream before building (state them explicitly in
the proposal):

1. *Cached PTKs may be used offline without replaying links.* The snapshot
   (`lcl.TeamChainState`) was fully verified before it was written -- and it
   already persists the historical-sender records the unboxing checks need
   -- so rehydrating keyring + roster + sender history from it carries the
   verification forward; the next online load re-verifies as usual. Worst
   case it is stale (a rotation or removal during the offline window), which
   matches the semantics of a message sent just before that change.
2. *The view bearer token is not needed offline.* It exists to gate server
   resources; a token-less wrapper is correct for local-only work, and any
   server operation attempted with one meets its own transport error at its
   own RPC.

Mechanically: `LoadTeamFromCache` rehydrates a wrapper from the snapshot
(keyring, roster, historical senders; no token, no roster details), unboxing
the cached PTK parcels with the caller's PUKs against the snapshot's
post-roster; `TeamLoader.Run` falls back to it on transport failure, and the
minder builds a direct team record when offline exploration is impossible.
Name resolution survives cold starts through a persisted name -> team index
(`TeamNameLookup`), written through on every exploration and team load. The
PUK minder gained the same snapshot fallback as `PopulateWithDevkey`, since
parcel decryption is what opens the team keys.

With all of that, the full arc runs from a cold offline start through the
real CLI and agent -- resolve by name, seal with cached PTKs, queue, stale
reads with the pending overlay, stale inbox with its badge, survive another
offline restart, reconnect, drain, server-confirmed delivery --
pinned by `TestRTOfflineCLIWalkthrough` (integration-tests/cli); the
warm-process case keeps its own coverage in `TestRTOfflineNoHooks`.

Known limits, by design: ad-hoc team names are not in the persisted name
index, so an ad-hoc team cannot be resolved from a cold offline start (RT
ad-hoc channels are gated on upstream Stage 1c anyway); persisted name rows
are written through but never deleted, and are consulted only when
exploration is impossible, so a stale row can only ever be served offline —
the same verified-but-possibly-behind semantics as every snapshot; and team
*mutations* (membership edits, rotations) always require a fresh online
load, failing with connect-class errors offline.

### Retention guard (forward-compatibility note)

The offline read design assumes inbox cursors never go stale, which holds
because nothing prunes RT tables. If message retention/expiry is ever added,
the server must also add a "cursor too old" signal on
`RtGetChangedThreads` (e.g. a minimum-supported inbox version in the
response) so clients fall back to a full resync instead of silently missing
deletions. Recording the requirement here so retention work inherits it.

## Security Considerations

Collected here in addition to the inline notes:

- **Replay ack authenticity.** The replay path is the one place the server
  vouches "already delivered" without inserting anything; the host + channel
  + sender comparison in D1 is what keeps that vouch scoped to the caller's
  own message. A server that lies about a replay (wrong seq, or acking a
  message it never stored) can lose a message — but that is exactly the trust
  already extended to a normal `RtSendRes`, so offline mode adds no new
  server capability.
- **No plaintext at rest.** Outbox rows store the sealed wrapper, pending
  read-marks store a seq — the existing rule that message plaintext never
  hits the local DB is preserved. The failure envelope stores server error
  strings; server-controlled text lands in the local soft DB either way via
  cached metadata, so this adds no new class of stored content.
- **Removed-member window.** A message sealed before a removal and drained
  after it is readable by the removed member (regular teams, D6). This
  matches the meaning of "sent before the removal" and is documented rather
  than fought; ad-hoc teams, whose contract is stricter, get the re-seal.
- **Resource bounds.** The outbox is attacker-free but not failure-free: a
  client stuck offline must not grow state unboundedly, hence the
  per-channel cap. Reconnect drains use per-channel serialization plus
  jittered backoff, so a fleet reconnecting after a server outage doesn't
  synchronize its retries into a thundering herd.
- **Multi-device scope.** The outbox and pending read-marks are per-device
  soft state. Another device of the same user cannot see or drain them; a
  message queued on a lost device is lost with it. This is stated behavior,
  not a bug — cross-device outbox sync would require server-visible pending
  state, which is a privacy regression.
- **Staleness has no horizon.** `TeamChainState` records no time of
  verification, and no load path bounds a snapshot's age. Verified-on-write is
  sound, but "verified as of T" is only a meaningful claim when T is recorded,
  and it is not. Anyone able to drop packets can therefore hold a client on
  arbitrarily old team state for as long as they like, with nothing escalating:
  the client cannot distinguish a snapshot from an hour ago from one from last
  quarter, and neither can the person using it. The fallback triggers are
  correct; what is missing is the timestamp that would let a caller, a UI, or a
  future policy say "too old to serve". Recording one is cheap and additive;
  deciding what to do past a horizon (warn, refuse team reads, refuse sealing)
  is a product call worth making deliberately rather than by omission.
- **Cold-start offline removes an accidental liveness gate.** Before the
  cold-start work, a client that could not reach the server could not come up
  at all, so a stolen device that never reconnected was inert, and a
  revocation published while it was away would meet it on the way back in. It
  now unlocks and serves user- and team-scoped state with no network, and a
  revocation can never reach a device that never returns. This is defensible —
  the data was already on disk under keys the device holds, so at-rest
  encryption and device unlock are the real controls, and an attacker with both
  could always read the local DB directly — but that round trip was acting as a
  revocation check by accident, and its removal should be a stated consequence
  of the design rather than something discovered later.
- **A TLS failure is indistinguishable from airplane mode.** `IsTransportError`
  classifies `net.Error` as transport, which covers TLS handshake failures.
  That is right for retry purposes, and it grants a network attacker nothing
  that dropping packets does not already grant. But a repeated
  certificate-validation failure is evidence of an attack, not of a tunnel, and
  it currently renders as the same "offline" badge as a subway ride. It
  deserves its own log line and its own signal to the user; conflating the two
  spends the one chance to notice.
- **The name index is corroborated, not trusted.** Persisted name rows are
  written through but never deleted, so a row outlives whatever made it. No
  row can go wrong today — teams cannot be renamed, and the server refuses to
  reuse a dead name — but `names.reuse_id` and `name_reservations.dtime` exist
  so that policy can change, and the server comment says as much ("for now we
  are not allowing the reuse of dead names"). Were it enabled, a stale row
  would be a name resolving to the team that used to hold it, and offline that
  is not merely behind: resolution feeds the PTKs the message is sealed with,
  so a message meant for one audience would be encrypted for another. Offline
  resolution therefore corroborates each row against the team's own verified
  snapshot and refuses a row the snapshot contradicts. The check loads the team
  the way the offline path will rather than reconstructing the snapshot key,
  since the loader arg is hashed into that key and any drift would fail open
  silently. It fails open when no snapshot loads, which is safe: with no cached
  PTKs there is nothing to seal with, and the load fails on its own.

## Implementation Plan

Status: Phases 1-3 are built, hardened by a max-effort review pass
(idempotent replay extended to CAS callers; per-user outbox locking;
offline-capable channel resolution; deterministic-failure step-aside;
state-aware pending rendering), and covered by integration tests
(`TestRTSendIdempotentReplay`, `TestRTOutbox*`, `TestRTDegradedReads`,
`TestRTReadMarksOfflineQueueAndReplay`, `TestRTInboxPendingCount`). Phase 4
waits on ad-hoc channels existing end-to-end; the outbox row already stores
the sealed generation (inside the boxed wrapper), so no migration will be
needed.

Phased so each lands independently, in the staged-build spirit of
`chat-server-design.md` (this is effectively Stage 1f, before push work in
Stage 2a — the drain triggers are also where background-push wakeups will
eventually hook in).

### Phase 1 — Server: idempotent replay (small, unblocks everything)

1. Name the unique constraint (`messages_enc_msg_id_key`) explicitly in a
   schema patch so the error check isn't tied to an auto-generated name.
2. In `insertMessage`, catch the `msg_id` duplicate, load the existing row,
   verify host + channel + sender, and return the original seq/insert time in
   an unchanged `RTSendRes` — or `RT_MSG_REPLAY_MISMATCH` on a failed match.
3. New status codes `RT_MSG_REPLAY_MISMATCH` and `RT_MSG_QUEUED` (the latter
   is client-generated but lives in the shared status space) via
   `status.snowp` + `lib/core/errors.go`; regenerate proto.
4. Tests: same `msgID` twice → same seq and insert time, no second row; same
   `msgID` on a different channel → mismatch error; concurrent duplicate
   sends → one row, both callers get the same seq.

### Phase 2 — Client: outbox drain (the core)

1. New outbox row format under a **new `DataType`**: a state envelope
   (queued/failed + attempt count + last error) wrapping today's
   `RTMsgCached`, keyed by `msgID` with `(channel, queue time)` recoverable
   for FIFO ordering. This fixes the same-millisecond overwrite and makes
   rows individually deletable. Legacy `RTOutboxMsg` rows are ignored, not
   migrated: nothing ever drained them (each is either the orphan of an
   acked send or a failure the caller already observed), and their ranged
   keying leaves no way to delete them individually — wiping soft state
   clears them.
2. Refactor `SendWithTestHooks` (~140 lines, monolithic) into
   seal → queue → attempt → finalize stages, so the drain loop reuses
   attempt/finalize instead of duplicating the RPC, cache-put, and
   order-check logic. This is where the D3 order-check exemption lands
   naturally: the drain path calls finalize with replay tolerance.
3. Drain loop in `Minder`: per-channel FIFO, transport/semantic
   classification (shared helper, see D7), backoff with jitter, triggers per
   D2.
4. `Send`: on transport error, leave the row queued and return
   `RTMsgQueuedError{msgID}`; on ack (fresh or replay), thread-cache put then
   outbox delete — fixing the orphan-row leak as a side effect.
5. Startup: resume queued rows (blind re-drain; D1 makes it safe).
6. Tests (`minder_test.go` + test hooks): kill the transport mid-send and
   verify replay convergence; crash between ack and delete (row survives,
   re-drain converges, exactly one cache entry); two queued sends in the same
   millisecond both survive and both deliver; ordering under a flaky link;
   failed row doesn't block its channel; drain never sends while a prior
   same-channel row is in-flight.

### Phase 3 — Client: read-side degradation + read-marks

1. Stale-tolerant returns for thread reads and inbox load (D4), including
   pending-outbox overlay on thread views.
2. Pending read-through persistence and replay (D5).
3. `rt` CLI: surface staleness and queued counts (e.g. `rt inbox` marks
   stale, `rt outbox ls` lists queued/failed, `rt outbox retry`/`discard`
   for failed rows — the manual escape hatch the default-semantic error
   classification requires).

### Phase 4 — Ad-hoc drain path (when ad-hoc channels exist end-to-end)

1. Rotate-if-needed at drain time; re-seal on gen advance (D6).
2. Tests: queue → rotate (member removal) → drain re-seals with new gen;
   `msgID` stable across re-seal.

## Open Questions

- Should the server *validate* `ptk_gen` against the team's current
  generation window (rejecting gens that predate a removal by more than the
  lazy-rotation contract allows), or is storing it opaquely — the current
  behavior — the intended trust model? The design above assumes the latter.
- Backoff parameters and outbox caps (max queued messages per channel, max
  age before a queued row is declared failed) — proposed defaults: cap 256
  rows/channel, no age limit, backoff 1s→2m with jitter. Worth maintainer
  input before hard-coding.
- Whether a replay indicator is ever worth surfacing to clients (as an
  `rtSendV2`, per D1) or stays a server-side metric.
