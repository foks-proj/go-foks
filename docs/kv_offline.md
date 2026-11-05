# Offline KV

How the KV store serves directory and file reads with no network, and how a
put made offline reaches the server later.

This is the third of the three offline tracks. `offline_verified_reads.md`
covers identity and teams — host zone, the user's sigchain, team snapshots,
keyring and name resolution — and establishes the trust model the other two
inherit. `rt_offline.md` covers realtime chat. This document covers the KV
store, which is independent of both: it sits on the same party keys as chat
but shares none of its transport, and it has its own coherence protocol that
neither of the other two has.

**Status.** Phases 1 and 2 are built: offline reads, and a durable write
outbox for small files, symlinks, `mkdir` and `unlink` with a CAS-checked
drain. Phase 3 (the conflict affordance) waits on the two product questions
below; Phase 4 (cache warming) is untouched. What each phase actually landed,
and what is still open inside it, is recorded against that phase in
"Implementation plan".

The other two offline tracks -- identity/teams and realtime chat -- are
specified in their own documents and land on their own schedule. This one
needs the transport classifier they share, and nothing else from them.

## Where this fits

| Track | Covers | Specified in | State |
|---|---|---|---|
| Identity and teams | host identity, cert chain, user sigchain, team snapshot, keyring, roster, names | `offline_verified_reads.md` | built, not yet proposed |
| Realtime chat | thread reads, inbox sync, send outbox, read-marks | `rt_offline.md` | built, not yet proposed |
| KV store | directory and file reads, queued writes | **this document** | Phases 1-2 built |

The three are independent bodies of work sharing one piece: the transport
classifier that decides what counts as "the server is unreachable". Nothing
below assumes anything else from the other tracks.

KV depends on the identity track and not the reverse: a KV operation needs a
loaded party and its current KV-store key, which is what an offline team or
user load supplies. It does not depend on chat, and chat does not depend on
it — attachments will one day live in KV, but that is Stage 2b and is not in
scope here.

That dependency bounds *when* offline KV helps, not whether it can be built.
An agent that loaded its party while online and then lost the network gets the
full benefit of Phase 1 with no identity work at all, because the party is
already in memory. Only the cold start — agent restarted, no network —
needs the identity track first. So Phase 1 is worth building on its own
schedule, and its tests should cover the warm case, which is the one it can
actually exercise today.

The distinctive thing about KV, and the reason the read half of this track is
cheaper than it looks, is that **it already has a cache-coherence protocol**.
Identity and chat each had to invent one. KV's has been in the protocol since
the store shipped; what is missing is a defined behaviour when the network is
gone.

The write half is *not* cheaper, and for a reason specific to KV: its dirents
are keyed to the parent directory's key material, which rotates independently
of everything else. That is what D4 is about, and it is the substantive
difference between this design and the chat outbox.

## Scope

**In scope:**

- Serving KV reads — stat, list, read of small files and symlinks, read of
  cached large-file chunks — from the local cache when the server is
  unreachable.
- A durable outbox for writes composed offline, and the drain that retires it.
  This covers every operation that is a dirent write: put of a small file or
  symlink, `mkdir`, and `unlink` — which is itself a dirent edit to a
  tombstone value (`unlinkInner` calls `edit(m, Tombstone(), …)`), so deletes
  need no separate machinery.
- Conflict handling when a drained write loses its CAS race.

**Not in scope:**

- Anything in the identity track. Loading the party, its keys, and its team
  snapshot is `offline_verified_reads.md`'s subject; this document assumes a
  loaded party and inherits its trust model wholesale.
- The staleness-horizon *policy*. `offline_verified_reads.md` proposes gating
  the production of new ciphertext rather than reads, dated from a
  `verifiedAt`-style stamp. KV adopts that policy if and when it lands; it does
  not define a second one, and it does not block on it — see D7 and D12.
- **A full-library mirror, and any search index over it.** Both want a
  per-FS change feed — "what changed since version X" — which the store does
  not have and which the version vector cannot supply (see "Discovery, and why
  it is not here"). That is a separate proposal.
- **Merkle sub-trees.** `kv_store.md` designs them; nothing implements them.
  They are the store's rollback protection and their absence is discussed
  under "Security considerations", but building them is a security workstream
  of its own and is not a precondition for this one.
- Queued *large-file* uploads. Large files upload chunk-by-chunk through a
  server-side `uploading` state machine with its own quota accounting;
  queueing that is a resumable-upload problem, not an outbox problem. Offline
  large-file *reads* from cached chunks are in scope; offline large-file
  writes are not.
- **`mv`.** A rename is two dirent writes with no transaction spanning them,
  so queueing it offline can leave a file linked twice or not at all. It wants
  its own treatment once single-dirent writes are proven.
- Offline `mkfs`, quota and credit allocation, and lock acquisition
  (`kvLockAcquire`), all of which are inherently server-side.

## What is built

Verified against the code. KV's read path is further along than the other two
tracks were at the same point, because the caching was built for latency and
happens to be most of what offline needs.

| Piece | Where | State |
|---|---|---|
| Disk-backed client cache | `libclient.CacheSettings{UseMem: true, UseDisk: true}`, `client/libkv/minder.go` | built |
| Cached types | root, dir (with its key seeds), dirent, symlink, small file, large-file metadata, chunks | built |
| Coherence protocol | `PathVersionVector` precondition on `KVReqHeader`; `kvCacheCheck`; `KV_STALE_CACHE_ERROR` carrying the server's current vector | built |
| Operate-then-validate | `client/libkv/retry.go` — the operation runs against the cache accumulating touched versions, one `KvCacheCheck` at the end confirms or invalidates | built |
| Precise invalidation | `clearCaches` walks the returned vector and clears exactly the stale root/dir/dirent entries, then retries | built |
| Authenticity | binding MACs verified client-side on root, dirent and list paths (`VerifyError("binding mac")`) | built |
| Rotation tolerance on read | `DirSeedPair{Active, Encrypting}` and `KVNodePathMultiple` — a lookup can carry the same name MAC'd under both the old and new dir key | built |
| Validation bypass | `SkipCacheCheck`, used by the git adapter because git objects are immutable | built |
| Transport classifier | `core.IsTransportError` | built (identity track) |

The shape worth noticing is in `retry.go`. A KV operation does **not** fetch
per node from the server; it runs to completion against the local cache,
recording a `PathVersionVector` of everything it touched, and then makes a
single `KvCacheCheck` call. If the server agrees, the result stands. If it
returns `KV_STALE_CACHE_ERROR`, the client clears exactly the named entries
and runs the operation again.

So a warm-cache read already executes entirely locally. **The only thing it
needs the network for is permission to believe itself.**

## What is missing

- ~~A transport failure at the validation call is fatal.~~ **Closed (Phase 1
  built).** The cache-race loop now serves a completed read when only the
  closing validation fails on transport, marked `Stale` on the result
  (`KVStat`, `CliKVListRes`, `GetFileRes`); write paths stay strict. Pinned by
  `TestKVOfflineReads` (integration-tests/lib), hookless via the network
  conditioner.
- **The cache is demand-filled.** Nothing warms it; offline coverage is
  exactly what the user happened to browse while online, and a cold client
  has nothing.
- ~~There is no outbox.~~ **Closed (Phase 2 built, mkdir excepted).** Writes
  seal before their first RPC; a transport failure at the node upload or the
  dirent put queues the sealed intent and returns `KVWriteQueuedError`
  (`client/libkv/outbox.go`). See the Phase 2 status below for what landed
  and what remains.

## Discovery, and why it is not here

The version vector answers "is what I already hold still current?" It cannot
answer "what else is there?" or "what changed while I was away", because it is
built from the client's own cache contents — an entry the client has never
seen contributes nothing to the vector and so cannot be reported stale.

Every ambition beyond serving a warm cache runs into this. A full local mirror
must be built by walking every directory, and kept current by walking them
again; there is no incremental delta. A search index over the whole store
needs that mirror first, because values are end-to-end encrypted and the
server can never index content. Both are therefore gated on a change feed the
store does not have — the KV analogue of the inbox versioning chat already
has.

That feed is worth designing. It is not designed here, and this document is
deliberately built to not need it: everything below works on the cache the
client already has.

## Design decisions

### D1 — A validation call that fails on transport serves the cached result, marked stale

The classification already exists (`core.IsTransportError`, from the identity
track). The retry loop learns one new branch: an operation that completed
against the cache, whose `flush()` then failed on transport rather than on
staleness, returns its result with a staleness marker instead of an error.
`KV_STALE_CACHE_ERROR` keeps its current meaning and its clear-and-retry path
untouched.

The marker rides on the result, not the error, for the same reason it does in
chat: callers that do not care should not have to catch anything, and callers
that do — a UI badge, a CLI banner — need the fact, not a failure.

This is the whole of the read change. No protocol change, no server change.

### D2 — An operation that misses the cache offline fails; it does not partially succeed

D1 covers the case where the operation *completed* and only validation failed.
When the operation itself needs a node the cache does not hold, its own RPC
fails, and that error stands. A `stat` of an uncached path is an outage, not
an empty result.

Directory listings are served whole or not at all. `kvList` is paginated, and
synthesizing a page boundary the server never produced would let a partial
cache render as a short but complete-looking directory. A directory whose
cached pages do not cover the requested range reports the outage.

The rule generalizes: **an empty or short result is never synthesized from an
absent cache.** Only content the cache actually holds is served.

### D3 — The outbox stores intent, not a prepared dirent

This is the decision D4 forces, stated first because it shapes the row format.

A queued write records: the parent directory, the name (see below), the
client-chosen node ID, the sealed content, the requested roles, the operation
(link or tombstone), and **the dirent version observed at queue time**. It
does *not* record a prepared `KVDirent`, because by D4 the prepared form
cannot survive the window it is queued for.

The name needs care. The local database stores values msgpack-encoded and
**not encrypted** (`core.EncodeToBytes` in `DB.PutTx`), which is exactly why
the chat inbox insists that plaintext never reaches it. A queued name must
therefore not be stored in the clear. It is stored sealed under the party's
KV-store key bundle — which the client holds, and which is independent of the
directory key that D4 is about — so the drain can open it and re-derive
whatever the current directory key requires.

Content is already sealed at queue time under the party key for the read role,
recording its `RoleAndGen`, exactly as a live put would seal it.

### D4 — The dirent is prepared at drain, because directory rotation re-keys it

**This is the KV analogue of `rt_offline.md` D6, and unlike that one it is a
correctness requirement rather than a security refinement.**

In chat, a queued message sealed to an old PTK generation is refused by the
server and re-sealed by the sender under the newest generation, which it holds
along with every older one (`docs/rt_offline.md`, D6).

KV is not like that. A dirent is bound to its parent directory's key material
in three separate places:

- the **name MAC**, which is how every reader and the server's own
  `dirent_name_idx` find the entry,
- the **name box**, sealed with the dir key (`SealNameIntoBox` derives both
  the nonce and the box key from `DirKeys`),
- the **binding MAC**, computed under `newKb`, documented in
  `lookupDirentRes` as "always the KeyBundle of the newer parent directory".

A directory rotation re-rolls that seed and, per `kv_store.md`, "everything
encrypted or MAC'ed with keys derived from the old seed must be re-encrypted
and re-MACed": every dirent is rewritten under the new key with an incremented
version, and the old `dir` row is then deleted.

So a dirent prepared before a rotation and drained after it is not merely
stale. It is:

- **unwritable** once the rotation has finished — its `dirVersion` references
  a `dir` row that rotation's final step deleted, and the `dirent` table's
  foreign key onto `dir(…, version)` refuses the insert; and
- **invisible if it were written** — its name MAC was computed under the
  retired key, so no reader using the current key would ever compute that MAC
  and find it.

The two halves do not fail at the same time, which is the trap. Rotation
inserts the new `dir` row (step 3) well before it deletes the old one (step
5), so for the whole span of a large directory's rotation **both rows exist
and the foreign key is satisfied**. A drain that relies on the FK to tell it
something changed would, inside that window, write a perfectly valid row that
no current reader can find. Detection therefore cannot rest on the foreign
key; D12 says what it rests on instead.

Failing closed is the right behaviour and it is what would happen, but the
user's write would be stuck forever with nothing wrong with it. Hence: the
drain loads the parent directory as a live put would, and prepares the dirent
there and then — name MAC, name box, version, `dirVersion` and binding MAC all
derived from whatever key material is current at drain time.

**Re-preparation is about keys, not about concurrency.** The drain re-derives
the crypto, but it does *not* adopt the current version as its own
expectation — that would silently overwrite whatever landed during the window.
The queue-time version recorded in D3 remains the CAS predicate, and a
mismatch is a conflict under D5. Keeping these two apart is the whole subtlety
of the decision: one is "which key am I speaking", the other is "what did I
think I was replacing".

Two consequences worth stating:

- Rotation tolerance already exists on the read path (`DirSeedPair`,
  `KVNodePathMultiple` carrying a name MAC'd at two dir versions), so the
  drain is reusing an understood mechanism rather than inventing one.
- Two queued writes to the same path serialize naturally: the first drains and
  bumps the version, the second re-prepares against the result and finds its
  queue-time expectation no longer matches — a conflict, correctly, because
  the user really did write twice from a stale view.

### D5 — Idempotency is established by node ID, not by the binding MAC

An ambiguous failure — the write landed, the ack was lost — must be
distinguishable from a genuine conflict, and D4 rules out the obvious test.
Comparing binding MACs works only when nothing rotated, since re-preparation
changes the MAC by construction.

The stable identity is the **node ID**. It is client-generated (`newNodeID`),
random over 16 bytes, fixed at queue time, and carried verbatim in the
dirent's `value` field through any amount of re-preparation. So on a CAS
failure the drain fetches the current dirent and inspects its `value`:

- **`value` equals the queued node ID** — this client's own write already
  landed. Retire the entry as delivered.
- **`value` differs** — a genuine conflict. D6.

For a tombstone (unlink) the same test reads the other way: a dirent whose
value is already the tombstone is our own delete, landed.

The comparison is free: `value` is part of the dirent the drain already
fetched, and the binding MAC over it was already verified on the way in. Where
no rotation occurred, the binding MAC still works as a corroborating fast
path, but nothing depends on it.

Content re-upload is likewise free. The node ID fixes the small file's
encryption nonce (`key.BoxPaddedWithNonce(&payload, nid.NaclNonce())`), so
re-sending a queued node is byte-identical rather than merely equivalent, and
a duplicate upload is a no-op rather than a second object.

### D6 — A conflicted write stops and surfaces; it is never auto-resolved

When the node IDs differ, another writer changed the entry during the offline
window. The drain marks the entry *conflicted*, retains the local content, and
surfaces it. It does **not** re-prepare at the new version and retry.

Retrying at the bumped version is the tempting move and it is wrong: it
silently discards the other writer's content, which is the precise outcome the
CAS precondition exists to prevent. A KV put is not an append; there is no
ordering under which both survive. Automatic last-writer-wins would make the
outbox a data-loss mechanism whose likelihood grows with the length of the
offline window.

Conflicted entries do not block the rest of the queue. Ordering within a
directory is preserved for entries still queued, but a conflicted entry steps
aside — the same rule chat uses for a rejected send.

### D7 — Content sealing inherits the horizon policy; it does not define one

D4 covers the dirent's keys. The *content* is a separate question with a
different answer, and separating them is what keeps D4 honest.

A queued write seals its content with the party's KV-store key derived from
the PTK for the read role, read from a team snapshot whose roster was last
verified at some point in the past. Unlike the dirent, this survives rotation
untouched: `SmallFileBox` records its `RoleAndGen`, current members hold
prior generations, and the content reads correctly. What it means is that a
member removed during the offline window can still read what the drain writes
— the identical exposure `rt_offline.md` accepts for queued sends, argued
there on the grounds that it matches "written just before the removal".

`offline_verified_reads.md` Q1 recommends the staleness horizon bite on
*sealing* rather than reading, and that is exactly the operation this document
adds to KV. So KV consults the same horizon and the same stamp when one lands,
and refuses to seal past it with the same explanation. Offline KV *reads* are
never gated on it, on the same reasoning — the plaintext is already on the
device.

The same calibration that document makes for chat applies here, and by the
same mechanism. KV reads authorize against live membership: a team-scoped
request carries a VO bearer token, and `CheckTeamVOBearerToken` joins
`team_members` and requires the row to be `active`. A removed member's token
dies with their membership — the client even has a name for the adjacent
case, `TeamBearerTokenStaleError`, since the token is pinned to one
`team_members` row and any roster write touching it invalidates it. So a
removed party reaches content sealed after their removal only by some route
other than asking the server for it. As there, this is defense in depth and
not the reason the design is safe: the store is end-to-end encrypted precisely
because the server is not trusted with content. It narrows the residual risk;
it does not substitute for D4 and D7 getting the key material right.

Re-sealing content at drain (as opposed to re-preparing the dirent) is
therefore **optional**, and it is the one place where chat's ad-hoc treatment
could be adopted wholesale if the horizon policy ever demands it: unseal with
the stored generation, re-seal with the current one, keep the node ID and
hence the nonce derivation stable. The machinery from D5 makes it safe. It is
not proposed now, because with no lazy-rotation contract to honour there is
nothing it buys that the horizon does not buy more cheaply.

### D8 — Two-phase writes need ordering, not atomicity

A small-file put is two RPCs: create the node (`kvPutSmallFileOrSymlink`),
then link the dirent (`kvPut`). A drain interrupted between them leaves a node
with no referent.

This needs no distributed transaction, because the store already collects
them: refcounts are incremented on link and decremented on unlink, and
unreferenced rows are deleted after a grace period of about 30 days
(`kv_store.md`, "Garbage collection"). An orphaned node is a self-healing
condition already contemplated by the design.

The drain therefore only guarantees *order* — node before dirent — and
re-issuing the node upload is free by D5.

### D9 — Writes are composable offline exactly where the parent directory is cached

A write may be composed with no connection at all, not merely queued after a
live attempt fails.

The reason to hesitate was that composing offline means fixing a dirent
version from cache and turning every such guess into a potential conflict.
D4 dissolves it: the dirent is prepared at drain from live key material
however the entry was composed, so an offline-composed write is not working
from staler material than a connection-lost one. Both re-derive identically,
and both carry a queue-time version as their CAS predicate. The remaining
difference is the *length* of the window, not its nature — and a longer window
means more conflicts, which D6 handles.

The condition is the same rule D2 applies to reads: **nothing is composed
against an absent cache.** The CAS predicate for a new file is "no dirent
exists" (`direntVers = 0`, which `assertDirentVersion` rejects if one turns up),
and that predicate is only meaningful if the parent directory's listing is
cached well enough to know the name is free. Where it is not, the write is
refused rather than queued on a guess — a queued write that predictably
conflicts is worse than an honest refusal, because the user has already moved
on by the time it fails.

### D10 — A queued write returns immediately; a conflict becomes durable state

An offline write returns `KVWriteQueuedError` carrying the node ID, the
analogue of the chat outbox's queued-send return. Not success — the write has
no version and no confirmed position. Not a plain failure — it will be
attempted. The caller that cares reconciles on the node ID when the drain
retires the entry.

A conflict is different in kind, because it is discovered at drain time when
there is no caller left to return to. So it is durable state on the outbox
entry (D6), not a transient error, and it survives restarts until something
resolves it. That much follows from the mechanics.

What that state *looks like* to a person does not follow from the mechanics,
and is left open below.

### D11 — Rotation drift is detected by the version-vector precondition

D4 requires re-preparation to be possible. It does not require it to happen on
every drain, and it should not: in the common case nothing has rotated and the
queued material is still valid, so loading the parent directory unconditionally
would pay a round trip on every entry to save one on an event nobody expects.

The drain therefore attempts the write first and re-prepares on rejection —
but the rejection it keys on is `KV_STALE_CACHE_ERROR`, not the foreign key.

This works because the precondition is already carried on writes.
`putDirent` goes through `clientWithCacheCheck`, which sets
`hdr.Precondition` from the client's version vector, and the server's
`preamble` runs `checkVersionVector` on every request that carries a
`KVReqHeader`. `getCurrentDirVersion` selects the *highest* dir version
(`ORDER BY version DESC LIMIT 1`), so during a rotation it returns the new one
while the old row still exists — and `checkVersionVector` reports the
directory stale (`v > d.Vers`) exactly where the foreign key would have let
the write through. The mechanism that closes D4's mid-rotation window is
already built; the drain only has to use it.

One implementation obligation follows: the drain must seed its version vector
from the **queue-time** dir version recorded on the outbox entry, not from
whatever the cache happens to hold when it runs. The vector is assembled from
`m.cacheAccess`, so a drain that loaded the directory for other reasons would
otherwise assert the current version, assert nothing meaningful, and lose the
detection it depends on.

### D12 — The design does not wait for merkle sub-trees

Offline KV neither depends on rollback protection nor worsens its absence.
The validation call detects benign staleness, not a malicious rollback —
the versions it checks are asserted by the same server that would be doing the
rolling back — so a client that skips it because the network is down gives up
nothing an online client was getting. There is no risk trade-off being made
here, which is why this is a decision rather than a judgment: blocking on a
large unbuilt security workstream would buy exactly nothing.

The sequencing does matter for the *horizon*, and that is a limit rather than
an open question. A staleness horizon on the identity track will be meaningful
because team snapshots are merkle-verified, so the stamp dates a real proof. A
horizon on KV content dates a validation call whose only authority is the
server's own assertion. Until sub-trees land, a KV horizon is a usability
signal and the documents should not describe it as more.

### D13 — Warming is a coverage problem, not a correctness one

Everything above is correct against a cold cache; it simply serves nothing.
Coverage is worth improving separately: warm the party root and the working
set on foreground, and keep a bounded recency set pinned. This is tuning, not
design — it changes what offline can serve, never whether serving it is
sound — so it is scoped as a phase rather than a decision, and the correctness
of D1–D12 does not depend on where it lands.

## Security considerations

- **KV has no rollback protection today, offline or online.** `kv_store.md`
  designs merkle sub-trees precisely to stop a compromised server rolling back
  dirs, dirents, small files and large-file keys. Nothing implements them —
  no sub-tree code in the client, the server, the protocol or the schema. The
  code says so itself, at the point where the binding MAC is computed: "It
  won't protect against rollback, which we need the transparency tree for."
  The version vector is not a substitute, since the versions it checks are
  asserted by the same server. Binding and name MACs mean the server cannot
  *forge* a dirent; what it can do is serve an authentic *old* one.
- **Offline serving does not widen that gap.** The validation call detects
  benign staleness, not a malicious rollback, so a client that skips it
  because the network is down gives up nothing an online client was getting.
  This is the honest form of the doctrine for KV: cached entries were
  authenticity-verified when written and are re-served without new
  verification, which is the same standing they had online. It is a weaker
  claim than the identity track's, and it is weaker for a reason that predates
  this design.
- **The doctrine still holds in its operative half.** Nothing enters the KV
  cache except through a read whose binding MAC verified, and the offline path
  adds no new entries at all — it only re-serves. The offline path cannot be
  used to introduce data the online path would have rejected.
- **Sealing against a stale roster** is the one genuinely new exposure, and
  D7 routes it to the shared horizon rather than accepting it indefinitely.
- **Queued names are ciphertext, and must stay that way.** The local database
  does not encrypt values. D3 seals the queued name under the party key for
  this reason; an implementation that stores the name plaintext "just for the
  outbox" would put directory names on disk in the clear, which no other cache
  in the client does.
- **A conflicted write holds sealed content on disk indefinitely.** Queued
  entries are ciphertext, so this is bounded — but a conflicted entry may sit
  unresolved by design (D6), which is a longer life than a chat outbox entry
  ever has. Worth an age-out policy eventually; not one this document sets.

## Known limits

- Offline coverage equals what was browsed online. Until D13 lands, a client
  that never visited a directory cannot list it offline.
- **A queued write is not visible to a later offline read.** The outbox holds
  intent; it does not update the read caches, so reading the path back while
  still offline returns the last validated content, not what was just queued.
  The chat outbox solves this by overlaying pending messages on the thread
  view; the KV equivalent -- a pending overlay covering the node and its
  dirent -- is not built. Until it is, "save offline, then reopen" shows the
  old bytes, which is the most surprising thing in this design.
- Deletions are invisible offline. A file removed by another party still reads
  locally until a validation call succeeds; there is no tombstone in the cache
  and no feed to learn one from.
- Large files read offline only if every needed chunk is cached. Partial chunk
  coverage is an outage under D2, not a truncated file: `kv get` now writes to
  a temp file beside the destination and renames on completion, so a stream
  that dies on an uncached chunk leaves the destination absent if it was
  absent and untouched if it already existed. `--force` no longer truncates up
  front either. Pinned by `TestKVGetWriterIsAtomic`.
- GC's ~30-day grace bounds how long a cached node ID stays resolvable on the
  server after it is unlinked, which bounds how stale a drained write's
  referents may be.
- Quota and credits cannot be checked offline, so a queued write may still
  fail on drain for reasons unrelated to conflict. It surfaces like any other
  semantic rejection.
- A directory rotation that begins while writes are queued for it will make
  every one of them re-prepare (D4). That is correct but not free; a client
  that queued a great many writes into one directory pays a load per entry.

## Implementation plan

**Phase 1 — Offline reads (D1, D2). BUILT.** The `flush()` failure is
classified; a completed read returns with a staleness marker on transport
failure (`retryCacheLoopRead`, opted into by `Stat`, `List`, `GetFile`); the
`kv` CLI prints an offline notice on stale `get`/`ls`. No server change, no
wire change beyond `stale` fields on the local (CLI↔agent) result structs.
Listings still enumerate on the server, so offline they fail honestly — the
D2 rule — until a listing cache exists. Pinned by `TestKVOfflineReads`: warm
reads flagged stale off the disk cache alone, uncached miss and listing and
put all transport-class errors, flag dropped on reconnect.

**Phase 2 — The outbox (D3, D4, D5, D8, D9, D10, D11).** Durable queued entries in the
intent form, with the name sealed under the party key. Drain that loads the
parent directory, prepares the dirent against current key material, applies
the queue-time version as its CAS predicate, and settles ambiguity by node ID.
Small files, symlinks, `mkdir` and `unlink`.

*Test the rotation case explicitly:* queue a write, rotate the parent
directory, drain, and assert the entry lands under the new key and is
retrievable by name. That is the case the design exists for, and it is the one
a naive implementation passes right up until someone rotates.

**Phase 3 — Conflict surfacing (D6).** Conflicted state, CLI listing
(`kv outbox ls`), and a resolution affordance. Worth splitting from Phase 2
because the queue is useful before the conflict UX is finished, and conflicts
are rare where the queue is short.

**Phase 4 — Warming (D13).** Root and working-set prefetch, bounded pinned
recency set.

Phases 1 and 2 are independently shippable and independently useful; 3 and 4
are refinements.

## Open questions

Four questions stood here in the previous draft. Three were settled by facts
about the code rather than by judgment, and have moved into the design as D9,
D11 and D12; D10 absorbed the half of the fourth that the mechanics decide.
What remains is genuinely open, and both items are product calls rather than
technical ones.

### Q1 — What does an unresolved conflict look like to the person who wrote it?

**No recommendation. This needs a product decision.**

D10 settles that a conflict is durable state on the outbox entry and that it
survives restarts. It does not settle the affordance, and the mechanics do not
imply one. `kv outbox ls` is enough to ship Phase 2 behind, and it is not
enough to rely on: a conflict is the one outcome in this design where the
system has quietly declined to do what the user asked, and a listing nobody
runs is indistinguishable from silent data loss.

The choices worth putting in front of someone: whether the conflicted local
content is offered as a file to recover, whether the entry can be re-applied
over the winner as an explicit act, and whether anything surfaces at all
before the user next opens the directory in question.

### Q2 — How long may an unresolved conflicted entry persist?

**No recommendation. This is a policy call, and it interacts with Q1.**

D6 keeps conflicted entries indefinitely on the grounds that discarding a
user's write is worse than holding it. Held indefinitely, they accumulate:
sealed content on disk, under keys from a generation that keeps receding, for
a directory the user may never revisit.

An age-out is defensible and so is keeping them forever; which is right
depends on what Q1 decides, since an entry the user has actually been shown
and has ignored is a different thing from one they were never told about. Not
worth settling before the affordance is.
