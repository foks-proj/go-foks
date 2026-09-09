# Offline Reads from Verified Snapshots

How the client comes up and serves identity, host, and team state with no
network, and on what basis it is entitled to.

This is the layer underneath `rt_offline.md`. That document covers the
realtime chat subsystem — thread reads, inbox sync, the send outbox,
read-marks — and assumes a client that has already loaded its user and the
team a channel belongs to. Getting to that point with no connectivity is what
this document specifies. The two were built together and the chat document
still carries a summary of this work; the trust model belongs here, because it
is not a property of chat.

Most of what follows is **built**. It is written down after the fact because
the change it makes is to the *trust model*, not to a feature, and a change of
that kind should be reviewable on its own terms rather than discovered inside
a document about message queues.

## Where this fits

Offline support divides along the three subsystems that hold client state.
They are at very different stages, each has its own coherence mechanism, and
none substitutes for another:

| Track | Covers | Specified in | State |
|---|---|---|---|
| Realtime chat | thread reads, inbox sync, the send outbox, read-marks | `rt_offline.md` | built; holds the only queued-write path in the system |
| Identity and teams | host identity, client-cert chain, the user's own sigchain and PUKs, team snapshot, keyring, roster, name resolution | **this document** | built; read-only by construction |
| KV store | directory and file reads; any queued put | not yet specified | not started |

The order matters. Chat sits on identity and teams: a client cannot open a
thread offline that it cannot resolve a team for, or unbox without cached
PTKs, so this track is what makes that one reachable from a cold start. KV is
independent of both.

KV is listed for orientation, not as work of this document; `kv_offline.md`
owns it. Worth knowing here is that it starts from a different place: an
operation runs against the local cache accumulating a `PathVersionVector` of
what it touched, and one `kvCacheCheck` at the end either confirms it or
returns `KV_STALE_CACHE_ERROR` carrying the server's current vector — so warm
reads already complete locally and only validation needs the network. Its
queued writes are also a harder problem than chat's, since a put can conflict
on its CAS precondition where an append-only message send cannot.

## Scope

**In scope:** serving previously verified local state — host identity, the
client-cert chain, the user's own sigchain and PUKs, a team's chain snapshot,
keyring, roster and name — when the server is unreachable.

**Not in scope:**

- Any offline *write*. Sigchain links commit to current server state and
  cannot be sealed ahead of time and drained later; team creation, membership
  changes, role changes and rotations all require a live, verified load. The
  one queued write in the system is the chat outbox, specified in
  `rt_offline.md`.
- The KV store. Its client cache has its own coherence protocol
  (`kvCacheCheck` plus a `PathVersionVector` precondition, with
  `KV_STALE_CACHE_ERROR` carrying the server's current vector) and its own
  staleness question. Nothing here changes it.
- Deciding what to do when local state is *too old*. This document specifies
  how to know; see "Open questions".

## The doctrine

One rule governs every cache described here:

> Nothing is served from cache that was not fully verified when it was
> written, and nothing new enters without verification.

Concretely: a snapshot is written only at the end of a successful online load,
after the merkle root check and link play. An offline load rehydrates that
snapshot and plays nothing. No link, key, or roster entry ever enters local
state through the offline path, so the offline path cannot be used to
introduce unverified data — it can only re-serve what a verified load already
accepted.

This is what makes the design defensible. It is also the whole of what it
claims, and the next section is about the part it does not claim.

## Trust model

An offline load answers "what did the server prove to me, the last time it
could?" It does not answer "what is true now."

The gap between those is a **staleness window**, and inside it the client
cannot observe:

- a member added to or removed from a team,
- a role change,
- a PTK or PUK rotation,
- a device revocation,
- anything else published to a sigchain after the device went offline.

None of this is a new exposure in the sense of an attacker gaining data they
could not otherwise reach: every byte served offline is already on the device's
disk, under keys the device holds. A party with the device and its unlock could
read the local database directly. At-rest encryption and device unlock are the
real controls; network liveness never was one, and the sections below say where
it nevertheless *acted* as one by accident.

What an attacker does gain is **control over the window**. Anyone able to drop
packets can hold a client offline indefinitely, and therefore hold it on state
of their choosing — specifically, state from before whatever they would rather
the client not learn. This is the classic freeze attack on a verified log, and
the mitigation is not cryptographic but temporal: record when verification last
happened, and let policy act on the age. `verifiedAt` (below) is that record.

### The server is an independent enforcement point

A stale client is not the only thing between a removed member and content
produced after their removal. Every realtime path — send, thread read, inbox
sync, channel operations — authorizes against the live `team_members` table
through `AuthorizeUserForTeam` (`server/realtime/auth.go`), so a removed member
is refused at the server on every subsequent read, whatever keys their device
still holds and whatever stale rows survive elsewhere.

This matters for calibration. A message sealed against a roster that has since
changed reaches the removed party only if they obtain the ciphertext by some
route other than asking the server for it: a compromised or colluding server,
or a copy they already held. The practical exposure is much narrower than "they
still have the keys" suggests.

It must not be over-read. This system is end-to-end encrypted precisely because
the server is not trusted with content, so server-side authorization cannot be
the *reason* a design is safe — it is defense in depth, and it is the layer
that disappears first in exactly the threat model E2E exists to address. Take
it as a reason the residual risk is small in practice, not as a substitute for
getting the key material right.

## What is built

Each layer caches only material a verified load produced, in the client's soft
(self-healing) database. Wiping any of it costs a resync, never correctness.

| Layer | Local state | Offline entry point |
|---|---|---|
| Host identity | `HostPublicZone @105` — the public zone, cached after signature verification | probe rehydrates when a network probe fails on transport |
| Transport | `UserCertChain @106` — the reg-issued client-cert chain, public material only, per key | mTLS clients construct offline; an expired chain fails the handshake, which reads as offline |
| User | `UserSigchainState @9` plus locally decryptable PUK parcels | `LoadMeFromCache`; `PopulateWithDevkey` falls back to it |
| Team | `TeamChainState @13` — keyring, roster, historical senders, name | `LoadTeamFromCache`; `TeamLoader.Run` falls back on transport failure |
| Team names | `TeamNameLookup @107` — `FQTeamString` → `FQTeam`, written through on every exploration and load | `resolveTeamNamedFromDB`, consulted only when exploration is impossible |
| Freshness | `TeamChainState.verifiedAt @15` | stamped on every successful online load; never by an offline one |

Supporting behaviour: the chain loader does not retry transport failures on the
merkle-race backoff schedule, so offline fallbacks engage immediately rather
than after a retry storm; and a user whose device holds none of these caches
(one that never completed an online load) stays loaded-but-locked with the
outage reported, since there is nothing verified to serve.

With all of it, a cold agent starts with no network, unlocks its user, resolves
a team by name, and serves team-scoped state. `TestRTOfflineCLIWalkthrough`
(integration-tests/cli) exercises the full arc through the real CLI and agent.

## Design decisions

### D1 — Cached PTKs may be used offline without replaying links

The snapshot was fully verified before it was written, and it persists the
historical-sender records the unboxing checks need, so rehydrating keyring,
roster and sender history carries that verification forward. The next online
load re-verifies as usual. Worst case the snapshot is stale — a rotation or
removal during the window — which matches the semantics of a message sent just
before that change.

*Confirmed with upstream before building.*

### D2 — The view bearer token is not needed offline

The token gates server resources. A token-less wrapper is correct for
local-only work, and any server operation attempted with one meets its own
transport error at its own RPC.

*Confirmed with upstream before building.*

### D3 — Offline resolution corroborates the name index against the snapshot

Persisted name rows are written through but never deleted, so a row outlives
whatever made it. No row can go wrong today: teams cannot be renamed, and the
server refuses to reuse a dead name ("for now we are not allowing the reuse of
dead names", `server/shared/name.go`). But `names.reuse_id` and
`name_reservations.dtime` exist precisely so that policy can change, and the
comment says as much.

Were reuse enabled, a stale row would be a name resolving to the team that used
to hold it. Offline that is not merely behind: resolution feeds the PTKs the
message is then sealed with, so a message meant for one audience would be
encrypted for another.

So offline resolution loads the team and refuses a row the team's own verified
snapshot does not claim. The check loads the team the way the offline path is
about to, rather than reading the snapshot under a reconstructed key: the
loader arg is hashed into that key, so any drift would fail open silently. It
*does* fail open when no snapshot loads, which is safe — with no cached PTKs
there is nothing to seal with, and the load fails on its own.

### D4 — `verifiedAt` dates the verification, not the read

`TeamChainState.verifiedAt` is stamped on every successful online load. A
reload that plays no new links takes `saveState`'s early-return path and
re-stamps there too, because a quiet team is still freshly checked; without
that, an idle team would age as though unchecked and any horizon built on the
field would punish teams for being idle. That path previously performed no
write and now performs one — a small cost, paid once per online team load.

`LoadTeamFromCache` never reaches `saveState`, so an offline load serves a
snapshot without advancing the stamp. Rows written before the field existed
import as zero.

The field records the fact only. Acting on it is deliberately left open.

### D5 — Staleness gates nothing on the client; the age is surfaced instead

Settling Q1. Reading stale content offline is close to harmless — the plaintext
is already on the device, and anyone able to read it past a refusal could read
the local database directly — so refusing reads spends usability and buys
little. Sealing is the operation where staleness has teeth, but a client-side
refusal to seal is the wrong instrument: the outbox stores a sealed wrapper and
never plaintext, so a client that will not seal cannot queue either, and the
refusal lands at the one moment the user cannot reconnect.

So: **surface the age, gate nothing locally, never gate unlock.** A device that
cannot unlock offline is useless in the situation offline support exists for,
and gating it protects nothing.

*Built:* the age reaches the team listing, the roster, and the offline
fallback's log, for both the team and account snapshots.

*Not built, and belonging elsewhere:* re-seal-at-drain, which fixes staleness at
its root by encrypting a queued message to the roster as of send time rather
than compose time. It is recorded as an open design item in `rt_offline.md` D6,
because it changes that document's outbox invariant (sealed-to-team becomes
sealed-to-self while queued) and the outbox is its to change. Any hard cutoff
likewise belongs server-side at reconnect, where enforcement has current
information.

### D6 — The account snapshot carries a verification time; the host zone does not

Settling Q2. The account chain is where device revocation lives, so its
verification time is the one that answers "is this device still supposed to be
operating?" — a policy that can date a team but not the account is half a
policy. `UserSigchainState.verifiedAt` is stamped on every successful online
load, including one that plays no new links, and never by `LoadMeFromCache`.

`HostPublicZone` is deliberately left alone. It is signature-verified, changes
rarely, and a stale zone yields a failed connection rather than a wrong
decision — the weakest of the three cases, and not worth the field until
something needs it.

### D7 — A certificate failure is named, but changes nothing else

Settling Q3, with three boundaries that matter more than the feature.

**Retry classification is untouched.** `IsTransportError` still treats a
certificate failure as transport, which is correct: the request never reached
the server and retrying is safe. `IsCertVerifyError` is a separate question
asked about the same error — what to *call* it, not what to *do* with it.

**Cached data is never withheld because of it.** Tempting and backwards: if a
bad certificate could stop the client serving what it already holds, anyone
able to present one could switch the app off from outside. The probe reports
the failure and serves the cached identity exactly as before.

**It fires on the second consecutive failure against a host this device has
already verified.** Captive portals — hotel, airport, conference — intercept
certificates as a matter of course; that is how their sign-in pages work. A
warning that fires there trains people to dismiss it, spending the attention it
exists to buy. The condition is available for free: reaching the fallback at
all means `hydrateFromCache` succeeded, which only happens for a host an
earlier probe verified. The counter is in memory, not the database, because the
offline path writes nothing to local state (R1) and a counter is not worth
being the exception.

## Requirements

The sections above explain; this one binds. Each requirement is meant to be
checkable, and each carries what currently checks it — so a claim nothing
verifies is visible as such rather than implied to be safe by sitting next to
ones that are.

### Integrity

**R1.** No offline path SHALL write a link, key, roster entry, or name binding
into local state. Only a verified online load may.
*`TestOfflineReadsWriteNothing` compares the soft database's logical contents —
every scoped row, global key and counter, timestamps included, since rewriting
identical bytes is still a write — either side of a batch of offline reads
(team load with snapshot fallback, name resolution, user-from-cache, roster
export) and requires them identical. Fails when an offline path is made to
write. The structural arrangement (`saveState` reachable only from the online
run) still holds, but is no longer the only thing holding.*

**R2.** A team snapshot SHALL be written only after the merkle root check and
link play have both succeeded.
*Half-covered by R1's test: with the network dead there is no root check, and
the snapshot is asserted unwritten. The other half — that a load whose
verification fails midway does not save — remains structural: `saveState` runs
after `checkRes`/`playLinks` and errors return before it.*

### Freshness

**R3.** Every successful online team load SHALL stamp `verifiedAt`, including
a load that plays no new links.
*`TestTeamSnapshotVerifiedAt`; fails when the no-new-links re-stamp is removed.*

**R4.** An offline load SHALL NOT advance `verifiedAt`.
*`TestTeamSnapshotVerifiedAt`, via `LoadTeamFromCache`.*

**R5.** `verifiedAt` SHALL persist, and SHALL be readable by a loader with no
in-memory preload.
*`TestTeamSnapshotVerifiedAt`; fails when the stamp is zeroed on read.*

**R6.** A staleness reading SHALL distinguish "no stamp recorded" from "zero
age", at the API and where it is rendered.
*`VerifiedAge` returns a bool; `describeVerifiedAge` prints "unknown".
`TestDescribeVerifiedAge` covers the absent stamp, an elapsed age, and a
future stamp (clock skew rather than a negative age).*

**R6a.** The verification time SHALL reach the surfaces a person reads, not
only the loader.
*`TestListMembershipsCarriesVerifiedAt` and `TestRosterCarriesVerifiedAt`: a
team listing and an exported roster each carry the stamp, dating the load that
produced them. Both fail when the export drops the field. `foks team
list-memberships` renders it as a "Verified" column; `foks team list` prints a
"Snapshot verified" footer under the roster, since one value describing a whole
listing belongs under it rather than repeated down every row.*

### Availability

**R7.** When an online team load fails on a transport-class error and a
verified snapshot exists, the loader SHALL serve that snapshot.
*`TestRTOfflineCLIWalkthrough`; also the control half of
`TestOfflineNameResolutionRejectsStaleRow`.*

**R8.** When no snapshot exists, the transport error SHALL propagate. No
offline path SHALL fabricate success or an empty result.
*`TestOfflineNoSnapshotPropagatesTransportError`: a name nothing ever persisted
and a persisted row whose team has no snapshot must each surface
`IsTransportError` — offline, the client cannot honestly say a team does not
exist, only that it cannot ask, so a semantic "not found" would be fabrication.
Fails when the offline branch is made to return one.*

**R9.** A cold start with no network SHALL unlock the active user when its
caches exist, and SHALL remain locked, reporting the outage, when they do not.
*First half: `TestRTOfflineCLIWalkthrough`. **Second half not covered.***

**R10.** Serving a snapshot offline SHALL NOT require a view bearer token.
*Exercised by `TestRTOfflineCLIWalkthrough`, not asserted directly.*

### Name resolution

**R11.** The persisted name index SHALL be consulted only when exploration is
impossible.
*`TestOfflineNameResolutionRejectsStaleRow` reaches it only after exploration
fails, so this holds along the tested path; nothing forbids a future caller
from consulting it while online.*

**R12.** Offline name resolution SHALL refuse a row the team's verified
snapshot does not claim.
*`TestOfflineNameResolutionRejectsStaleRow`; fails when the guard is disabled.*

**R13.** Where corroboration is impossible, resolution SHALL proceed and SHALL
record that it declined to check.
*`TestGuardDeclineIsLogged` asserts both halves through an injected observer
core (`GlobalContext.SetLog`): the resolution succeeds, and the decline appears
in the log stream. Fails when the warn is demoted below the observed level —
which is exactly the silent loss this requirement exists to prevent.*

### Boundaries

**R14.** Team mutations — creation, membership edits, role changes, rotations
— SHALL fail with a connect-class error offline. None SHALL be queued.
*`TestOfflineTeamMutationsFail`: creation and a membership edit are each
attempted from a cold offline start and must fail `IsTransportError`
specifically, not merely error; the team "created" offline must then be absent
once the network returns. Fails when an offline create is allowed to swallow
its transport error. Rotations are not separately exercised.*

**R15.** Only transport-class failures SHALL trigger snapshot fallback. A
semantic refusal SHALL propagate unchanged.
*`TestIsTransportError` (lib/core) tables both directions, and
`TestIsTransportErrorUnwraps` covers annotated errors, since the fallback sites
see errors wrapped on the way up. Fails when the default is flipped to
permissive — the dangerous direction, where a refusal would be served from
cache instead.*

**R16.** The account snapshot SHALL carry a verification time under the same
rules as the team snapshot: stamped by every successful online load including
one that plays no new links, never advanced by a load from cache.
*`TestUserSnapshotVerifiedAt`; fails when the no-new-links re-stamp is removed.*

**R17.** A certificate-validation failure SHALL be reported distinctly from an
outage, SHALL NOT change retry classification, and SHALL NOT withhold cached
data. It SHALL be reported only on a repeat failure against a host this device
has previously verified.
*`TestIsCertVerifyError` and `TestCertVerifyStillRetriesAsTransport` (lib/core)
pin the naming and the unchanged retry contract; `TestNoteCertOutcome`
(lib/chains) pins the two-strike rule, including that an outage never counts
and that a success or an intervening outage clears the run. Fails when the
threshold drops to one. The "previously verified" condition is structural: the
report is emitted only where `hydrateFromCache` has already succeeded, which
requires a chain and zone an earlier probe accepted.*

### Coverage

Fourteen requirements are pinned by tests that fail when the behaviour is
removed (R1, R3, R4, R5, R6, R6a, R7, R8, R12, R13, R14, R15, R16, R17). R2 is
half-pinned by R1's test, its failed-verification half still structural. Three
hold along a tested path without being asserted (R9 in part, R10, R11), as does
R17's "previously verified" condition, which is structural rather than
asserted.

Nothing on this list is unverified any more. What remains is the weakest tier,
not a missing one: R9's stays-locked half, R10, and R11 are exercised without
being the thing a test asserts, and R2's mid-verification half rests on
`saveState` running after `checkRes`/`playLinks`. Reasonable residue for a
system this size — listed so it is chosen, not discovered.

## Security considerations

- **Staleness has no horizon yet.** `verifiedAt` makes the age *knowable*;
  nothing yet makes it *actionable*. Until a policy exists, a client held
  offline serves arbitrarily old team state with nothing escalating, and the
  person using it cannot distinguish an hour from a quarter. D5 settles this: the client
  gates nothing and surfaces the age instead, with re-sealing at drain and a
  server-side expiry at reconnect as the instruments that would actually work.
  The stamp should be anchored to attested time before anything gates on the
  number.
- **Cold-start offline removes an accidental liveness gate.** Before this work
  a client that could not reach the server could not come up at all, so a
  stolen device that never reconnected was inert, and a revocation published
  while it was away would meet it on the way back in. It now unlocks and serves
  user- and team-scoped state with no network, and a revocation can never reach
  a device that never returns. Defensible — the data was already on disk under
  keys the device holds — but that inertness was a side effect of the network
  requirement rather than a designed control, and losing it is a stated
  consequence of this design rather than an oversight. The replacement, if one
  is wanted, is a server-side inactivity expiry (D5):
  enforcement at reconnect is the only point that can act on a device which has
  been away, and it is where comparable products put it.
- **A certificate failure is now named, and that is all it changes.** D7
  reports it distinctly on a repeat against a previously verified host, while
  leaving retry classification and cache-serving untouched. The restraint is
  the point: withholding cached data on a bad certificate would hand anyone
  able to present one a switch for turning the client off.
- **A TLS failure is otherwise indistinguishable from airplane mode.**
  `core.IsTransportError` classifies `net.Error` as transport, which covers TLS
  handshake failures. That is right for retry purposes and grants a network
  attacker nothing that dropping packets does not already grant. But a repeated
  certificate-validation failure is evidence of an attack, not of a tunnel, and
  it currently renders as the same "offline" state as a subway ride. It
  deserves its own log line and its own signal — conditioned on repetition
  against a previously verified host, so captive portals do not train people to
  dismiss it (Q3).
- **An expired cert chain reads as offline.** Correct behaviour — the client
  cannot mint a new chain without the server — but it means chain expiry and
  connectivity loss are the same event to a caller. Worth distinguishing for
  the same reason as the previous item.
- **Team mutations always require the network.** Membership edits, role
  changes and rotations fail with connect-class errors offline. This is not a
  limitation to be engineered away; it is what keeps the offline path
  read-only, and therefore what keeps the doctrine true.

## Known limits

- Ad-hoc team names are not in the persisted name index, so an ad-hoc team
  cannot be resolved from a cold offline start.
- Name rows are written through but never deleted, and are consulted only when
  exploration is impossible — so a stale row can only ever be served offline,
  and only if the team's snapshot corroborates it (D3).
- A device that never completed an online load has nothing verified to serve
  and stays locked. This is correct, and it is also the reason the offline path
  cannot bootstrap a new device.
- `cachedTeamClaimsName` (D3) fails open when it cannot load a snapshot to
  check against. That is safe — with no cached PTKs there is nothing to seal
  with — but it used to be silent, which meant a guard that had quietly stopped
  guarding looked identical to one with nothing to complain about. It now logs
  when it declines to check, so the difference is visible in the field.
- `cachedTeamClaimsName` (D3) is covered by
  `TestOfflineNameResolutionRejectsStaleRow`, which plants a contradictory name
  row and then cold-starts a second client context over the *same* home
  directory with the network dead. The same-home constructor is what made this
  testable: every other one makes a fresh temp home, discarding the local state
  an offline test exists to read, and a context with warm in-memory state
  explores successfully even with the network down and so never consults the
  index at all. Both halves are asserted — the contradicted row is refused, and
  the name the snapshot claims still resolves — so the test distinguishes the
  guard firing from offline resolution being broken outright.

## Follow-on work

Three things this document names but does not resolve.

**Generalize re-seal-at-drain, or decide not to.** Q1 recommends extending it
beyond ad-hoc teams. `rt_offline.md` D6 now records this as an open design item
on its own side, along with the invariant that blocks it — the outbox stores a
sealed wrapper, so a message not sealed at compose time must be held as
something, and the shape that works is sealed-to-self while queued. The two
documents no longer contradict each other; what remains is the decision, which
belongs with whoever owns the outbox.

**`verifiedAt` now reaches a person, and should reach more of them.**
`TeamWrapper.VerifiedAge()` returns the age with a bool for "no stamp on this
snapshot" — not knowable and not stale are different answers, and folding them
together fails open on the oldest snapshots. Three surfaces read it now: the
offline fallback in `TeamLoader.Run` logs it when it serves a snapshot,
`lcl.TeamMembership` carries it outward, and `foks team list-memberships`
renders it as a "Verified" column. That satisfies the first step Q1 asks for —
surface the age before any policy acts on it.

Breadth is now two surfaces: the team listing and the roster — the latter
being the one where staleness actually misleads, since a roster is exactly what
a staleness window hides changes to. What remains uncovered is the chat side. A
thread view served from cache and an inbox rendered from a stale snapshot carry
a `Stale` boolean but no age, so a reader there learns *that* the data is
behind and never *how far*. Those surfaces belong to `rt_offline.md`, and their
staleness has a different clock — when the inbox last synced, not when a team
snapshot was last verified — so closing the gap there means giving the RT sync
state its own stamp rather than borrowing this one.

**The fallback shape is repeated, not factored.** Twelve `IsTransportError`
sites across seven files each hand-roll the same decision: try the network, and
on transport failure serve the verified snapshot instead. Each one
independently chooses whether to fail open or closed, what to log, and whether
to mark the result stale. That is how the doctrine drifts — the name guard's
silent fail-open was exactly this shape before it was made to say so. A shared
helper carrying the decision and its logging would make the doctrine
enforceable rather than conventional. Not urgent, but cheaper now than after
the surface grows.
