+++
date = '2026-08-28T00:00:00-05:00'
title = 'FOKS Realtime Presence (Typing Indicators)'
description = 'Proposal for an ephemeral presence path on the realtime server'
draft = false
[_build]
  list = 'never'
  render = 'always'
  publishResources = true
+++

# Design for FOKS Realtime Presence

- Version: v0.1
- Date: 2026.08.28
- Author: Stefan Leßle (stefan.lessle@mediakular.com)

## Motivation

`chat-server-design.md` lists typing notifications under "Other Important
Features, Not Covered Yet". This proposes a design for them.

The persisted message pipeline is the wrong carrier. A presence signal sent
through `rtSend` would insert a `messages_enc` row, bump `user_inbox` for every
member, and enqueue `push_outbox` entries — durable log rows, unread counts and
phone buzzes, for a signal that is worthless five seconds later.

What follows is a separate, non-persisting path on the existing realtime
connection. No new connection, no new table, no migration.

## Relation to `read_through`

`read_through` is the server's existing client-driven state signal. It persists
and bumps the inbox deliberately: read state must survive a restart and reach
the user's other devices.

Presence is its ephemeral twin — same shape, opposite durability. Every decision
below follows from that inversion.

## Non-goals

- No history. A presence event that is missed is lost.
- No durability across a realtime-server restart.
- No delivery guarantee. Best-effort only.
- Not general pub/sub: one entry per `(channel, user)`, TTL-bounded.
- **Not authenticated end-to-end.** The server attests `uid` from the device
  cert, but presence entries are not signed, so a malicious server can fabricate
  or suppress them. Nothing security-relevant may depend on presence.

## Protocol

`proto-src/lib/realtime.snowp`:

```
struct RTPresenceEntry {
    uid       @0 : UID;
    expiresIn @1 : DurationMilli;   // remaining, at send time
    kindBox   @2 : RTBoxRG;
}

struct RTChannelPresence {
    chid    @0 : RTChannelIDShort;
    entries @1 : List(RTPresenceEntry);
}
```

Presence is returned grouped by channel, never as a flat list. A caller may
watch more than one channel, and the grouping is what tells it which
conversation an entry belongs to. It is also required for correctness rather
than only display: `kindBox` is sealed at its own channel's read role, so a
receiver needs the channel to select the key that opens it.

`kindBox` is a PTK box at the channel read role, the same construction as
`name_box` and `desc_box`. Its plaintext is a client-defined variant (typing,
recording, …). The server never opens it and never routes on it.

Two properties the box must have:

- **Fresh nonce.** `SealIntoSecretBox` draws a random 24-byte nonce per box, so
  repeated publishes under one PTK carry no reuse risk. No noncer construction
  is needed — unlike `msg_box`, which derives its nonce from `RTMsgNoncer`
  because messages must bind to their metadata.
- **Fixed length.** Kind variants encode to different lengths, so an unpadded
  box would let the server separate "typing" from "recording" by ciphertext
  size alone, defeating the reason for boxing it. Seal with a non-zero `padMin`
  (`SealIntoSecretBoxWithPadding`) so every kind produces an identical length.

`expiresIn` is a remaining duration rather than an absolute `Time`. At a TTL of
a few seconds, client/server clock skew is a large fraction of the lifetime, and
an absolute timestamp would make expiry unreliable in both directions.

`proto-src/rem/realtime.snowp`:

```
struct RTSetPresenceArg {
    chid    @0 : lib.RTChannelIDShort;   // short form; see below
    kindBox @1 : lib.RTBoxRG;
    ttl     @2 : lib.DurationMilli;      // capped server-side; 0 = clear
}
```

Two existing structs gain a field:

- `RTPollInboxArg` — `presenceInterest : List(lib.RTChannelIDShort)`, the
  channels the caller wants presence for. Empty disables presence for that call.
- `RTInboxPollRes` — `presence : List(RTChannelPresence)`.

```
struct RTSetPresenceInterestArg {
    interest @0 : List(lib.RTChannelIDShort);
}
```

Two new RPCs: `rtSetPresence(RTSetPresenceArg) -> void` and
`rtSetPresenceInterest(RTSetPresenceInterestArg) -> void`.

`presenceInterest` on the poll argument is the authoritative set for each call,
but a poll is parked for up to `maxPollInboxTimeout` (55s). Without a way to
change interest mid-park, a client that opens a channel would wait out the
deadline before receiving any presence for it. `rtSetPresenceInterest` replaces
the registered interest for the caller's parked poll and wakes it, so the
return carries the new set and the re-issue keeps it. Cost is one round trip.

Entries carry `uid` only. Display names resolve through the existing
team-mediated sender-name path, the same one that names message senders.

Both new fields use `RTChannelIDShort` rather than the full `RTChannelID`,
following `RTSendArg`'s precedent ("send short channel ID to save bytes").
`rtSetPresence` is the highest-frequency call in the system, and the interest
list rides every poll.

## Server

### Store

`shared.RTPresenceStore`: in-memory, keyed `(shortHostID, channelID)` to a map
of entries. Presence never crosses a vhost boundary.

It is built as a sibling of `RTInboxHub` and shares its lifecycle, so the Stage
2c pub/sub swap covers both (see Scaling).

Entries are keyed by `(uid, deviceID)`, not by `uid` alone, and collapsed to one
entry per uid on read. Keying by uid would let a user's second device clear the
first device's signal with a `ttl = 0` while it is still typing.

A publish overwrites that device's entry. `ttl = 0` deletes it, which is how a
client retracts a signal before it lapses; a clear wakes pollers exactly as a
publish does, or the retraction would not be observable until the original TTL
ran out. TTL is capped server-side.

Sweep lazily on read plus a coarse background tick; a channel whose entries have
all expired drops its map.

On a server restart the store is empty and every indicator disappears.
Publishers restore their own entries on their next tick.

### Interest registry

The inbox hub is keyed by user, and an inbox writer already has the recipient
list: `fanoutInboxVersions` collects `wakeUIDs` from its own `RETURNING uid`. A
presence publisher has no such step, and resolving channel membership per
publish would reintroduce exactly the query cost this design exists to avoid.

So the presence store carries the reverse index the hub lacks: `channelID` to
the set of parked waiters that declared interest in it.

Registration is owned by the RPC call and keyed by `(uid, deviceID)`, not by
`uid`. The hub's own key is per-user, so two devices share it — fine for
inbox wakes, which carry no data, but interest is per-device state and one
device must not overwrite the other's. `rtSetPresenceInterest` targets the
calling device's entry, and is a no-op when that device has nothing parked;
the poll argument remains authoritative on the next call either way.

Registration spans the whole call, not each round of `PollInbox`'s
subscribe/read/park loop. Re-registering per round would churn the index for
no benefit.

A publish is then O(interested waiters) with no membership lookup at all. This
is the structural reason presence can be cheap where messages cannot.

### Wake

`RTInboxHub.Wake` gains a kind: inbox or presence. Wakes still carry no payload
— a woken poller reads the presence store, exactly as an inbox wake sends it to
re-read its version. Spurious wakes stay harmless, and the subscribe-before-read
ordering is untouched.

**Wake kinds must accumulate, not replace.** A presence wake and an inbox bump
can land together. If the presence wake alone decides the round, the poller
skips its version read (below) and returns `Bumped: false`, and the message that
arrived alongside it waits for the next wake — up to the poll deadline. So a
waiter carries pending-inbox and pending-presence flags that OR together; the
woken poller reads and clears both, and any pending inbox flag forces the
version read. The wake kind is a hint about what to skip, never a claim about
what did not happen.

Presence wakes for one channel are coalesced within a short window (a few
hundred ms), on the leading edge: the first publish into a quiet channel fires
immediately and subsequent ones are absorbed. A trailing-edge debounce would add
latency to precisely the event a user notices. Without coalescing, a busy
channel returns and re-arms every parked poller in lockstep on each publish.

### PollInbox

Presence rides the parked `rtPollInbox` call:

- **Every** return carries current presence for the declared interests — not
  only presence wakes. A client is unparked for a fraction of each cycle while
  it re-issues, and entries published in that gap would otherwise stay invisible
  until the next unrelated event.
- On a presence-only wake — no pending inbox flag — return `{Bumped: false,
  InboxVersion: unchanged, Presence: [...]}` without calling `pollInboxOnce`.
- On re-issue with an unchanged `since`, skip `reconcileUserChannels`, but
  **bound the skip**: run it at least once every few seconds regardless. It is
  the late-join fan-in (issue #301), and a client held in a fast presence loop
  would otherwise defer its own channel backfill indefinitely. Bounding it keeps
  the steady state at zero queries amortized without turning an optimization
  into a liveness bug.

A presence event therefore costs **zero database queries**. This is
load-bearing. Messages are rare and presence is continuous, so a presence path
that paid the inbox read cost would quickly become the dominant query source on
the realtime host.

Only channels belonging to the polled `appID` are returned. The caller's own
uid is filtered out; a client knows its own state and would only have to discard
it.

### Authorization

- Publishing requires the channel's write role — the same check as `rtSend`.
- Interest requires the channel's read role, which also excludes channels the
  caller sees as `unreadable`. Interests that fail are dropped silently rather
  than erroring, so a stale client cannot be made to fail its whole poll.
- `uid` is taken from the device cert. A caller cannot publish for anyone else.
- Publish failures return one error for both "no such channel" and "not
  authorized", so the call is not a channel-existence oracle.
- Presence is visible to exactly the channel's read role — the same audience
  that already sees the sender of every message in it.

**Authorization must be cached, or the zero-query claim is false.** A role check
costs a `channels` row read plus `AuthorizeUserForTeam` against the users DB —
two queries. Paid per interest on every poll re-issue, and per publish, that is
precisely the load this design set out to avoid.

So decisions are cached per `(uid, channel)` for a bounded grace period,
re-checked when a caller's interest list changes or the grace lapses, and shared
by the publish and interest paths. The exposure is a revoked reader continuing
to see presence for at most the grace window — acceptable given presence carries
no content and is already best-effort. A tighter binding is possible; see open
questions.

### Abuse limits

`rtSetPresence` is an amplification primitive: one request wakes every
interested poller, each of which returns and re-issues an RPC. `server/realtime`
has no rate limiting today, so the limits have to come with the feature.

- A per-`(uid, channel)` minimum publish interval. Publishes inside the window
  are absorbed — the existing entry's TTL is refreshed, but no wake is issued.
- A per-connection ceiling on `rtSetPresence` calls, expressed with the existing
  `shared.RateLimit{Num, WindowSecs}` config idiom and returning
  `core.RateLimitError`, as `BadLoginRateLimit` does.
- A cap on entries per channel. Past it, further publishes refresh existing
  entries but do not add new ones. Readers need "someone is typing", not a
  complete roster.
- A cap on `presenceInterest` length (small — a client watches what is on
  screen), bounding wake fan-out, per-poll work, and the interest registry.

Presence is not metered. It writes nothing and its cost is bounded by the limits
above.

### Expiry

The server never signals expiry. Entries carry `expiresIn` and receivers drop
them locally when it lapses. Timer-driven expiry wakes would cost one wake per
entry per channel and buy nothing.

## Metadata exposure

Presence adds one routing fact: uid U was active in channel C at time T. The
server needs it and cannot avoid it, and it is the same vocabulary the message
tables already use — opaque channel IDs and binary UIDs, with channel names
PTK-boxed and unknown to the server.

The kind is different. `msg_type` is cleartext because the server routes push
and badging on it; presence has no equivalent need, so the kind is boxed and
padded to a fixed length. That keeps "user is recording audio" — a stronger
disclosure than "user is typing" — off the server.

Worth stating plainly: this raises the cost of the inference without
eliminating it. Kinds have different rhythms — a recording is one sustained
signal, typing is bursty — and a server willing to analyse publish timing can
still separate them. Boxing removes the trivial read, not the determined one.

This also makes the visibility preference the design doc anticipates a purely
client-side matter. A user who publishes nothing discloses nothing, so no
server-side preference state is required.

## Capability

The poll fields are additive: an older server ignores `presenceInterest` and
returns no `presence`, which a client reads as "nobody is present". `rtSetPresence`
is not additive — on an older server it fails as an unknown method.

There is no mechanism today that lets a client tell the difference in advance.
The signed public zone (`PublicServices.realtime`) says only that a host runs a
realtime service, not which features it has, and the realtime service advertises
no capability set of its own. So either this design introduces one, or clients
are left probing by error and reading unknown-method as "presence unsupported".

A version or feature-bit field on an existing realtime response would be enough.
The choice is left open here because it affects more than presence.

## Scaling

The store is in-memory, so cross-instance presence is wrong rather than merely
slow: a poller on server A never sees a publisher on server B. That is the same
constraint the inbox hub carries today, with a sharper failure mode.

Because the store is a hub sibling, Stage 2c covers both at once — the presence
publish becomes a pub/sub fan-out on the same key, and pollers and publishers
are unchanged. Until then, presence is correct only on a single-server
deployment.

## Cost

Per presence event, per interested receiver: one hub wake, one map read, one RPC
return and re-issue. No rows, no queries, no push.

Fan-out is bounded by interest rather than membership — only users with the
channel in `presenceInterest` are woken, not every member of the team.

With a 1s minimum publish interval and leading-edge coalescing, a receiver sees
at most roughly one poll return per second per watched channel, however many
people in it are typing.

## Staging

Builds on the Stage 1d inbox machinery. No dependency on 2a or 2b; ships before
2c and is designed to survive it.

Footprint is roughly 600–900 lines across proto, `server/shared`,
`server/realtime` and tests, with no SQL migration. Reference client plumbing
(`client/librt` and a CLI command to exercise it) is in the same repo but out of
scope for this document.

## Open questions

1. Default and maximum TTL, and the publish-coalescing window. 5s / 10s and a
   1s minimum publish interval are a starting point, not a recommendation.
2. Should the authorization cache be invalidated on a signal rather than a
   timer? `user_membership_vers` already bumps with every `team_members` change
   and `reconcileUserChannels` already reads it cheaply, and `channels.seqno`
   CAS-bumps on role edits. Together they would bound staleness exactly, at the
   cost of tracking two markers.
3. Should presence also ride `rtGetChangedThreads`, or poll only? Poll-only is
   simpler and covers the foreground case, which is the only one that matters.
4. Is `RTBoxRG` at the channel read role the right box for the kind, or should
   presence get its own `RTKeyType` derivation alongside `ChannelName`,
   `ChannelDesc` and `Data`?
5. Should presence be suppressed above some channel membership size, where a
   typing indicator is noise rather than signal?
