+++
date = '2026-05-21T00:00:00-05:00'
title = 'FOKS Realtime Server (for Chat, Notifications, etc)'
description = 'Proposal for a realtime chat server for FOKS'
draft = false
[_build]
  list = 'never'
  render = 'always'
  publishResources = true
+++

# Design for FOKS Chat Server

- Version: v0.1
- Date: 2026.05.21
- Author: Max Krohn (max@ne43.com)

## Intro

This design is based off of OkCupid's Gregor service. In the days before chat, this was
keybase's general notification service. It would update the keybase app with badging 
information (i.e., how many new folders the user has), and also various cache-busting
updates. The general architecture is that every client, when in the foreground, has
a long-lived open TCP connection to the server. The server calls an RPC on the client
with state updates. So the server is pushing to the client. Note this is different
from Apple's push service notification, which also would work when the app is
backgrounded. 

Eventually, when chat was launched, it was glommed onto the existing Gregor service,
if only to keep the client down to one persistent open TCP connection to the server.

Because gregor worked well for Keybase, and continues to work well, I would recommend
a similar architecture for FOKS. As we'll see, there are several important cases
to optimize, which are the same in either system. Of course, we are starting from
scratch here, since I have no access to Gregor code or design documents.

## High-Level Design

Here is the high-level design of the system, as currently proposed. We'll go into more
detail below:

- chat Server
    - Server is written in Go. It keeps one TCP connection open per client, and can push or pull on the connection.
    - N of these server run in parallel, load-balanced by a level-4 load balancer. That is, the load balancer
      does not terminate the TLS connection, but simply forwards the TCP connection to one of the N servers.
    - All data stored in PostgreSQL
    - No need for shared state otherwise, but we need Redis for pubsub/fan-out of new messages
    - Non-ephemeral attachments stored in FOKS KV storage (for now, might choose otherwise for scaling)
    - can queue push-notifications on notifiable chat events, like message receipt, message reads, etc (see below for push-notifications server)
    - use raw TCP connections with Snowpack rather than WebSockets
    - IPv6 support (need to check that FOKS currently supports this elsewhere)
    - Auth via mTLS with device keys as client certificates
- push Notifications server
    - Read from a PostgreSQL table of pending notifications, and push to clients as needed
    - For iOS, use Apple Push Notification Service (APNS)
    - For Android, use Firebase Cloud Messaging (FCM)
- database architecture
    - channels table -- every team can have one or more channels
    - messages table -- one row per message
    - user_channels table --- one row per user X channel pair, to keep track of read state and other settings
    - user_inbox table --- to manage global inbox state for a user and drive syncs
    - adhoc_teams table -- maps hash(all users) -> adHocTeamID, which is a random ID
    - push_outbox table -- ephemeral queue for push notifications (via APNs, FCM, etc)
- "ad-hoc" teams
    - like regular teams, but with special bits set so that the team doesn't have a name
    - otherwise, same team machinery applies
    - rotates lazily, before message send, to avoid lots of rotation churn on dead channels

Those are the high-level points, we can dig deeper below.

## Design Considerations

There are several design trade-offs to consider:

### Design & Infrastructure

In terms of the basic infrastructure:

#### TCP Connections vs. WebSockets

Some ask why use a TCP connection instead of WebSockets. WebSockets are the
only game in town for browser-based applications, but for native applications, raw TCP connections
work just fine, and Web sockets offer very little additional benefit. I think it makes 
sense to continue using raw TCP connections if the client-server communication scheme
will be a binary protocol, like Snowpack. This would work well here and is the path of
least resistance in my opinion.

#### Attachment Upload and Storage

The simplest way to handle attachment uploads and storage is just as key-value
pairs in the existing key-value store. We can set aside a dedicated part of the
namespace here.  The advantage to keeping the same mechanism is simplicity, and
also that we can use existing tools (like quota, etc) to access and manage
attachments. However, there might be optimizations we'd like to pursue that are
made challenging by the KV-store design and interface. For instance, attachment
video-upload might be streaming/chunked.  The current system should work for
that, but it hasn't been tested in this setting.

It might also make sense to move all KV-storage into S3, for attachments and
regular files too. In these cases, it might make sense to upload directly to S3,
which would be slightly better performance.

The current plan is to migrate to this configuration as required. It is likely 
cheaper to store data this way (rather than in PostgreSQL), and it simplifies backups.

#### User discovery -- open or closed?

Currently in FOKS, there are two modes of operation that can be toggled per-server.
_Closed_ membership, in which Alice needs to grant Bob permission to view her sigchain,
before they can exchange keys. And _open_ membership, which is more like keybase,
in which anyone is always allowed to view anyone else's keys and sigchains. Keep
in mind that sharing this information does give Bob information as to when
Alice added and removed devices, how many devices she has, etc. It does
not grant him the ability to see her device names.

For a chat-based system, we should consider a downstream question, which is: 
can Bob send messages to Alice just by knowing her name? Or does he need
to request her permission before doing so?

If requesting permission is the right fit, we might need a slightly
different mechanism from our 3-way group invitation handshake, that works
better for ad-hoc conversations like DMs.

#### How Many Channels Per Team Should be Supported?

If in the ~10s of channels, then we are fine to eagerly suck down
the list of channels from the server frequently. If more like ~1000s
of channels, we'll have to find a way to index a channel by name,
which is slightly tricky since channel names are encrypted.

#### Federation

FOKS supports federation, but as it turns out, federation crossed with arbitrary
team graph membership, crossed with per-receiver state needed in a realtime
system is a **nasty** problem. So let's simplify here and say only
local teams and users are considered as part of the chat system. The 
remote parts of the team graph are simply ignored for the purposes of chat.
We might relax this assumption for strategic locations down the line.

#### Team Topology

In a lot of cases for chat, it makes sense to have a materialized, denormalized
view of each recipient in a chat. We don't have this now in FOKS, since the team
structure hides who is explicitly in each team. Clients understand this, but
servers don't. Thus, we'll need to build a server-side representation of team
closures, so we can intelligently update per-receiver information on message
sends and reads. 

There is a way to do this generally and correctly (if we disregard federation!!
see above). We do not specify the details here, but we can add this set of
concerns back in at a later date. For now, we can simplify chat to say that it
only works with users who are directly members of a given team (or an ad-hoc
team).  In later stages, we can build this out with all generality.

### Cryptography

#### Ad-hoc conversations: with PTKs or do PUKs suffice?

When Alice and Bob start DM-ing, they form a new ad-hoc team. When they decide
to add Charlie later on, they form a new ad-hoc team with the bigger membership.
In general, these types of teams are different from normal FOKS teams for the
following reasons: (1) they don't have (or need) names; (2) they have immutable
membership; and therefore, (3) the concept of an admin or owner matters less.
But they might share many properties with current FOKS groups: they might have
"bots" join the conversation; they need to rotate keys whenever a user revokes a
device; they have IDs like named teams; they live in the Merkle tree; they reuse
most of the existing team infrastructure, etc.

One way to implement adhoc teams is with the existing team machinery, with 
slight modifications. Then, Alice and Bob's ad-hoc conversation gets
a PTK like a regular named team, and this PTK rotates whenever Alice or
Bob revokes a device. If Alice accumulates lots of DM channels,
then the pressure on the Merkle tree might increase here, since every 
rotation by Alice will cascade into that many rotations. However,
we can mitigate this pressure by only rotating the adhoc team 
before message send. This way the dormant adhoc teams don't get needlessly
rotated.

One missing piece for adhoc teams is how to find them. We'll need a database
table that maps Membership->teamID. We can do this by hashing the membership in a
canonical order, and then mapping that to a random teamID. If we're storing the
teamIDs in the MerkleTree, it feels incorrect to index by this deterministic
hash, as it leaves a predictable, indelible trace that Alice and Bob formed a
team, without the benefit of random masking. With random adhoc team IDs, the
server can cheat and make multiple conversations for each group. But users can 
catch this cheating via their team membership chains. 

The other way to implement adhoc teams is just for Alice and Bob
to share a key via their most recent PUKs. These keys can be 
derived opportunistically, when Alice and Bob need them. There isn't
much downside to this approach, other than that we need to build
new cryptographic flows, though they are simple. 

I think the right plan is to extend the normal machinery but with lazy adhoc
team rotations.

### Signal vs. Keybase-Style Exploding Messages

Some people seem to like Signal or MLS protocol for secure messages. It's
definitely possible to integrate these systems with FOKS but it might be a
headache, since much of that code is in Rust. There are some Signal libraries
that are in Go, but don't seem very actively maintained ([1],[2]). For instance,
neither implements SPQR, the PQ-extension to the original Signal Protocol.

From here, there are several possibilities: (1) glom Rust and Go together in the
same address space --- which is doable, but might really be pushing things if
you also need to integrate a third stack, like Swift; (2) rewrite the FOKS
client libraries in Rust, which might be doable quickly with LLM tools; (3)
start with what's there and port over SPQR to Go; or (4) maybe just don't use
Signal.

Instead of Signal, Keybase has an alternative mechanism for achieving Forward
and Future Secrecy, which is via rotating ephemeral keysets. [3] They don't rotate
quite as obsessively as Signal's keys, but they do rotate, and it might be
good enough for DMs, etc, which aren't the main thrust of the app. 

There might be a minor PR loss to not use Signal or MLS, but I think it's 
pretty minor, and 99% of people won't care. You're really talking about 
scenarios in which someone hacks a device but only for a small amount of time,
and can't get the plaintext from the device. Here Signal would protect
you and Keybase would open you up to a wider window of compromise. 

- [1] https://github.com/crossle/libsignal-protocol-go
- [2] https://github.com/RadicalApp/libsignal-protocol-go
- [3] https://book.keybase.io/docs/chat/ephemeral

### MLS or not for Big Groups

Related to the last issue, will big groups use MLS or some Keybase-like system.
One issue with MLS is that it's not standardized yet, though it's getting
closer. Another issue, as with signal, is that the Go support is much weaker
than the Rust support. Another issue is that it's plenty of additional complexity.

At Keybase, we had teams that scaled up to 1k+ users (**chia** and **keybasefriends**).
To rotate PTKs naively might be expensive, since the total amount of work is
roughly $n^2$, where $n$ is the number of users in the group. That is,
rotations are proportional to the number of users in the group, and the number
of _boxes_ is also proportional to the number of users in the group.

The simple mitigating strategy we used was to rotate big groups (bigger than 1k people)
at most once a day, regardless of how often users are removed, or users revoke
devices. This is probably a good strategy and simple to implement.

Another possibility is to implement a tree-like system as in MLS, maintained by the
group administrators. There is likely a point in the design space that
achieves logarithmic per-rotation chatter, and is far simpler than MLS, if
you use the other primitives in FOKS, like the Merkle tree, as tools.

### How Users ``Sign'' Messages

In a chat, there are two types of integrity to consider: can the server inject
or tamper with messages; and can an evil server (maybe collaborating with a user)
misattribute messages.

In FOKS, authenticated encryption assures that anyone outside the group
(like the server) cannot tamper with the messages in the chat. However,
there is currently no protection to prevent the server from misattributing
messages --- from saying Bob wrote a message that really Alice wrote.
If there is collusion between a user in the chat and the server, then
it's possible for Bob to edit Alice's message, and to present to the 
group that Alice authored the message.

To solve this type of problem, we have several options: 
(1) do nothing and use server-trust; (2) for
smaller groups, do *pairwise-MACs*, which gives repudiable
protection against this attack (by repudiable, Alice 
can't prove to an outside observer that Bob wrote the message);
(3) to sign the messages with non-repudiable signatures;
or (4) as in Signal, use a slightly longer-lived sender key,
and distribute it to the group with pairwise MACs as in (3).
The downside of (2) is that it doesn't scale well, as it introduces
chatter proportional to the number of people in the group.
(4) scales better. (1) and (2) scale the best.

### A Note on Crypto Trade-offs in General

As we see above, there is a big trade-off space between simple
basic FOKS-style key distribution, and varieties where keys rotate
faster (like Keybase ephemeral keys) and faster (like Signal and MLS).
However, none of this really makes sense for long-lived documents 
that the group is sharing. If you want the property that a newly-added
member gets access to all of the group's resources, then the
general idea of forward and future secrecy don't really apply.
A newly-added legitimate user is not distinguishable from an
attacker in the Signal threat model who roots a victim's phone.

Most of the complexity comes up when the messages are meant to disappear,
or at least to be inaccessible to future members.

### Recursive Team Membership

As a follow-on to the signing discussion, let's say Alice is a 
member of "audit-committee", which is a member of "board-of-directors".
In other words, Alice is not a member of "board-of-directors" directly,
but only via the "audit-committee". It's not a requirement, currently,
that the "board-of-directors" team admins have access to Alice's sigchain,
though it is required that the "board-of-directors" team admins have access
to the "audit-committee"'s chain.

It would be weird if, in the above signing scenario, we saw messages signed by
"audit-committee", rather than "Alice", when Alice posts messages into the
"board-of-directors" chat. Hence, it makes sense that Alice grants read access to
her sigchain to all members of "board-of-directors", both direct, and indirect,
so they can verify signatures by her in the context of this chat. This flow does
not currently exist, but can be constructed from the same viewership permission
propagation that we use elsewhere. And of course, with open servers, no
explicit permission is needed at all.

## System Design

Here we describe the system design. What needs to be built, etc.

### FOKS Architecture Additions 

Most of the basic keying infrastructure is in place, but we need to add one
piece (at least), that doesn't already exist:

#### DMs and Ad-hoc groups 

DMs and Ad-hoc teams will use a modification of the existing teams machinery.
Each of these teams will get a teamID, to serve as a primary key
for databases on the client and server sides.  On client and server, the
teamID maps to an immutable list of PartyIDs who are in the team. Also, the
creating partyID should be noted along with the team creation.

The server can deliver a server-trusted membership list for an adhoc team to the
client, and the client can check the hash invariant. This isn't entirely
necessary since it would suffice to render the name of the AdHocTeam via
MerkleTree lookups.

For use with libsignal (if desired), can use device keys and PUKs as
long-lived identity keys for the participants, and then signal ratchet
for all the ephemeral keying.

#### libsignal integration

If going down the Signal-integration path for DMs, there are many options, as
discussed above.  I lean toward reimplementing Signal in Go. We can punt this
until later, as it can be largely layered on top of getting the regular,
archived chat running. Signal integration does not involve any changes to
sigchains, merkle trees, or the hard-to-mess-with attributes of the FOKS
systems.

##### Option A - CGo-Linking

- Use cgo to link against the Rust libsignal library. There are several wrappers to
      either use or pattern after ([1], [2], [3]).
- Add libsignal ACI public keys into the sigchains
- Rotate the ACI whenever a PUK would re-rotate
- Use PUKs to distribute the associated private key packages to all devices.

This is a nice best-of-both-worlds situation, since we won't bother the users 
with safety-numbers-changed style UX noise.

The bummer here will likely be in the build, which will get more complicated.
Cross-compilation in particular will get much worse, and debugging might
become an issue.

- [1] https://github.com/mautrix/signal
- [2] https://github.com/gwillem/signal-go
- [3] https://github.com/sumnerevans/libsignalgo

##### Option B - FOKS-style rewrite

- Use Libsignal spec
- Use existing FOKS primitives 
- Use existing FOKS keys
- Rewrite PQXDH, Double-Ratchet, SPQR, potentially using Claude code
- Cross-verify against existing Rust implementation, and test vectors
- Claude guesses this is around 2000 LoC
- Commission a security audit at some point

### Chat Databases

The main chat databases will be the same as normal FOKS --- PostgreSQL.
Every conversation lives inside a table indexed by (teamId, channelId).
Recall that teamIds can refer to either standard FOKS teams, or 
ad-hoc teams as described above. For any such team, there are one
or more channels, each given by a channelId.

Probably it makes sense to make a new SQL database, call it 
foks_realtime. Recall there are currently databases for 
foks_users, foks_server_config, and sharded DBs for foks_kv_store.
There is little annoyance here about reaching across this boundary
for team membership, but we were planning to denormalize this data
anyways.

#### Channels

channels:
    - channelId (unique across all teams)
    - parentTeamId
    - appID (can be for chat, CRDTs, notifications, etc)
    - name_box (encryption of the channel and related fields)
    - msg_type (edit, data, reactji, attachment, etc)
    - seqno
    - mtime
    - ctime
    - lastUpdatedbyUID
    - lastSenderPartyID
    - lastSendTime (when the last message was sent into the channel)

indices:
    - channelID - primary
    - (parentTeamID X appID) - non-unique index (no FK possible due to DB split (see above))

The name_box field contains the encryption of the channel name with the team's
latest PTK. Users should rotate this encryption whenever the PTK rotates.  This
can be done lazily and in the background like CLKRs. seqno has to increase by
one on every update and the update will fail due to a race if not. seqno
applies to all the channel metadata (like name_box) in the row for this channel.

The plaintext input to name_box might have some structure, like a variant
that can indicate the _general_ or _default_ channel, versus a named
channel, versus something else we dream up in the future.

Note that we're not able to scale this system out to 1000s of channels,
since there is no way to look up a channel without downloading them all.
I'm guessing this is OK and it was OK for keybase, but if not, we
might consider a different design. In particular, we probably want
to have a pattern similar to directories in the KV store.

#### Messages (Boxed or Encrypted)

The messages_enc table looks like:

messages_enc:
    - channelID
    - seq (monotonic per-thread sequence)
    - type (messages can have different flavors that the server can know about for notification purposes)
    - msg_box
    - ptk_gen
    - role
    - viz_level
    - sentAtTime 
    - insertTime (might be later than sentAtTime if retries were needed, etc)
    - senderId

indices:
    - (channelID X seq) - primary

Note we might have a separate table for unencrypted messages if necessary. That
table will be like the above, but won't have pkt_gen, role or viz_level,
and will have a msgs column instead of msg_box (encrypted).

#### user_channels

The user_channels table is a denormalized view of all of the conversations that
the user has access to. We are going to go with fan-out-on-write, so that whenever
the user receives a new message or an update in a channel, the inboxVersion
on this row bumps to the updated version in user_inbox (see just below).

user_channels:
    - channelID
    - userID
    - inboxVersion (version # of the receiver's inbox)
    - lastMsgTime (timestamp of last fetched message)
    - earliestMsgTime (timestamp of first fetched message)
    - hidden (bool)
    - muted (bool)
    - readThrough (seq # of messages that the client has read through)
indices:
    - (channelID X userID) - primary key
    - (userID X inboxVersion) - non-unique key

The key on (userID, inboxVersion), might get hot. That's for reading which
channels got updated since the user last refreshed inbox.

We can also dangle server-synced preferences here, like whether a channel is hidden
or muted for a user.

#### user_inbox

Whenever the user receives any new message, we bump the inboxVersion, and then bump
the thread it came in on to this version. We have an appID field so we can
use this machinery for chat, and other real-time systems too.

user_inbox:
    - userID
    - appID
    - inboxVersion (bumped every time the subscriber receives a new message)
    - mtime (bumped whenever the inboxVersion is bumped)

indices:
    - (userID X appID) - primary

Note we'll likely put other fields into the table, if we need settings
(like notification settings) on a per (userID X appID) basis.

#### push_outbox

For keeping track of notifications that the push system will push out via
APNs, FCM, etc. Messages get queued into this log, and live for a short
period of time, before removal on send. We might eventually swap this out
for Redis or a queueing service, but for now, to keep the system simple,
all IPC is via PostgreSQL

push_outbox:
    - serial or uuid7
    - userID
    - channelID
    - type
    - seq (if applicable, the sequence in the messages table this corresponds to)
    - data (might be boxed)
    - status (queued / sending / done)
    - timestamp

indices:
    - serial or uuid7 - primary key

Note that the receiving push server might debounce these, or aggregate them,
based on frequency in the log. It might also sequester sends if they
advertise messages the user has already read.

#### adhoc_teams

adhoc_teams:
    - teamID - random team ID, with no semantic meaning
    - mashedID - Hash(party1, party2, ..., partyN), sorted

indices:
    - teamID - primary key
    - mashedID - unique key

And then we use the rest of the team machinery to handle PTKs, members, etc.
AdhocTeamIDs probably get a different leading byte than regular teams
to easily distinguish them if given an EntityID.

### Server

The chat server is a simple FOKS service like the KV-store server, or the
user server. It listens on a TCP port for incoming TCP connections.
It speaks the Snowpack protocol with the foks client. It uses the same
mTLS/auth strategy as the KV-store server.

It will have to scale horizontally more so than other services, since
every chat client will always have an open connection to a chat server
when in the foreground. Other services, like KV-store and user, 
have short-lived pull-based connections (from the client's perspective).
An always-open connection to chat server allows for fast pushes
from the server to the client, and is the right idea for battery life
(see the section on keep-alives below).

#### Chat

##### Sending

Presend on an adhoc team in client:
    - check that the PTK is sufficiently rotated for the team, and if not, rotate.
    - then....

How to send a message into a normal team or an adhoc team:
    - server verifies that user is authorized to send into that team
    - server might verify some aspects of the msg_box, but clearly cannot decrypt
    - write a new row to messages table
    - for each recipient:
        - read current inboxVersion in user_inbox for appID=Chat
        - inboxVersion++
        - update user_channels for this conversation ID to new inboxVersion; set latestMsgTime=NOW()
        - update user_inbox to new inboxVersion; set mtime=NOW()
        - append push notification to push_outbox

##### Inbox View

- get_changed_threads:
    - Client queries with lastInboxVersion
    - if current inbox version is the same, then done
    - get channels that have inboxVersions greater than lastInboxVersion
    - for each channel:
        - select max seq # in the inbox
        - select channel metadata, like seq and lastRead time by the user

Note that the inbox will likely need to render the last message in the conversation, and who
sent it, which at Keybase was called "the snippet". Depending on which conversations are in view,
we'll need to fetch some portion of the threads. We can do many of these in parallel as necessary.

Mainly used when the app is coming into the foreground, or when it's started up after
a period of being offline. For online, foregrounded apps, we'll get a feed of incoming
messages in real time from the server.

##### Thread View

- get_thread:
    - gets all messages in a channel between two points, between what's on the user's device and what's
        on the server
    - might be paginated for giant threads

- read_through:
    - When the user clicks into a thread, it's said that the user is reading through to the end
     of the thread, and we need to update the server and other clients about this.
    - the client calls read_through(channelID, seq) to push this up to the server
    - this changes:
        - the readThrough field on user_channels
        - increments the user inbox version
        - adjusts the inboxVersion on the channel to be the new user version (like a send would do)

##### Foregrounded Push

When Alice's app is foregrounded, and Bob writes a message into a conversation that she's in,
the realtime chat server will push the message out to Alice's device. This is simple
to do when there is one server, but for several servers, we'll need to use some orchestration
fabric, since Alice and Bob might be mapped to separate servers. We recommend Redis for this.
See Stage 2c.

##### Attachments

The simplest way to put attachments to the server is via FOKS KV-store.
Messages with attachments can contain paths into the KV-store that indicate
where to find the attachment, and maybe some additional metadata.
Also, attachments usually have text fields, which are like regular
messages.

##### Reactjis

Just a different message type, with the body including the emoji reaction.

##### Replies

A message that includes a pointer to the message that it's a reply to.

##### @-Mentions

When the client sends up a message to the server with an @-mention, it needs
to notify the server of who was @-mentioned. There might also be an
@channel notification wildcard, that forces notifications to all people
in the channel. The server will wind up sending pushes to all people
@-mentioned, with a special message about the mention. There are likely
going to be intricate rules regarding badging vs muting vs @mentioning
that we will not cover here. See Slack's legendary flowchart for 
more details on this sort of logic.

##### Other Important Features, Not Covered Yet

- Unfurls - the sending client visits a link and embeds an image / snippet with 
 the message, to serve as a preview for the link.
    - Note that for privacy, the sender does this, rather than the receiver
    visiting the link on receipt
    - Need a way to disable this feature, or to allow-list only certain
    hosts.
- Typing notifications
    - Again we need preferences around making this public or not
- Giphy
    - Need a secure proxy system so that the users aren't sharing their IP with giphy;
    and especially so that Alice can't force Bob to share his IP with giphy, etc.

#### Badging

- The "badge" on the app is computed as follows:
    - b := 0
    - for each channel the user is in:
        - b += (max(channel seqno) - readThrough)
- This can be computed on the server or on the client
- It is updated whenever the user reads a message or receives a new message
- As usual, we need to be careful that badging doesn't race, since receiving
  a new message happens on the server, and reading a new message happens
  on the client.
    - One path is for the server to always drive the badging. There could be a slight
      lag on this, but this might be OK.
    - Another option is for the client to recompute badging after reading a thread,
      but then get overwritten by the server when its eventual notification comes in.
    - Trade-offs here, should be examined later what exactly to do. The important
      thing is that both client and server can compute the right answer w/r/t
      some ground truth.

#### Push-Notifications

Every message receive operation and every message read operation generates a 
push notification from Apple or Google. There should likely be a DB queue and then
a separate process in charge of this, rather than the chat server doing it
directly. See push_outbox for more details.

Outside of the scope of this document, but the device needs to send up its
Apple-style push-token, so that push notifications can be properly addressed.
This often is accompanied with a settings update in the application onboarding,
as I'm sure you have seen before.  Same goes for Android. Also, similarly, the
apps need to have systems to enable and disable push notifications, and the push
server components need to honor them.

#### Authentication

Authentication scheme will be mTLS as in the user server. There will be
no need for KV-store-style non-home-server authentication, at least at first,
because chat is only available on the home server.

### Client

Discovery of chat server can happen via the same mechanism as kv-store uses now.
We can iterate on this later, but it's the simplest path forward. 

For keep-alives, we need to be a little bit smart with regard to battery life.
It does drain the battery to constantly wake up the radio, so we need to 
space pings out more than we'd like. We can set the client and 
the load balancer on the other side to not timeout the connections, but
there could be middleboxes in between that are more aggressive.

#### Crypto

How to encrypt messages? The simplest idea is just to use a symmetric key
per channel derived from the most recent PTK. And then just box as we do
values in the Key-Value store.

There are a few wrinkles to consider. First, for exploding chats, we
plan to use the signal protocol as discussed above. Second, what
should we do about signatures, and how in particular will attachments
be signed. This gets tricky when we consider hierarchical group
structures, and closed hosts. Alice might sign a message but the
rest of the group won't be able to read her sigchain and verify
her key.

Up to now, we have taken the stance that there isn't much upside
in signing messages, since it only evades the attack of misattribution
within a channel. The downside to signing a message is non-repudiability,
and a lot more complexity. For now we are going to keep this approach
and might revisit in the future. See Stage 1c.

## Deployment and Scaling

We're not going to detail much about deployment and scaling, but in general,
this can fit well as an ECS/Fargate cluster on AWS, with an application
load balancer in front of the various chat servers. The load balancers
should not terminate TLS, but rather should pass raw TCP packets onto
downstream chat servers.

As such, it makes sense to implement the well-known "proxy protocol", by which
the load balancer reveals the IP address of the original client.  This is useful
for logging.

We should be careful to limit logging and storing of IP addresses. Perhaps,
output of IP addresses should be toggled on/off in the chat server, and should
default off. It can be turned on in emergencies or debugging.  Some care should
be put into this. For instance, it probably makes sense to never write the
IP addresses to disk in any way.

As mentioned above, when multiple chat servers are in place, we'll need
something like Redis publish-subscribe to facilitate real-time push
notifications down to clients, across the multiple servers.

For stage 1, and prototype development, we can postpone work on many
of these issues.

## Staged Build

If we don't want to build everything at once, we can build according to the
following staged progression. Note that whenever we build server components, we
have to build client components at the same time, otherwise there is no way to
test. The clients can be rudimentary at first, and are likely going to be
CLI-only in the core FOKS repository.

### Stage 1a

- Simple direct team membership
- Minimal features
- Simple CLI-based interface

### Stage 1b

- build ad-hoc team machinery into core FOKS
- Complementary client features

### Stage 1c

- potentially build signatures for KV-store, and messages
    - ward off misattribution attacks
- might not be needed, still trying to decide

### Stage 2a

- Push server
    - infrastructure for queuing and processing background push notifications
    - Client logic for handling incoming encrypted pushes from Apple (or Google)

### Stage 2b

- Feature build-outs
    - attachments
    - Reactjis
    - @-mentions

### Stage 2c

- Multiple realtime servers:
    - use pubsub to propagate message sends
    - load-balancer
    - proxy protocol

### Stage 3

- Compute transitive team membership
- Open up team chat to all transitively included members of a team
- Make adjustments on team add, remove, user add, remove, up and down the DAG.

### Stage 4

- Add in Signal ratchet for ad-hoc teams and ephemeral chats

### Stage 5

- Some story for federation, or at least, federated ad-hoc chats, if not full teams.
