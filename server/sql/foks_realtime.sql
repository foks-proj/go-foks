/*
 * foks_realtime: chat / notifications / realtime push state.
 * Design: see chat-server-design.md (v0.1, 2026-05-21).
 *
 * Lives in its own DB. No FKs across to foks_users or foks_kv_store; IDs
 * (team_id, uid, party_id, etc.) are referenced by value only, same
 * convention as foks_kv_store.
 */

/*
 * app_id lets the same realtime fabric carry chat, CRDTs, notifications, etc.
 * Each (user, app) has its own inbox version stream.
 */
CREATE TYPE app_id AS ENUM('chat', 'crdt', 'notif');

/* shape of a stored message; informs server-side notification routing only */
CREATE TYPE msg_type AS ENUM(
    'text', 'edit', 'delete', 'reactji', 'attachment',
    'reply', 'system', 'join', 'leave'
);

/* kind of push notification queued for APNs/FCM */
CREATE TYPE notif_kind AS ENUM('msg', 'mention', 'read', 'system');

CREATE TYPE push_status AS ENUM('queued', 'sending', 'done', 'failed');

CREATE TYPE push_platform AS ENUM('apns', 'fcm');

/*
 * channel_set: one row for each (teamID X appID) pair. We'll keep track of sequential
 * versions to detect races in channel creations. Slightly annoying to do since the
 * server doesn't know channel names, and the PTK encrypting channels can of course 
 * rotate.
 */
CREATE TABLE channel_sets (
    short_host_id SMALLINT NOT NULL,
    parent_team_id BYTEA NOT NULL,
    app_id app_id NOT NULL,
    vers INTEGER NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, parent_team_id, app_id)
);

/*
 * At first, there are two classes of channels: bottom and admin. For admin class,
 * only admins and above can see the name of the channel. For bottom, anyone (including lowly bots)
 * can see the channel name. So a class can have two "general" channels, one for *, 
 * and one for admin+. Note that there can be finer granularity on channel descriptions
 * and channel data. But for channel names, we need to enforce this simplification so
 * that clients won't collide in generating channel names.
 */
CREATE TYPE channel_class AS ENUM('bottom', 'admin');

/*
 * channels: every (team, app) pair has 1+ channels. channel_id is unique
 * across all teams. seqno CAS-increments on any metadata update (name, etc).
 * last_* fields are denormalized for inbox-snippet rendering.
 */
CREATE TABLE channels (
    short_host_id SMALLINT NOT NULL,
    channel_id BIGINT NOT NULL, /* random 63-bit; see ChatChannelID in chat.snowp */
    parent_team_id BYTEA NOT NULL,
    app_id app_id NOT NULL,
    channel_id_full BYTEA NOT NULL, /* an ID16 for what the channel is; top 8 bytes are channel_id */
    seqno INTEGER NOT NULL, /* metadata seqno; CAS on update */
    name_box BYTEA NOT NULL, /* PTK-encrypted channel name + structural variant */
    name_box_ptk_gen INTEGER NOT NULL, /* PTK gen used for name_box */
    class channel_class NOT NULL, /* see desc of channel_class above */
    desc_box BYTEA, /* PTK-encrypted channel descriptio + structural variant */
    desc_box_ptk_gen INTEGER, /* PTK gen used for desc_box */
    read_role_type SMALLINT NOT NULL, /* read role of the data (not channel name) */
    read_role_viz_level SMALLINT NOT NULL,
    write_role_type SMALLINT NOT NULL,
    write_role_viz_level SMALLINT NOT NULL,
    last_msg_type msg_type,
    last_msg_seq BIGINT, /* max(seq) delivered; 0 if none */
    last_sender_no INTEGER, /* -> channel_parties.party_no; NULL if no msg / server-authored */
    last_send_time TIMESTAMPTZ,
    ctime TIMESTAMPTZ NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    updated_at_set_vers INTEGER NOT NULL, /* corresponds to channel_sets at time of update */
    PRIMARY KEY(short_host_id, channel_id)
);
/* no FK to teams (cross-DB); enforced at app layer */
CREATE INDEX channels_team_app_idx ON channels(short_host_id, parent_team_id, app_id);

/*
 * channel_parties: per-channel dictionary that interns message senders into a
 * small ordinal, so the unbounded messages tables carry a 4-byte sender_no
 * instead of two wide EntityID columns. Mirrors the short_host_id pattern.
 *
 * A party is a user or a team (PartyID); party_id is always set. uid carries
 * the human attribution and equals party_id for ordinary user messages, or is
 * NULL for team/bot-authored. party_no is append-only and never reused, so a
 * message from someone who later leaves the channel still resolves.
 */
CREATE TABLE channel_parties (
    short_host_id SMALLINT NOT NULL,
    channel_id BIGINT NOT NULL,
    party_no INTEGER NOT NULL, /* per-channel ordinal; append-only */
    party_id BYTEA NOT NULL, /* user or team EntityID */
    uid BYTEA, /* human attribution; NULL for team/bot-authored */
    ctime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, channel_id, party_no),
    UNIQUE(short_host_id, channel_id, party_id),
    FOREIGN KEY(short_host_id, channel_id) REFERENCES channels(short_host_id, channel_id)
);

/*
 * messages_enc: encrypted message log, one row per message.
 * (channel_id, seq) is monotonic per channel.
 */
CREATE TABLE messages_enc (
    short_host_id SMALLINT NOT NULL,
    channel_id BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    typ msg_type NOT NULL,
    msg_box BYTEA NOT NULL,
    ptk_gen INTEGER NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    sender_no INTEGER NOT NULL, /* -> channel_parties.party_no */
    sent_at_time TIMESTAMPTZ NOT NULL, /* client-asserted */
    insert_time TIMESTAMPTZ NOT NULL, /* server-asserted */
    PRIMARY KEY(short_host_id, channel_id, seq),
    FOREIGN KEY(short_host_id, channel_id) REFERENCES channels(short_host_id, channel_id),
    FOREIGN KEY(short_host_id, channel_id, sender_no) REFERENCES channel_parties(short_host_id, channel_id, party_no)
);

/*
 * messages_clear: plaintext messages the server is allowed to read (system
 * notices, join/leave records, etc.). Same shape as messages_enc, no PTK fields.
 */
CREATE TABLE messages_clear (
    short_host_id SMALLINT NOT NULL,
    channel_id BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    typ msg_type NOT NULL,
    msg BYTEA NOT NULL,
    sender_no INTEGER, /* -> channel_parties.party_no; NULL for server-authored */
    sent_at_time TIMESTAMPTZ NOT NULL,
    insert_time TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, channel_id, seq),
    FOREIGN KEY(short_host_id, channel_id) REFERENCES channels(short_host_id, channel_id),
    FOREIGN KEY(short_host_id, channel_id, sender_no) REFERENCES channel_parties(short_host_id, channel_id, party_no)
);

/*
 * user_channels: denormalized fan-out-on-write view. One row per (user,
 * channel). Also serves as the channel-membership table for direct membership
 * (stage 1a). inbox_version is bumped to user_inbox.inbox_version on every
 * delivery into this channel for this user.
 *
 * app_id is denormalized from channels so the (uid, app_id, inbox_version)
 * index supports "what changed since" without joining.
 */
CREATE TABLE user_channels (
    short_host_id SMALLINT NOT NULL,
    channel_id BIGINT NOT NULL,
    uid BYTEA NOT NULL,
    app_id app_id NOT NULL,
    inbox_version BIGINT NOT NULL,
    last_msg_time TIMESTAMPTZ NOT NULL,
    earliest_msg_time TIMESTAMPTZ, /* server's lower bound on this user's reachable history */
    read_through BIGINT NOT NULL, /* max seq the user has read; 0 = unread */
    hidden BOOLEAN NOT NULL,
    muted BOOLEAN NOT NULL,
    ctime TIMESTAMPTZ NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, channel_id, uid),
    FOREIGN KEY(short_host_id, channel_id) REFERENCES channels(short_host_id, channel_id)
);
/* hot index: drives the get_changed_threads inbox sync */
CREATE INDEX user_channels_inbox_idx ON user_channels(short_host_id, uid, app_id, inbox_version);

/*
 * user_inbox: per (user, app) global inbox version. Bumped on every
 * receive/read. Driver for client inbox sync.
 */
CREATE TABLE user_inbox (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    app_id app_id NOT NULL,
    inbox_version BIGINT NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, uid, app_id)
);

/*
 * push_outbox: ephemeral queue of pending push notifications. Drained by the
 * push server; rows pruned after send. May later be replaced by Redis.
 */
CREATE TABLE push_outbox (
    short_host_id SMALLINT NOT NULL,
    id BIGSERIAL NOT NULL,
    uid BYTEA NOT NULL,
    channel_id BIGINT NOT NULL,
    kind notif_kind NOT NULL,
    seq BIGINT, /* messages_enc.seq if applicable */
    data BYTEA, /* opaque, may be boxed */
    status push_status NOT NULL,
    ctime TIMESTAMPTZ NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, id)
);
CREATE INDEX push_outbox_queue_idx ON push_outbox(status, ctime) WHERE status IN ('queued', 'sending');
CREATE INDEX push_outbox_user_idx ON push_outbox(short_host_id, uid, ctime);

/*
 * push_tokens: APNs/FCM tokens registered per device. enabled honors the
 * user's notification-settings toggles.
 */
CREATE TABLE push_tokens (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    device_verify_key BYTEA NOT NULL,
    platform push_platform NOT NULL,
    token BYTEA NOT NULL,
    enabled BOOLEAN NOT NULL,
    ctime TIMESTAMPTZ NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, uid, device_verify_key)
);
CREATE INDEX push_tokens_user_idx ON push_tokens(short_host_id, uid) WHERE enabled = true;

CREATE TABLE schema_patches (
    id INTEGER NOT NULL PRIMARY KEY,
    ctime TIMESTAMPTZ NOT NULL
);
INSERT INTO schema_patches (id, ctime) VALUES (1, NOW());
