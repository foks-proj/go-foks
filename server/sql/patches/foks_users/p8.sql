/* Social invites (docs/social_signup_spec.md). One row per invitation; the
 * exchange is a child table, one row per turn, append-only. */

CREATE TYPE social_invite_state AS ENUM
    ('open', 'replied', 'ask_again', 'accepted', 'declined', 'canceled');

CREATE TABLE social_invites (
    short_host_id SMALLINT NOT NULL,
    id BYTEA NOT NULL,           /* HMAC(s,"id"); the invitee's only handle */
    inviter BYTEA NOT NULL,
    team_id BYTEA NOT NULL,
    state social_invite_state NOT NULL,
    last_seq INTEGER NOT NULL,   /* highest seq in social_invite_msgs */
    invite_code BYTEA,           /* standard single-use code, if one is attached */
    wk_commit BYTEA NOT NULL,    /* hash of wk; gates the reply */
    seed_box BYTEA NOT NULL,     /* Enc(PUK_inviter, s) */
    seed_box_gen INTEGER NOT NULL, /* PUK generation the box was sealed to */
    invitee BYTEA,               /* from the replying session; a hint, not proof */
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, id),
    FOREIGN KEY(short_host_id, inviter) REFERENCES users(short_host_id, uid),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id),
    FOREIGN KEY(short_host_id, invite_code)
        REFERENCES invite_codes(short_host_id, code) ON DELETE SET NULL
);

CREATE INDEX social_invites_inviter_idx
    ON social_invites(short_host_id, inviter, state, ctime);

CREATE TYPE social_invite_party AS ENUM('inviter', 'invitee');

CREATE TABLE social_invite_msgs (
    short_host_id SMALLINT NOT NULL,
    id BYTEA NOT NULL,
    seq INTEGER NOT NULL,        /* 1-based; 1 is the opening message */
    sender social_invite_party NOT NULL,
    box BYTEA NOT NULL,          /* Enc(ek, M) */
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, id, seq),
    FOREIGN KEY(short_host_id, id)
        REFERENCES social_invites(short_host_id, id) ON DELETE CASCADE
);
