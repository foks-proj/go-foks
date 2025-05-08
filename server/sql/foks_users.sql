
CREATE TYPE reservation_state as ENUM('reserved', 'in_use', 'dead');

CREATE TYPE name_state as ENUM('in_use', 'dead');
CREATE TYPE name_type AS ENUM('user', 'team');

CREATE TABLE name_reservations (
    short_host_id SMALLINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    id BYTEA NOT NULL UNIQUE,
    state reservation_state NOT NULL,
    typ name_type NOT NULL,
    ctime TIMESTAMP NOT NULL /* 'when it was created' */,
    dtime TIMESTAMP /* 'when it died, can be null' */,
    PRIMARY KEY(short_host_id, name)
);

CREATE TABLE names (
    short_host_id SMALLINT NOT NULL,
    name_ascii VARCHAR(255),
    reuse_id INT NOT NULL,
    name_utf8 VARCHAR(255),
    state name_state NOT NULL,
    typ name_type NOT NULL,
    ctime TIMESTAMP,
    mtime TIMESTAMP,
    PRIMARY KEY(short_host_id, name_ascii)
);

CREATE TABLE shared_key_box_metadata (
    short_host_id SMALLINT NOT NULL,
    box_set_id BYTEA NOT NULL, /* a 16-byte random ID to identify this box set */
    signer_id BYTEA NOT NULL, /* an entity that can sign updates, use it to lookup DH sender public keys */
    ephemeral_dh_key BYTEA, /* if boxing yubi-to-native or vice-versa */
    PRIMARY KEY(short_host_id, box_set_id)
);

CREATE TABLE shared_key_boxes (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    gen INTEGER NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    target_entity_id BYTEA NOT NULL, /* device key for boxing PUKs. PartyID for boxing PTKs */
    target_host_id BYTEA NOT NULL, /* for =current host, this is 0x00 */
    target_gen INTEGER NOT NULL, /* 0 for boxing PUKs. Gen of shared party Key (at role) for boxing PTKs */
    target_role_type SMALLINT NOT NULL, 
    target_viz_level SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    box_set_id BYTEA NOT NULL,
    box BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, entity_id, 
          target_entity_id, target_host_id, 
          target_role_type, target_viz_level,
          gen, role_type, viz_level),
    FOREIGN KEY(short_host_id, box_set_id) REFERENCES shared_key_box_metadata(short_host_id, box_set_id)
);

CREATE TABLE shared_key_generations (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    gen INTEGER NOT NULL,
    PRIMARY KEY(short_host_id, entity_id, role_type, viz_level)
);

CREATE TYPE merkle_work_state AS ENUM('staged', 'processing', 'committed');

CREATE TABLE links (
    short_host_id SMALLINT NOT NULL,
    chain_type SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    seqno INTEGER NOT NULL,
    body BYTEA NOT NULL,
    hash BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    qtime TIMESTAMP,
    PRIMARY KEY(short_host_id, chain_type, entity_id, seqno)
);

CREATE TABLE shared_key_seed_chain (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    gen INTEGER NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    secret_box BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, entity_id, gen, role_type, viz_level)
);

CREATE TYPE key_state as ENUM('valid', 'revoked', 'superseded');

CREATE TABLE commitments (
    short_host_id SMALLINT NOT NULL,
    id BYTEA NOT NULL,
    random_key BYTEA NOT NULL,
    data BYTEA NOT NULL,
    normalization_preimage BYTEA,
    PRIMARY KEY(short_host_id, id)
);

/* Ensure no intentional short_party collisions */
CREATE TABLE short_party (
    short_host_id SMALLINT NOT NULL,
    short_party_id BYTEA NOT NULL, 
    PRIMARY KEY(short_host_id, short_party_id)
);

CREATE TABLE shared_keys (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    gen INTEGER NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    creator_uid BYTEA NOT NULL, /* in the case of teams, this will be the PTKVerifyKey or PUKVerifyKey of the signer */
    verify_key BYTEA NOT NULL,
    hepk_fp BYTEA NOT NULL, /* fingerprint of the HEPK */
    key_state key_state NOT NULL,
    provision_epno INTEGER,
    PRIMARY KEY(short_host_id, entity_id, role_type, viz_level, gen)
);

/* In device and shared_key tables, we only mark down the HEPK fingerprint.
 * The body of those HEPKs are stored here. Note there is no owner entity
 * here, we might change this later, but for now, it feels pretty safe.
 */
CREATE TABLE hepks (
    short_host_id SMALLINT NOT NULL,
    hepk_fp BYTEA NOT NULL,
    hepk BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, hepk_fp)
);

CREATE INDEX shared_keys_verify_key_idx ON shared_keys (short_host_id, entity_id, verify_key);

CREATE TABLE teams (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    name_ascii VARCHAR(255) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id),
    FOREIGN KEY(short_host_id, name_ascii) REFERENCES names(short_host_id, name_ascii)
);

CREATE TABLE team_quota_masters (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    uid BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);
CREATE INDEX team_quota_masters_uid_idx ON team_quota_masters(short_host_id, uid);

CREATE TYPE quota_scope as ENUM('teams', 'vhost');

CREATE TABLE quota_plans (
    plan_id BYTEA NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    max_seats INT NOT NULL,
    quota_scope quota_scope NOT NULL,
    max_vhosts INT NOT NULL,
    quota BIGINT NOT NULL,
    details JSONB NOT NULL,
    stripe_prod_id VARCHAR(100) NOT NULL,
    promoted BOOLEAN NOT NULL,
    sso_support BOOLEAN NOT NULL,
    ctime TIMESTAMP NOT NULL
);

CREATE TYPE long_interval as ENUM('day', 'month', 'year');

CREATE TABLE quota_plan_prices (
    plan_id BYTEA NOT NULL,
    price_id BYTEA NOT NULL,
    stripe_price_id VARCHAR(100) NOT NULL,
    interval long_interval NOT NULL,
    interval_count SMALLINT NOT NULL,
    price_cents INT NOT NULL,
    promoted BOOLEAN NOT NULL,
    pri INT NOT NULL,
    PRIMARY KEY(plan_id, price_id),
    FOREIGN KEY(plan_id) REFERENCES quota_plans(plan_id)
);

CREATE UNIQUE INDEX quota_plans_name_idx ON quota_plans(name);
CREATE UNIQUE INDEX quota_plans_stripe_prod_idx ON quota_plans(stripe_prod_id);
CREATE UNIQUE INDEX quota_plan_prices_stripe_price_idx ON quota_plan_prices(stripe_price_id);

CREATE TABLE team_index_ranges (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    seqno INTEGER NOT NULL,
    low BYTEA NOT NULL,
    high BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, seqno),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);

CREATE TABLE team_members (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    member_id BYTEA NOT NULL, /* can be a team or a user */
    member_host_id BYTEA NOT NULL,
    src_role_type SMALLINT NOT NULL,
    src_viz_level SMALLINT NOT NULL,
    seqno INTEGER NOT NULL, /* the team seqno the change happened */
    key_gen INTEGER NOT NULL, /* key gen for this user (not the team) */
    verify_key BYTEA NOT NULL,
    hepk_fp BYTEA NOT NULL,
    dst_role_type SMALLINT NOT NULL,
    dst_viz_level SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    active BOOLEAN NOT NULL, /* only true for the most-recent appearance in the group, and only if it's active */
    create_header_epno INTEGER NOT NULL, /* epno at time of link generation */
    tree_epno INTEGER, /* can be null until it's signed into the tree */
    removal_seqno INTEGER, /* the seqno of the removal link, if any */
    tree_removal_epno INTEGER, /* can be NULL until the user is removed from the team */
    tir BYTEA, /* reported team index range, can be NULL if a user */
    PRIMARY KEY(short_host_id, team_id, member_id, member_host_id, 
        src_role_type, src_viz_level, seqno),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);

CREATE INDEX team_members_member_idx ON team_members(short_host_id, member_host_id, member_id, active);

CREATE TABLE team_removal_keys (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    member_id BYTEA NOT NULL,
    member_host_id BYTEA NOT NULL, /* will be '0x00' for localhost */
    src_role_type SMALLINT NOT NULL,
    src_viz_level SMALLINT NOT NULL,
    create_seqno INTEGER NOT NULL, /* the team seqno where the member was introduced */
    rk_comm BYTEA NOT NULL, /* commitment to the removal key */
    rk_member BYTEA NOT NULL, /* removal key boxed for the team member */
    rk_team BYTEA NOT NULL, /* removal key boxed for the team admins */
    rk_removal BYTEA, /* removal of the user, MAC'ed with the removal key */
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, member_id, member_host_id, src_role_type, src_viz_level, create_seqno)
);
CREATE UNIQUE INDEX team_removal_keys_hash_idx ON team_removal_keys(short_host_id, rk_comm);

CREATE TYPE device_type as ENUM('computer', 'mobile', 'yubikey', 'backup', 'yubibackup', 'none');

CREATE TABLE device_keys (
    short_host_id SMALLINT NOT NULL,
    verify_key BYTEA NOT NULL,
    uid BYTEA NOT NULL,
    seqno INTEGER NOT NULL, /* which seqno we added the device key, in case of reuse */
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    key_state key_state NOT NULL,
    hepk_fp BYTEA NOT NULL,
    device_name_commitment BYTEA NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    device_name_normalized VARCHAR(255) NOT NULL,
    device_name_normalization_version INTEGER NOT NULL,
    device_serial INT NOT NULL,
    device_type device_type NOT NULL,
    provision_epno INTEGER, /* can be null until it's signed into the tree */
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, verify_key)
);

/*
 * for every yubi key, write its YubiPQKeyID, regardless of whether it's being used
 * as a PQ key. This can prevent future PQ keys from mistakenly reusing previous PQ 
 * classical keys.
 */ 
CREATE TABLE yubi_pq_key_ids (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    pqkeyid BYTEA NOT NULL,
    known_preimage BOOLEAN NOT NULL,
    PRIMARY KEY(short_host_id, uid, pqkeyid)
);

CREATE TABLE yubi_pq_hints (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    parent BYTEA NOT NULL,
    slot INTEGER NOT NULL,
    pqkeyid BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, pqkeyid)
);

/* hold a device lock when revoking, to lock out any concurrent use of the device. */
CREATE TABLE revoke_key_locks (
    short_host_id SMALLINT NOT NULL,
    party_id BYTEA NOT NULL,
    verify_key BYTEA NOT NULL,
    seqno INTEGER NOT NULL, /* yubikeys can be reused, so we need to show which generation this is */
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, party_id, verify_key, seqno)
);

CREATE UNIQUE INDEX device_keys_name_idx ON device_keys (short_host_id, uid, device_name_normalized, device_serial);
CREATE INDEX device_keys_uid_idx ON device_keys (short_host_id, uid, key_state, ctime);

CREATE TABLE revoked_device_keys (
    short_host_id SMALLINT NOT NULL,
    verify_key BYTEA NOT NULL,
    revoke_header_epno INTEGER NOT NULL, /* merkle epno at the time the link was generated */
    uid BYTEA NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    key_state key_state NOT NULL,
    hepk_fp BYTEA NOT NULL,
    device_name_commitment BYTEA NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    device_name_normalized VARCHAR(255) NOT NULL,
    device_name_normalization_version INTEGER NOT NULL,
    device_serial INT NOT NULL,
    device_type device_type NOT NULL,
    provision_epno INTEGER, /* can be null until it's signed into the tree */
    revoke_tree_epno INTEGER, /* can be null until it's signed into the tree */
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, verify_key, revoke_header_epno)
);

CREATE TABLE self_view_tokens (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    view_token BYTEA NOT NULL, /* use this view token to view SELF after revocation */
    verify_key BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, view_token)
);

CREATE INDEX revoked_device_keys_uid_idx ON revoked_device_keys (short_host_id, uid, key_state, ctime);

CREATE TABLE user_salts (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid)
);

CREATE TABLE subkeys (
    short_host_id SMALLINT NOT NULL,
    parent BYTEA NOT NULL,
    verify_key BYTEA NOT NULL,
    key_state key_state NOT NULL,
    box BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY (short_host_id, parent, verify_key),
    FOREIGN KEY (short_host_id, parent) 
        REFERENCES device_keys(short_host_id, verify_key)
        ON DELETE CASCADE
);

CREATE TABLE passphrase_boxes (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    ppgen INTEGER NOT NULL,
    verify_key BYTEA NOT NULL,
    skwk_box BYTEA NOT NULL,
    passphrase_box BYTEA NOT NULL,
    puk_box BYTEA,
    puk_gen INTEGER NOT NULL, /* for the backup box, which PUK gen we're encrypting for */
    stretch_version SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, ppgen)
);

CREATE TYPE challenge_type AS ENUM('login', 'user_lookup', 'subkey_box', 'team_vo_bearer_token', 'csrf_protect');

CREATE TABLE challenge_keys (
    short_host_id SMALLINT NOT NULL,
    key_id BYTEA NOT NULL,
    key_secret BYTEA NOT NULL,
    typ challenge_type NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, key_id)
);

CREATE INDEX challenge_keys_ctime_idx ON challenge_keys (typ, ctime);

/*
 * Entities commit to tree location i+1 in the ith link. We keep these locations hidden so
 * attackers can't impute chain updates. The clients can compute these locations deterministically
 * using a VRF to allow for "fast-forwards" when playing back chains, etc. In that case, the server
 * needs to see the VRF public key, which it can share with chain observers. Not sure if we're going
 * to build all of that, but it's a very nice option.
 */
CREATE TABLE tree_locations (
    short_host_id SMALLINT NOT NULL,
    chain_type SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    seqno INTEGER NOT NULL,
    loc BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, chain_type, entity_id, seqno)
);

CREATE TABLE subchain_tree_location_seeds (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    seed BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, entity_id)
);

/* 
 * chain can optionally compute their commitment locations via VRF, and if so, can store their public
 * keys here.  They can rotate them should their privates get leaked (maybe they should be rotated along 
 * with PUKS?).
 */
CREATE TABLE location_vrf_public_keys (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    seqno INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, entity_id, seqno)
);

CREATE TABLE used_random_challenges (
    short_host_id SMALLINT NOT NULL,
    challenge BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, challenge)
);

CREATE TABLE bad_login_attempts (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, ctime)
);

CREATE TABLE chain_locks (
    short_host_id SMALLINT NOT NULL,
    entity_id BYTEA NOT NULL,
    chain_type SMALLINT NOT NULL,
    seqno INTEGER NOT NULL,
    PRIMARY KEY(short_host_id, entity_id, chain_type, seqno)
);

CREATE TABLE kex_msgs (
    short_host_id SMALLINT NOT NULL,
    session_id BYTEA NOT NULL,
    seqno INTEGER NOT NULL,
    sender_device_id BYTEA NOT NULL,
    msg BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, session_id, seqno, sender_device_id)
);
/* For garbage collection */
CREATE INDEX key_msgs_ctime_idx ON kex_msgs (ctime);

CREATE TABLE users (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    name_ascii VARCHAR(255) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid),
    FOREIGN KEY(short_host_id, name_ascii) REFERENCES names(short_host_id, name_ascii)
);

CREATE TABLE user_web_sessions (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    session_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL,
    active BOOLEAN NOT NULL,
    PRIMARY KEY(short_host_id, uid, session_id)
);

CREATE UNIQUE INDEX user_web_sessions_session_idx ON user_web_sessions (session_id);

CREATE TABLE emails (
    short_host_id SMALLINT NOT NULL,
    email VARCHAR(255) NOT NULL,
    uid BYTEA NOT NULL,
    verified SMALLINT NOT NULL,
    verify_code BYTEA,
    verified_at TIMESTAMP,
    PRIMARY KEY(short_host_id, email),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE TABLE invite_codes (
    short_host_id SMALLINT NOT NULL,
    code BYTEA NOT NULL,
    creator BYTEA NOT NULL,
    used_by BYTEA,
    used_on TIMESTAMP,
    PRIMARY KEY(short_host_id, code),
    FOREIGN KEY(short_host_id, creator) REFERENCES users(short_host_id, uid)
);

CREATE TABLE multiuse_invite_codes (
    short_host_id SMALLINT NOT NULL,
    code VARCHAR(255) NOT NULL,
    num_uses INT NOT NULL,
    valid BOOLEAN NOT NULL,
    last_use TIMESTAMP,
    PRIMARY KEY(short_host_id, code)
);

CREATE TABLE multiuse_invite_code_users (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    code VARCHAR(255) NOT NULL,
    ctime TIMESTAMP,
    PRIMARY KEY(short_host_id, uid, code)
);

/*
 * algorithm
 *  - select items where state ='staged' limit 200 items sorted by ctime ASC
 *  - collect all unique IDs
 *  - select all items in that ID set where state='staged'
 *  - discard all but the lowest seqno for each ID
 *  - mark those as 'processing', set qtime=NOW()
 *  - write batch down in RAFT
 */
CREATE TABLE merkle_work_queue (
    short_host_id SMALLINT NOT NULL,
    id BYTEA NOT NULL,
    chain_type SMALLINT NOT NULL,
    seqno INTEGER NOT NULL,
    ctime TIMESTAMP NOT NULL,
    qtime TIMESTAMP,
    key BYTEA NOT NULL,
    val BYTEA NOT NULL,
    state merkle_work_state NOT NULL,
    signer BYTEA NOT NULL,
    epno INTEGER,
    update_trigger BYTEA NOT NULL, /* SNOWP-encoded descriptor on what to update when it's in tree */
    PRIMARY KEY(short_host_id, id, chain_type, seqno)
);
CREATE INDEX merkle_work_queue_ctime_idx ON merkle_work_queue (short_host_id, id, ctime) WHERE state != 'committed';
CREATE INDEX merkle_work_queue_signer_idx ON merkle_work_queue (short_host_id, id, signer, state);

CREATE TYPE wait_list_status AS ENUM('waiting', 'invited');
CREATE TABLE waitlist (
    short_host_id SMALLINT NOT NULL,
    wlid BYTEA NOT NULL,
    email VARCHAR(255) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    status wait_list_status NOT NULL,
    code BYTEA, /* if invited then it's non-null and corresponds to an invite code */
    PRIMARY KEY(short_host_id, wlid)
);
CREATE INDEX waitlist_status_ctime_idx ON waitlist(short_host_id, status, ctime);

CREATE TABLE local_view_permissions (
    short_host_id SMALLINT NOT NULL,
    target_eid BYTEA NOT NULL, /* can be a team or a user */
    viewer_eid BYTEA NOT NULL, /* can be a team or a user */
    state key_state NOT NULL,
    token BYTEA NOT NULL, /* random 32-byte ID */
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, target_eid, viewer_eid)
);
CREATE UNIQUE INDEX local_view_permissions_token_idx ON local_view_permissions(short_host_id, token);

CREATE TABLE remote_view_permissions (
    short_host_id SMALLINT NOT NULL,
    target_eid BYTEA NOT NULL,
    viewer_eid BYTEA NOT NULL,
    viewer_host_id BYTEA NOT NULL,
    token BYTEA NOT NULL,
    state key_state NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, target_eid, viewer_eid, viewer_host_id, token)
);
CREATE UNIQUE INDEX remote_view_permissions_token_idx ON remote_view_permissions(short_host_id, token);

CREATE TYPE joinreq_state as ENUM('pending', 'approved', 'rejected', 'withdrawn');

CREATE TABLE local_joinreqs (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    token BYTEA NOT NULL, /* random 16-byte token of type TeamLocalJoinReqToken */
    joiner_party_id BYTEA NOT NULL,
    joiner_src_role_type SMALLINT NOT NULL,
    joiner_src_viz_level SMALLINT NOT NULL,
    state joinreq_state NOT NULL,
    permission_token BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, token),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);
CREATE UNIQUE INDEX local_joinreq_joiner_idx ON local_joinreqs(short_host_id, team_id, joiner_party_id, joiner_src_role_type, joiner_src_viz_level);
CREATE INDEX local_joinreqs_inbox_idx ON local_joinreqs(short_host_id, team_id, state, ctime);

CREATE TYPE team_bearer_token_state as ENUM('inert', 'active', 'expired', 'revoked');

CREATE TABLE team_bearer_tokens (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    token BYTEA NOT NULL,
    state team_bearer_token_state NOT NULL,
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,
    gen SMALLINT NOT NULL,
    holder_uid BYTEA NOT NULL,
    holder_host_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, token),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);
CREATE INDEX team_bearer_tokens_token_idx ON team_bearer_tokens(short_host_id, token);

/* 
 * team View-Only (vo) bearer tokens -- useful for loading a team up. It does not assume
 * the team is already loaded, and instead, aassumes the user has access to one of the 
 * member keys, and the member is still on the team. The member gets the token with the
 * privilege afforded by their role_type and viz_level.
 */
CREATE TABLE team_vo_bearer_tokens (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    token BYTEA NOT NULL,
    state team_bearer_token_state NOT NULL,
    member_id BYTEA NOT NULL,
    member_host_id BYTEA NOT NULL,
    src_role_type SMALLINT NOT NULL,
    src_viz_level SMALLINT NOT NULL,
    seqno INTEGER NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, token),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id),
    FOREIGN KEY(short_host_id, team_id, member_id, member_host_id, src_role_type, src_viz_level, seqno) 
       REFERENCES team_members(short_host_id, team_id, member_id, member_host_id, 
            src_role_type, src_viz_level, seqno) 
);
CREATE INDEX team_vo_bearer_tokens_token_idx ON team_vo_bearer_tokens(short_host_id, token);

/*
 * team_certs are used as "team invitations" -- they contain data needed to load the team
 * for an invitee
 */
CREATE TABLE team_certs (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    hsh BYTEA NOT NULL,
    gen INTEGER NOT NULL,
    cert BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, hsh),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);
CREATE INDEX team_certs_hsh_idx ON team_certs(short_host_id, hsh);

/* eventually these will be stored in an inbox, so that team admins
 * can process all of their requests in a batch. We might also one
 * a similar table for local join requests
 */
CREATE TABLE remote_joinreqs (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    state joinreq_state NOT NULL, 
    token BYTEA NOT NULL, /* random 16-byte token of type TeamRemoteJoinReqToken */
    req BYTEA NOT NULL, /* JoinReq object (has box of joiner's permission token, and also the joiner's ID/host, and also some viible data) */
    cert_hsh BYTEA NOT NULL, /* tied to a cert hash, which we can block to stop DoS */
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, token),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id),
    FOREIGN KEY(short_host_id, team_id, cert_hsh) REFERENCES team_certs(short_host_id, team_id, hsh)
);
CREATE INDEX remote_joinreqs_inbox_idx ON remote_joinreqs(short_host_id, team_id, state, ctime);

CREATE TABLE team_remote_member_view_tokens (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    member_id BYTEA NOT NULL,
    member_host_id BYTEA NOT NULL,
    ptk_gen INTEGER NOT NULL,
    secret_box BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id, member_id, member_host_id),
    FOREIGN KEY(short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);

CREATE TABLE user_plans (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    cancel_id BYTEA NOT NULL, /* a random 16-byte ID if canceled, and 0x00 if not */
    plan_id BYTEA NOT NULL,
    price_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    paid_through TIMESTAMP NOT NULL,
    stripe_sub_id VARCHAR(100) NOT NULL,
    pending_cancel BOOLEAN NOT NULL, /* pending a cancel from the stripe side, via lack of renewal payment */
    pending_cancel_time TIMESTAMP, /* when the cancel was requested */
    cancel_time TIMESTAMP, /* when the cancel was processed, or when the rage quit happened */
    PRIMARY KEY(short_host_id, uid, cancel_id),
    FOREIGN KEY(plan_id) REFERENCES quota_plans(plan_id),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE INDEX user_plans_paid_through_idx ON user_plans(short_host_id, paid_through) WHERE cancel_id = '\x00';

CREATE TABLE quota_poke (
    short_host_id SMALLINT NOT NULL,
    party_id BYTEA NOT NULL,
    poke_id BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, party_id)
);

CREATE TABLE stripe_sessions (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    cancel_id BYTEA NOT NULL, /* 00 if live, and not-00 otherwise (if it's successful, for instance) */
    session_id VARCHAR(100) NOT NULL,
    plan_id BYTEA NOT NULL, /* what plan they're buying when we sent them over */
    price_id BYTEA NOT NULL, /* which price they're buying when we sent them over */
    ctime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL, /* when it expires, remove it via non-00 cancel_id */
    sub_id VARCHAR(100), /* if the session ended in a new subscription */
    PRIMARY KEY(short_host_id, uid, cancel_id),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid),
    FOREIGN KEY(plan_id) REFERENCES quota_plans(plan_id),
    FOREIGN KEY(plan_id,price_id) REFERENCES quota_plan_prices(plan_id,price_id)
);

CREATE UNIQUE INDEX stripe_sessions_session_id_idx ON stripe_sessions(session_id);

/* sessions can only be processed once on the backend. first writer gets to 
 * insert here. The second will block until the first's TX commits, and then will 
 * fail. Same goes for stripe events, via StripEventIDs.
 */
CREATE TABLE stripe_locks (
    stripe_id VARCHAR(100) NOT NULL PRIMARY KEY,
    ctime TIMESTAMP NOT NULL
);

CREATE TABLE stripe_users (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    cancel_id BYTEA NOT NULL, /* 00 if live, and not-00 otherwise (should hopefully never happen) */
    customer_id VARCHAR(100) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, cancel_id)
);
CREATE INDEX stripe_users_customer_id_idx ON stripe_users(customer_id);

CREATE TABLE stripe_invoices (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    invoice_id VARCHAR(100) NOT NULL,
    price_id VARCHAR(100) NOT NULL,
    prod_id VARCHAR(100) NOT NULL,
    subscription_id VARCHAR(100) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, invoice_id)
);

CREATE TABLE kv_shards (
    short_host_id SMALLINT NOT NULL,
    party_id BYTEA NOT NULL,
    shard_id INTEGER NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, party_id)
);

CREATE TYPE host_build_stage AS ENUM('none', 'complete', 'aborted', 'stage1', 'stage2a', 'stage2b', 'stage2c', 'stage3');

CREATE TABLE vanity_host_build (
    vhost_id BYTEA NOT NULL PRIMARY KEY,
    short_host_id SMALLINT NOT NULL, /* the admin host, not the vanity host, which hasn't been assigned yet */
    uid BYTEA NOT NULL,
    stem VARCHAR(255) NOT NULL,
    vanity_host VARCHAR(255) NOT NULL,
    vanity_host_cancel_id BYTEA NOT NULL, /* 00 if live, and not-00 otherwise (on abort) */
    ctime TIMESTAMP NOT NULL,
    is_canned BOOLEAN NOT NULL,
    stage host_build_stage NOT NULL
);


CREATE UNIQUE INDEX vanity_host_build_vanity_host_idx ON vanity_host_build(vanity_host, vanity_host_cancel_id);
CREATE UNIQUE INDEX vanity_host_build_stem_idx ON vanity_host_build(stem);
CREATE INDEX vanity_host_build_uid_idx ON vanity_host_build(short_host_id, uid);

/* for Vanity HOSTS or plain-old virtual hosts, the UIDs authorized to administrate them */
CREATE TABLE vhost_admins (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    vhost_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, vhost_id),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE TABLE vhost_quota_masters (
    vhost_id BYTEA NOT NULL PRIMARY KEY, /* vhost ID of the vhost */
    short_host_id SMALLINT NOT NULL, /* host ID of the admin user */
    uid BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE INDEX vhost_quota_masters_short_id_idx ON vhost_quota_masters(short_host_id, uid);

CREATE TABLE canned_vhost_build (
    vhost_id BYTEA NOT NULL PRIMARY KEY,
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    canned_domain VARCHAR(255) NOT NULL,
    cancel_id BYTEA NOT NULL /* 00 if live, and not-00 otherwise (on abort) */
);

CREATE INDEX canned_vhost_build_user_idx ON canned_vhost_build (short_host_id, uid);
CREATE UNIQUE INDEX canned_vhost_build_hostname_idx ON canned_vhost_build (hostname, canned_domain, cancel_id);

CREATE TABLE oauth2_sessions (
    short_host_id SMALLINT NOT NULL,
    oauth2_session_id BYTEA NOT NULL, /* also used as the "state" variable */
    config_id BYTEA NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    pkce_verifier VARCHAR(255) NOT NULL,
    ctime TIMESTAMP NOT NULL,
    vtime TIMESTAMP,
    code TEXT,
    id_token TEXT,
    access_token TEXT,
    refresh_token TEXT,
    preferred_username VARCHAR(255), /* e.g. "john.doe" */
    name TEXT, /* e.g. "John Doe" */
    email TEXT, /* e.g. "john.doe@nike.com" */
    sub TEXT, /* e.g., "3", the unique subject assigned by the IdP */
    issuer TEXT,
    etime TIMESTAMP,
    uid BYTEA, /* =NULL during registration, and set to the user's UID when relogging in */
    PRIMARY KEY(short_host_id, oauth2_session_id)
);

CREATE TABLE oauth2_identity (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    config_id BYTEA NOT NULL,
    email VARCHAR(255) NOT NULL, /* e.g. "john.doe@nike.com" */
    preferred_username VARCHAR(255) NOT NULL, /* e.g. "john.doe" */
    name TEXT NOT NULL, /* e.g. "John Doe" */
    ctime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL,
    id_token BYTEA NOT NULL, /* ID Token from Issuer, might be expired */
    sig BYTEA NOT NULL,   /* Signature of the ID Token with user's devkey */
    device_key_id BYTEA NOT NULL, /* Entity ID of user's signing key */
    PRIMARY KEY(short_host_id, uid),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE TABLE oauth2_access (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    config_id BYTEA NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    sub TEXT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL,
    valid BOOLEAN NOT NULL,
    PRIMARY KEY(short_host_id, uid),
    FOREIGN KEY(short_host_id, uid) REFERENCES users(short_host_id, uid)
);

CREATE TABLE data_loss_nag (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    num_active_devices INT NOT NULL,
    cleared BOOLEAN NOT NULL,
    PRIMARY KEY(short_host_id, uid)
);

CREATE TABLE yubi_mgmt_keys (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    key_id BYTEA NOT NULL,
    box BYTEA NOT NULL,
    puk_gen INTEGER NOT NULL,
    puk_role_type SMALLINT NOT NULL,
    puk_viz_level SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, uid, key_id)
);