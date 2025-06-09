
CREATE TYPE key_state as ENUM('valid', 'revoked', 'superseded');

CREATE table host_keys (
    short_host_id SMALLINT NOT NULL,
    type INTEGER NOT NULL,
    key_id BYTEA NOT NULL,
    state key_state NOT NULL,
    seqno INTEGER NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, type, key_id)
);

CREATE INDEX host_keys_seqno_idx ON host_keys (short_host_id, type, seqno);

CREATE TYPE merkle_work_state AS ENUM('staged', 'processing', 'committed');

CREATE TABLE hostchain_links (
    short_host_id SMALLINT NOT NULL,
    seqno INTEGER NOT NULL,
    signing_key_id BYTEA NOT NULL,
    body BYTEA NOT NULL,
    hash BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    merkle_state merkle_work_state NOT NULL,
    qtime TIMESTAMP,
    PRIMARY KEY(short_host_id, seqno)
);

CREATE INDEX hostchain_links_state_idx ON hostchain_links (short_host_id, seqno) WHERE merkle_state != 'committed';

CREATE TABLE service_keys (
    key_id BYTEA NOT NULL PRIMARY KEY, /* type: device ID  */
    service_id BYTEA NOT NULL, /* type : UID */
    secret_key BYTEA NOT NULL, /* for now store in DB but can later store in secret vault, etc */
    key_state key_state NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL
);

CREATE TABLE signed_endpoints (
    short_host_id SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, ctime)
);

CREATE TABLE signed_probes (
    short_host_id SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, ctime)
);

CREATE TABLE global_kv (
    k VARCHAR(64) NOT NULL PRIMARY KEY,
    v BYTEA NOT NULL
);

CREATE TABLE host_kv (
    short_host_id SMALLINT NOT NULL,
    k VARCHAR(64) NOT NULL,
    v BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, k)
);

CREATE TABLE hosts (
    short_host_id SMALLINT NOT NULL PRIMARY KEY,
    host_id BYTEA NOT NULL,
    vhost_id BYTEA NOT NULL,
    root_short_host_id SMALLINT NOT NULL,
    parent_short_host_id SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX hosts_host_id_idx ON hosts (host_id);
CREATE UNIQUE INDEX hosts_vhost_id_idx ON hosts (vhost_id);
CREATE INDEX hosts_scope_idx ON hosts (root_short_host_id, ctime);

CREATE TABLE hostnames (
    short_host_id SMALLINT NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    cancel_id BYTEA NOT NULL, /* == 0x00 if not replaced */
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, cancel_id),
    FOREIGN KEY(short_host_id) REFERENCES hosts(short_host_id)
);
/*
 * We're only allowed to have a hostname be active once at a time.
 */
CREATE UNIQUE INDEX hostnames_hostname_idx ON hostnames (hostname, cancel_id);

/*
 * for a given base host + virtual host cluster, we can only use an DNS alias once.
 * For multiple colocated host+vhost clusters, we allow reuse of a DNA alias. So far
 * this only is needed in test.
 */
CREATE TABLE server_aliases (
    root_short_host_id SMALLINT NOT NULL,
    alias VARCHAR(255) NOT NULL,
    short_host_id SMALLINT NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(root_short_host_id, alias),
    FOREIGN KEY(short_host_id) REFERENCES hosts(short_host_id),
    FOREIGN KEY(root_short_host_id) REFERENCES hosts(short_host_id)
);

CREATE TYPE host_type AS ENUM('big_top', 'vhost_management', 'vhost', 'standalone');

CREATE TYPE viewership_mode AS ENUM('closed', 'open_to_admin', 'open_to_all');

/*
 * one row in host-config for every host, whether virtual or not.
 */
CREATE TABLE host_config (
    short_host_id SMALLINT NOT NULL PRIMARY KEY,

    user_metering BOOLEAN NOT NULL, /* meter # of users created */
    vhost_metering BOOLEAN NOT NULL, /* meter # of vhosts created */
    per_vhost_disk_metering BOOLEAN NOT NULL, /* disk quota for this vhost */

    user_viewing viewership_mode NOT NULL, /* allow users to openly view signchains on this vhost */

    host_type host_type NOT NULL
);

CREATE TYPE sso_protocol_type AS ENUM('none', 'oauth2', 'saml');

CREATE TABLE sso_config (
    short_host_id SMALLINT NOT NULL PRIMARY KEY,
    active sso_protocol_type NOT NULL,
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL
);

CREATE TABLE sso_oauth2_config (
    short_host_id SMALLINT NOT NULL,
    cancel_id BYTEA NOT NULL,
    config_id BYTEA NOT NULL,
    config_url VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret TEXT NOT NULL, /* can be "" if using PKCE */
    ctime TIMESTAMP NOT NULL,
    mtime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, cancel_id)
);

CREATE UNIQUE INDEX sso_oauth2_config_config_id_idx ON sso_oauth2_config (short_host_id, config_id);

CREATE TABLE locks (
    short_host_id SMALLINT NOT NULL,
    server_type SMALLINT NOT NULL,
    hbtime TIMESTAMP NOT NULL,
    lock_id BYTEA NOT NULL,
    pid INTEGER NOT NULL,
    PRIMARY KEY(short_host_id, server_type)
);

CREATE TYPE autocert_status AS ENUM('staged', 'granted', 'aborted');

CREATE TYPE host_build_stage AS ENUM('none', 'complete', 'aborted', 'stage1', 'stage2a', 'stage2b', 'stage2c');

/*
 * base vhosts are the vhosts that are created when the system is first initialized, 
 * before there are any users. They are similar to vanity or canned vhosts, but different
 * enough to warrant their own machinery. Note there is no owner UID here, so we can run
 * this table in this database
 */
CREATE TABLE base_vhost_build (
    vhost_id BYTEA NOT NULL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    cancel_id BYTEA NOT NULL, /* 00 if live, and not-00 otherwise (on abort) */
    mtime TIMESTAMP NOT NULL,
    stage host_build_stage NOT NULL
);

CREATE INDEX base_vhost_build_name_idx ON base_vhost_build (hostname, cancel_id);

CREATE TYPE autocert_host_state  AS ENUM('none', 'ok', 'failing', 'failed');

CREATE TABLE autocert_run_queue (
    short_host_id SMALLINT NOT NULL,
    autocert_id BYTEA NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    cancel_id BYTEA NOT NULL,
    scheduled_next TIMESTAMP NOT NULL,
    priority INT NOT NULL,
    num_succ INT NOT NULL,
    num_failures INT NOT NULL, /* reset on success */
    ctime TIMESTAMP NOT NULL,
    issued TIMESTAMP,
    expires TIMESTAMP,
    last_succ TIMESTAMP,
    server_type SMALLINT NOT NULL, /* see proto.ServerType */
    is_vanity BOOLEAN NOT NULL,
    state autocert_host_state NOT NULL,
    PRIMARY KEY (short_host_id, autocert_id)
);

CREATE TABLE autocert_log (
    short_host_id SMALLINT NOT NULL,
    autocert_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    num_failures INT NOT NULL,
    num_succ INT NOT NULL,
    succ BOOLEAN NOT NULL,
    error TEXT NOT NULL,
    PRIMARY KEY (short_host_id, autocert_id, ctime)
);

CREATE INDEX autocert_run_queue_hostname_idx ON autocert_run_queue (hostname, server_type, cancel_id);
CREATE INDEX autocert_run_queue_work_idx ON autocert_run_queue(scheduled_next, priority)
    WHERE cancel_id='\x00' AND state!='failed';

CREATE TYPE x509_asset_type AS ENUM(
		'none',
		'internal_client_ca',
		'external_client_ca',
		'hostchain_frontend_ca',
		'backend_ca',
		'root_pki_frontend_x509_cert',
        'root_pki_beacon_x509_cert',
		'hostchain_frontend_x509_cert',
		'backend_x509_cert',
		'error'
);

CREATE TABLE x509_assets (
    short_host_id SMALLINT NOT NULL,
    typ x509_asset_type NOT NULL,
    key_id BYTEA NOT NULL,
    active BOOLEAN NOT NULL,
    pri BOOLEAN NOT NULL,
    ctime TIMESTAMP NOT NULL,
    etime TIMESTAMP NOT NULL,
    keybox BYTEA NOT NULL, /* encrypted via cks machinery */
    cert_chain BYTEA NOT NULL,
    PRIMARY KEY(short_host_id, key_id, typ)
);

CREATE INDEX x509_assets_ctime_idx ON x509_assets(short_host_id, typ, ctime) WHERE active=true;

CREATE TABLE schema_patches (
    id INTEGER NOT NULL PRIMARY KEY,
    ctime TIMESTAMP NOT NULL
);

INSERT INTO schema_patches (id, ctime) VALUES (1, NOW());