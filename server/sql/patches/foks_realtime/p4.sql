
/*
 * fanin_cursors: the persistent tier of the late-join fan-in's
 * reconciled-through cursor (issue #301). vers is the user_membership_vers
 * value (users DB) that the fan-in has successfully reconciled this (user,
 * app) through; it is written in the same transaction as the backfill it
 * describes. An in-memory tier (RTInboxHub) fronts it; this row is read only
 * when the memory tier misses (process restart, or an actual membership
 * change), and re-warms it. Soft state: deleting rows is always safe -- the
 * fan-in just re-reconciles from ground truth.
 */
CREATE TABLE fanin_cursors (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    app_id app_id NOT NULL,
    vers BIGINT NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, uid, app_id)
);
