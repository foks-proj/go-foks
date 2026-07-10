
/*
 * user_membership_vers: one row per (host, user), whose vers is bumped -- in
 * the same transaction as the team_members write it describes -- whenever the
 * user is added to a team, has a team role changed, or is removed. Readers
 * (the realtime service's late-join fan-in, issue #301) compare vers against
 * the version they last reconciled through, turning "did this user's team
 * memberships change?" into a single point read. The same-transaction rule is
 * what makes the signal exact: an unchanged vers proves an unchanged
 * membership set.
 */
CREATE TABLE user_membership_vers (
    short_host_id SMALLINT NOT NULL,
    uid BYTEA NOT NULL,
    vers BIGINT NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, uid)
);
