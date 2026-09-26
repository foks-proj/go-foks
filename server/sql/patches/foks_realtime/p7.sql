/*
 * Push holds, part 2.
 *
 * push_holds: at most one per (team, app). While the holder is an active team
 * member, a send into a channel of the team whose read role the holder's role
 * clears writes its push_outbox rows as 'held' (p6). Placing and clearing a
 * hold needs team admin; releasing held rows and queueing notify pushes needs
 * the holder.
 */
CREATE TABLE push_holds (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    app_id app_id NOT NULL,
    holder_uid BYTEA NOT NULL,
    ctime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, team_id, app_id)
);

/* For the holder's release and for releasing a team's held rows. */
CREATE INDEX push_outbox_held_idx ON push_outbox(short_host_id, channel_id, uid, seq) WHERE status = 'held';
