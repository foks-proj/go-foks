-- Roster delegation: a team may set a "delegation
-- floor" in its sigchain; members at or above it may sign a restricted set
-- of roster changes. This table holds the server copy of each team's floor
-- history, one row per chain link that set or cleared it. Applying this
-- patch changes no behavior on its own: rows only appear once the operator
-- also enables team.roster_delegation in the server config.
CREATE TABLE team_roster_delegation_floor (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,

    -- The seqno of the team chain link that set this floor. The effective
    -- floor is the row with the highest seqno; a NONE role there means
    -- delegation was turned off.
    seqno INTEGER NOT NULL,

    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,

    ctime TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(short_host_id, team_id, seqno)
);
