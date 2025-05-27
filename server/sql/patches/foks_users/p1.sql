
CREATE TABLE team_member_load_floor (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,

    seqno INTEGER NOT NULL,

    -- If alice is in the team, she can use the team to load other members if she is at 
    -- a target role at or above the member_load_floor.
    role_type SMALLINT NOT NULL,
    viz_level SMALLINT NOT NULL,

    ctime TIMESTAMP NOT NULL,

    PRIMARY KEY (short_host_id, team_id, seqno),
    FOREIGN KEY (short_host_id, team_id) REFERENCES teams(short_host_id, team_id)
);


/*
 * Also here is a multi-line comment
 * to test our stripper.
 */ 
ALTER TABLE local_view_permissions ADD COLUMN viewer_role_type SMALLINT NOT NULL DEFAULT 2; -- 2 == "admin"
ALTER TABLE local_view_permissions ADD COLUMN viewer_viz_level SMALLINT NOT NULL DEFAULT 0;