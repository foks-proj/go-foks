

CREATE TABLE teams_adhoc (
    short_host_id SMALLINT NOT NULL,
    team_id BYTEA NOT NULL,
    mashed_id BYTEA NOT NULL, /* H(sorted partyIDs); deterministic lookup by membership */
    creator_party_id BYTEA NOT NULL,
    ctime TIMESTAMP NOT NULL,
    PRIMARY KEY(short_host_id, team_id)
);
CREATE UNIQUE INDEX teams_adhoc_mashed_idx ON teams_adhoc(short_host_id, mashed_id);
