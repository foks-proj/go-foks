-- The VO bearer token GC (shared.DeleteExpiredVOBearerTokens) selects expired
-- tokens by ctime. Without this index every batch scans the whole table.
--
-- On a host whose table already holds millions of rows, building this index
-- blocks token activations (every team load) until it finishes; delete the
-- expired rows first.
CREATE INDEX team_vo_bearer_tokens_ctime_idx ON team_vo_bearer_tokens(ctime);
