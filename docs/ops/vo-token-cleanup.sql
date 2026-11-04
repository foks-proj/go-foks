-- One-off cleanup of expired team VO bearer tokens, for a host that ran
-- before the token GC existed (foks_users only).
--
-- Every team load minted a token and nothing ever deleted one, so
-- team_vo_bearer_tokens and used_random_challenges grow by one row each per
-- mint. A token is refused 6h after it was minted and its challenge 24h after,
-- so rows older than 48h guard nothing -- the same cutoff the GC in
-- server/shared/vo_bearer_token_gc.go uses with the default token lifespan
-- (if team_bearer_token_lifespan is set higher, raise the interval to
-- lifespan + 24h in both places below). Challenges from logins and sign-ups
-- have no token row and are left alone.
--
-- Run it BEFORE deploying the release that adds patch p11: p11 indexes
-- team_vo_bearer_tokens(ctime), and on a table with millions of rows that
-- build holds up every token mint (every team load) until it finishes.
--
--   docker exec -i <postgres container> \
--     psql -U postgres -d foks_users -v ON_ERROR_STOP=1 < vo-token-cleanup.sql
--
-- Parts 1 and 2 are online: they take no table locks, so clients keep minting
-- and presenting tokens throughout. They are heavy on disk and WAL; prefer a
-- quiet hour. Rerunning the script is safe.

\timing on

-- Part 1: the used challenges of expired tokens, in one statement. A batched
-- delete would look each challenge up in an index larger than RAM; one hash
-- join reads each table once instead. work_mem bounds the hash (Postgres
-- spills the rest to disk); keep it modest on a box without swap.
BEGIN;
SET LOCAL work_mem = '128MB';
DELETE FROM used_random_challenges AS c
USING team_vo_bearer_tokens AS t
WHERE t.short_host_id = c.short_host_id
  AND t.token = c.challenge  -- a token's bytes are its challenge's random bytes
  AND t.ctime < (now() AT TIME ZONE 'UTC') - interval '48 hours';
COMMIT;

-- Part 2: the expired tokens, in batches of heap pages, committing each.
DO $$
DECLARE
  cutoff timestamp := (now() AT TIME ZONE 'UTC') - interval '48 hours';
  -- Pages that exist now. Rows written later land past them or in space
  -- vacuum frees, and are recent either way.
  pages bigint := pg_relation_size('team_vo_bearer_tokens')
                  / current_setting('block_size')::int;
  step constant int := 4000;
  lo bigint := 0;
  t_lo tid;
  t_hi tid;
  n bigint;
  total bigint := 0;
BEGIN
  RAISE NOTICE 'deleting tokens created before % across % pages', cutoff, pages;
  WHILE lo < pages LOOP
    t_lo := format('(%s,0)', lo)::tid;
    t_hi := format('(%s,0)', lo + step)::tid;
    DELETE FROM team_vo_bearer_tokens
    WHERE ctid >= t_lo AND ctid < t_hi AND ctime < cutoff;
    GET DIAGNOSTICS n = ROW_COUNT;
    COMMIT;
    total := total + n;
    lo := lo + step;
    RAISE NOTICE 'page % of %: deleted % tokens (% so far)', least(lo, pages), pages, n, total;
  END LOOP;
END $$;

-- Part 3 gives the space back to the OS and rebuilds the indexes compactly.
-- VACUUM FULL locks each table while it rewrites it, so token mints and
-- checks wait for it (about a minute each on a small box). Run it in a quiet
-- hour; if that is not possible, use plain VACUUM (ANALYZE) instead, which
-- only makes the space reusable.
VACUUM (FULL, ANALYZE) team_vo_bearer_tokens;
VACUUM (FULL, ANALYZE) used_random_challenges;

SELECT relname,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       n_live_tup
FROM pg_stat_user_tables
WHERE relname IN ('team_vo_bearer_tokens', 'used_random_challenges');
