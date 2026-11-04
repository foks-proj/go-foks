// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"time"
)

// Every team load mints a team VO bearer token (a challenge RPC and an activate
// RPC), and each activation leaves two rows behind: the token in
// team_vo_bearer_tokens and its challenge in used_random_challenges. Nothing
// ever deleted either, although a token is refused once it is older than
// TeamBearerTokenLifespan, so both tables grew without bound -- tens of
// millions of dead rows on a busy host, with random-key indexes far larger
// than RAM that every new activation has to insert into.

const (
	// challengeWindow is how long a signed challenge stays acceptable: proto
	// Time.IsStale refuses one older than 24h before the replay check runs, so
	// a used_random_challenges row only guards anything for this long.
	challengeWindow = 24 * time.Hour

	// voTokenGCMargin keeps rows a day past the point where they stop
	// mattering, so clock skew between server processes can never make the GC
	// race a token or challenge that is still live.
	voTokenGCMargin = 24 * time.Hour

	// voTokenGCStartDelay holds the first round back after startup. A restart
	// is when every client reconnects at once, and a GC batch then has to wait
	// for one of the user server's pooled connections behind that burst: on
	// a 10-connection pool it waited out voTokenGCBatchTimeout, while the next
	// hourly round deleted 30k rows in about a second.
	voTokenGCStartDelay = 5 * time.Minute
	voTokenGCInterval   = time.Hour
	voTokenGCBatch      = 10000

	// voTokenGCBatchTimeout bounds one batch, like looperDbTimeout does for the
	// poll loops: a dead pooled connection must not wedge the loop.
	voTokenGCBatchTimeout = 60 * time.Second
)

// voTokenRetention is how long a VO bearer token row is kept after its ctime.
// The token's ctime is its challenge's time (insertTeamVOBearerToken), so past
// this point the server refuses both the token (age) and a replay of its
// challenge (staleness) without reading either row.
func voTokenRetention(lifespan time.Duration) time.Duration {
	return max(lifespan, challengeWindow) + voTokenGCMargin
}

// DeleteExpiredVOBearerTokens deletes up to limit team VO bearer tokens created
// before cutoff, together with the used-challenge rows of their activations (a
// token's bytes are its challenge's random bytes, see ActivateTeamVOBearerToken).
// It reports how many tokens it deleted. Rows of every host go: retention
// depends only on server-wide settings.
func DeleteExpiredVOBearerTokens(m MetaContext, cutoff time.Time, limit int) (int, error) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return 0, err
	}
	defer db.Release()
	var n int
	// Data-modifying CTEs always run to completion, so `chal` deletes the
	// challenges even though the outer SELECT reads only `gone`.
	err = db.QueryRow(m.Ctx(),
		`WITH gone AS (
		   DELETE FROM team_vo_bearer_tokens
		   WHERE (short_host_id, team_id, token) IN (
		     SELECT short_host_id, team_id, token
		     FROM team_vo_bearer_tokens
		     WHERE ctime < $1
		     LIMIT $2)
		   RETURNING short_host_id, token
		 ), chal AS (
		   DELETE FROM used_random_challenges AS c
		   USING gone AS g
		   WHERE c.short_host_id = g.short_host_id AND c.challenge = g.token
		 )
		 SELECT COUNT(*) FROM gone`,
		cutoff,
		limit,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// gcExpiredVOBearerTokens deletes every expired token, a batch at a time so no
// single statement holds locks or builds WAL for long.
func gcExpiredVOBearerTokens(m MetaContext) (int, error) {
	settings, err := m.G().Config().Settings(m.Ctx())
	if err != nil {
		return 0, err
	}
	cutoff := m.Now().Add(-voTokenRetention(settings.TeamBearerTokenLifespan()))
	total := 0
	for {
		mb, cancel := m.WithContextTimeout(voTokenGCBatchTimeout)
		n, err := DeleteExpiredVOBearerTokens(mb, cutoff, voTokenGCBatch)
		cancel()
		total += n
		if err != nil {
			return total, err
		}
		if n < voTokenGCBatch {
			return total, nil
		}
	}
}

// RunVOBearerTokenGC deletes expired team VO bearer tokens voTokenGCStartDelay
// after startup and then every voTokenGCInterval, until m's context ends. A
// failed round is logged and retried on the next tick: a missed round only
// delays the cleanup. Running it in more than one process is harmless, as the
// deletes are idempotent.
func RunVOBearerTokenGC(m MetaContext) {
	wait := voTokenGCStartDelay
	for {
		select {
		case <-time.After(wait):
		case <-m.Ctx().Done():
			return
		}
		wait = voTokenGCInterval
		n, err := gcExpiredVOBearerTokens(m)
		if err != nil {
			m.Warnw("RunVOBearerTokenGC", "deleted", n, "err", err)
		} else if n > 0 {
			m.Infow("RunVOBearerTokenGC", "deleted", n)
		}
	}
}
