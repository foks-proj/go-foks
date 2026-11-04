// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/stretchr/testify/require"
)

func newRaceTestContext(t *testing.T, cfg MerkleRaceRetryConfig) MetaContext {
	ctx := context.Background()
	g := NewGlobalContext()
	g.Cfg().TestSetHomeCLIFlag(t.TempDir())
	g.Cfg().TestSetLogTargets("stdout", "stderr")
	g.Cfg().TestSetTestingMode()
	require.NoError(t, g.Configure(ctx))
	t.Cleanup(g.Shutdown)
	g.Cfg().TestSetMerkleRaceRetryConfig(cfg)
	return NewMetaContext(ctx, g)
}

// A caller's deadline ends the merkle-race backoff, rather than the loader
// sleeping out the rest of it.
func TestRunManyMerkleRaceWaitStopsAtDeadline(t *testing.T) {
	m := newRaceTestContext(t, MerkleRaceRetryConfig{NumRetries: 10, Wait: time.Hour})
	m, cancel := m.WithContextTimeout(50 * time.Millisecond)
	defer cancel()

	runs := 0
	race := func(MetaContext) error {
		runs++
		return core.ChainLoaderError{Err: core.InternalError("not in merkle yet"), Race: true}
	}

	var b BaseChainLoader
	start := time.Now()
	err := b.runMany(m, race, nil)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, core.IsTransportError(err))
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, 1, runs)
}

// Without a deadline, a race still retries until it clears.
func TestRunManyMerkleRaceRetriesUntilClear(t *testing.T) {
	m := newRaceTestContext(t, MerkleRaceRetryConfig{NumRetries: 10, Wait: time.Millisecond})

	runs := 0
	raceTwice := func(MetaContext) error {
		runs++
		if runs <= 2 {
			return core.ChainLoaderError{Err: core.InternalError("not in merkle yet"), Race: true}
		}
		return nil
	}

	var b BaseChainLoader
	require.NoError(t, b.runMany(m, raceTwice, nil))
	require.Equal(t, 3, runs)
}
