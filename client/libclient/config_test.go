// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestApplyJitterZero(t *testing.T) {
	bg := NewBgTiming(time.Minute*13, time.Second*10, 0)
	for i := 0; i < 100; i++ {
		require.Equal(t, time.Minute*13, bg.Sleep())
		require.Equal(t, time.Second*10, bg.Pause())
	}
}

func TestApplyJitterStaysInPercentBand(t *testing.T) {
	base := time.Minute * 13
	bg := NewBgTiming(base, time.Second*10, 10)

	lo := base - base/10
	hi := base + base/10

	var sawJitter bool
	for i := 0; i < 10000; i++ {
		d := bg.Sleep()
		require.GreaterOrEqual(t, d, lo)
		require.LessOrEqual(t, d, hi)
		if d != base {
			sawJitter = true
		}
	}

	// The whole point of the setting: a fleet of clients must not tick in
	// lockstep. An implementation that truncates the jitter factor to 0
	// returns base every time and passes the bounds check above.
	require.True(t, sawJitter, "jitter=10 never perturbed the duration")
}

func TestApplyJitterCoversBothDirections(t *testing.T) {
	base := time.Minute * 13
	bg := NewBgTiming(base, time.Second*10, 25)

	var sawShorter, sawLonger bool
	for i := 0; i < 10000 && (!sawShorter || !sawLonger); i++ {
		switch d := bg.Sleep(); {
		case d < base:
			sawShorter = true
		case d > base:
			sawLonger = true
		}
	}
	require.True(t, sawShorter, "jitter never shortened the duration")
	require.True(t, sawLonger, "jitter never lengthened the duration")
}

func TestApplyJitterLargeValuesStayBounded(t *testing.T) {
	bases := []time.Duration{
		time.Nanosecond,
		time.Millisecond,
		time.Second * 10,
		time.Minute * 17,
		time.Hour * 24,

		// Past this point base*pct leaves int64 range for a large jitter,
		// and a wrapped product lands negative about half the time.
		time.Hour * 48,
		time.Hour * 24 * 7,
	}
	jitters := []uint16{100, 101, 1000, 32767, 32768, 65535}

	for _, jit := range jitters {
		for _, base := range bases {
			bg := NewBgTiming(base, base, jit)
			for i := 0; i < 1000; i++ {
				for _, d := range []time.Duration{bg.Sleep(), bg.Pause()} {
					// Positive on its own is too weak: an overflowed
					// product clamps to 1ns and passes. The jitter is
					// capped at 100%, so nothing may exceed 2*base
					// either.
					require.Positive(t, d,
						"jitter=%d base=%s produced a non-positive duration", jit, base)
					require.LessOrEqual(t, d, 2*base,
						"jitter=%d base=%s exceeded 2*base", jit, base)
				}
			}
		}
	}
}
