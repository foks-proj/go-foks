// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"testing"
	"time"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// TestDescribeVerifiedAge: this column is the only thing telling a reader
// whether a team listing reflects something current or a snapshot from last
// month, so the case that matters most is the absent stamp. A snapshot written
// before the field existed is the *most* likely to be badly stale; rendering
// it as a zero duration would state the opposite of the truth, which is worse
// than saying nothing.
func TestDescribeVerifiedAge(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	t.Run("no stamp is not zero age", func(t *testing.T) {
		out := describeVerifiedAge(proto.Time(0), now)
		require.Equal(t, "unknown", out)
		require.NotContains(t, out, "0s")
	})

	t.Run("age renders as elapsed time", func(t *testing.T) {
		stamped := proto.ExportTime(now.Add(-90 * time.Second))
		require.Equal(t, "1m30s ago", describeVerifiedAge(stamped, now))
	})

	t.Run("a stamp in the future reads as skew, not a negative age", func(t *testing.T) {
		stamped := proto.ExportTime(now.Add(time.Hour))
		require.Equal(t, "clock skew", describeVerifiedAge(stamped, now))
	})
}
