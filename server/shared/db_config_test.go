// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestDbConfigPoolMaxConns(t *testing.T) {
	parse := func(d DbConfigJSON) int32 {
		cfg, err := pgxpool.ParseConfig(d.ToString())
		require.NoError(t, err)
		return cfg.MaxConns
	}
	base := DbConfigJSON{Host: "localhost", Name: "foks_users", NoTLS: true}
	require.Equal(t, int32(defaultPoolMaxConns), parse(base))
	base.PoolMaxConns = 12
	require.Equal(t, int32(12), parse(base))
}
