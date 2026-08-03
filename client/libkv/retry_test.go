// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
)

func TestIsStaleTeamTokenError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"stale member", core.TeamBearerTokenStaleError{Which: "stale member"}, true},
		{"aged out", core.TeamBearerTokenStaleError{Which: "age"}, true},
		{"wrapped", fmt.Errorf("kv put: %w",
			core.TeamBearerTokenStaleError{Which: "stale member"}), true},
		{"token row gone", core.NotFoundError("team vo bearer token"), true},
		{"unrelated not-found", core.NotFoundError("dirent"), false},
		{"permission", core.PermissionError("nope"), false},
		{"stale cache", core.KVStaleCacheError{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isStaleTeamTokenError(c.err); got != c.want {
				t.Fatalf("isStaleTeamTokenError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
