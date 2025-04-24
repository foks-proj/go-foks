// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/stretchr/testify/require"
)

func TestHostname(t *testing.T) {

	testVectors := []struct {
		input string
		err   error
	}{
		{"", core.BadArgsError("hostname too short")},
		{"aa", core.BadArgsError("hostname too short")},
		{"aabbccdd", core.BadArgsError("host lacks a TLD")},
		{"me.com", core.BadArgsError("hostname cannot be an apex domain")},
		{"aa.bb.cc", nil},
		{"a-aa.b-c.com", nil},
		{"com", core.BadArgsError("host lacks a TLD")},
		{"localhost", core.BadArgsError("host lacks a TLD")},
		{"127.0.0.1", core.BadArgsError("invalid TLD")},
		{"8.8.8.8", core.BadArgsError("invalid TLD")},
		{"foks.xn--bcher-kva.com", core.BadArgsError("invalid hostname part")},
		{"a.b.c.d.e.f.g.h.i.job", core.BadArgsError("too many hostname parts")},
		{"a$$.bu++.de", core.BadArgsError("invalid hostname part")},
		{"a--b.x.com", core.BadArgsError("invalid hostname part")},
		{"a-.x.com", core.BadArgsError("invalid hostname part")},
		{"-j.x.com", core.BadArgsError("invalid hostname part")},
		{"a.b.c.d-e", core.BadArgsError("invalid TLD")},
	}

	var args Args

	for i, tv := range testVectors {
		_, err := args.validateHostname(tv.input, "test", false)
		if tv.err == nil {
			require.NoError(t, err, "vector %d / %s", i, tv.input)
		}
		if tv.err != nil {
			require.Error(t, err, "vector %d / %s", i, tv.input)
			httpErr, ok := err.(core.HttpError)
			require.True(t, ok, "vector %d / %s", i, tv.input)
			require.Equal(t, tv.err, httpErr.Err, "vector %d / %s", i, tv.input)
		}
	}
}
