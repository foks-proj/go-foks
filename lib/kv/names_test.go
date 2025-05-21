// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kv

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestParseAbsPath(t *testing.T) {

	for i, tst := range []struct {
		in  string
		res *ParsedPath
		err error
	}{
		{
			in:  "",
			err: core.KVPathError("empty path"),
		},
		{
			in: "/a",
			res: &ParsedPath{
				Components:   []proto.KVPathComponent{"a"},
				LeadingSlash: true,
			},
		},
		{
			in: "/a/b/c",
			res: &ParsedPath{
				Components:   []proto.KVPathComponent{"a", "b", "c"},
				LeadingSlash: true,
			},
		},
		{
			in: "//a/////b/c///",
			res: &ParsedPath{
				Components:    []proto.KVPathComponent{"a", "b", "c"},
				TrailingSlash: true,
				LeadingSlash:  true,
			},
		},
		{
			in:  "a/b",
			err: core.KVAbsPathError{Path: proto.KVPath("a/b")},
		},
	} {
		p, err := ParseAbsPath(proto.KVPath(tst.in))
		require.Equal(t, tst.err, err, "case %d", i)
		if tst.res == nil {
			require.Nil(t, p, "case %d", i)
		} else {
			require.NotNil(t, p, "case %d", i)
			require.Equal(t, *tst.res, *p, "case %d", i)
		}

	}
}
