// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPaddedLen(t *testing.T) {
	for i, tst := range []struct {
		in  int64
		res int64
	}{
		{0, 34},
		{1, 34},
		{16, 34},
		{17, 34},
		{33, 34},
		{34, 34},
		{35, 66},
		{64, 66},
		{65, 66},
		{66, 66},
		{67, 130},
		{127, 130},
		{128, 130},
		{129, 130},
		{130, 130},
		{131, 259},
		{255, 259},
		{256, 259},
		{16384, 16387},
		{16385, 16387},
		{16386, 16387},
		{16387, 16387},
		{16388, 32771},
		{20000, 32771},
	} {
		p, err := PaddedLen(tst.in)
		require.NoError(t, err)
		require.Equal(t, tst.res, p, "case %d", i)
	}
}

func TestPaddedLenInv(t *testing.T) {

	for i, tst := range []struct {
		in  int64
		res int64
	}{
		{34, 32},
		{66, 64},
		{130, 128},
		{259, 256},
		{16387, 16384},
	} {
		p, err := PaddedLenInv(tst.in)
		require.NoError(t, err)
		require.Equal(t, tst.res, p, "case %d", i)
	}

}
