// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestBackpointSequence(t *testing.T) {
	var tests = []struct {
		e proto.MerkleEpno
		v []proto.MerkleEpno
	}{
		{
			proto.MerkleEpno(32),
			[]proto.MerkleEpno{31, 30, 28, 24, 16},
		}, {
			proto.MerkleEpno(2),
			[]proto.MerkleEpno{1},
		}, {
			proto.MerkleEpno(1),
			nil,
		}, {
			proto.MerkleEpno(3),
			[]proto.MerkleEpno{2, 1},
		}, {
			proto.MerkleEpno(4),
			[]proto.MerkleEpno{3, 2, 1},
		}, {
			proto.MerkleEpno(5),
			[]proto.MerkleEpno{4},
		}, {
			proto.MerkleEpno(100001),
			[]proto.MerkleEpno{100000},
		}, {
			proto.MerkleEpno(0x58),
			[]proto.MerkleEpno{0x57, 0x56, 0x54, 0x50},
		}, {
			proto.MerkleEpno(0x5ffffff8),
			[]proto.MerkleEpno{0x5ffffff7, 0x5ffffff6, 0x5ffffff4, 0x5ffffff0},
		},
	}
	for _, tst := range tests {
		require.Equal(t, tst.v, MerkleBackpointerSequence(tst.e))
	}

}

func TestCollectRoots(t *testing.T) {

	var vectors = []struct {
		start  int
		finish int
	}{
		{0xfffff, 1},
		{0xfffffff, 0x44ca},
		{0xfffffffff, 0x8},
	}

	log2 := func(i int) int {
		c := 0
		for i > 0 {
			i >>= 1
			c++
		}
		return c
	}

	for _, e := range vectors {
		p, r := MerkleCollectRoots(proto.MerkleEpno(e.start), proto.MerkleEpno(e.finish))
		l2 := log2(e.start)
		require.Less(t, len(p), 2*l2)
		require.Less(t, len(r), l2*l2)
	}
}
