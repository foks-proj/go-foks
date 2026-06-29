// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"slices"
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// mkTestFQParty builds an FQParty whose Party and Host bytes are each a single
// repeated value, so tests can cheaply make distinct, ordered parties.
func mkTestFQUser(party byte, host byte) proto.FQUser {
	var h proto.HostID
	for i := range h {
		h[i] = host
	}
	p := make([]byte, len(h))
	for i := range p {
		p[i] = party
	}
	return proto.FQUser{
		Uid:    proto.UID(p),
		HostID: h,
	}
}

func TestMashAdHocTeamID(t *testing.T) {
	a := mkTestFQUser(0x01, 0xaa)
	b := mkTestFQUser(0x02, 0xaa)
	c := mkTestFQUser(0x03, 0xbb)
	d := mkTestFQUser(0x04, 0xbb)

	// mash derefs to a value so the comparisons below are value-based.
	mash := func(users ...proto.FQUser) proto.AdHocTeamMashedID {
		h, err := MashFQUsersIntoAdHocTeamID(users, proto.HostID{0xaa})
		require.NoError(t, err)
		require.NotNil(t, h)
		return *h
	}

	// Deterministic: same set, same order -> same ID.
	h1 := mash(a, b, c)
	require.Equal(t, h1, mash(a, b, c))

	// Something was actually written.
	require.NotEqual(t, proto.AdHocTeamMashedID{}, h1)

	// Order-independent: a different input ordering of the same set mashes to
	// the same ID, because the function canonicalizes by sorting the parties.
	require.Equal(t, h1, mash(c, a, b))

	// Sensitive to membership: dropping a party changes the ID...
	require.NotEqual(t, h1, mash(a, b))

	// ...and swapping one party for a different one changes the ID.
	require.NotEqual(t, h1, mash(a, b, d))

	// A single-party team is fine and distinct from the multi-party ones.
	require.NotEqual(t, h1, mash(a))
}

// TestMashAdHocTeamIDSortsInputInPlace documents that the function sorts its
// input slice in place as a side effect of canonicalizing before hashing.
func TestMashAdHocTeamIDSortsInputInPlace(t *testing.T) {
	a := mkTestFQUser(0x01, 0xaa)
	b := mkTestFQUser(0x02, 0xaa)
	c := mkTestFQUser(0x03, 0xbb)

	// Deliberately unsorted (Host 0xbb sorts after 0xaa).
	parties := []proto.FQUser{c, b, a}
	_, err := MashFQUsersIntoAdHocTeamID(parties, proto.HostID{0xaa})
	require.NoError(t, err)

	require.True(t, slices.IsSortedFunc(parties, func(x, y proto.FQUser) int {
		return x.ToFQParty().Cmp(y.ToFQParty())
	}))
}
