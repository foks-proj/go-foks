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
func mkTestFQParty(party byte, host byte) proto.FQParty {
	var h proto.HostID
	for i := range h {
		h[i] = host
	}
	p := make([]byte, len(h))
	for i := range p {
		p[i] = party
	}
	return proto.FQParty{
		Party: proto.PartyID(p),
		Host:  h,
	}
}

func TestMashAdHocTeamID(t *testing.T) {
	a := mkTestFQParty(0x01, 0xaa)
	b := mkTestFQParty(0x02, 0xaa)
	c := mkTestFQParty(0x03, 0xbb)

	// Deterministic: same set, same order -> same ID.
	h1, err := MashAdHocTeamID([]proto.FQParty{a, b, c})
	require.NoError(t, err)
	h2, err := MashAdHocTeamID([]proto.FQParty{a, b, c})
	require.NoError(t, err)
	require.Equal(t, h1, h2)

	// Something was actually written.
	require.NotEqual(t, proto.AdHocTeamMashedID{}, h1)

	// Order-independent: a different input ordering of the same set mashes to
	// the same ID, because the function canonicalizes by sorting the parties.
	h3, err := MashAdHocTeamID([]proto.FQParty{c, a, b})
	require.NoError(t, err)
	require.Equal(t, h1, h3)

	// Sensitive to membership: dropping a party changes the ID...
	h4, err := MashAdHocTeamID([]proto.FQParty{a, b})
	require.NoError(t, err)
	require.NotEqual(t, h1, h4)

	// ...and swapping one party for a different one changes the ID.
	d := mkTestFQParty(0x04, 0xbb)
	h5, err := MashAdHocTeamID([]proto.FQParty{a, b, d})
	require.NoError(t, err)
	require.NotEqual(t, h1, h5)

	// A single-party team is fine and distinct from the multi-party ones.
	h6, err := MashAdHocTeamID([]proto.FQParty{a})
	require.NoError(t, err)
	require.NotEqual(t, h1, h6)
}

// TestMashAdHocTeamIDSortsInputInPlace documents that the function sorts its
// input slice in place as a side effect of canonicalizing before hashing.
func TestMashAdHocTeamIDSortsInputInPlace(t *testing.T) {
	a := mkTestFQParty(0x01, 0xaa)
	b := mkTestFQParty(0x02, 0xaa)
	c := mkTestFQParty(0x03, 0xbb)

	// Deliberately unsorted (Host 0xbb sorts after 0xaa).
	parties := []proto.FQParty{c, b, a}
	_, err := MashAdHocTeamID(parties)
	require.NoError(t, err)

	require.True(t, slices.IsSortedFunc(parties, func(x, y proto.FQParty) int {
		return x.Cmp(y)
	}))
}
