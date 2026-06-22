// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package librt

import (
	"bytes"
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// threadMsgsFromSeqs builds a thread run carrying only seqs, which is all
// findHoles inspects.
func threadMsgsFromSeqs(seqs ...int) []ThreadMessage {
	out := make([]ThreadMessage, len(seqs))
	for i, s := range seqs {
		out[i] = ThreadMessage{Seq: proto.RTMsgSeq(s)}
	}
	return out
}

func seqList(seqs ...int) []proto.RTMsgSeq {
	out := make([]proto.RTMsgSeq, len(seqs))
	for i, s := range seqs {
		out[i] = proto.RTMsgSeq(s)
	}
	return out
}

func TestFindHoles(t *testing.T) {
	tests := []struct {
		name  string
		in    []ThreadMessage
		holes []proto.RTMsgSeq
		err   bool
	}{
		// Degenerate runs: nothing to find, never an error.
		{name: "empty", in: nil},
		{name: "single", in: threadMsgsFromSeqs(5)},

		// Contiguous runs in both directions => no holes.
		{name: "two_adjacent_asc", in: threadMsgsFromSeqs(5, 6)},
		{name: "two_adjacent_desc", in: threadMsgsFromSeqs(6, 5)},
		{name: "no_holes_asc", in: threadMsgsFromSeqs(5, 6, 7, 8)},
		{name: "no_holes_desc", in: threadMsgsFromSeqs(8, 7, 6, 5)},

		// Single hole, both directions. The desc case is the one the old
		// implementation wrongly rejected as non-monotonic.
		{name: "single_hole_asc", in: threadMsgsFromSeqs(6, 7, 9, 10), holes: seqList(8)},
		{name: "single_hole_desc", in: threadMsgsFromSeqs(10, 9, 7, 6), holes: seqList(8)},

		// Wide gaps spanning several missing seqs.
		{name: "wide_gap_asc", in: threadMsgsFromSeqs(6, 10), holes: seqList(7, 8, 9)},
		{name: "wide_gap_desc", in: threadMsgsFromSeqs(10, 6), holes: seqList(9, 8, 7)},

		// Several disjoint holes; order of holes follows the run direction.
		{name: "multiple_holes_asc", in: threadMsgsFromSeqs(5, 7, 8, 10), holes: seqList(6, 9)},
		{name: "multiple_holes_desc", in: threadMsgsFromSeqs(10, 8, 7, 5), holes: seqList(9, 6)},

		// Holes adjacent to the run's endpoints.
		{name: "hole_after_start_desc", in: threadMsgsFromSeqs(11, 9, 8), holes: seqList(10)},
		{name: "hole_before_end_asc", in: threadMsgsFromSeqs(5, 6, 8), holes: seqList(7)},

		// Bad server data: out of order, or not strictly monotonic.
		{name: "out_of_order", in: threadMsgsFromSeqs(10, 8, 9, 6), err: true},
		{name: "duplicate_adjacent", in: threadMsgsFromSeqs(10, 10, 9), err: true},
		{name: "duplicate_non_adjacent", in: threadMsgsFromSeqs(10, 9, 9, 8), err: true},

		// Invalid (zero) seqs are rejected wherever they appear.
		{name: "invalid_zero_seq_middle", in: threadMsgsFromSeqs(10, 0, 8), err: true},
		{name: "invalid_zero_seq_first", in: threadMsgsFromSeqs(0, 8), err: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			holes, err := findHoles(tc.in)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.holes, holes)
		})
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name        string
		left, right []int
		inc         int
		want        []int
	}{
		// Degenerate inputs.
		{name: "both_empty", inc: 1},
		{name: "left_empty_asc", right: []int{1, 2, 3}, inc: 1, want: []int{1, 2, 3}},
		{name: "right_empty_asc", left: []int{1, 2, 3}, inc: 1, want: []int{1, 2, 3}},
		{name: "left_empty_desc", right: []int{3, 2, 1}, inc: -1, want: []int{3, 2, 1}},
		{name: "right_empty_desc", left: []int{3, 2, 1}, inc: -1, want: []int{3, 2, 1}},

		// One element on each side.
		{name: "single_each_asc", left: []int{1}, right: []int{2}, inc: 1, want: []int{1, 2}},
		{name: "single_each_desc", left: []int{2}, right: []int{1}, inc: -1, want: []int{2, 1}},

		// Fully interleaved, both directions.
		{name: "interleave_asc", left: []int{1, 3, 5}, right: []int{2, 4, 6}, inc: 1, want: []int{1, 2, 3, 4, 5, 6}},
		{name: "interleave_desc", left: []int{6, 4, 2}, right: []int{5, 3, 1}, inc: -1, want: []int{6, 5, 4, 3, 2, 1}},

		// Disjoint ranges -- result is the same regardless of which side is lower.
		{name: "disjoint_left_low_asc", left: []int{1, 2}, right: []int{3, 4}, inc: 1, want: []int{1, 2, 3, 4}},
		{name: "disjoint_left_high_asc", left: []int{3, 4}, right: []int{1, 2}, inc: 1, want: []int{1, 2, 3, 4}},
		{name: "disjoint_desc", left: []int{4, 3}, right: []int{2, 1}, inc: -1, want: []int{4, 3, 2, 1}},

		// Uneven lengths: one side drains after the other is exhausted.
		{name: "uneven_lengths_asc", left: []int{1, 5}, right: []int{2, 3, 4, 6, 7}, inc: 1, want: []int{1, 2, 3, 4, 5, 6, 7}},

		// merge does not dedup: equal seqs from both sides are both kept.
		{name: "duplicates_kept_asc", left: []int{1, 2}, right: []int{2, 3}, inc: 1, want: []int{1, 2, 2, 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := merge(threadMsgsFromSeqs(tc.left...), threadMsgsFromSeqs(tc.right...), tc.inc)
			require.Equal(t, threadMsgsFromSeqs(tc.want...), got)
			// No dedup: total length is always the sum of inputs.
			require.Len(t, got, len(tc.left)+len(tc.right))
		})
	}
}

// TestMergeCopiesPayload checks that merge carries the whole message (not just
// the Seq it keys on) into the result, in the right interleaved positions.
func TestMergeCopiesPayload(t *testing.T) {
	mk := func(seq int, body string) ThreadMessage {
		return ThreadMessage{Seq: proto.RTMsgSeq(seq), Body: []byte(body)}
	}
	left := []ThreadMessage{mk(1, "one"), mk(3, "three")}
	right := []ThreadMessage{mk(2, "two"), mk(4, "four")}
	want := []ThreadMessage{mk(1, "one"), mk(2, "two"), mk(3, "three"), mk(4, "four")}
	require.Equal(t, want, merge(left, right, 1))
}

// fqParty builds an FQParty whose Party and Host bytes are each a single
// repeated value, so callers can cheaply vary one axis at a time.
func fqParty(party byte, host byte) proto.FQParty {
	var h proto.HostID
	for i := range h {
		h[i] = host
	}
	return proto.FQParty{
		Party: proto.PartyID(bytes.Repeat([]byte{party}, 16)),
		Host:  h,
	}
}

// TestCookNonceBindsHost guards against a regression where the message nonce was
// derived only from PartyIDs and omitted the HostID. Without the host in the
// nonce, two virtual hosts that happened to share a team/sender PartyID would
// cook identical nonces, so a chat sealed on one host could be opened (mixed
// in) on another. The fix folds the full FQParty (party + host) into the
// noncer; this test asserts that flipping only the host changes the cooked
// nonce, which is what makes a cross-host open fail the box's MAC check.
func TestCookNonceBindsHost(t *testing.T) {
	base := func() proto.RTMsgNoncer {
		sndr := fqParty(0x11, 0xaa)
		return proto.RTMsgNoncer{
			Md:     proto.RTMsgMetadata{Typ: proto.RTMsgType_Basic},
			Sender: &sndr,
			AppID:  proto.RTAppID_Chat,
			Team:   fqParty(0x22, 0xaa),
			Chid:   proto.RTChannelID{0x33},
		}
	}

	// Control: identical noncers cook identical nonces.
	a, err := cookNonce(ptr(base()))
	require.NoError(t, err)
	b, err := cookNonce(ptr(base()))
	require.NoError(t, err)
	require.Equal(t, *a, *b)

	// Changing only the team's host must change the nonce.
	teamHost := base()
	teamHost.Team = fqParty(0x22, 0xbb)
	c, err := cookNonce(&teamHost)
	require.NoError(t, err)
	require.NotEqual(t, *a, *c)

	// Changing only the sender's host must change the nonce.
	sndrHost := base()
	s := fqParty(0x11, 0xbb)
	sndrHost.Sender = &s
	d, err := cookNonce(&sndrHost)
	require.NoError(t, err)
	require.NotEqual(t, *a, *d)
}

func ptr[T any](v T) *T { return &v }
