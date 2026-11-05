// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"bytes"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockedInGetLockedNode reports whether the goroutine whose stack header
// starts with hdr ("goroutine N [") is blocked on a lock inside getLockedNode.
func blockedInGetLockedNode(hdr []byte) bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.HasPrefix(g, hdr) &&
			bytes.Contains(g, []byte("(*PartyLoaderCache).getLockedNode")) &&
			bytes.Contains(g, []byte("sync.(*Mutex).lockSlow")) {
			return true
		}
	}
	return false
}

// A caller waiting in getLockedNode for a node another goroutine holds must not
// hold the cache lock, or loadTeam (which takes it while holding the node)
// deadlocks. See getLockedNode.
func TestPartyLoaderCacheNodeWaiterDoesNotHoldCacheLock(t *testing.T) {
	fqp := proto.FQParty{Party: mkTestTeamID(t, proto.EntityType_NamedTeam).ToPartyID()}
	fqef, err := fqp.FQEntity().Fixed()
	require.NoError(t, err)

	p := NewPartyLoaderCache(nil)
	node := &PLCNode{id: fqp}
	p.parties[*fqef] = node

	node.Lock() // a stale reload in progress

	got := make(chan *PLCNode, 1)
	hdrCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		buf = buf[:runtime.Stack(buf, false)]
		hdrCh <- buf[:bytes.IndexByte(buf, '[')+1]
		n, _ := p.getLockedNode(fqp)
		got <- n
	}()
	hdr := <-hdrCh

	require.Eventually(t, func() bool { return blockedInGetLockedNode(hdr) },
		5*time.Second, time.Millisecond, "getLockedNode never blocked on the held node")

	// Take the cache lock while still holding the node, as loadTeam does when
	// a reload finishes.
	require.True(t, p.TryLock(), "a goroutine waiting on a node lock is holding the cache lock")
	p.fqptCache[proto.StdHash{}] = &fqp
	p.Unlock()
	node.Unlock()

	select {
	case n := <-got:
		require.Same(t, node, n)
		n.Unlock()
	case <-time.After(5 * time.Second):
		t.Fatal("getLockedNode never acquired the released node")
	}
}

// Concurrent first loads of one party all get the same node, and it is locked
// on return.
func TestPartyLoaderCacheCreatesOneNodePerParty(t *testing.T) {
	fqp := proto.FQParty{Party: mkTestTeamID(t, proto.EntityType_NamedTeam).ToPartyID()}
	p := NewPartyLoaderCache(&UserContext{})

	const n = 16
	nodes := make([]*PLCNode, n)
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			node, err := p.getLockedNode(fqp)
			if !assert.NoError(t, err) {
				return
			}
			assert.False(t, node.TryLock(), "getLockedNode returned an unlocked node")
			node.skm = nil // a write that -race flags if two callers hold the node at once
			nodes[i] = node
			node.Unlock()
		}()
	}
	wg.Wait()

	require.NotNil(t, nodes[0])
	for _, node := range nodes {
		require.Same(t, nodes[0], node)
	}
	require.Len(t, p.parties, 1)
}

// fakeKeySeq holds private keys at the given generations; the highest is
// Current.
type fakeKeySeq []proto.Generation

func (s fakeKeySeq) At(g proto.Generation) core.SharedPrivateSuiter {
	for _, h := range s {
		if h == g {
			return &core.SharedPrivateSuite25519{Md: core.SharedKeyMetadata{Gen: g}}
		}
	}
	return nil
}

func (s fakeKeySeq) Current() core.SharedPrivateSuiter {
	if len(s) == 0 {
		return nil
	}
	return s.At(slices.Max(s))
}

// Only a generation newer than every one held means the cached team missed a
// rekey; an older or held generation must never trigger a reload.
func TestGenAhead(t *testing.T) {
	tests := []struct {
		name string
		held fakeKeySeq
		gen  proto.Generation
		want bool
	}{
		{"held", fakeKeySeq{1, 2}, 2, false},
		{"older and missing", fakeKeySeq{2, 3}, 1, false},
		{"newer than current", fakeKeySeq{1, 2}, 3, true},
		{"far newer", fakeKeySeq{1}, 1000, true},
		{"nothing held", fakeKeySeq{}, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, genAhead(tt.held, tt.gen))
		})
	}
}

// A sender picks the generation in its box, so reloads it can trigger on one
// node are spaced at least genAheadReloadFloor apart.
func TestClaimGenAheadReloadFloor(t *testing.T) {
	n := &PLCNode{}
	t0 := time.Unix(1_000_000, 0)
	require.True(t, n.claimGenAheadReloadLocked(t0), "first claim")
	require.False(t, n.claimGenAheadReloadLocked(t0.Add(genAheadReloadFloor-time.Second)), "inside the floor")
	require.True(t, n.claimGenAheadReloadLocked(t0.Add(genAheadReloadFloor)), "at the floor")
	require.False(t, n.claimGenAheadReloadLocked(t0.Add(genAheadReloadFloor+time.Second)), "floor restarts from the last claim")
}
