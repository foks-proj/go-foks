// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"

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
