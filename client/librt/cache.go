// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package librt

import (
	"container/list"
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// LRU is a fixed-capacity, least-recently-used cache. It is safe for concurrent
// use: all access is guarded by an internal RWMutex. Reads that don't change
// recency (Peek, Len) take the read lock; everything else takes the write lock.
//
// A capacity <= 0 disables eviction, so the cache grows without bound.
type LRU[
	K comparable,
	V any,
] struct {
	mu       sync.RWMutex
	capacity int
	ll       *list.List // front = most-recently-used, back = least
	items    map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

// NewLRU returns an empty cache holding at most `capacity` entries (unbounded
// if capacity <= 0).
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	return &LRU[K, V]{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[K]*list.Element),
	}
}

// Get returns the value stored for k and marks it most-recently-used. The bool
// is false if k isn't present.
func (l *LRU[K, V]) Get(k K) (V, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[k]; ok {
		l.ll.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// Peek returns the value stored for k without changing its recency.
func (l *LRU[K, V]) Peek(k K) (V, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if el, ok := l.items[k]; ok {
		return el.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// Put inserts or updates k=v, marks it most-recently-used, and evicts the
// least-recently-used entry if that pushes the cache over capacity.
func (l *LRU[K, V]) Put(k K, v V) *V {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[k]; ok {
		prev := el.Value.(*lruEntry[K, V]).val
		el.Value.(*lruEntry[K, V]).val = v
		l.ll.MoveToFront(el)
		return &prev
	}
	l.items[k] = l.ll.PushFront(&lruEntry[K, V]{key: k, val: v})
	if l.capacity > 0 && l.ll.Len() > l.capacity {
		l.removeElement(l.ll.Back())
	}
	return nil
}

// Remove deletes k, returning true if it was present.
func (l *LRU[K, V]) Remove(k K) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[k]; ok {
		l.removeElement(el)
		return true
	}
	return false
}

// Len returns the number of entries currently cached.
func (l *LRU[K, V]) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.ll.Len()
}

// Purge drops every entry.
func (l *LRU[K, V]) Purge() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ll.Init()
	l.items = make(map[K]*list.Element)
}

// removeElement unlinks el from the list and the index. The caller must hold
// the write lock.
func (l *LRU[K, V]) removeElement(el *list.Element) {
	l.ll.Remove(el)
	delete(l.items, el.Value.(*lruEntry[K, V]).key)
}

type ChannelSetCache struct {
	*libclient.Cache[
		*proto.FQParty,
		lcl.RTChannelSetID,
		rem.RTChannelSet,
		*rem.RTChannelSet,
		lcl.RTChannelMetadataPlaintextAbbrev,
	]
}

func NewChannelSetCache(p proto.FQParty, settings libclient.CacheSettings) *ChannelSetCache {
	return &ChannelSetCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			lcl.RTChannelSetID,
			rem.RTChannelSet,
			*rem.RTChannelSet,
			lcl.RTChannelMetadataPlaintextAbbrev,
		](lcl.DataType_RTChannelSet, &p, settings),
	}
}

type caches struct {
	channelSets *ChannelSetCache
}

func newCaches(
	p proto.FQParty,
	settings libclient.CacheSettings,
) *caches {
	return &caches{
		channelSets: NewChannelSetCache(p, settings),
	}
}

func DeriveRTChannelSetID(
	p proto.FQParty,
	i proto.RTAppID,
) (
	*lcl.RTChannelSetID,
	error,
) {
	var ret lcl.RTChannelSetID
	err := core.PrefixedHashInto(
		&lcl.RTChannelSetHashInput{
			Fqp:   p,
			AppID: i,
		},
		ret[:],
	)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}
