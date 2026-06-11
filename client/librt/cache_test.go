// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package librt

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLRUBasic(t *testing.T) {
	c := NewLRU[string, int](2)

	_, ok := c.Get("missing")
	require.False(t, ok)
	require.Equal(t, 0, c.Len())

	c.Put("a", 1)
	c.Put("b", 2)
	require.Equal(t, 2, c.Len())

	v, ok := c.Get("a")
	require.True(t, ok)
	require.Equal(t, 1, v)

	// Updating an existing key changes the value without growing the cache.
	c.Put("a", 10)
	require.Equal(t, 2, c.Len())
	v, _ = c.Get("a")
	require.Equal(t, 10, v)
}

func TestLRUEviction(t *testing.T) {
	c := NewLRU[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3) // over capacity -> evict least-recently-used ("a")

	require.Equal(t, 2, c.Len())
	_, ok := c.Get("a")
	require.False(t, ok, "a should have been evicted")
	_, ok = c.Get("b")
	require.True(t, ok)
	_, ok = c.Get("c")
	require.True(t, ok)
}

func TestLRUGetRefreshesRecency(t *testing.T) {
	c := NewLRU[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)

	// Touch "a" so "b" is now the least-recently-used.
	_, ok := c.Get("a")
	require.True(t, ok)

	c.Put("c", 3) // should evict "b", not "a"
	_, ok = c.Get("b")
	require.False(t, ok, "b should have been evicted")
	_, ok = c.Get("a")
	require.True(t, ok, "a was refreshed and should survive")
}

func TestLRUPeekDoesNotRefresh(t *testing.T) {
	c := NewLRU[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)

	// Peek must not change recency, so "a" stays least-recently-used.
	v, ok := c.Peek("a")
	require.True(t, ok)
	require.Equal(t, 1, v)

	c.Put("c", 3) // evicts "a"
	_, ok = c.Peek("a")
	require.False(t, ok, "Peek should not have rescued a from eviction")
}

func TestLRURemoveAndPurge(t *testing.T) {
	c := NewLRU[string, int](3)
	c.Put("a", 1)
	c.Put("b", 2)

	require.True(t, c.Remove("a"))
	require.False(t, c.Remove("a"), "second remove is a no-op")
	_, ok := c.Get("a")
	require.False(t, ok)
	require.Equal(t, 1, c.Len())

	c.Purge()
	require.Equal(t, 0, c.Len())
	_, ok = c.Get("b")
	require.False(t, ok)
}

func TestLRUUnbounded(t *testing.T) {
	c := NewLRU[int, int](0) // capacity <= 0 => no eviction
	for i := 0; i < 100; i++ {
		c.Put(i, i)
	}
	require.Equal(t, 100, c.Len())
	v, ok := c.Get(0)
	require.True(t, ok, "nothing should be evicted when unbounded")
	require.Equal(t, 0, v)
}

// TestLRUConcurrent is a smoke test for the internal RWMutex; run under -race.
func TestLRUConcurrent(t *testing.T) {
	c := NewLRU[int, int](64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				k := (g*1000 + i) % 128
				c.Put(k, i)
				_, _ = c.Get(k)
				_, _ = c.Peek(k)
				_ = c.Len()
				if i%50 == 0 {
					c.Remove(k)
				}
			}
		}(g)
	}
	wg.Wait()
	require.LessOrEqual(t, c.Len(), 64)
}
