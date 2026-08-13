// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type nameCacheEntry struct {
	name      proto.NameUtf8
	expiresAt time.Time
}

const (
	// nameCacheTTLBase is the central lifetime of a cached key->name entry;
	// nameCacheTTLJitter is the random spread added on top so a burst of
	// entries cached together don't all expire at once and stampede the server.
	nameCacheTTLBase   = 6 * time.Hour
	nameCacheTTLJitter = 2 * time.Hour
)

// jitteredNameTTL returns a lifetime uniformly in
// [base - jitter/2, base + jitter/2), centered on base (~6h).
func jitteredNameTTL() time.Duration {
	return nameCacheTTLBase - nameCacheTTLJitter/2 +
		time.Duration(rand.Int63n(int64(nameCacheTTLJitter)))
}

// nameCache memoizes K -> display-name with two tiers: an in-memory map in
// front of the soft local DB, so entries survive agent restarts. It's the
// shared core of UsernameLoader and TeamnameLoader, which differ only in key
// type, DataType, and how a key maps to a DB row address. Soft state
// throughout: a failed read or write of the DB tier degrades to a cache miss,
// never an error.
type nameCache[K comparable] struct {
	sync.RWMutex
	m map[K]nameCacheEntry

	typ lcl.DataType
	// rowAddr maps a key to its (scope, key) address in the soft DB.
	rowAddr func(K) (Scoper, any)
}

func newNameCache[K comparable](
	typ lcl.DataType,
	rowAddr func(K) (Scoper, any),
) nameCache[K] {
	return nameCache[K]{typ: typ, rowAddr: rowAddr}
}

// Get returns a cached, unexpired display name for k, if any, trying the
// memory tier and then the soft DB. A fresh DB hit warms the memory tier, with
// its expiry anchored at the row's write time, so the ~TTL staleness bound
// holds across both tiers.
func (c *nameCache[K]) Get(m MetaContext, k K) (proto.NameUtf8, bool) {
	if nm, ok := c.getMem(m, k); ok {
		return nm, true
	}
	return c.getDb(m, k)
}

// Set records k -> name in both tiers, with a fresh jittered TTL. A DB-tier
// write failure is returned but the memory tier is set regardless.
func (c *nameCache[K]) Set(m MetaContext, k K, nm proto.NameUtf8) error {
	c.putMem(k, nm, m.Now().Add(jitteredNameTTL()))
	if c.rowAddr == nil {
		// Zero-value cache (not made via newNameCache): soft state, so degrade
		// to memory-only rather than crash.
		m.Warnw("nameCache.Set", "err", "no rowAddr; memory tier only")
		return nil
	}
	scope, key := c.rowAddr(k)
	return m.DbPut(DbTypeSoft, PutArg{
		Scope: scope,
		Typ:   c.typ,
		Key:   key,
		Val:   &nm,
	})
}

// getMem returns an unexpired entry from the memory tier. An expired entry is
// reported as a miss but left in place rather than deleted (no lock upgrade);
// the Set or DB-warm that follows a miss overwrites it.
func (c *nameCache[K]) getMem(m MetaContext, k K) (proto.NameUtf8, bool) {
	c.RLock()
	defer c.RUnlock()
	ent, ok := c.m[k]
	if !ok || !m.Now().Before(ent.expiresAt) {
		return "", false
	}
	return ent.name, true
}

func (c *nameCache[K]) putMem(k K, nm proto.NameUtf8, expiresAt time.Time) {
	c.Lock()
	defer c.Unlock()
	if c.m == nil {
		c.m = make(map[K]nameCacheEntry)
	}
	c.m[k] = nameCacheEntry{
		name:      nm,
		expiresAt: expiresAt,
	}
}

func (c *nameCache[K]) getDb(m MetaContext, k K) (proto.NameUtf8, bool) {
	if c.rowAddr == nil {
		return "", false // zero-value cache; see Set
	}
	var nm proto.NameUtf8
	scope, key := c.rowAddr(k)
	tm, err := m.DbGet(&nm, DbTypeSoft, scope, c.typ, key)
	if err != nil {
		if !errors.Is(err, core.RowNotFoundError{}) {
			m.Warnw("nameCache.getDb", "typ", c.typ, "key", k, "err", err)
		}
		return "", false
	}
	expiresAt := tm.Import().Add(jitteredNameTTL())
	if !m.Now().Before(expiresAt) {
		return "", false
	}
	c.putMem(k, nm, expiresAt)
	return nm, true
}
