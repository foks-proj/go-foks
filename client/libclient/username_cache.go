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

type usernameCacheEntry struct {
	name      proto.NameUtf8
	expiresAt time.Time
}

const (
	// usernameCacheTTLBase is the central lifetime of a cached UID->name entry;
	// usernameCacheTTLJitter is the random spread added on top so a burst of
	// entries cached together don't all expire at once and stampede the server.
	usernameCacheTTLBase   = 6 * time.Hour
	usernameCacheTTLJitter = 2 * time.Hour
)

// jitteredUsernameTTL returns a lifetime uniformly in
// [base - jitter/2, base + jitter/2), centered on base (~6h).
func jitteredUsernameTTL() time.Duration {
	return usernameCacheTTLBase - usernameCacheTTLJitter/2 +
		time.Duration(rand.Int63n(int64(usernameCacheTTLJitter)))
}

// UsernameCache memoizes FQUser -> display-name resolutions, each of which is
// otherwise a full user-chain load. It hangs off the GlobalContext so that all
// layers share one cache: team loads fill it whenever a member's user chain is
// loaded, and RT sender-name resolution fills it on demand.
//
// It is two-tiered: an in-memory map in front of the soft local DB (scope:
// HostID; key: UID; value: utf8 username), so entries survive agent restarts.
// It's soft state -- a failed read or write of the DB tier degrades to a cache
// miss, never an error.
//
// Keys are fully-qualified (UID + HostID), not bare UIDs: the GlobalContext
// spans all of the agent's active users, who may live on different hosts, and
// the same eldest key -- hence the same UID -- can be signed up under different
// usernames on different hosts.
type UsernameCache struct {
	sync.RWMutex
	m map[proto.FQUser]usernameCacheEntry
}

// Get returns a cached, unexpired display name for fqu, if any, trying the
// memory tier and then the soft DB. A fresh DB hit warms the memory tier, with
// its expiry anchored at the row's write time, so the ~TTL staleness bound
// holds across both tiers.
func (u *UsernameCache) Get(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	if nm, ok := u.getMem(m, fqu); ok {
		return nm, true
	}
	return u.getDb(m, fqu)
}

// Set records fqu -> name in both tiers, with a fresh jittered TTL. A DB-tier
// write failure is returned but the memory tier is set regardless.
func (u *UsernameCache) Set(m MetaContext, fqu proto.FQUser, nm proto.NameUtf8) error {
	u.putMem(fqu, nm, m.G().Now().Add(jitteredUsernameTTL()))
	return m.DbPut(DbTypeSoft, PutArg{
		Scope: &fqu.HostID,
		Typ:   lcl.DataType_UsernameCacheEntry,
		Key:   fqu.Uid,
		Val:   &nm,
	})
}

// getMem returns an unexpired entry from the memory tier. An expired entry is
// reported as a miss but left in place rather than deleted (no lock upgrade);
// the Set or DB-warm that follows a miss overwrites it.
func (u *UsernameCache) getMem(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	u.RLock()
	defer u.RUnlock()
	ent, ok := u.m[fqu]
	if !ok || !m.G().Now().Before(ent.expiresAt) {
		return "", false
	}
	return ent.name, true
}

func (u *UsernameCache) putMem(fqu proto.FQUser, nm proto.NameUtf8, expiresAt time.Time) {
	u.Lock()
	defer u.Unlock()
	if u.m == nil {
		u.m = make(map[proto.FQUser]usernameCacheEntry)
	}
	u.m[fqu] = usernameCacheEntry{
		name:      nm,
		expiresAt: expiresAt,
	}
}

func (u *UsernameCache) getDb(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	var nm proto.NameUtf8
	tm, err := m.DbGet(&nm, DbTypeSoft, &fqu.HostID,
		lcl.DataType_UsernameCacheEntry, fqu.Uid)
	if err != nil {
		if !errors.Is(err, core.RowNotFoundError{}) {
			m.Warnw("UsernameCache.getDb", "fqu", fqu, "err", err)
		}
		return "", false
	}
	expiresAt := tm.Import().Add(jitteredUsernameTTL())
	if !m.G().Now().Before(expiresAt) {
		return "", false
	}
	u.putMem(fqu, nm, expiresAt)
	return nm, true
}
