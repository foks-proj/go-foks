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

// usernameFlight is a single-flight slot for one FQUser's user-chain load;
// see UsernameLoader.Load. Only a successful result is recorded -- waiters
// fall back to their own load on failure.
type usernameFlight struct {
	done chan struct{}
	nm   proto.NameUtf8
	ok   bool
}

// UsernameLoader resolves FQUser -> display-name, integrating a two-tier
// cache with a single-flighted user-chain load on miss. It hangs off the
// GlobalContext so that all layers share it: team loads fill it whenever a
// member's user chain is loaded, and RT sender-name resolution fills it on
// demand.
//
// The cache is two-tiered: an in-memory map in front of the soft local DB
// (scope: HostID; key: UID; value: utf8 username), so entries survive agent
// restarts. It's soft state -- a failed read or write of the DB tier degrades
// to a cache miss, never an error.
//
// Keys are fully-qualified (UID + HostID), not bare UIDs: the GlobalContext
// spans all of the agent's active users, who may live on different hosts, and
// the same eldest key -- hence the same UID -- can be signed up under different
// usernames on different hosts.
type UsernameLoader struct {
	sync.RWMutex
	m map[proto.FQUser]usernameCacheEntry

	flightMu sync.Mutex
	flights  map[proto.FQUser]*usernameFlight
}

// Load returns the display name for fqu, trying the cache tiers and then
// falling back to a user-chain load with the given arg. Concurrent Loads of
// the same fqu are single-flighted: one caller performs the network load and
// the rest wait and share a successful result. Only successes are shared --
// on a failed load each waiter falls back to its own load with its own auth
// arguments, since the winner's auth mode may not apply to them.
//
// The returned UserWrapper is non-nil only when this call performed the load
// itself; cache hits and flight waiters get (name, nil).
func (u *UsernameLoader) Load(
	m MetaContext,
	fqu proto.FQUser,
	arg LoadUserArg,
) (proto.NameUtf8, *UserWrapper, error) {
	if nm, ok := u.Get(m, fqu); ok {
		return nm, nil, nil
	}

	f, winner := u.joinFlight(fqu)
	if !winner {
		select {
		case <-f.done:
		case <-m.Ctx().Done():
			return "", nil, m.Ctx().Err()
		}
		if f.ok {
			return f.nm, nil, nil
		}
		return u.loadAndFill(m, fqu, arg)
	}
	defer u.retireFlight(fqu, f)

	// Double-check the cache now that we hold the flight slot; another
	// flight may have completed between our miss and here.
	if nm, ok := u.Get(m, fqu); ok {
		f.nm, f.ok = nm, true
		return nm, nil, nil
	}

	nm, uw, err := u.loadAndFill(m, fqu, arg)
	if err != nil {
		return "", nil, err
	}
	f.nm, f.ok = nm, true
	return nm, uw, nil
}

// joinFlight returns the in-flight slot for fqu, creating it (and returning
// winner=true) if none exists.
func (u *UsernameLoader) joinFlight(fqu proto.FQUser) (*usernameFlight, bool) {
	u.flightMu.Lock()
	defer u.flightMu.Unlock()
	if f, ok := u.flights[fqu]; ok {
		return f, false
	}
	f := &usernameFlight{done: make(chan struct{})}
	if u.flights == nil {
		u.flights = make(map[proto.FQUser]*usernameFlight)
	}
	u.flights[fqu] = f
	return f, true
}

func (u *UsernameLoader) retireFlight(fqu proto.FQUser, f *usernameFlight) {
	u.flightMu.Lock()
	delete(u.flights, fqu)
	u.flightMu.Unlock()
	close(f.done)
}

// loadAndFill performs the user-chain load and fills both cache tiers. A
// cache-write failure is a warning, not an error -- we have the name in hand.
func (u *UsernameLoader) loadAndFill(
	m MetaContext,
	fqu proto.FQUser,
	arg LoadUserArg,
) (proto.NameUtf8, *UserWrapper, error) {
	arg.Uid = fqu.Uid // the flight key governs; don't let a mismatched arg drift
	uw, err := LoadUser(m, arg)
	if err != nil {
		return "", nil, err
	}
	nm := uw.Name()
	err = u.Set(m, fqu, nm)
	if err != nil {
		m.Warnw("UsernameLoader.loadAndFill", "stage", "cacheSet", "fqu", fqu, "err", err)
	}
	return nm, uw, nil
}

// Get returns a cached, unexpired display name for fqu, if any, trying the
// memory tier and then the soft DB. A fresh DB hit warms the memory tier, with
// its expiry anchored at the row's write time, so the ~TTL staleness bound
// holds across both tiers.
func (u *UsernameLoader) Get(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	if nm, ok := u.getMem(m, fqu); ok {
		return nm, true
	}
	return u.getDb(m, fqu)
}

// Set records fqu -> name in both tiers, with a fresh jittered TTL. A DB-tier
// write failure is returned but the memory tier is set regardless.
func (u *UsernameLoader) Set(m MetaContext, fqu proto.FQUser, nm proto.NameUtf8) error {
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
func (u *UsernameLoader) getMem(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	u.RLock()
	defer u.RUnlock()
	ent, ok := u.m[fqu]
	if !ok || !m.G().Now().Before(ent.expiresAt) {
		return "", false
	}
	return ent.name, true
}

func (u *UsernameLoader) putMem(fqu proto.FQUser, nm proto.NameUtf8, expiresAt time.Time) {
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

func (u *UsernameLoader) getDb(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	var nm proto.NameUtf8
	tm, err := m.DbGet(&nm, DbTypeSoft, &fqu.HostID,
		lcl.DataType_UsernameCacheEntry, fqu.Uid)
	if err != nil {
		if !errors.Is(err, core.RowNotFoundError{}) {
			m.Warnw("UsernameLoader.getDb", "fqu", fqu, "err", err)
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
