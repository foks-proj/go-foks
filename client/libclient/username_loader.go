// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"sync"

	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// usernameFlight is a single-flight slot for one FQUser's user-chain load;
// see UsernameLoader.Load. Only a successful result is recorded -- waiters
// fall back to their own load on failure.
type usernameFlight struct {
	done chan struct{}
	nm   proto.NameUtf8
	ok   bool
}

// UsernameLoader resolves FQUser -> display-name, integrating the two-tier
// nameCache with a single-flighted user-chain load on miss. It hangs off the
// GlobalContext so that all layers share it: team loads fill it whenever a
// member's user chain is loaded, and RT sender-name resolution fills it on
// demand.
//
// Keys are fully-qualified (UID + HostID), not bare UIDs: the GlobalContext
// spans all of the agent's active users, who may live on different hosts, and
// the same eldest key -- hence the same UID -- can be signed up under different
// usernames on different hosts.
type UsernameLoader struct {
	nameCache[proto.FQUser]

	flightMu sync.Mutex
	flights  map[proto.FQUser]*usernameFlight
}

func NewUsernameLoader() *UsernameLoader {
	return &UsernameLoader{
		nameCache: newNameCache(
			lcl.DataType_UsernameCacheEntry,
			func(fqu proto.FQUser) (Scoper, any) {
				return &fqu.HostID, fqu.Uid
			},
		),
	}
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
