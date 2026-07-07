// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"math/rand"
	"sync"
	"time"

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
// layers share one cache: RT sender-name resolution fills it on demand, and
// ad-hoc team explore/reindex fills it as a side-effect (member chains are
// loaded there anyway to name the team by its participant list).
//
// Keys are fully-qualified (UID + HostID), not bare UIDs: the GlobalContext
// spans all of the agent's active users, who may live on different hosts, and
// the same eldest key -- hence the same UID -- can be signed up under different
// usernames on different hosts.
type UsernameCache struct {
	sync.RWMutex
	m map[proto.FQUser]usernameCacheEntry
}

// Get returns a cached, unexpired display name for fqu, if any. An expired
// entry is reported as a miss but left in place rather than deleted (no lock
// upgrade); the Set that follows every miss overwrites it.
func (u *UsernameCache) Get(m MetaContext, fqu proto.FQUser) (proto.NameUtf8, bool) {
	u.RLock()
	defer u.RUnlock()
	ent, ok := u.m[fqu]
	if !ok || !m.G().Now().Before(ent.expiresAt) {
		return "", false
	}
	return ent.name, true
}

// Set records fqu -> name with a fresh jittered TTL.
func (u *UsernameCache) Set(m MetaContext, fqu proto.FQUser, nm proto.NameUtf8) {
	u.Lock()
	defer u.Unlock()
	if u.m == nil {
		u.m = make(map[proto.FQUser]usernameCacheEntry)
	}
	u.m[fqu] = usernameCacheEntry{
		name:      nm,
		expiresAt: m.G().Now().Add(jitteredUsernameTTL()),
	}
}
