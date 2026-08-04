// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func (m MetaContext) clearCaches(
	vv proto.PathVersionVector,
) error {
	if m.cacheAccess == nil {
		return core.InternalError("no cache")
	}
	kvp := m.cacheAccess.kvp
	if kvp == nil {
		// nothing to clear
		return nil
	}

	err := kvp.caches.root.ClearBefore(m, vv.Root)
	if err != nil {
		return err
	}
	for _, dir := range vv.Path {
		err = kvp.caches.dir.ClearBefore(m.Base(), dir.Id, dir.Vers)
		if err != nil {
			return err
		}
		for _, de := range dir.De {

			cd, ok := m.cacheAccess.Dir[dir.Id]
			if !ok {
				continue
			}
			cde, ok := cd.Dirents[de.Id]
			if !ok {
				continue
			}

			err = kvp.caches.dirent.ClearBefore(m.Base(), cde.Hmac, de.Vers)
			if err != nil {
				return err
			}
		}
	}
	m.cacheAccess.clear()
	return nil
}

// returns a core.KVStaleCacheError if e is one of them, and null otherwise.
// If e is nil, then we also clear out cache context so we don't need to check
// again in the future.
func (m MetaContext) catchStaleCacheError(e error) error {

	if e == nil {
		m.cacheAccess.clear() // we didn't return a KVStaleCacheError, so we are OK to clear and try again
		return nil
	}

	if sce, ok := e.(core.KVStaleCacheError); ok {
		return sce
	}

	return nil
}

func (m MetaContext) makeVersionVector() (
	*proto.PathVersionVector,
	error,
) {
	if m.cacheAccess == nil {
		return nil, nil
	}

	var ret proto.PathVersionVector
	ret.Root = m.cacheAccess.Root
	ret.Path = make([]proto.DirVersion, 0, len(m.cacheAccess.Dir))

	for id, dir := range m.cacheAccess.Dir {
		var pv proto.DirVersion
		pv.Id = id
		pv.Vers = dir.Version
		pv.De = make([]proto.DirentVersion, 0, len(dir.Dirents))
		for id, de := range dir.Dirents {
			var dv proto.DirentVersion
			dv.Id = id
			dv.Vers = de.Version
			pv.De = append(pv.De, dv)
		}
		ret.Path = append(ret.Path, pv)
	}
	if len(ret.Path) == 0 && ret.Root == 0 {
		return nil, nil
	}
	return &ret, nil
}

type kvRetryOptions struct {
	skipCacheCheck bool
}

// isStaleTeamTokenError reports the server refusing the team VO bearer token
// that this party has cached. It goes stale on any roster write touching the
// member it was minted for -- the token is pinned to one team_members row --
// and also once it ages out. Both are cured by minting a new one.
func isStaleTeamTokenError(err error) bool {
	if err == nil {
		return false
	}
	var stale core.TeamBearerTokenStaleError
	if errors.As(err, &stale) {
		return true
	}
	var nf core.NotFoundError
	if errors.As(err, &nf) && nf == core.NotFoundError("team vo bearer token") {
		return true
	}
	return false
}

// withFreshToken runs f, and if the server rejected the party's cached VO bearer
// token, re-mints it and runs f exactly once more. The rejection happens in the
// server's auth step, before any part of the operation is applied, so replaying
// f is safe.
//
// This is what makes a freshly-admitted member's first write work: admission
// supersedes the team_members row their token was minted against, and nothing
// else in the client notices until the freshness window expires.
func (k *Minder) withFreshToken(
	m MetaContext,
	kvp *KVParty,
	f func(m MetaContext) error,
) error {
	err := f(m)
	if !isStaleTeamTokenError(err) {
		return err
	}
	rerr := k.au.PartyLoaderCache().Refresh(m.Base(), kvp.plcn)
	if rerr != nil {
		// Report the rejection, not the refresh failure -- the former is what
		// the caller's operation actually hit.
		m.Warnw("withFreshToken", "stage", "refresh", "err", rerr, "orig", err)
		return err
	}
	// Logged because a successful recovery is otherwise invisible: the server
	// returns both rejections without logging, and a replayed op looks exactly
	// like one that never went stale. Without this line the only way to tell
	// whether this path ran is a negative control against a build without it.
	m.Infow("withFreshToken", "stage", "re-minted", "party", kvp.Id(), "rejection", err)
	return f(m)
}

func (k *Minder) retryCacheLoop(
	m MetaContext,
	kvp *KVParty,
	f func(m MetaContext) error,
) error {
	return k.retryCacheLoopWithOptions(m, kvp, kvRetryOptions{}, f)
}

func (k *Minder) retryCacheLoopWithOptions(
	m MetaContext,
	kvp *KVParty,
	opts kvRetryOptions,
	f func(m MetaContext) error,
) error {
	// Wraps the whole cache-race loop rather than f alone, so a stale token
	// surfacing from the loop's own cache check is caught too.
	return k.withFreshToken(m, kvp, func(m MetaContext) error {
		return k.cacheRaceLoop(m, kvp, opts, f)
	})
}

func (k *Minder) cacheRaceLoop(
	m MetaContext,
	kvp *KVParty,
	opts kvRetryOptions,
	f func(m MetaContext) error,
) error {

	err := m.InitCacheContext(kvp)
	if err != nil {
		return err
	}

	cfg, err := m.G().Cfg().KvConfig()
	if err != nil {
		return err
	}
	n := cfg.CacheRace.NumRetries + 1
	wait := cfg.CacheRace.Wait

	// If at the end of operation, there are items that we hit the
	// cache for and didn't check with the server, we need to check
	// one last time on those items. And only then can we declare
	// success.
	flush := func() (bool, error) {
		vv, err := m.makeVersionVector()
		if err != nil {
			return false, err
		}
		if vv == nil {
			return false, nil
		}
		auth, client, err := k.client(m, kvp)
		if err != nil {
			return false, err
		}
		err = client.KvCacheCheck(m.Ctx(), rem.KVReqHeader{
			Auth:         *auth,
			Precondition: vv,
		})
		return true, err
	}

	isCacheRetriableError := func(err error) bool {
		if err == nil {
			return false
		}
		switch err.(type) {
		case core.KVNeedDirError, core.KVNeedFileError, core.KVPathTooDeepError:
			return true
		default:
			return false
		}
	}

	for i := 0; i < n; i++ {

		err := f(m)

		if (err == nil && !opts.skipCacheCheck) || isCacheRetriableError(err) {
			didFlush, ferr := flush()
			switch {

			// the FS operation succeeded, and either
			// there were no unchecked cache uses, or
			// we successfully checked them with the server
			case err == nil && ferr == nil:
				return nil

				// the FS operation succeeded, but the cache check showed there
				// were stale items used in the operation. We need to clear the
				// cache and try again.
			case err == nil && ferr != nil:
				err = ferr

				// The FS operation failed, but we didn't actually wind up
				// checking the cache with the server, either due to some
				// failure, or that no cache items were used. In this case,
				// just return the original error.
			case err != nil && !didFlush:
				return err

				// The FS operation failed, and we did check the cache, but that
				// check returned that the cache was actually fresh. In this case,
				// the original error stands.
			case err != nil && didFlush && ferr == nil:
				return err

				// The FS operation failed, we did check the cache with the server,
				// and that check failed either because of an error with the check,
				// or beacuse the server returned "stale" (the way more likely error).
				// In this case, we clobber the original error with the stale cache error.
			case err != nil && didFlush && ferr != nil:
				err = ferr

			}
		}

		serr, ok := err.(core.KVStaleCacheError)
		if !ok {
			return err
		}
		err = m.clearCaches(serr.PathVersionVector)
		if err != nil {
			return err
		}
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	return core.KVStaleCacheError{}
}
