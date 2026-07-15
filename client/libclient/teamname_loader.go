// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// TeamnameLoader memoizes FQTeam -> display-name, the team-side sibling of
// UsernameLoader (same two-tier nameCache underneath). It hangs off the
// GlobalContext so all layers share it; team loads fill it at the load site
// (TeamMinder.LoadTeamWithFQTeam), and the RT inbox renderer reads it to show
// team names instead of IDs.
//
// Unlike UsernameLoader there's no integrated network load (yet): a miss is
// just a miss and the caller falls back (e.g. displaying the team ID). Wiring
// a single-flighted team load behind misses -- and plugging the cache into
// more display paths -- is follow-up work.
type TeamnameLoader struct {
	nameCache[proto.FQTeam]
}

func NewTeamnameLoader() *TeamnameLoader {
	return &TeamnameLoader{
		nameCache: newNameCache(
			lcl.DataType_TeamnameCacheEntry,
			func(fqt proto.FQTeam) (Scoper, any) {
				return &fqt.Host, fqt.Team
			},
		),
	}
}
