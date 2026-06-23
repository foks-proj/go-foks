// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func mkTestTeamID(t *testing.T, et proto.EntityType) proto.TeamID {
	eid, err := et.MakeEntityID(make([]byte, et.Len()-1))
	require.NoError(t, err)
	tid, err := eid.ToTeamID()
	require.NoError(t, err)
	return tid
}

// TestRejectAdHocMembershipChange exercises the team player's defense-in-depth
// guard: an ad-hoc team's membership is fixed in the eldest link, so any later
// link carrying roster changes must be rejected during replay, while named
// teams and changeless/eldest links pass through.
func TestRejectAdHocMembershipChange(t *testing.T) {
	adHoc := mkTestTeamID(t, proto.EntityType_AdHocTeam)
	named := mkTestTeamID(t, proto.EntityType_NamedTeam)
	immutable := core.ChainLoaderError{Err: core.TeamError(team.AdHocTeamImmutableMsg)}

	type tc struct {
		name     string
		team     proto.TeamID
		seqno    proto.Seqno
		nChanges int
		want     error
	}
	cases := []tc{
		{"adhoc eldest founding members ok", adHoc, proto.ChainEldestSeqno, 4, nil},
		{"adhoc non-eldest membership change rejected", adHoc, proto.Seqno(2), 1, immutable},
		{"adhoc non-eldest no changes ok", adHoc, proto.Seqno(2), 0, nil},
		{"named non-eldest membership change ok", named, proto.Seqno(2), 2, nil},
		{"named eldest ok", named, proto.ChainEldestSeqno, 3, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := rejectAdHocMembershipChange(c.team, c.seqno, c.nChanges)
			require.Equal(t, c.want, err)
		})
	}
}
