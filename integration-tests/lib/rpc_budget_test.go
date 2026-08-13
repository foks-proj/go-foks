// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/stretchr/testify/require"
)

// TestListMembershipsRoundTripBudget pins how many server round trips a team
// exploration costs.
//
// Round-trip count is invisible on loopback and dominant over a WAN link: a
// device profile against a 50ms-shaped server measured ListMemberships at
// 7.4s wall of which 7.2s -- 97% -- was time in RPCs, with local crypto and
// SQLite accounting for the rest. Nothing in a normal test run notices an
// extra chain load, so the count needs asserting rather than eyeballing.
//
// The per-method assertions are the point; the total is a backstop. If this
// fails after an intentional change, re-measure and move the numbers
// deliberately -- do not just bump them until it passes.
func TestListMembershipsRoundTripBudget(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	owner := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	const nTeams = 3
	for i := 0; i < nTeams; i++ {
		tew.makeTeamForOwner(t, owner)
	}
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, owner)
	tmm, err := mc.G().TeamMinder()
	require.NoError(t, err)

	mc, stats := mc.WithRpcStats()
	lst, err := tmm.ListMemberships(mc, nil)
	require.NoError(t, err)
	require.Equal(t, nTeams, len(lst.Teams))

	byMethod := make(map[string]int)
	for _, ms := range stats.ByMethod() {
		byMethod[ms.Method] = ms.Calls
	}
	t.Logf("ListMemberships over %d teams: %d RPCs, by method %v",
		nTeams, stats.Calls(), byMethod)

	// One chain load per team. This was two per team until the explore path
	// started handing its completed loader to the membership loader instead
	// of letting it load the same team again (NewTMLTeamFromLoaded).
	require.Equal(t, nTeams, byMethod["TeamLoader.loadTeamChain"],
		"expected one team chain load per team, not one per load site")

	// The membership chain is the second, genuinely distinct fetch per team.
	require.Equal(t, nTeams, byMethod["TeamLoader.loadTeamMembershipChain"])

	// A view token is minted per team load and never cached, so its two RPCs
	// track loadTeamChain exactly. Caching tokens across loads is the next
	// reduction available here; if that lands, these drop and should be
	// re-pinned rather than deleted.
	require.Equal(t, nTeams, byMethod["TeamLoader.getTeamVOBearerTokenChallenge"])
	require.Equal(t, nTeams, byMethod["TeamLoader.activateTeamVOBearerToken"])

	// Backstop on the total: per-team cost is 4 RPCs above plus the membership
	// chain, and the user's own chain loads are a small fixed prelude. Well
	// clear of the pre-fix count (8 per team) so this fails on a regression
	// rather than on noise.
	require.LessOrEqual(t, stats.Calls(), nTeams*6+8,
		"round-trip budget exceeded; re-measure before raising this")
}
