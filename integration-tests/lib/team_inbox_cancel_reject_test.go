// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// Exercise TeamMinder.TeamCancelRequest and TeamMinder.TeamReject through a
// full join-request round trip: accept an invite, cancel the request
// (requester side), reject the request (admin side), and re-accept after
// rejection -- the last leg working because RejectJoinReq marks the joinreq
// 'rejected' and the local_joinreq_joiner_idx partial index only constrains
// pending rows.
func TestTeamMinderCancelAndRejectJoinReq(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	owner := tew.NewTestUser(t)
	joiner := tew.NewTestUser(t)
	m := tew.MetaContext()
	tew.DirectMerklePokeForLeafCheck(t)

	tm := tew.makeTeamForOwner(t, owner)
	tm.setIndexRange(t, m, owner, index0)
	tew.DirectDoubleMerklePokeInTest(t)

	poke := &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}

	ownerMc := tew.NewClientMetaContext(t, owner)
	ownerTmm, err := ownerMc.G().TeamMinder()
	require.NoError(t, err)
	ownerTmm.TestHooks = poke

	joinerMc := tew.NewClientMetaContext(t, joiner)
	joinerTmm, err := joinerMc.G().TeamMinder()
	require.NoError(t, err)
	joinerTmm.TestHooks = poke

	fqtp, err := core.ParseFQTeam(proto.FQTeamString(tm.nm))
	require.NoError(t, err)

	invite, err := ownerTmm.CreateInvite(ownerMc, *fqtp)
	require.NoError(t, err)
	inviteStr, err := team.ExportTeamInvite(*invite)
	require.NoError(t, err)

	accept := func() {
		_, err := joinerTmm.AcceptInvite(joinerMc, lcl.TeamAcceptInviteArg{I: *invite})
		require.NoError(t, err)
		tew.DirectDoubleMerklePokeInTest(t)
	}

	// The joiner's request state as recorded in their own team membership
	// chain, reloaded from scratch each call.
	joinerTMLState := func() proto.TeamMembershipLinkState {
		tmlu, err := libclient.NewTMLUser(joinerMc, joinerMc.G().ActiveUser().Info.Role)
		require.NoError(t, err)
		lw, err := libclient.LoadTeamMembershipReturnLoader(joinerMc, tmlu)
		require.NoError(t, err)
		var key libclient.FQTeamSrcRole
		err = key.Import(tm.FQTeam(t), team.UserSrcRole)
		require.NoError(t, err)
		link, found := lw.Wrapper.Map[key]
		require.True(t, found)
		typ, err := link.State.GetT()
		require.NoError(t, err)
		return typ
	}

	inboxLen := func() int {
		inb, err := ownerTmm.TeamInbox(ownerMc, *fqtp)
		require.NoError(t, err)
		return len(inb.Rows)
	}

	accept()
	require.Equal(t, proto.TeamMembershipLinkState_Requested, joinerTMLState())
	require.Equal(t, 1, inboxLen())

	// Requester withdraws: their chain flips to Removed. Note the
	// server-side joinreq is not retired by cancel; the admin still sees
	// the row until they act on it (issue #336 -- when fixed, this leg
	// should instead assert the inbox row disappears and that re-accept
	// works immediately, with no admin reject in between).
	err = joinerTmm.TeamCancelRequest(joinerMc, inviteStr)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)
	require.Equal(t, proto.TeamMembershipLinkState_Removed, joinerTMLState())

	// Admin rejects the (now-withdrawn) request; the inbox row is retired
	// and stays gone on subsequent loads.
	inb, err := ownerTmm.TeamInbox(ownerMc, *fqtp)
	require.NoError(t, err)
	require.Equal(t, 1, len(inb.Rows))
	err = ownerTmm.TeamReject(ownerMc, *fqtp, inb.Rows[0].Tok)
	require.NoError(t, err)
	require.Equal(t, 0, inboxLen())

	// A rejected joiner can ask again: rejection leaves no pending joinreq
	// row, so the partial unique index doesn't block a fresh RSVP.
	accept()
	require.Equal(t, proto.TeamMembershipLinkState_Requested, joinerTMLState())
	require.Equal(t, 1, inboxLen())
}
