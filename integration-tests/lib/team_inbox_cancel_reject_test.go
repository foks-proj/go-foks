// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// inboxFixture is an owner with a team, a joiner, and an invite the joiner has
// accepted -- i.e. exactly one pending RSVP sitting in the owner's inbox. It is
// the starting point for both cancel (joiner withdraws) and reject (owner
// refuses).
type inboxFixture struct {
	tew    *TestEnvWrapper
	owner  *TestUser
	joiner *TestUser
	tm     *teamObj
	fqtp   proto.FQTeamParsed

	mo  libclient.MetaContext
	tmo *libclient.TeamMinder // owner's minder
	mj  libclient.MetaContext
	tmj *libclient.TeamMinder // joiner's minder

	invite    proto.TeamInvite
	inviteStr string
}

func (f *inboxFixture) minderFor(t *testing.T, u *TestUser) (libclient.MetaContext, *libclient.TeamMinder) {
	m := f.tew.NewClientMetaContext(t, u)
	tmm, err := m.G().TeamMinder()
	require.NoError(t, err)
	// Chain posts need the merkle tree to advance before the next read, which
	// in production happens on the server's own schedule.
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			f.tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}
	return m, tmm
}

func newInboxFixture(t *testing.T) *inboxFixture {
	tew := testEnvBeta(t)
	f := &inboxFixture{tew: tew}

	f.owner = tew.NewTestUser(t)
	f.joiner = tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	f.tm = tew.makeTeamForOwner(t, f.owner)
	tew.DirectDoubleMerklePokeInTest(t)

	// An invite carries a team index range, so the team needs one before the
	// owner can issue invites.
	f.tm.setIndexRange(t, tew.MetaContext(), f.owner, index0)
	tew.DirectDoubleMerklePokeInTest(t)

	f.fqtp = *f.tm.ToFQTeamParsed(t)
	f.mo, f.tmo = f.minderFor(t, f.owner)
	f.mj, f.tmj = f.minderFor(t, f.joiner)

	inv, err := f.tmo.CreateInvite(f.mo, f.fqtp)
	require.NoError(t, err)
	f.invite = *inv
	tew.DirectDoubleMerklePokeInTest(t)

	s, err := team.ExportTeamInvite(f.invite)
	require.NoError(t, err)
	f.inviteStr = s

	_, err = f.tmj.AcceptInvite(f.mj, lcl.TeamAcceptInviteArg{I: f.invite})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	return f
}

// inboxRows returns the owner's current pending RSVPs.
func (f *inboxFixture) inboxRows(t *testing.T) []lcl.TeamInboxRow {
	inbox, err := f.tmo.TeamInbox(f.mo, f.fqtp)
	require.NoError(t, err)
	return inbox.Rows
}

// membershipState reports the state the joiner's own membership chain records
// for the team, and whether it has any entry at all. This is the chain
// TeamCancelRequest writes to, and it is distinct from the team roster.
func (f *inboxFixture) membershipState(t *testing.T) (proto.TeamMembershipLinkState, bool) {
	// Forces the membership chain to load; the wrapper is nil until it does.
	_, err := f.tmj.DumpMembershipChain(f.mj)
	require.NoError(t, err)

	tmw := f.tmj.UserTMW()
	require.NotNil(t, tmw)
	require.NotNil(t, tmw.Wrapper)

	fqt, err := f.tmj.Resolve(f.mj, f.fqtp)
	require.NoError(t, err)
	require.NotNil(t, fqt)

	var key libclient.FQTeamSrcRole
	err = key.Import(*fqt, team.UserSrcRole)
	require.NoError(t, err)

	link, ok := tmw.Wrapper.Map[key]
	if !ok {
		return proto.TeamMembershipLinkState_Requested, false
	}
	typ, err := link.State.GetT()
	require.NoError(t, err)
	return typ, true
}

// A joiner withdraws their own pending request. The invite is accepted, the
// RSVP lands in the owner's inbox, and cancelling flips the joiner's own
// membership record from Requested to Removed.
func TestTeamCancelRequest(t *testing.T) {
	f := newInboxFixture(t)

	require.Len(t, f.inboxRows(t), 1)

	state, found := f.membershipState(t)
	require.True(t, found, "accepting an invite should record a membership link")
	require.Equal(t, proto.TeamMembershipLinkState_Requested, state)

	err := f.tmj.TeamCancelRequest(f.mj, f.inviteStr)
	require.NoError(t, err)
	f.tew.DirectDoubleMerklePokeInTest(t)

	state, found = f.membershipState(t)
	require.True(t, found)
	require.Equal(t, proto.TeamMembershipLinkState_Removed, state,
		"cancelling should reset the requester's membership state")
}

// Cancel takes the raw FOKS invite code, not a team name, because
// ResolveAndReindex only indexes Approved teams and cannot resolve a
// Requested-state entry. A string that is not an invite must be refused
// rather than silently resolving to something else.
func TestTeamCancelRequestRejectsNonInvite(t *testing.T) {
	f := newInboxFixture(t)

	err := f.tmj.TeamCancelRequest(f.mj, "not-a-foks-invite")
	require.Error(t, err)
}

// An admin refuses a pending request. The row is deleted server-side, so it
// does not come back on a later inbox read -- unlike a row merely left
// unadmitted.
func TestTeamReject(t *testing.T) {
	f := newInboxFixture(t)

	rows := f.inboxRows(t)
	require.Len(t, rows, 1)
	require.Equal(t, f.joiner.uid.ToPartyID(), rows[0].Nfqp.Fqp.Party)

	err := f.tmo.TeamReject(f.mo, f.fqtp, rows[0].Tok)
	require.NoError(t, err)
	f.tew.DirectDoubleMerklePokeInTest(t)

	require.Empty(t, f.inboxRows(t), "a rejected request must not reappear in the inbox")
}

// Rejecting twice is safe. The server sets state='rejected' without filtering
// on the current state, so the second call updates the same row again and
// succeeds -- which makes reject retryable after a network failure, where the
// admin cannot tell whether the first attempt landed. Pinned because a future
// state filter would turn a harmless retry into an error.
func TestTeamRejectIsRetryable(t *testing.T) {
	f := newInboxFixture(t)

	rows := f.inboxRows(t)
	require.Len(t, rows, 1)

	err := f.tmo.TeamReject(f.mo, f.fqtp, rows[0].Tok)
	require.NoError(t, err)
	f.tew.DirectDoubleMerklePokeInTest(t)

	err = f.tmo.TeamReject(f.mo, f.fqtp, rows[0].Tok)
	require.NoError(t, err, "a repeated reject should be a harmless no-op")
	require.Empty(t, f.inboxRows(t))
}

// A rejected request cannot then be admitted in the same session.
//
// This is the case the inbox cache gets wrong if reject does not evict: the
// cache is deliberately held indefinitely so a later admit can skip a round
// trip, so a rejected row stays admittable from memory even though the server
// has moved it out of 'pending'. The admin refuses the party and then, one
// call later, admits them.
func TestTeamRejectThenAdmitFails(t *testing.T) {
	f := newInboxFixture(t)

	rows := f.inboxRows(t)
	require.Len(t, rows, 1)
	tok := rows[0].Tok

	err := f.tmo.TeamReject(f.mo, f.fqtp, tok)
	require.NoError(t, err)
	f.tew.DirectDoubleMerklePokeInTest(t)

	err = f.tmo.TeamAdmit(f.mo, lcl.TeamAdmitArg{
		Team: f.fqtp,
		Members: []lcl.TokRole{
			{Tok: tok, Role: proto.DefaultRole},
		},
	})
	require.Error(t, err)
}
