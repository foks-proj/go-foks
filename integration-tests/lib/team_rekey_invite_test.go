// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// A team cert is stacked-signed by the current PTK and then by the gen-1 PTK,
// so the verifier list has to be in that same order. At gen 1 the two keys
// coincide and any order works, which is why only rekeyed teams hit this. Once
// the team has rotated its admin PTK, a swapped verifier order makes every
// invite to it unacceptable with a signature verify error.
func TestAcceptInviteToRekeyedTeam(t *testing.T) {
	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	joiner := tew.NewTestUser(t)
	transient := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, owner)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()

	// Add and then remove an admin, which forces the team to rotate its admin
	// PTK; the cert is signed with that key, so this is what puts the cert at
	// gen > 1.
	tm.makeChanges(t, m, owner, []proto.MemberRole{
		transient.toMemberRole(t, proto.AdminRole, tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	tm.makeChanges(t, m, owner, []proto.MemberRole{
		transient.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)

	adminPtk, ok := tm.ptks[core.AdminRole]
	require.True(t, ok)
	require.False(t, adminPtk.Metadata().Gen.IsFirst(),
		"the team must actually have rekeyed for this test to mean anything")

	// An invite carries a team index range, so the team needs one before the
	// owner can issue invites.
	tm.setIndexRange(t, m, owner, index0)
	tew.DirectDoubleMerklePokeInTest(t)

	fqtp := *tm.ToFQTeamParsed(t)

	mo, tmo := tew.teamMinderFor(t, owner)
	mj, tmj := tew.teamMinderFor(t, joiner)

	inv, err := tmo.CreateInvite(mo, fqtp)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	_, err = tmj.AcceptInvite(mj, lcl.TeamAcceptInviteArg{I: *inv})
	require.NoError(t, err)
}
