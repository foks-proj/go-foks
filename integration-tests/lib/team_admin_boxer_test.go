// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// A plain member holds no admin PTK, but the team chain gives them its public
// half. A removal key boxed for that public half must open with the admins'
// private key, exactly as one boxed by an admin does. Checked at the first
// admin key generation and again after the admin key rotates.
func TestAdminBoxerFromPublicKeys(t *testing.T) {
	tew := testEnvBeta(t)
	abe := tew.NewTestUser(t)
	bella := tew.NewTestUser(t)
	transient := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, abe)
	m := tew.MetaContext()
	mem := proto.NewRoleWithMember(0)

	tm.makeChanges(t, m, abe, []proto.MemberRole{
		bella.toMemberRole(t, mem, tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)

	check := func() {
		mc := tew.NewClientMetaContext(t, bella)
		wrp, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
			Team:    tm.FQTeam(t),
			As:      bella.FQUser().FQParty(),
			Keys:    bella.KeySeq(t, proto.OwnerRole),
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
		kr := wrp.KeyRing()
		require.Nil(t, kr.CurrentPrivateKeyAtRole(core.AdminRole),
			"a plain member must not hold the admin PTK for this test to mean anything")

		pub, err := kr.CurrentPublicSuiteAtRole(core.AdminRole)
		require.NoError(t, err)
		require.NotNil(t, pub)

		adminPtk, ok := tm.ptks[core.AdminRole]
		require.True(t, ok)
		fromPriv, err := core.PublicizeToSPSBoxer(adminPtk, tm.FQTeam(t).FQParty())
		require.NoError(t, err)
		require.Equal(t, fromPriv.SharedPublicSuite, *pub)

		sender := bella.KeySeq(t, proto.OwnerRole).Current()
		memberRcvr, err := core.PublicizeToSPSBoxer(sender, bella.FQUser().FQParty())
		require.NoError(t, err)
		teamRcvr := &core.SPSBoxer{SharedPublicSuite: *pub, Parent: tm.FQTeam(t).FQParty()}
		box, key, err := team.NewBoxedTeamRemovalKey(sender, teamRcvr, memberRcvr,
			rem.TeamRemovalKeyMetadata{
				Tm:      tm.FQTeam(t),
				Member:  bella.FQUser().FQParty(),
				SrcRole: proto.OwnerRole,
				Dst:     proto.RoleAndSeqno{Role: mem},
			},
		)
		require.NoError(t, err)

		var payload rem.TeamRemovalKeyBoxPayload
		_, err = adminPtk.UnboxFor(&payload, box.Team.Box, nil)
		require.NoError(t, err)
		require.Equal(t, *key, payload.Key)
		require.Equal(t, adminPtk.Metadata().Gen, box.Team.EncKey.Gen)
	}

	check()

	// Add and then remove an admin, which rotates the admin PTK.
	tm.makeChanges(t, m, abe, []proto.MemberRole{
		transient.toMemberRole(t, proto.AdminRole, tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	tm.makeChanges(t, m, abe, []proto.MemberRole{
		transient.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	require.False(t, tm.ptks[core.AdminRole].Metadata().Gen.IsFirst(),
		"the admin PTK must have rotated")

	check()
}

// The team editor must box each new member's removal key at the admin role,
// and nowhere lower: a box at the member role would let every member read
// every other member's removal key. Admins also hold the member PTK, so a
// removal by an admin would still succeed and would not catch that mistake.
func TestTeamAddBoxesRemovalKeyAtAdminRole(t *testing.T) {
	tew := testEnvBeta(t)
	vh := tew.openVHost(t)
	abe := tew.NewTestUserAtVHost(t, vh)
	bella := tew.NewTestUserAtVHost(t, vh)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, abe)

	mo, tmo := tew.teamMinderFor(t, abe)
	err := tmo.Add(mo, lcl.TeamAddArg{
		Team: *tm.ToFQTeamParsed(t),
		Members: []lcl.FQPartyParsedAndRole{{
			Fqp: proto.FQPartyParsed{Party: proto.NewParsedPartyWithFalse(bella.uid.ToPartyID())},
		}},
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	ctx := context.Background()
	tok := makeTeamBearerToken(t, abe, tm, core.AdminRole)
	tcli, closer := abe.newTeamAdminClient(t, ctx)
	defer closer()
	box, err := tcli.LoadRemovalKeyBoxForTeamAdmin(ctx, rem.LoadRemovalKeyBoxForTeamAdminArg{
		Tok:     tok,
		Member:  bella.FQUser().FQParty(),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)

	rk, err := core.ImportRole(box.EncKey.Role)
	require.NoError(t, err)
	require.True(t, rk.Eq(core.AdminRole), "removal key boxed at %v, want admin", *rk)

	var payload rem.TeamRemovalKeyBoxPayload
	_, err = tm.ptks[core.AdminRole].UnboxFor(&payload, box.Box, nil)
	require.NoError(t, err)
	_, err = tm.ptks[core.MemberRole].UnboxFor(&payload, box.Box, nil)
	require.Error(t, err)
}
