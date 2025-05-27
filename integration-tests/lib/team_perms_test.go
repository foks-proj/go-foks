// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestTeamLoaderPermissions(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	chloe := tew.NewTestUser(t)
	boto := tew.NewTestUser(t)

	vh := tew.VHostMakeI(t, 0)
	muffin := tew.NewTestUserAtVHost(t, vh)
	tew.DirectMerklePokeForLeafCheck(t)
	tm0 := tew.makeTeamForOwner(t, bluey)
	tm0prime := tew.makeTeamForOwner(t, bluey)
	tm1 := tew.makeTeamForOwner(t, chloe)
	tm2 := tew.makeTeamForOwner(t, muffin)

	require.NotNil(t, tm0)

	// test that the load fails with no authentication whatsoever
	larg := libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               bluey.FQUser().FQParty(),
		TestSkipArgCheck: true,
	}
	bingoMc := tew.NewClientMetaContext(t, bingo)
	_, err := libclient.LoadTeam(bingoMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("no view token"), err)

	// Client shouldn't allow this sort of load, so test that too.
	larg.TestSkipArgCheck = false
	_, err = libclient.LoadTeam(bingoMc, larg)
	require.Error(t, err)
	require.Equal(t, core.InternalError("need keys, a permission token, or a local parent team token"), err)

	// also check that a remote user gets the same err as a local one
	larg = libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               muffin.FQUser().FQParty(),
		TestSkipArgCheck: true,
	}
	muffinMc := tew.NewClientMetaContext(t, muffin)
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("no view token"), err)

	// chloe loads an unrelated team
	chloeMc := tew.NewClientMetaContext(t, chloe)
	larg = libclient.LoadTeamArg{
		Team:             tm1.FQTeam(t),
		As:               chloe.FQUser().FQParty(),
		Keys:             chloe.KeySeq(t, proto.OwnerRole),
		SrcRole:          proto.OwnerRole,
		TestSkipArgCheck: false,
	}
	tl, _, err := libclient.LoadTeamReturnLoader(chloeMc, larg)
	require.NoError(t, err)
	tok := tl.Tok()
	require.NotNil(t, tok)

	// chloe loads bluey's team with her own token, and it should fail
	tv := rem.NewTokenVariantWithTeamvobearer(*tok)
	larg = libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               bluey.FQUser().FQParty(),
		TestTokenVariant: &tv,
		TestSkipArgCheck: true,
	}
	_, err = libclient.LoadTeam(chloeMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("wrong token for team load"), err)

	// muffin loads an unrelated team, on the other host
	larg = libclient.LoadTeamArg{
		Team:             tm2.FQTeam(t),
		As:               muffin.FQUser().FQParty(),
		Keys:             muffin.KeySeq(t, proto.OwnerRole),
		SrcRole:          proto.OwnerRole,
		TestSkipArgCheck: false,
	}
	tl, _, err = libclient.LoadTeamReturnLoader(muffinMc, larg)
	require.NoError(t, err)
	tok = tl.Tok()
	require.NotNil(t, tok)

	tv = rem.NewTokenVariantWithTeamvobearer(*tok)
	larg = libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               muffin.FQUser().FQParty(),
		TestTokenVariant: &tv,
		TestSkipArgCheck: true,
	}
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.Error(t, err)
	require.Equal(t, core.NotFoundError("team vo bearer token"), err)

	// do a successful load for bluey, so we can mutate the token and make sure it fails
	larg = libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               bluey.FQUser().FQParty(),
		Keys:             bluey.KeySeq(t, proto.OwnerRole),
		SrcRole:          proto.OwnerRole,
		TestSkipArgCheck: false,
	}
	blueyMc := tew.NewClientMetaContext(t, bluey)
	tl, _, err = libclient.LoadTeamReturnLoader(blueyMc, larg)
	require.NoError(t, err)
	tok = tl.Tok()
	require.NotNil(t, tok)
	tok[4] ^= 0x1
	tv = rem.NewTokenVariantWithTeamvobearer(*tok)
	larg = libclient.LoadTeamArg{
		Team:             tm0.FQTeam(t),
		As:               bluey.FQUser().FQParty(),
		TestTokenVariant: &tv,
		TestSkipArgCheck: true,
	}
	_, err = libclient.LoadTeam(blueyMc, larg)
	require.Error(t, err)
	require.Equal(t, core.NotFoundError("team vo bearer token"), err)

	// winton gets a legit token to view bluey's team
	m := tew.MetaContext()
	tm2.setIndexRange(t, m, muffin, index3)
	tm0.setIndexRange(t, m, bluey, index1)
	tew.DirectMerklePokeInTest(t)

	ptok := runRemoteJoinSequenceForTeam(t, m, tm2, tm0, muffin, bluey, proto.AdminRole, proto.NewRoleWithMember(0))
	tew.DirectMerklePokeInTest(t)
	require.NotNil(t, ptok)
	larg = libclient.LoadTeamArg{
		Team: tm0.FQTeam(t),
		As:   muffin.FQUser().FQParty(),
		Tok:  &ptok,
	}
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.NoError(t, err)

	ptokCopy := ptok
	ptokCopy[len(ptokCopy)-1] ^= 0x1
	larg.Tok = &ptokCopy

	// Check that the token needs to be exactly right or it won't work.
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("permission token not valid for team"), err)

	// Check that another team on the same host won't load with the same token.
	larg.Tok = &ptok
	larg.Team = tm0prime.FQTeam(t)
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("permission token not valid for team"), err)

	// Check that it works again
	larg.Team = tm0.FQTeam(t)
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.NoError(t, err)

	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	tag, err := db.Exec(
		m.Ctx(),
		"UPDATE remote_view_permissions SET state='revoked' WHERE token=$1",
		ptok.ExportToDB(),
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())

	// Check that it doesn't work after revocation
	_, err = libclient.LoadTeam(muffinMc, larg)
	require.Error(t, err)
	require.Equal(t, core.PermissionError("permission token not valid for team"), err)

	tl, _, err = libclient.LoadTeamReturnLoader(blueyMc, libclient.LoadTeamArg{
		Team:    tm0.FQTeam(t),
		As:      bluey.FQUser().FQParty(),
		Keys:    bluey.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	tok = tl.Tok()
	require.NotNil(t, tok)

	// check that we can't yet load tm1 with tm0's view-only token
	_, err = libclient.LoadTeam(blueyMc, libclient.LoadTeamArg{
		Team:               tm1.FQTeam(t),
		As:                 tm0.FQTeam(t).FQParty(),
		LocalParentTeamTok: tok,
	})
	require.Error(t, err)
	require.Equal(t, core.PermissionError("no view permission"), err)

	tm1.setIndexRange(t, m, chloe, index0)
	tew.DirectMerklePokeInTest(t)

	runLocalJoinSequenceForTeam(t, m, tm0, tm1, bluey, chloe, proto.AdminRole,
		proto.NewRoleWithMember(0),
	)
	tew.DirectMerklePokeInTest(t)

	// now it shiould work -- bluey is an owner of tm0, and members
	// of tm0 at level *admin and above* have permission to load tm1.
	_, err = libclient.LoadTeam(blueyMc, libclient.LoadTeamArg{
		Team:               tm1.FQTeam(t),
		As:                 tm0.FQTeam(t).FQParty(),
		LocalParentTeamTok: tok,
	})
	require.NoError(t, err)

	// should fail though if the token is bad
	badTok := *tok
	badTok[5] ^= 0x1
	// now it shiould work
	_, err = libclient.LoadTeam(blueyMc, libclient.LoadTeamArg{
		Team:               tm1.FQTeam(t),
		As:                 tm0.FQTeam(t).FQParty(),
		LocalParentTeamTok: &badTok,
	})
	require.Error(t, err)
	require.Equal(t, core.NotFoundError("team vo bearer token"), err)

	// Add boto to tm0 as a member/0. We're going to test that
	// he can't load tm1 with tm0's view-only token, since his role
	// in tm0 is not high enough.
	mr := boto.toMemberRole(t, proto.DefaultRole, tm0.hepks)
	tm0.makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{mr},
		nil,
	)
	botoMc := tew.NewClientMetaContext(t, boto)
	tl, _, err = libclient.LoadTeamReturnLoader(botoMc, libclient.LoadTeamArg{
		Team:    tm0.FQTeam(t),
		As:      boto.FQUser().FQParty(),
		Keys:    boto.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	tok = tl.Tok()
	require.NotNil(t, tok)

	_, err = libclient.LoadTeam(botoMc, libclient.LoadTeamArg{
		Team:               tm1.FQTeam(t),
		As:                 tm0.FQTeam(t).FQParty(),
		LocalParentTeamTok: tok,
	})
	require.Error(t, err)
	require.Equal(t,
		core.PermissionError("view permission insufficient"),
		err,
	)

}
