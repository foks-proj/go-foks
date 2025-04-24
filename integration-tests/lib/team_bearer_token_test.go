// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

type voBearerTokenOpts struct {
	byName bool
}

func makeVOBearerTokenForUser(t *testing.T, tm *teamObj, u *TestUser, srcRole *proto.Role) rem.TeamVOBearerToken {
	return makeVOBearerTokenForUserFull(t, tm, u, srcRole, voBearerTokenOpts{})
}

func makeVOBearerTokenForUserFull(t *testing.T, tm *teamObj, u *TestUser, srcRole *proto.Role, opts voBearerTokenOpts) rem.TeamVOBearerToken {
	ctx := context.Background()
	tcli, closer := u.newTeamLoaderClient(t, ctx, tm.host.Eq(u.host))
	defer closer()

	if srcRole == nil {
		srcRole = &proto.OwnerRole
	}

	req := rem.TeamVOBearerTokenReq{
		Team:    tm.FQTeam(t).ToFQTeamIDOrName(),
		Member:  u.FQUser().FQParty(),
		Gen:     proto.FirstGeneration,
		SrcRole: *srcRole,
	}

	if opts.byName {
		nnm, err := core.NormalizeName(tm.nm)
		require.NoError(t, err)
		req.Team.IdOrName = proto.NewTeamIDOrNameWithFalse(nnm)
	}

	ch, err := tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.NoError(t, err)

	puk := u.puks[core.OwnerRole]
	require.NotNil(t, puk)

	require.Equal(t, ch.Payload.Req, req)
	sig, err := puk.Sign(&ch)
	require.NoError(t, err)
	tok, err := tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.NoError(t, err)
	require.Equal(t,
		rem.ActivatedVOBearerToken{
			Tok: ch.Payload.Tok,
			Id:  tm.FQTeam(t).Team,
		},
		tok,
	)

	tid, err := tcli.CheckTeamVOBearerToken(ctx, rem.CheckTeamVOBearerTokenArg{
		Host: tm.host,
		Tok:  tok.Tok,
	})
	require.NoError(t, err)
	require.Equal(t, tid, tm.FQTeam(t).Team)

	return tok.Tok
}

func TestTeamVOBearerTokenHappyPath(t *testing.T) {

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)

	// since we're writing to a secondary chain (in create), we need to poke merkle
	// so that the signing key is fully provisioned.
	tew.DirectDoubleMerklePokeInTest(t)

	team := tew.makeTeamForOwner(t, u)

	makeVOBearerTokenForUser(t, team, u, nil)
	makeVOBearerTokenForUserFull(t, team, u, nil, voBearerTokenOpts{byName: true})
}

func TestTeamVOBearerTokenSadPaths(t *testing.T) {

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	o2 := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, u)
	vHostID := tew.VHostMakeI(t, 0)
	ru := tew.NewTestUserAtVHost(t, vHostID)

	// have a second owner up in so we can do a ptk rotation later.
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_OWNER), tm.hepks),
		},
		nil,
	)

	ctx := context.Background()
	tcli, closer := u.newTeamLoaderClient(t, ctx, true)
	defer closer()

	req := rem.TeamVOBearerTokenReq{
		Team:   tm.FQTeam(t).ToFQTeamIDOrName(),
		Member: u.FQUser().FQParty(),
		Gen:    proto.FirstGeneration,
	}
	_, err := tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.Error(t, err)
	require.Equal(t, core.TeamNoSrcRoleError{}, err)

	req = rem.TeamVOBearerTokenReq{
		Team:    tm.FQTeam(t).ToFQTeamIDOrName(),
		Member:  u.FQUser().FQParty(),
		Gen:     proto.FirstGeneration,
		SrcRole: proto.OwnerRole,
	}
	ch, err := tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.NoError(t, err)

	// First try to mess with the internals of the challenge token, and that it's
	// rejected due to a MAC failure.
	chBad := ch
	chBad.Mac[2] ^= 0xf
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch: chBad,
	})
	require.Error(t, err)
	require.Equal(t, core.ValidationError("hmac failed"), err)
	chBad.Mac[2] ^= 0xf

	// Now check that if we mess with the MAC'ed payload, we'll get the same failure.
	chBad = ch
	chBad.Payload.Tok[2] ^= 0xf
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch: chBad,
	})
	require.Error(t, err)
	require.Equal(t, core.ValidationError("hmac failed"), err)
	chBad.Payload.Tok[2] ^= 0xf

	// If you mess with the HMAC key ID, there is a different spot in HELL for your attempt
	chBad = ch
	chBad.Payload.Id[2] ^= 0xf
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch: chBad,
	})
	require.Error(t, err)
	require.Equal(t, core.KeyNotFoundError{Which: "hmac"}, err)
	chBad.Payload.Id[2] ^= 0xf

	// Now ensure that if you're not in the team, you can't get a token
	req = rem.TeamVOBearerTokenReq{
		Team:    tm.FQTeam(t).ToFQTeamIDOrName(),
		Member:  ru.FQUser().FQParty(),
		Gen:     proto.FirstGeneration,
		SrcRole: proto.OwnerRole,
	}
	ch, err = tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.NoError(t, err)
	puk := ru.puks[core.OwnerRole]
	require.NotNil(t, puk)
	sig, err := puk.Sign(&ch)
	require.NoError(t, err)
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.Error(t, err)
	bte := core.PermissionError("team member permission failed (vo bearer token)")
	require.Equal(t, bte, err)

	// IF you are on the team but you blow the signature, you also fail, but with the same error
	req = rem.TeamVOBearerTokenReq{
		Team:    tm.FQTeam(t).ToFQTeamIDOrName(),
		Member:  o2.FQUser().FQParty(),
		Gen:     proto.FirstGeneration,
		SrcRole: proto.OwnerRole,
	}
	ch, err = tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.NoError(t, err)
	puk = u.puks[core.OwnerRole]
	require.NotNil(t, puk)
	sig, err = puk.Sign(&ch)
	require.NoError(t, err)
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, bte, err)

	// just check the above works as expected if correect. We'll need it later.
	puk = o2.puks[core.OwnerRole]
	require.NotNil(t, puk)
	sig, err = puk.Sign(&ch)
	require.NoError(t, err)
	o2tok, err := tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.NoError(t, err)

	// Replays ought to fail!
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, core.ReplayError{}, err)

	// o2's token should still work despite the fact that he replayed and failed.
	tid, err := tcli.CheckTeamVOBearerToken(ctx, rem.CheckTeamVOBearerTokenArg{
		Host: tm.host,
		Tok:  o2tok.Tok,
	})
	require.NoError(t, err)
	require.Equal(t, tid, tm.FQTeam(t).Team)

	// But if we time travel into the future, it should expire
	db, err := m.Db(shared.DbTypeUsers)
	defer db.Release()
	require.NoError(t, err)
	mtmp, err := m.WithProtoHostID(&tm.host)
	require.NoError(t, err)
	_, err = shared.CheckTeamVOBearerToken(mtmp, db, o2tok.Tok, time.Hour*48)
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "age"}, err)

	// remove o2 from the team, and he should be failing his check
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), nil),
		},
		nil,
	)
	_, err = tcli.CheckTeamVOBearerToken(ctx, rem.CheckTeamVOBearerTokenArg{
		Host: tm.host,
		Tok:  o2tok.Tok,
	})
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "stale member"}, err)

	// now check o2 can't get back in even if he tried, shoudl be the same failure as above,
	// but worth double-checing.
	req = rem.TeamVOBearerTokenReq{
		Team:    tm.FQTeam(t).ToFQTeamIDOrName(),
		Member:  o2.FQUser().FQParty(),
		Gen:     proto.FirstGeneration,
		SrcRole: proto.OwnerRole,
	}
	ch, err = tcli.GetTeamVOBearerTokenChallenge(ctx, req)
	require.NoError(t, err)
	puk = o2.puks[core.OwnerRole]
	require.NotNil(t, puk)
	sig, err = puk.Sign(&ch)
	require.NoError(t, err)
	_, err = tcli.ActivateTeamVOBearerToken(ctx, rem.ActivateTeamVOBearerTokenArg{
		Ch:  ch,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, bte, err)
}
