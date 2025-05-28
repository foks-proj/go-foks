// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
)

func (u *UserClientConn) LoadTeamChain(
	ctx context.Context,
	arg rem.LoadTeamChainArg,
) (
	rem.TeamChain,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	return shared.LoadTeamChain(m, arg)
}

func (r *RegClientConn) LoadTeamChain(
	ctx context.Context,
	arg rem.LoadTeamChainArg,
) (
	rem.TeamChain,
	error,
) {
	m := shared.NewMetaContextConn(ctx, r)
	return shared.LoadTeamChain(m, arg)
}

func getTeamVOBearerTokenChallenge(
	ctx context.Context,
	c shared.ClientConn,
	req rem.TeamVOBearerTokenReq,
) (
	rem.TeamVOBearerTokenChallenge,
	error,
) {
	var ret rem.TeamVOBearerTokenChallenge
	m := shared.NewMetaContextConn(ctx, c)
	tmp, err := shared.GetTeamVOBearerTokenChallenge(m, req)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (r *RegClientConn) GetTeamVOBearerTokenChallenge(
	ctx context.Context,
	req rem.TeamVOBearerTokenReq,
) (
	rem.TeamVOBearerTokenChallenge,
	error,
) {
	return getTeamVOBearerTokenChallenge(ctx, r, req)
}

func (r *UserClientConn) GetTeamVOBearerTokenChallenge(
	ctx context.Context,
	req rem.TeamVOBearerTokenReq,
) (
	rem.TeamVOBearerTokenChallenge,
	error,
) {
	return getTeamVOBearerTokenChallenge(ctx, r, req)
}

func activateTeamVOBearerToken(
	ctx context.Context,
	c shared.ClientConn,
	arg rem.ActivateTeamVOBearerTokenArg,
) (
	rem.ActivatedVOBearerToken,
	error,
) {
	var ret rem.ActivatedVOBearerToken
	m := shared.NewMetaContextConn(ctx, c)
	tmp, err := shared.ActivateTeamVOBearerToken(m, arg)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (r *RegClientConn) ActivateTeamVOBearerToken(
	ctx context.Context,
	arg rem.ActivateTeamVOBearerTokenArg,
) (
	rem.ActivatedVOBearerToken,
	error,
) {
	return activateTeamVOBearerToken(ctx, r, arg)
}

func (u *UserClientConn) ActivateTeamVOBearerToken(
	ctx context.Context,
	arg rem.ActivateTeamVOBearerTokenArg,
) (
	rem.ActivatedVOBearerToken,
	error,
) {
	return activateTeamVOBearerToken(ctx, u, arg)
}

func checkTeamVOBearerToken(
	ctx context.Context,
	c shared.ClientConn,
	arg rem.CheckTeamVOBearerTokenArg,
	testTimeTravel time.Duration,
) (
	proto.TeamID,
	error,
) {
	var ret proto.TeamID
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	m, err = m.WithProtoHostID(&arg.Host)
	if err != nil {
		return ret, err
	}
	tmp, err := shared.CheckTeamVOBearerToken(m, db, arg.Tok, testTimeTravel)
	if err != nil {
		return ret, err
	}
	isId, err := tmp.Req.Team.IdOrName.GetId()
	if err != nil {
		return ret, err
	}
	if !isId {
		return ret, core.InternalError("did not expect teamName name in checkTeamVOBearerToken")
	}
	ret = tmp.Req.Team.IdOrName.True()
	return ret, nil
}

func (u *UserClientConn) CheckTeamVOBearerToken(
	ctx context.Context,
	arg rem.CheckTeamVOBearerTokenArg,
) (
	proto.TeamID,
	error,
) {
	return checkTeamVOBearerToken(ctx, u, arg, 0)
}

func (u *RegClientConn) CheckTeamVOBearerToken(
	ctx context.Context,
	arg rem.CheckTeamVOBearerTokenArg,
) (
	proto.TeamID,
	error,
) {
	return checkTeamVOBearerToken(ctx, u, arg, 0)
}

func (r *RegClientConn) LoadTeamMembershipChain(
	ctx context.Context,
	arg rem.LoadTeamMembershipChainArg,
) (
	rem.GenericChain,
	error,
) {
	m := shared.NewMetaContextConn(ctx, r)
	return shared.LoadTeamMembershipChain(m, arg)
}

func (u *UserClientConn) LoadTeamMembershipChain(
	ctx context.Context,
	arg rem.LoadTeamMembershipChainArg,
) (
	rem.GenericChain,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	return shared.LoadTeamMembershipChain(m, arg)
}

func (u *UserClientConn) LoadRemovalForMember(
	ctx context.Context,
	arg rem.LoadRemovalForMemberArg,
) (
	rem.TeamRemovalAndKeyBox,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	return shared.LoadRemovalForMember(m, arg)
}

func (u *RegClientConn) LoadRemovalForMember(
	ctx context.Context,
	arg rem.LoadRemovalForMemberArg,
) (
	rem.TeamRemovalAndKeyBox,
	error,
) {
	var zed rem.TeamRemovalAndKeyBox
	m, err := shared.NewMetaContextFromArg(ctx, u, &arg.Team.Host)
	if err != nil {
		return zed, err
	}
	return shared.LoadRemovalForMember(m, arg)
}

func (u *RegClientConn) LoadTeamRemoteViewTokens(
	ctx context.Context,
	arg rem.LoadTeamRemoteViewTokensArg,
) (
	rem.TeamRemoteViewTokenSet,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	return shared.LoadTeamRemoteViewTokens(m, arg)
}

func (u *UserClientConn) LoadTeamRemoteViewTokens(
	ctx context.Context,
	arg rem.LoadTeamRemoteViewTokensArg,
) (
	rem.TeamRemoteViewTokenSet,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	return shared.LoadTeamRemoteViewTokens(m, arg)
}

func (u *UserClientConn) GetServerConfig(
	ctx context.Context,
) (
	proto.RegServerConfig,
	error,
) {
	m := shared.NewMetaContextConn(ctx, u)
	var zed proto.RegServerConfig
	ret, err := shared.GetServerConfig(m)
	if err != nil {
		return zed, err
	}
	return *ret, nil
}

var _ rem.TeamLoaderInterface = (*UserClientConn)(nil)
var _ rem.TeamLoaderInterface = (*RegClientConn)(nil)
