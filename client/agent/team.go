// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (c *AgentConn) teamInit(ctx context.Context) (libclient.MetaContext, *libclient.TeamMinder, error) {
	m := c.MetaContext(ctx)
	ret, err := m.TeamMinder()
	return m, ret, err
}

func (c *AgentConn) TeamCreate(ctx context.Context, nm proto.NameUtf8) (lcl.TeamCreateRes, error) {
	var zed lcl.TeamCreateRes
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.Create(m, nm)
	if err != nil {
		return zed, err
	}
	return lcl.TeamCreateRes{Id: *ret}, nil
}

func (c *AgentConn) TeamList(ctx context.Context, fqtp proto.FQTeamParsed) (lcl.TeamRoster, error) {
	var zed lcl.TeamRoster
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	roster, err := tm.ListTeamRoster(m, fqtp)
	if err != nil {
		return zed, err
	}
	return *roster, nil
}

func (c *AgentConn) TeamCreateInvite(ctx context.Context, fqtp proto.FQTeamParsed) (proto.TeamInvite, error) {
	var zed proto.TeamInvite
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	invite, err := tm.CreateInvite(m, fqtp)
	if err != nil {
		return zed, err
	}
	return *invite, nil

}

func (c *AgentConn) TeamAcceptInvite(
	ctx context.Context,
	arg lcl.TeamAcceptInviteArg,
) (
	lcl.TeamAcceptInviteRes,
	error,
) {
	var zed lcl.TeamAcceptInviteRes
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	res, err := tm.AcceptInvite(m, arg)
	if err != nil {
		return zed, err
	}
	return *res, nil
}

func (c *AgentConn) TeamInbox(
	ctx context.Context,
	t proto.FQTeamParsed,
) (
	lcl.TeamInbox,
	error,
) {
	var zed lcl.TeamInbox
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	inbox, err := tm.TeamInbox(m, t)
	if err != nil {
		return zed, err
	}
	return *inbox, nil
}

func (c *AgentConn) TeamAdmit(
	ctx context.Context,
	arg lcl.TeamAdmitArg,
) error {
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return err
	}
	return tm.TeamAdmit(m, arg)
}

func (c *AgentConn) TeamIndexRangeGet(
	ctx context.Context,
	fqp proto.FQTeamParsed,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	tmp, err := tm.GetIndexRange(m, fqp)
	if err != nil {
		return zed, err
	}
	return tmp.Export(), nil
}

func (c *AgentConn) TeamIndexRangeLower(
	ctx context.Context,
	fqt proto.FQTeamParsed,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.LowerIndexRange(m, fqt)
	if err != nil {
		return zed, err
	}
	return ret.Export(), nil
}

func (c *AgentConn) TeamIndexRangeRaise(
	ctx context.Context,
	fqt proto.FQTeamParsed,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.RaiseIndexRange(m, fqt)
	if err != nil {
		return zed, err
	}
	return ret.Export(), nil
}

func (c *AgentConn) TeamIndexRangeSet(
	ctx context.Context,
	arg lcl.TeamIndexRangeSetArg,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.SetIndexRange(m, arg)
	if err != nil {
		return zed, err
	}
	return ret.Export(), nil
}

func (c *AgentConn) TeamIndexRangeSetHigh(
	ctx context.Context,
	arg lcl.TeamIndexRangeSetHighArg,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.SetIndexRangeHigh(m, arg)
	if err != nil {
		return zed, err
	}
	return ret.Export(), nil
}

func (c *AgentConn) TeamIndexRangeSetLow(
	ctx context.Context,
	arg lcl.TeamIndexRangeSetLowArg,
) (
	proto.RationalRange,
	error,
) {
	var zed proto.RationalRange
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := tm.SetIndexRangeLow(m, arg)
	if err != nil {
		return zed, err
	}
	return ret.Export(), nil
}

func (c *AgentConn) TeamListMemberships(
	ctx context.Context,
) (
	lcl.ListMembershipsRes,
	error,
) {
	m := c.MetaContext(ctx)
	var zed lcl.ListMembershipsRes

	teamMinder, err := m.G().TeamMinder()
	if err != nil {
		return zed, err
	}

	tmp, err := teamMinder.ListMemberships(m)
	if err != nil {
		return zed, err
	}
	return *tmp, nil
}

func (c *AgentConn) TeamAdd(
	ctx context.Context,
	arg lcl.TeamAddArg,
) error {
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return err
	}
	return tm.Add(m, arg)
}

func (c *AgentConn) TeamChangeRoles(
	ctx context.Context,
	arg lcl.TeamChangeRolesArg,
) error {
	m, tm, err := c.teamInit(ctx)
	if err != nil {
		return err
	}
	return tm.TeamChangeRoles(m, arg)
}

var _ lcl.TeamInterface = (*AgentConn)(nil)
