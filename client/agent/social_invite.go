// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
)

func (c *AgentConn) SocialInviteCreate(
	ctx context.Context,
	arg lcl.SocialInviteCreateArg,
) (
	lcl.SocialInviteCreateRes,
	error,
) {
	res, err := libclient.SocialInviteCreate(c.MetaContext(ctx), arg)
	if err != nil {
		return lcl.SocialInviteCreateRes{}, err
	}
	return *res, nil
}

func (c *AgentConn) SocialInviteList(ctx context.Context) ([]lcl.SocialInviteLocalRow, error) {
	return libclient.SocialInviteList(c.MetaContext(ctx))
}

// SocialInviteFetch needs no active user: the invitee may not have an
// account yet.
func (c *AgentConn) SocialInviteFetch(
	ctx context.Context,
	arg lcl.SocialInviteFetchArg,
) (
	lcl.SocialInviteLocalView,
	error,
) {
	m := c.MetaContext(ctx)
	prb, err := c.probe(m, arg.Host, 30*time.Second)
	if err != nil {
		return lcl.SocialInviteLocalView{}, err
	}
	res, err := libclient.SocialInviteFetch(m, prb, arg.Seed)
	if err != nil {
		return lcl.SocialInviteLocalView{}, err
	}
	return *res, nil
}

func (c *AgentConn) SocialInviteReply(ctx context.Context, arg lcl.SocialInviteReplyArg) error {
	return libclient.SocialInviteReply(c.MetaContext(ctx), arg)
}

func (c *AgentConn) SocialInviteAskAgain(ctx context.Context, arg lcl.SocialInviteAskAgainArg) error {
	return libclient.SocialInviteAskAgain(c.MetaContext(ctx), arg)
}

func (c *AgentConn) SocialInviteClose(ctx context.Context, arg lcl.SocialInviteCloseArg) error {
	return libclient.SocialInviteClose(c.MetaContext(ctx), arg)
}

var _ lcl.SocialInviteInterface = (*AgentConn)(nil)
