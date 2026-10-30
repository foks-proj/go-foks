// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
)

// Social invites (docs/social_signup_spec.md), inviter side. All calls but
// ReplySocialInvite authorize on the caller being the row's inviter; Reply is made by
// the invitee and carries the write key instead.

func (c *UserClientConn) CreateSocialInvite(ctx context.Context, arg rem.CreateSocialInviteArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.InsertSocialInvite(m, arg, m.UID())
}

func (c *UserClientConn) ListSocialInvites(ctx context.Context) ([]rem.SocialInviteRow, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ListSocialInvites(m, m.UID())
}

func (c *UserClientConn) ReplySocialInvite(ctx context.Context, arg rem.ReplySocialInviteArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ReplySocialInvite(m, arg, m.UID())
}

func (c *UserClientConn) AskAgainSocialInvite(ctx context.Context, arg rem.AskAgainSocialInviteArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.AskAgainSocialInvite(m, arg, m.UID())
}

func (c *UserClientConn) CloseSocialInvite(ctx context.Context, arg rem.CloseSocialInviteArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.CloseSocialInvite(m, arg, m.UID())
}

// NewInviteCode mints a standard single-use code against the caller's
// basket, capped by the caller's outstanding unused codes. Richer allocation
// policy (budgets, per-diem, admin exceptions) is host economics and
// deliberately not built here; see "Left open" in the spec.
func (c *UserClientConn) NewInviteCode(ctx context.Context) (rem.InviteCode, error) {
	m := shared.NewMetaContextConn(ctx, c)
	code, err := shared.NewUserInviteCode(m, m.UID())
	if err != nil {
		return rem.InviteCode{}, err
	}
	return *code, nil
}

var _ rem.SocialInviteInterface = (*UserClientConn)(nil)

// socialInviteSweepTimeout bounds one sweep over every host. Like the poll
// loops' database timeout, it only fires on a wedged connection.
const socialInviteSweepTimeout = time.Minute

// RunBackgroundLoops sweeps social invitations on a timer. The sweep lives on
// the user server because every deployment runs one, standalone included. It
// takes no run-lock: replicas may sweep at the same time, which is safe since
// each host's sweep is one transaction of idempotent deletes.
func (s *UserServer) RunBackgroundLoops(m shared.MetaContext, _ chan<- error) error {
	set, err := m.G().Config().Settings(m.Ctx())
	if err != nil {
		return err
	}
	go sweepSocialInvitesLoop(m, set.SocialInviteSweepInterval())
	return nil
}

func sweepSocialInvitesLoop(m shared.MetaContext, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			mt, cancel := m.WithContextTimeout(socialInviteSweepTimeout)
			err := shared.SweepSocialInvitesAllHosts(mt)
			cancel()
			if err != nil {
				m.Warnw("sweepSocialInvitesLoop", "err", err)
			}
		case <-m.Ctx().Done():
			return
		}
	}
}
