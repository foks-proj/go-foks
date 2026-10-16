// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
)

// Fetch is the invitee's unauthenticated read (docs/social_signup_spec.md).
// The 32-byte id is derived by HMAC from the seed, so it can't be guessed
// and needs no other gate. TODO: rate-limit per IP once the remote address
// is plumbed through to handlers; nothing does that today.
func (c *RegClientConn) Fetch(
	ctx context.Context,
	id proto.SocialInviteID,
) (
	rem.SocialInviteGuestView,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	view, err := shared.LoadSocialInviteGuestView(m, id)
	if err != nil {
		return rem.SocialInviteGuestView{}, err
	}
	return *view, nil
}

var _ rem.SocialInviteGuestInterface = (*RegClientConn)(nil)
