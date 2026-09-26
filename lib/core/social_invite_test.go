// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestSocialInviteKeyDerivation(t *testing.T) {
	var seed proto.SocialInviteSeed
	err := RandomFill(seed[:])
	require.NoError(t, err)

	id, err := DeriveSocialInviteID(seed)
	require.NoError(t, err)
	ek, err := DeriveSocialInviteBoxKey(seed)
	require.NoError(t, err)
	wk, err := DeriveSocialInviteWriteKey(seed)
	require.NoError(t, err)

	// The three arms must not collide.
	require.NotEqual(t, id[:], ek[:])
	require.NotEqual(t, id[:], wk[:])
	require.NotEqual(t, ek[:], wk[:])

	// Deterministic: the invitee rederives the same keys from s.
	id2, err := DeriveSocialInviteID(seed)
	require.NoError(t, err)
	require.Equal(t, *id, *id2)
	wk2, err := DeriveSocialInviteWriteKey(seed)
	require.NoError(t, err)
	require.Equal(t, *wk, *wk2)

	// A different seed gives a different id.
	var seed2 proto.SocialInviteSeed
	err = RandomFill(seed2[:])
	require.NoError(t, err)
	id3, err := DeriveSocialInviteID(seed2)
	require.NoError(t, err)
	require.NotEqual(t, *id, *id3)
}

func TestSocialInviteWriteKeyCommitment(t *testing.T) {
	var seed proto.SocialInviteSeed
	err := RandomFill(seed[:])
	require.NoError(t, err)
	wk, err := DeriveSocialInviteWriteKey(seed)
	require.NoError(t, err)

	commit, err := CommitSocialInviteWriteKey(*wk)
	require.NoError(t, err)
	require.NoError(t, CheckSocialInviteWriteKey(*wk, *commit))

	bad := *wk
	bad[0] ^= 0x1
	err = CheckSocialInviteWriteKey(bad, *commit)
	require.Error(t, err)
	require.True(t, IsPermissionError(err))
}
