// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/hmac"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

// Social invites (docs/social_signup_spec.md): three keys come off the seed s
// through the standard derivation. The id is the server's handle, the box key
// encrypts the exchange, and the write key proves the right to reply.

func deriveSocialInviteKey32(
	s proto.SocialInviteSeed,
	typ proto.SocialInviteKeyType,
) (
	*proto.SecretSeed32,
	error,
) {
	d := proto.NewSocialInviteKeyDerivationDefault(typ)
	return GenericDeriveKey32(proto.SecretSeed32(s), &d)
}

func DeriveSocialInviteID(s proto.SocialInviteSeed) (*proto.SocialInviteID, error) {
	tmp, err := deriveSocialInviteKey32(s, proto.SocialInviteKeyType_ID)
	if err != nil {
		return nil, err
	}
	ret := proto.SocialInviteID(*tmp)
	return &ret, nil
}

func DeriveSocialInviteBoxKey(s proto.SocialInviteSeed) (*proto.SecretBoxKey, error) {
	tmp, err := deriveSocialInviteKey32(s, proto.SocialInviteKeyType_Box)
	if err != nil {
		return nil, err
	}
	ret := proto.SecretBoxKey(*tmp)
	return &ret, nil
}

func DeriveSocialInviteWriteKey(s proto.SocialInviteSeed) (*proto.SocialInviteWriteKey, error) {
	tmp, err := deriveSocialInviteKey32(s, proto.SocialInviteKeyType_Write)
	if err != nil {
		return nil, err
	}
	ret := proto.SocialInviteWriteKey(*tmp)
	return &ret, nil
}

// CommitSocialInviteWriteKey hashes wk over its type-prefixed encoding. The
// inviter publishes the commitment at create time; the reply presents wk.
func CommitSocialInviteWriteKey(
	wk proto.SocialInviteWriteKey,
) (
	*proto.SocialInviteWriteKeyCommitment,
	error,
) {
	h, err := PrefixedHash(&wk)
	if err != nil {
		return nil, err
	}
	ret := proto.SocialInviteWriteKeyCommitment(*h)
	return &ret, nil
}

// CheckSocialInviteWriteKey recomputes the commitment for wk and compares in
// constant time. Only someone holding the seed can produce a matching wk.
func CheckSocialInviteWriteKey(
	wk proto.SocialInviteWriteKey,
	commit proto.SocialInviteWriteKeyCommitment,
) error {
	recomputed, err := CommitSocialInviteWriteKey(wk)
	if err != nil {
		return err
	}
	if !hmac.Equal(recomputed[:], commit[:]) {
		return PermissionError("bad social invite write key")
	}
	return nil
}
