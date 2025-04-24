// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	e1, err := NewEntityPrivateEd25519(proto.EntityType_Device)
	require.NoError(t, err)
	var blob [32]byte
	err = RandomFill(blob[:])
	require.NoError(t, err)
	lo := proto.LinkOuterV1{
		Inner: blob[:],
	}
	sig, err := e1.Sign(&lo)
	require.NoError(t, err)
	pub, err := e1.EntityPublic()
	require.NoError(t, err)
	err = pub.Verify(*sig, &lo)
	require.NoError(t, err)

	// Corrupt the message and make sure we get an error
	lo.Inner[1] ^= 0xf
	err = pub.Verify(*sig, &lo)
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)

	// Fix it and make sure it still works.
	lo.Inner[1] ^= 0xf
	err = pub.Verify(*sig, &lo)
	require.NoError(t, err)

	// Verify that verifciation fails if using the wrong public key
	e2, err := NewEntityPrivateEd25519(proto.EntityType_Device)
	require.NoError(t, err)
	pub, err = e2.EntityPublic()
	require.NoError(t, err)
	err = pub.Verify(*sig, &lo)
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)

	// Should fail since the tag is wrong
	lo2 := proto.TestLinkOuterV1{
		Inner: blob[:],
	}
	err = pub.Verify(*sig, &lo2)
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)
}

// Ensure that we can sign/verify this stack
var _ StackedVerifiable = (*proto.LinkOuterV1)(nil)

func TestSignVerifyStacked(t *testing.T) {
	var e []Signer
	for i := 0; i < 5; i++ {
		tmp, err := NewEntityPrivateEd25519(proto.EntityType_Device)
		e = append(e, tmp)
		require.NoError(t, err)
	}

	var blob [32]byte
	err := RandomFill(blob[:])
	require.NoError(t, err)
	lo := proto.LinkOuterV1{
		Inner: blob[:],
	}

	err = SignStacked(&lo, e[0:4])
	require.NoError(t, err)

	var pub []Verifier
	for _, priv := range e {
		tmp, err := priv.(EntityPrivate).EntityPublic()
		require.NoError(t, err)
		pub = append(pub, tmp)
	}

	err = VerifyStackedSignature(&lo, pub[0:4])
	require.NoError(t, err)

	err = VerifyStackedSignature(&lo, pub[0:3])
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)

	err = VerifyStackedSignature(&lo, pub[1:5])
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)

	// Confirm that stacked signatures work if only one signature
	err = SignStacked(&lo, e[0:1])
	require.NoError(t, err)
	err = VerifyStackedSignature(&lo, pub[0:1])
	require.NoError(t, err)

	err = VerifyStackedSignature(&lo, pub[0:0])
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)
	require.Equal(t, VerifyError("cannot verify with 0 keys"), err)
}
