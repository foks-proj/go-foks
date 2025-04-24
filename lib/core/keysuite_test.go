// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestKeySuite(t *testing.T) {

	type player struct {
		priv PrivateSuiter
		pub  PublicSuiter
	}

	type suiteAlgo func(seed proto.SecretSeed32, hostID proto.HostID) (PrivateSuiter, error)

	makePlayer := func(
		constructor func(proto.SecretSeed32, proto.HostID) (PrivateSuiter, error),
	) *player {
		host := RandomHostID()
		var tmp proto.SecretSeed32
		err := RandomFill(tmp[:])
		require.NoError(t, err)
		priv, err := constructor(tmp, host)
		require.NoError(t, err)
		pub, err := priv.Publicize(&host)
		require.NoError(t, err)
		return &player{priv, pub}
	}

	makePair := func(
		constructor func(proto.SecretSeed32, proto.HostID) (PrivateSuiter, error),
	) (*player, *player) {
		return makePlayer(constructor), makePlayer(constructor)
	}

	algo25519 := func(seed proto.SecretSeed32, hostID proto.HostID) (PrivateSuiter, error) {
		return NewPrivateSuite25519(proto.EntityType_Device, proto.OwnerRole, seed, hostID)
	}

	testSuccess := func(constructor func(proto.SecretSeed32, proto.HostID) (PrivateSuiter, error)) {

		sndr, rcvr := makePair(constructor)

		payload := RandomHostID()

		box, err := sndr.priv.BoxFor(&payload, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		require.NotNil(t, box)

		var res proto.HostID
		dh, err := rcvr.priv.UnboxFor(&res, *box, sndr.pub)
		require.NoError(t, err)
		require.Equal(t, payload, res)
		pubDh, err := sndr.pub.DHPublicKey()
		require.NoError(t, err)

		typ, err := pubDh.GetT()
		require.NoError(t, err)
		switch typ {
		case proto.DHType_Curve25519:
			x := dh.Curve25519()
			require.NotNil(t, x)
			require.Equal(t, pubDh.Curve25519(), *x)
		case proto.DHType_P256:
			x := dh.ECDSA()
			require.NotNil(t, x)
			require.Equal(t, pubDh.P256(), proto.ExportECDSAPublic(x))
		default:
			require.Fail(t, "unknown DH type")
		}
	}

	testDecryptFail := func(priv PrivateSuiter, pub PublicSuiter, box proto.Box) {
		var res proto.HostID
		_, err := priv.UnboxFor(&res, box, pub)
		require.Error(t, err)
		require.Equal(t, DecryptionError{}, err)
	}

	// Test that if the receiver uses the wrong sender key,
	// the decryption will fail. This is for two reasons, since
	// both the shared key and the recipient KEM Encap key
	// are in the final key.
	testBadKemKey := func(algo suiteAlgo) {
		sndr, rcvr := makePair(algo)
		ek, err := rcvr.pub.KemEncapKey()
		require.NoError(t, err)
		(*ek.F_1__)[5] ^= 0x4

		payload := RandomHostID()

		box, err := sndr.priv.BoxFor(&payload, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		require.NotNil(t, box)

		testDecryptFail(rcvr.priv, sndr.pub, *box)

	}

	testBadKemCiphertext := func(algo suiteAlgo) {
		sndr, rcvr := makePair(algo)
		paylod := RandomHostID()
		box, err := sndr.priv.BoxFor(&paylod, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		box.F_2__.F_1__.KemCtext[5] ^= 0x4
		testDecryptFail(rcvr.priv, sndr.pub, *box)
	}

	testBadDHKey := func(algo suiteAlgo) {
		sndr, rcvr := makePair(algo)
		payload := RandomHostID()
		dhk, err := rcvr.pub.DHPublicKey()
		require.NoError(t, err)
		dhk.F_0__[5] ^= 0x4
		box, err := sndr.priv.BoxFor(&payload, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		require.NotNil(t, box)
		testDecryptFail(rcvr.priv, sndr.pub, *box)
	}

	testBadCiphertext := func(algo suiteAlgo) {
		sndr, rcvr := makePair(algo)
		payload := RandomHostID()
		box, err := sndr.priv.BoxFor(&payload, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		box.F_2__.F_1__.Sbox.F_0__.Ciphertext[5] ^= 0x4
		testDecryptFail(rcvr.priv, sndr.pub, *box)
	}

	testBadNonce := func(algo suiteAlgo) {
		sndr, rcvr := makePair(algo)
		payload := RandomHostID()
		box, err := sndr.priv.BoxFor(&payload, rcvr.pub, BoxOpts{})
		require.NoError(t, err)
		box.F_2__.F_1__.Sbox.F_0__.Nonce[5] ^= 0x4
		testDecryptFail(rcvr.priv, sndr.pub, *box)
	}

	testAlgo := func(algo suiteAlgo) {
		testSuccess(algo)
		testBadKemKey(algo)
		testBadKemCiphertext(algo)
		testBadDHKey(algo)
		testBadCiphertext(algo)
		testBadNonce(algo)
	}

	testAlgo(algo25519)
}
