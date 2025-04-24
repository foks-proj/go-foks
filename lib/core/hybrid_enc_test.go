// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestHybridEncryption(t *testing.T) {

	testAlgo := func(constructor func(proto.SecretSeed32) (PrivateBoxer, error)) {

		n := 2
		privs := make([]PrivateBoxer, n)
		pubs := make([]PublicBoxer, n)
		for i := 0; i < 2; i++ {
			var tmp proto.SecretSeed32
			err := RandomFill(tmp[:])
			require.NoError(t, err)
			priv, err := constructor(tmp)
			require.NoError(t, err)
			privs[i] = priv
			pub, err := priv.PublicizeToBoxer()
			require.NoError(t, err)
			pubs[i] = pub
		}

		payload := RandomHostID()

		box, err := privs[0].BoxFor(&payload, pubs[1], BoxOpts{})
		require.NoError(t, err)
		require.NotNil(t, box)

		var res proto.HostID
		dh, err := privs[1].UnboxFor(&res, *box, pubs[0])
		require.NoError(t, err)
		require.Equal(t, payload, res)
		pubDh, err := pubs[0].DHPublicKey()
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
	hostid := RandomHostID()
	testAlgo(func(seed proto.SecretSeed32) (PrivateBoxer, error) {
		return NewPrivateSuite25519(proto.EntityType_Device, proto.OwnerRole, seed, hostid)
	})
	testAlgo(func(seed proto.SecretSeed32) (PrivateBoxer, error) {
		return NewPrivateSuiteECDSA(seed)
	})
}
