// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/rand"
	"testing"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func randomSecretBoxKey(t *testing.T) proto.SecretBoxKey {
	var ret proto.SecretBoxKey
	_, err := rand.Read(ret[:])
	require.NoError(t, err)
	return ret
}

func TestSealOpenSecretBox(t *testing.T) {

	testWithPadding := func(padding int) int {

		lst := RandomSKMWKList()
		key := randomSecretBoxKey(t)

		box, err := SealIntoSecretBoxWithPadding(&lst, &key, padding)
		require.NoError(t, err)
		require.NotNil(t, box)

		ret := len(box.F_0__.Ciphertext)

		chk := func() (bool, error) {
			var lst2 lcl.SKMWKList
			err = OpenSecretBoxInto(&lst2, *box, &key)
			if err != nil {
				return false, err
			}
			eq, err := Eq(&lst, &lst2)
			return eq, err
		}

		eq, err := chk()
		require.NoError(t, err)
		require.True(t, eq)

		// Check that after the first 8 bytes, we break decryption by changing the nonce.
		box.F_0__.Nonce[9] ^= 0x10
		_, err = chk()
		require.Error(t, err)
		require.IsType(t, DecryptionError{}, err)

		// Check that we can flip things back
		box.F_0__.Nonce[9] ^= 0x10
		eq, err = chk()
		require.NoError(t, err)
		require.True(t, eq)

		// If we decrypt with the wrong key, it should fail
		key[1] ^= 0x4
		_, err = chk()
		require.Error(t, err)
		require.IsType(t, DecryptionError{}, err)

		// Check that we can flip things back
		key[1] ^= 0x4
		eq, err = chk()
		require.NoError(t, err)
		require.True(t, eq)

		// A single bit mutation to the ciphretext should break it
		box.F_0__.Ciphertext[3] ^= 0x20
		_, err = chk()
		require.Error(t, err)
		require.IsType(t, DecryptionError{}, err)

		return ret
	}
	rawlen := testWithPadding(0)
	paddedlen := testWithPadding(64)
	require.True(t, paddedlen > rawlen)
	require.Equal(t, 157, rawlen)
	require.Equal(t, 256+16, paddedlen) // 256 bytes of ciphertext, and 16-byte pad
}
