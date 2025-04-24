// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cks

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestBoxHappyPath(t *testing.T) {
	key, err := NewEncKey()
	require.NoError(t, err)

	kr := NewKeyring()
	err = kr.Add(*key)
	require.NoError(t, err)

	var data [40]byte
	err = core.RandomFill(data[:])
	require.NoError(t, err)
	cksKeyData := proto.CKSKeyData(data[:])

	box, err := key.Seal(&cksKeyData)
	require.NoError(t, err)

	var out proto.CKSKeyData
	err = kr.Open(&out, box)
	require.NoError(t, err)

	require.Equal(t, cksKeyData, out)
}
