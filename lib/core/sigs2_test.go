// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func randomFill(t *testing.T, b []byte) {
	err := RandomFill(b)
	require.NoError(t, err)
}

func TestSigs2(t *testing.T) {
	e1, err := NewEntityPrivateEd25519(proto.EntityType_Device)
	require.NoError(t, err)

	var mr1 proto.MerkleRootV1
	mr1.Epno = 100
	mr1.Time = proto.Now()
	randomFill(t, mr1.BackPointers[:])
	require.NoError(t, err)
	randomFill(t, mr1.RootNode[:])
	mr1.Hostchain.Seqno = 10
	randomFill(t, mr1.Hostchain.Hash[:])

	mr := proto.NewMerkleRootWithV1(mr1)
	sig, blob, err := Sign2(e1, &mr)
	require.NoError(t, err)

	mr2, err := Verify2(e1, *sig, blob)
	require.NoError(t, err)

	v, err := mr2.GetV()
	require.NoError(t, err)
	require.Equal(t, proto.MerkleRootVersion_V1, v)
	require.Equal(t, mr2.V1().Hostchain.Seqno, mr1.Hostchain.Seqno)
	require.Equal(t, mr2.V1().RootNode, mr1.RootNode)
}
