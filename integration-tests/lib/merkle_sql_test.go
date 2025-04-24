// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func randomFill(t *testing.T, b []byte) {
	err := core.RandomFill(b)
	require.NoError(t, err)
}

func TestMerkleSimpleInsert(t *testing.T) {
	// We can get a flake here if we race the background merkle builder, so
	// to be sure, let's just fork the envorinment to get a new host ID, etc.
	env := globalTestEnv.Fork(t, common.SetupOpts{})
	defer func() {
		_ = env.ShutdownFn()
	}()
	m := env.MetaContext()

	stor := shared.NewSQLStorage(m)
	eng := merkle.NewEngine(stor)

	n := 3
	var leaves []proto.MerkleLeaf
	for i := 0; i < n; i++ {
		var tmp proto.MerkleLeaf
		randomFill(t, tmp.Key[:])
		randomFill(t, tmp.Value[:])
		leaves = append(leaves, tmp)
	}

	for _, leaf := range leaves {
		err := eng.InsertKeyValue(m, merkle.InsertKeyValueArg{Key: leaf.Key, Val: leaf.Value})
		require.NoError(t, err)
	}

	for _, leaf := range leaves {
		res, err := eng.LookupPath(m, rem.MerkleLookupArg{Key: leaf.Key})
		require.NoError(t, err)
		require.NotNil(t, res.Leaf)
		require.True(t, res.Leaf.Matches)
		require.Equal(t, leaf.Key, res.Leaf.Leaf.Key)
		require.Equal(t, leaf.Value, res.Leaf.Leaf.Value)

		_, err = eng.CheckKeyExists(m, leaf.Key)
		require.NoError(t, err)
	}
}
