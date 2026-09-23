// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// TestKvGetNodeMissingSmallFile covers kvGetNode for a small-file or symlink
// node ID that has no row.
//
// mLoadSmallFilesOrSymlinks returns one entry per requested key by appending
// a map lookup, so a key it did not find contributes a nil entry rather than
// a shorter slice. loadSmallFileOrSymlink checked only the length, so a
// missing node returned (nil, nil), and loadNode dereferenced the nil box --
// crashing the kv-store process for any authenticated caller who asked about
// a node ID that does not exist.
//
// Both node types that route through that loader are covered, since they
// reach it down separate arms of loadNode's switch.
func TestKvGetNodeMissingSmallFile(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)

	m := tew.NewClientMetaContext(t, bluey)
	cli := kvStoreClientForUser(t, tew, bluey)

	for _, typ := range []proto.KVNodeType{
		proto.KVNodeType_SmallFile,
		proto.KVNodeType_Symlink,
	} {
		var nid proto.KVNodeID
		nid[0] = byte(typ)
		require.NoError(t, core.RandomFill(nid[1:]))

		_, err := cli.KvGetNode(m.Ctx(), rem.KvGetNodeArg{Id: nid})
		require.Error(t, err, "%v: a missing node must answer, not crash", typ)
		require.Equal(t, core.NotFoundError("small file"), err)
	}

	// A tombstone node ID reaches the same nil return by a different route:
	// KVNodeType_None is a legal value of the type -- Type() returns it
	// without error -- but loadNode's switch has no arm for it, so ret stays
	// nil and the handler dereferences it. Covered here because a fix for
	// the missing-row route alone leaves kvGetNode crashable.
	var tombstone proto.KVNodeID // first byte 0 == KVNodeType_None
	require.NoError(t, core.RandomFill(tombstone[1:]))
	_, err := cli.KvGetNode(m.Ctx(), rem.KvGetNodeArg{Id: tombstone})
	require.Error(t, err, "a tombstone node ID must answer, not crash")

	// The connection is still usable afterwards, which is the part that
	// mattered: a panic here took the server down rather than failing one
	// call.
	_, err = cli.KvUsage(m.Ctx(), rem.KVAuth{})
	require.NoError(t, err)
}
