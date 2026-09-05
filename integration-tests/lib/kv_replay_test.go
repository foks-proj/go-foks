package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// kvStoreClientForUser opens a raw KV-store client for the given user, so a
// test can drive the RPCs directly rather than through libkv (which mints a
// fresh node ID per call and so cannot express a replay).
func kvStoreClientForUser(t *testing.T, tew *TestEnvWrapper, u *TestUser) rem.KVStoreClient {
	m := tew.NewClientMetaContext(t, u)
	au := m.G().ActiveUser()
	cert, err := au.ClientCert(m)
	require.NoError(t, err)
	pr := au.HomeServer()
	require.NotNil(t, pr)
	gcli, err := pr.RPCClient(m, proto.ServerType_KVStore, cert)
	require.NoError(t, err)
	return core.NewKVStoreClient(gcli, m)
}

// TestKVPutSmallFileReplay covers retrying a small-file write. The node ID is
// chosen by the client and fixes the encryption nonce, so a retry after an
// ambiguous failure sends byte-identical bytes; that must succeed as a no-op
// rather than failing on the primary key. The same ID with different bytes
// must still be refused.
func TestKVPutSmallFileReplay(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)

	m := tew.NewClientMetaContext(t, bluey)
	cli := kvStoreClientForUser(t, tew, bluey)

	var nid proto.KVNodeID
	nid[0] = byte(proto.KVNodeType_SmallFile)
	require.NoError(t, core.RandomFill(nid[1:]))

	mk := func(body string) rem.KvPutSmallFileOrSymlinkArg {
		return rem.KvPutSmallFileOrSymlinkArg{
			Id: nid,
			Sfb: proto.SmallFileBox{
				Rg:      proto.RoleAndGen{Role: proto.OwnerRole},
				DataBox: proto.NaclCiphertext(body),
			},
		}
	}

	// First write lands.
	require.NoError(t, cli.KvPutSmallFileOrSymlink(m.Ctx(), mk("ciphertext")))

	// The same write again is the retry case: a no-op, not an error, and not
	// a second charge against usage.
	before, err := cli.KvUsage(m.Ctx(), rem.KVAuth{})
	require.NoError(t, err)
	require.NoError(t, cli.KvPutSmallFileOrSymlink(m.Ctx(), mk("ciphertext")))
	after, err := cli.KvUsage(m.Ctx(), rem.KVAuth{})
	require.NoError(t, err)
	require.Equal(t, before.Small, after.Small, "a replay must not be charged twice")

	// The same ID carrying different bytes is refused.
	err = cli.KvPutSmallFileOrSymlink(m.Ctx(), mk("different ciphertext"))
	require.Error(t, err)
	var race core.KVRaceError
	require.ErrorAs(t, err, &race)
}
