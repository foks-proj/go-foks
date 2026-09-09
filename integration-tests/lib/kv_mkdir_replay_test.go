package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// TestKVMkdirReplay covers retrying a directory creation. The directory ID is
// chosen by the client, so a retry after an ambiguous failure carries the same
// sealed seed; that must succeed as a no-op rather than failing on the primary
// key. The same ID with a different seed box must still be refused.
func TestKVMkdirReplay(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)

	// Drive the RPC directly: libkv mints a fresh directory ID per call and
	// so cannot express a replay.
	m := tew.NewClientMetaContext(t, bluey)
	au := m.G().ActiveUser()
	cert, err := au.ClientCert(m)
	require.NoError(t, err)
	pr := au.HomeServer()
	require.NotNil(t, pr)
	gcli, err := pr.RPCClient(m, proto.ServerType_KVStore, cert)
	require.NoError(t, err)
	cli := core.NewKVStoreClient(gcli, m)

	var dirID proto.DirID
	require.NoError(t, core.RandomFill(dirID[:]))

	mk := func(seed string) rem.KvMkdirArg {
		return rem.KvMkdirArg{
			Dir: proto.KVDir{
				Id:      dirID,
				Version: proto.KVVersion(1),
				Box: proto.SeedBoxExternalNonce{
					Rg:    proto.RoleAndGen{Role: proto.OwnerRole},
					Ctext: proto.NaclCiphertext(seed),
				},
				WriteRole: proto.OwnerRole,
				Status:    proto.KVDirStatus_Active,
			},
		}
	}

	// First creation lands, and is not a replay.
	res, err := cli.KvMkdir(m.Ctx(), mk("sealed seed"))
	require.NoError(t, err)
	require.False(t, res.WasReplay)

	// The same creation again is the retry case: a no-op that reports itself
	// as a replay, not an error.
	res, err = cli.KvMkdir(m.Ctx(), mk("sealed seed"))
	require.NoError(t, err)
	require.True(t, res.WasReplay)

	// The same ID carrying a different seed box is refused.
	_, err = cli.KvMkdir(m.Ctx(), mk("a different sealed seed"))
	require.Error(t, err)
	var race core.KVRaceError
	require.ErrorAs(t, err, &race)
}
