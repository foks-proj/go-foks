// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"bytes"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/engine"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

type workQueueItem struct {
	shortHostID core.ShortHostID
	eid         proto.EntityID
	signer      proto.DeviceID
	typ         proto.ChainType
	seqno       proto.Seqno
	ctime       proto.Time
	key         proto.MerkleTreeRFOutput
	val         proto.StdHash
	state       shared.MerkleWorkState
}

func randomWorkQueueItem(
	t *testing.T,
	hid core.ShortHostID,
	eid proto.EntityID,
	signer proto.DeviceID,
	typ proto.ChainType,
	seqno proto.Seqno,
) *workQueueItem {

	ret := &workQueueItem{
		shortHostID: hid,
		eid:         eid,
		typ:         typ,
		signer:      signer,
		seqno:       seqno,
		ctime:       proto.Time(0),
		state:       shared.MerkleWorkStateStaged,
	}
	err := core.RandomFill(ret.key[:])
	require.NoError(t, err)
	err = core.RandomFill(ret.val[:])
	require.NoError(t, err)

	return ret
}

func insertBatch(t *testing.T, m shared.MetaContext, items []*workQueueItem) {
	tx, dbCleanupFn, err := m.G().DbTx(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer func() {
		err := dbCleanupFn()
		require.NoError(t, err)
	}()
	trig := proto.NewUpdateTriggerDefault(proto.UpdateTriggerType_None)
	trigEnc, err := core.EncodeToBytes(&trig)
	require.NoError(t, err)

	for _, item := range items {
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO merkle_work_queue (
			short_host_id, id, chain_type, seqno, ctime, key, val, state, signer, update_trigger
		) VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9)`,
			int(item.shortHostID),
			item.eid.ExportToDB(),
			int(item.typ),
			int(item.seqno),
			item.key.ExportToDB(),
			item.val.ExportToDB(),
			string(item.state),
			item.signer.ExportToDB(),
			trigEnc,
		)
		require.NoError(t, err)
		require.Equal(t, int64(1), tag.RowsAffected())
	}

	err = tx.Commit(m.Ctx())
	require.NoError(t, err)
}

func redoItem(t *testing.T, m shared.MetaContext, item *workQueueItem) {
	tx, dbCleanupFn, err := m.G().DbTx(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer func() {
		err := dbCleanupFn()
		require.NoError(t, err)
	}()
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE merkle_work_queue
		 SET state=$1
		 WHERE short_host_id=$2
		 AND id=$3
		 AND chain_type=$4
		 AND seqno=$5`,
		string(shared.MerkleWorkStateStaged),
		int(item.shortHostID),
		item.eid.ExportToDB(),
		int(item.typ),
		int(item.seqno),
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
	err = tx.Commit(m.Ctx())
	require.NoError(t, err)
}

func selectCurrentBatch(
	t *testing.T,
	m shared.MetaContext,
) (
	*proto.MerkleBatcherState,
	*proto.MerkleBatch,
	error,
) {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeMerkleRaft)
	require.NoError(t, err)
	defer db.Release()

	var stateRaw []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT v FROM raft_kv_store WHERE short_host_id=$1 AND k=$2`,
		int(m.ShortHostID()),
		engine.BatchStateKey,
	).Scan(&stateRaw)
	require.NoError(t, err)

	var state proto.MerkleBatcherState
	err = core.DecodeFromBytes(&state, stateRaw)
	require.NoError(t, err)

	batchNo := state.Next - 1

	var batchRaw []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT v FROM raft_kv_store WHERE short_host_id=$1 AND k=$2`,
		int(m.ShortHostID()),
		engine.BatchKey(batchNo),
	).Scan(&batchRaw)
	require.NoError(t, err)

	var batch proto.MerkleBatch
	err = core.DecodeFromBytes(&batch, batchRaw)
	require.NoError(t, err)

	return &state, &batch, nil
}

func TestSimpleBatch(t *testing.T) {
	env := globalTestEnv.Fork(t, common.SetupOpts{
		MerklePollWait: time.Hour,
	})
	defer func() {
		_ = env.ShutdownFn()
	}()
	m := env.MetaContext()

	alice := core.RandomUID().EntityID()
	bob := core.RandomUID().EntityID()
	aliceDev := core.RandomDeviceID()
	bobDev := core.RandomDeviceID()
	shortHostID := m.G().HostChain().HostID().Short

	items := []*workQueueItem{
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_User, 1),
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_User, 2),
		randomWorkQueueItem(t, shortHostID, bob, bobDev, proto.ChainType_User, 1),
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_User, 3),
		randomWorkQueueItem(t, shortHostID, bob, bobDev, proto.ChainType_User, 2),
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_UserSettings, 1),
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_Name, 1),
		randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_UserSettings, 2),
	}

	// batch is sorted lexicographically by key, so let's just make sure that
	// alice||1 < bob||1, to simplify.
	items[0].key[0] = 0x11
	items[2].key[0] = 0xee

	insertBatch(t, m, items)
	cli, closeFn := common.TestMerkleBatcherCli(t, m)
	defer func() {
		err := closeFn()
		require.NoError(t, err)
	}()

	err := cli.Poke(m.Ctx())
	require.NoError(t, err)

	state, batch, err := selectCurrentBatch(t, m)
	require.NoError(t, err)
	require.Equal(t, proto.MerkleBatchNo(2), state.Next)
	require.Equal(t, proto.MerkleBatchNo(1), batch.Batchno)

	// one for alice and one for bob
	require.GreaterOrEqual(t, len(batch.Leaves), 2)

	find := func(k proto.MerkleTreeRFOutput) int {
		for i, leaf := range batch.Leaves {
			if bytes.Equal(leaf.Key[:], k[:]) {
				return i
			}
		}
		return -1
	}
	alicePos := find(items[0].key)
	bobPos := find(items[2].key)
	require.Less(t, alicePos, bobPos)
	require.GreaterOrEqual(t, alicePos, 0)
	require.GreaterOrEqual(t, bobPos, 0)

	// Now build part of the tree, let's make sure that we're getting some
	// good progress.
	builderCli, builderCloseFn := common.TestMerkleBuilderCli(t, m)
	defer func() {
		err := builderCloseFn()
		require.NoError(t, err)
	}()
	err = builderCli.Poke(m.Ctx())
	require.NoError(t, err)

	queryCli, queryCloseFn := common.TestMerkleQueryCli(t, m)
	defer func() {
		err := queryCloseFn()
		require.NoError(t, err)
	}()

	checkHostChainAt := func(path proto.MerklePathCompressed, seqno proto.Seqno) {
		// Also check that the hostchain was updated.
		v, err := path.Root.GetV()
		require.NoError(t, err)
		require.Equal(t, proto.MerkleRootVersion_V1, v)
		v1 := path.Root.V1()
		require.Equal(t, seqno, v1.Hostchain.Seqno)
	}

	check := func(key proto.MerkleTreeRFOutput, present bool, seqno proto.Seqno) proto.MerkleEpno {
		path, err := queryCli.Lookup(m.Ctx(), rem.MerkleLookupArg{Key: key})
		require.NoError(t, err)
		if present {
			_, err = merkle.VerifyPresence(&path, &key)
		} else {
			err = merkle.VerifyAbsence(&path, &key)
		}
		require.NoError(t, err)
		checkHostChainAt(path, seqno)

		v, err := path.Root.GetV()
		require.NoError(t, err)
		require.Equal(t, proto.MerkleRootVersion_V1, v)
		v1 := path.Root.V1()
		return v1.Epno
	}

	// check alice||1 and bob||1 are both in the tree!:
	check(items[0].key, true, 1)
	check(items[2].key, true, 1)

	// check also that alice||1 for UserSettings/Useranme is also in the tree
	check(items[5].key, true, 1)
	check(items[6].key, true, 1)

	// check that alice and bob's second path is not yet in the tree
	// should be race-free since we're in a private host instance.
	check(items[1].key, false, 1)
	check(items[3].key, false, 1)

	// also the 2nd seqno in the Setting chain shold not be in the tree
	check(items[7].key, false, 1)

	pokepoke := func() {
		err = cli.Poke(m.Ctx())
		require.NoError(t, err)
		err = builderCli.Poke(m.Ctx())
		require.NoError(t, err)
	}

	pokepoke()

	check(items[1].key, true, 1)
	check(items[4].key, true, 1)
	check(items[3].key, false, 1)

	pokepoke()

	check(items[3].key, true, 1)

	// now add a link to the hostchain and make sure that the hostchain is
	// reflected in the merkle root.
	hk := m.G().HostChain()
	fn := globalTestEnv.Dir().JoinStrings("k2.key")
	err = hk.NewKey(m, fn, proto.EntityType_HostMetadataSigner)
	require.NoError(t, err)

	pokepoke()
	check(items[3].key, true, 2)

	signerCli, signerCleanupFn := common.TestMerkleSignerCli(t, m)
	defer func() {
		err := signerCleanupFn()
		require.NoError(t, err)
	}()
	err = signerCli.Poke(m.Ctx())
	require.NoError(t, err)

	_, err = queryCli.GetCurrentRootSigned(m.Ctx(), nil)
	require.NoError(t, err)

	// Once we have a signed root, it should work to load a probe from the server
	p, err := shared.LoadProbe(m, rem.ProbeArg{})
	require.NoError(t, err)
	require.NotEqual(t, 0, len(p.Hostchain))

	alice3 := items[3]
	alice4 := randomWorkQueueItem(t, shortHostID, alice, aliceDev, proto.ChainType_User, 4)

	// It should not break the system to replay a leaf.
	// Check that nothing gets stuck behind the repeated item...
	// Also, the repeated leaf should not result in an epno
	// bump. It should noop the update. Check that too
	epno := check(alice3.key, true, 2)
	redoItem(t, m, alice3)
	pokepoke()
	insertBatch(t, m, []*workQueueItem{alice4})
	pokepoke()
	epnoPost := check(alice4.key, true, 2)
	require.Equal(t, epno+1, epnoPost)
}
