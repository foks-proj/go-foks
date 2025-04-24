// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func setupTestAgent(t *testing.T) (libclient.MetaContext, func()) {
	m := libclient.NewMetaContextMain()
	tmp, err := os.MkdirTemp("", "foks_agent_test_")
	require.NoError(t, err)
	m.G().Cfg().TestSetHomeCLIFlag(tmp)
	err = Startup(m, StartupOpts{})
	require.NoError(t, err)
	return m, func() {
		os.RemoveAll(tmp)
	}
}

func TestDB(t *testing.T) {
	m, cleanup := setupTestAgent(t)
	defer cleanup()

	aType := lcl.DataType_YubiKey
	noType := lcl.DataType_None

	putGet := func(which libclient.DbType) {
		typ := aType
		fqu := core.RandomFQU()
		val := core.RandomSKMWKList()
		scope := &fqu.HostID
		key := &fqu.Uid
		err := m.DbPut(which, libclient.PutArg{Key: key, Typ: typ, Val: &val, Scope: scope})
		require.NoError(t, err)

		var res lcl.SKMWKList
		tm, err := m.DbGet(&res, which, scope, typ, key)
		require.NoError(t, err)
		require.Equal(t, res, val)
		require.Greater(t, tm, proto.Time(0))
	}

	putGet(libclient.DbTypeHard)
	putGet(libclient.DbTypeHard)
	putGet(libclient.DbTypeSoft)
	putGet(libclient.DbTypeSoft)

	var res lcl.SKMWKList
	fqu := core.RandomFQU()
	_, err := m.DbGet(&res, libclient.DbTypeHard, &fqu.HostID, aType, &fqu.Uid)
	require.Error(t, err)
	require.True(t, errors.Is(err, core.RowNotFoundError{}))

	putGetGlobalKV := func(which libclient.DbType) {
		fqu := core.RandomFQU()
		key := core.KVKey(hex.EncodeToString(fqu.HostID[:]))
		err := m.DbPut(which, libclient.PutArg{Key: key, Typ: noType, Val: &fqu.Uid})
		require.NoError(t, err)

		var res proto.UID
		tm, err := m.DbGetGlobalKV(&res, which, key)
		require.NoError(t, err)
		require.Equal(t, res, fqu.Uid)
		require.Greater(t, tm, proto.Time(0))
	}

	putGetGlobalKV(libclient.DbTypeHard)
	putGetGlobalKV(libclient.DbTypeHard)
	putGetGlobalKV(libclient.DbTypeSoft)
	putGetGlobalKV(libclient.DbTypeSoft)
}

func randomFill(t *testing.T, b []byte) {
	err := core.RandomFill(b)
	require.NoError(t, err)
}

func TestMerkleLocalStorage(t *testing.T) {
	m, cleanup := setupTestAgent(t)
	defer cleanup()

	epno := proto.MerkleEpno(40247)

	hostID := core.RandomHostID()
	var hash proto.MerkleRootHash
	randomFill(t, hash[:])
	v1 := proto.MerkleRootV1{
		Epno: epno,
		Time: proto.Now(),
	}
	randomFill(t, v1.RootNode[:])
	root := proto.NewMerkleRootWithV1(v1)

	rootEq := func(r1, r2 proto.MerkleRoot) bool {
		b1, err := core.EncodeToBytes(&r1)
		require.NoError(t, err)
		b2, err := core.EncodeToBytes(&r2)
		require.NoError(t, err)
		return bytes.Equal(b1, b2)
	}

	stor := libclient.NewMerkleAgentLocalStorage(m.G(), hostID)
	err := stor.Store(m.Ctx(), epno, &hash, &root, true)
	require.NoError(t, err)

	r2, err := stor.GetLatestRootFromCache(m.Ctx())
	require.NoError(t, err)
	require.True(t, rootEq(root, *r2))

	hsh, err := stor.GetRootHashFromCache(m.Ctx(), epno)
	require.NoError(t, err)
	require.Equal(t, hash, *hsh)

	r3, err := stor.GetRootFromCache(m.Ctx(), epno)
	require.NoError(t, err)
	require.True(t, rootEq(root, *r3))

	r4, err := stor.GetRootFromCache(m.Ctx(), epno+1)
	require.Nil(t, r4)
	require.NoError(t, err)

	h3, err := stor.GetRootHashFromCache(m.Ctx(), epno-1)
	require.Nil(t, h3)
	require.NoError(t, err)
}

func TestMerkleLatestRace(t *testing.T) {

	m, cleanup := setupTestAgent(t)
	defer cleanup()

	makeRoot := func(epno proto.MerkleEpno) (*proto.MerkleRoot, *proto.MerkleRootHash) {
		v1 := proto.MerkleRootV1{
			Epno: epno,
			Time: proto.Now(),
		}
		randomFill(t, v1.RootNode[:])
		root := proto.NewMerkleRootWithV1(v1)
		var hash proto.MerkleRootHash
		err := merkle.HashRoot(&root, &hash)
		require.NoError(t, err)
		return &root, &hash
	}

	hostID := core.RandomHostID()
	stor := libclient.NewMerkleAgentLocalStorage(m.G(), hostID)
	r1, h1 := makeRoot(4027)
	err := stor.Store(m.Ctx(), r1.V1().Epno, h1, r1, true)
	require.NoError(t, err)

	r, err := stor.GetLatestRootFromCache(m.Ctx())
	require.NoError(t, err)
	require.Equal(t, r1, r)

	// If we store an old root, check that it doesn't overwrite the latest
	r0, h0 := makeRoot(1020)
	err = stor.Store(m.Ctx(), r0.V1().Epno, h0, r0, true)
	require.NoError(t, err)

	r, err = stor.GetLatestRootFromCache(m.Ctx())
	require.NoError(t, err)
	require.Equal(t, r1, r)
	require.Equal(t, r1.V1().Epno, r1.V1().Epno)

	// But of course it's still stored and retrieved without a problem
	r, err = stor.GetRootFromCache(m.Ctx(), r0.V1().Epno)
	require.NoError(t, err)
	require.Equal(t, r0, r)

}

func TestGlobalSet(t *testing.T) {
	i1 := proto.UserInfo{}
	i2 := proto.UserInfo{}
	i1.Fqu.Uid[0] = 1
	i2.Fqu.Uid[0] = 2

	m, cleanup := setupTestAgent(t)
	defer cleanup()

	err := m.DbPutTx(libclient.DbTypeHard, []libclient.PutArg{
		{
			Key: core.KVKeyAllUsers,
			Val: &i1,
			Set: true,
		},
		{
			Key: core.KVKeyAllUsers,
			Val: &i2,
			Set: true,
		},
	})
	require.NoError(t, err)
	res, _, err := libclient.DbGetGlobalSet[proto.UserInfo](
		m, libclient.DbTypeHard, core.KVKeyAllUsers,
	)
	require.NoError(t, err)
	require.Equal(t, 2, len(res))
	sort.Slice(res, func(i, j int) bool {
		return res[i].Fqu.Uid[0] < res[j].Fqu.Uid[0]
	})
	require.Equal(t, i1, res[0])
	require.Equal(t, i2, res[1])

	hash, err := core.PrefixedHash(&i1)
	require.NoError(t, err)

	err = m.DbDeleteFromGlobalSet(libclient.DbTypeHard, core.KVKeyAllUsers, *hash)
	require.NoError(t, err)

	res, _, err = libclient.DbGetGlobalSet[proto.UserInfo](
		m, libclient.DbTypeHard, core.KVKeyAllUsers,
	)
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, i2, res[0])
}
