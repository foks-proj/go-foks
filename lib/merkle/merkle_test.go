// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"context"
	cryptoRand "crypto/rand"
	"errors"
	"math/rand"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

type testRoot struct {
	Root
	hash proto.MerkleRootHash
}

type testDB struct {
	roots         []testRoot
	nodes         map[proto.MerkleNodeHash]Node
	leaves        map[proto.MerkleNodeHash]proto.MerkleLeaf
	leavesByKey   map[proto.MerkleTreeRFOutput]bool
	leafEpnos     map[proto.MerkleTreeRFOutput]proto.MerkleEpno
	hostchainTail *proto.HostchainTail
	bk            Bookkeeping
}

func NewTestDB() *testDB {
	return &testDB{
		roots:       nil,
		nodes:       make(map[proto.MerkleNodeHash]Node),
		leaves:      make(map[proto.MerkleNodeHash]proto.MerkleLeaf),
		leavesByKey: make(map[proto.MerkleTreeRFOutput]bool),
		leafEpnos:   make(map[proto.MerkleTreeRFOutput]proto.MerkleEpno),
	}
}

var _ StorageWriter = (*testDB)(nil)
var _ StorageReader = (*testDB)(nil)
var _ StorageTransactor = (*testDB)(nil)

func (t *testDB) RunRetryTx(m MetaContext, s string, f func(m MetaContext, tx StorageTransactor) error) error {
	return f(m, t)
}

func (t *testDB) RunRead(m MetaContext, s string, f func(MetaContext, StorageReader) error) error {
	return f(m, t)
}

func (t *testDB) InsertRoot(m MetaContext, epno proto.MerkleEpno, time proto.Time,
	rootHash proto.MerkleRootHash, body []byte, topNode *PrefixedHash, hct *proto.HostchainTail,
) error {
	if int(epno) != len(t.roots)+1 {
		return errors.New("got out-of-order root updates")
	}
	root := testRoot{
		Root: Root{
			Epno:     epno,
			Body:     body,
			RootNode: topNode,
		},
		hash: rootHash,
	}
	t.roots = append(t.roots, root)
	t.hostchainTail = hct

	return nil
}

func (t *testDB) assertDoesNotExist(h proto.MerkleNodeHash) error {
	_, found := t.nodes[h]
	if found {
		return errors.New("inserted hash already exists as node")
	}
	_, found = t.leaves[h]
	if found {
		return errors.New("inserted hash already exists as a leaf")
	}
	return nil
}

func (t *testDB) InsertNode(m MetaContext, hash *proto.MerkleNodeHash, segment Segment, left *PrefixedHash, right *PrefixedHash) error {
	err := t.assertDoesNotExist(*hash)
	if err != nil {
		return err
	}
	t.nodes[*hash] = Node{Prefix: segment, Left: left, Right: right}
	return nil
}

func (t *testDB) InsertLeaf(
	m MetaContext,
	hash proto.MerkleNodeHash,
	key proto.MerkleTreeRFOutput,
	val proto.StdHash,
	epno proto.MerkleEpno,
) error {
	err := t.assertDoesNotExist(hash)
	if err != nil {
		return err
	}
	t.leaves[hash] = proto.MerkleLeaf{Key: key, Value: val}
	t.leafEpnos[key] = epno
	t.leavesByKey[key] = true
	return nil
}

func (t *testDB) SelectRootForTraversal(m MetaContext, signed bool, epno *proto.MerkleEpno) (root *Root, err error) {
	l := len(t.roots)
	if l == 0 {
		return nil, core.MerkleNoRootError{}
	}
	if epno == nil {
		return &t.roots[l-1].Root, nil
	}
	for _, r := range t.roots {
		if r.Epno == *epno {
			return &r.Root, nil
		}
	}
	return nil, core.MerkleNoRootError{}
}

func (t *testDB) SelectCurrentRootHash(m MetaContext) (*proto.TreeRoot, error) {
	l := len(t.roots)
	if l == 0 {
		return nil, core.MerkleNoRootError{}
	}
	lst := &t.roots[l-1]
	return &proto.TreeRoot{
		Hash: lst.hash, Epno: lst.Epno,
	}, nil
}

func (t *testDB) SelectCurrentHostchainTail(m MetaContext) (*proto.HostchainTail, error) {
	return t.hostchainTail, nil
}

func (t *testDB) SelectNode(m MetaContext, h *PrefixedHash) (*Node, error) {
	if h.Typ != proto.MerkleNodeType_Node {
		return nil, errors.New("asked to select a node for Leaf hash")
	}
	node, found := t.nodes[*h.Hash]
	if !found {
		return nil, nil
	}
	return &node, nil
}

func (t *testDB) SelectLeaf(m MetaContext, h *PrefixedHash) (*proto.MerkleLeaf, error) {
	if h.Typ != proto.MerkleNodeType_Leaf {
		return nil, errors.New("asked to select a leaf for a node hash")
	}
	leaf, found := t.leaves[*h.Hash]
	if !found {
		return nil, nil
	}
	return &leaf, nil
}

func (t *testDB) CheckLeafExists(m MetaContext, h proto.MerkleTreeRFOutput) (rem.MerkleExistsRes, error) {
	var res rem.MerkleExistsRes
	if t.leavesByKey[h] {
		res.Epno = t.leafEpnos[h]
		res.Signed = true
		return res, nil
	}
	return res, core.MerkleLeafNotFoundError{}
}

func (t *testDB) SelectRootHashes(m MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRootHash, error) {
	var ret []proto.MerkleRootHash
	for _, ep := range seq {
		if !ep.IsValid() {
			return nil, errors.New("invalid epno in SelectRootHashes")
		}
		if int(ep) >= len(t.roots)+1 {
			return nil, errors.New("overflow error in SelectRootHashes")
		}
		ret = append(ret, t.roots[ep-1].hash)
	}
	return ret, nil
}

func (t *testDB) SelectRoots(m MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRoot, error) {
	var ret []proto.MerkleRoot
	for _, ep := range seq {
		if !ep.IsValid() {
			return nil, errors.New("invalid epno in SelectRoots")
		}
		if int(ep) >= len(t.roots)+1 {
			return nil, errors.New("overflow error in SelectRoots")
		}
		body := t.roots[ep-1].Body
		var tmp proto.MerkleRoot
		err := core.DecodeFromBytes(&tmp, body)
		if err != nil {
			return nil, err
		}
		ret = append(ret, tmp)
	}
	return ret, nil
}

func (t *testDB) SelectBookkeeping(m MetaContext) (*Bookkeeping, error) {
	return &t.bk, nil
}

func (t *testDB) UpdateBookkeeping(m MetaContext, bk Bookkeeping) error {
	t.bk = bk
	return nil
}

func (t *testDB) UpdateBookkeepingForBatcher(m MetaContext, bn proto.MerkleBatchNo) error {
	return nil
}

func (t *testDB) InsertHostchainTo(ctx context.Context, end proto.Seqno) (int, error) {
	return 0, nil
}

func (t *testDB) ConfirmRoot(m MetaContext, root proto.TreeRoot) error {
	return core.NotImplementedError{}
}

func makeDummyKey(b byte) proto.MerkleTreeRFOutput {
	var ret proto.MerkleTreeRFOutput
	ret[0] = b
	return ret
}

func longTo32byteHash(targ []byte, l uint32) {
	targ[0] = byte((l >> 24) & 0xff)
	targ[1] = byte((l >> 16) & 0xff)
	targ[2] = byte((l >> 8) & 0xff)
	targ[3] = byte((l >> 0) & 0xff)
}

func makeDummyKey4(l uint32) proto.MerkleTreeRFOutput {
	var ret proto.MerkleTreeRFOutput
	longTo32byteHash(ret[:], l)
	return ret
}

func makeDummyValue4(l uint32) proto.StdHash {
	var ret proto.StdHash
	longTo32byteHash(ret[:], l)
	return ret
}

func makeDummyValue(b byte) proto.StdHash {
	var ret proto.StdHash
	ret[0] = b
	return ret
}

type testMetaContext struct {
	ctx context.Context
}

func (m testMetaContext) Ctx() context.Context {
	return m.ctx
}
func (m testMetaContext) Warnw(msg string, keysAndValues ...interface{})  {}
func (m testMetaContext) Debugw(msg string, keysAndValues ...interface{}) {}
func (m testMetaContext) Infow(msg string, keysAndValues ...interface{})  {}
func (m testMetaContext) Errorw(msg string, keysAndValues ...interface{}) {}
func (m testMetaContext) ShortHostID() core.ShortHostID                   { return 0 }
func (m testMetaContext) HostID() core.HostID                             { return core.HostID{} }

var _ MetaContext = testMetaContext{}

func newTestMetaContext() testMetaContext {
	return testMetaContext{ctx: context.Background()}
}

type testMerkleClient struct {
	eng    *Engine
	hostID proto.HostID
	init   bool
	hashes map[proto.MerkleEpno]*proto.MerkleRootHash
	roots  map[proto.MerkleEpno]*proto.MerkleRoot
	latest proto.MerkleEpno
}

func (t *testMerkleClient) HostID() proto.HostID {
	return t.hostID
}
func (t *testMerkleClient) GetRootHashFromCache(ctx context.Context, e proto.MerkleEpno) (*proto.MerkleRootHash, error) {
	return t.hashes[e], nil
}
func (t *testMerkleClient) GetRootFromCache(ctx context.Context, e proto.MerkleEpno) (*proto.MerkleRoot, error) {
	return t.roots[e], nil
}
func (t *testMerkleClient) GetLatestRootFromCache(ctx context.Context) (*proto.MerkleRoot, error) {
	if !t.init {
		return nil, core.MerkleNoRootError{}
	}
	return t.roots[t.latest], nil
}

func (t *testMerkleClient) Store(ctx context.Context, ep proto.MerkleEpno, h *proto.MerkleRootHash, r *proto.MerkleRoot, latest bool) error {
	if latest && t.latest < ep {
		t.init = true
		t.latest = ep
	}
	if h != nil {
		tmp := *h
		t.hashes[ep] = &tmp
	}
	if r != nil {
		tmp := *r
		t.roots[ep] = &tmp
	}
	return nil
}

func (t *testMerkleClient) GetRootsFromServer(
	ctx context.Context,
	roots []proto.MerkleEpno,
	hashes []proto.MerkleEpno,
) (
	[]proto.MerkleRoot,
	[]proto.MerkleRootHash,
	error,
) {
	m := testMetaContext{ctx: ctx}
	return t.eng.GetHistoricalRoots(m, roots, hashes)
}

func (t *testMerkleClient) GetLatestRootFromServer(
	ctx context.Context,
) (
	proto.MerkleRoot,
	error,
) {
	m := testMetaContext{ctx: ctx}
	return t.eng.GetCurrentRoot(m)
}

func newTestMerkleClient(eng *Engine) *testMerkleClient {
	return &testMerkleClient{
		eng:    eng,
		hashes: make(map[proto.MerkleEpno]*proto.MerkleRootHash),
		roots:  make(map[proto.MerkleEpno]*proto.MerkleRoot),
	}
}

var _ ClientInterface = (*testMerkleClient)(nil)

func TestAbsenceFailOnNodeNotLeafSimple(t *testing.T) {
	d := NewTestDB()
	eng := NewEngine(d)
	m := newTestMetaContext()

	ins := func(b byte) {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: makeDummyKey(b), Val: makeDummyValue(b)})
		require.NoError(t, err)
	}

	ins(0x1)
	ins(0x2)
	k := makeDummyKey(0x21)
	path, err := eng.LookupPath(m, rem.MerkleLookupArg{Key: k})
	require.NoError(t, err)
	var cpath proto.MerklePathCompressed
	err = path.Compress(&cpath)
	require.NoError(t, err)
	err = VerifyAbsence(&cpath, &k)
	require.NoError(t, err)
}

func TestAbsenceFailOnNodeNotLeafTrickier(t *testing.T) {
	d := NewTestDB()
	eng := NewEngine(d)
	m := newTestMetaContext()

	ins4 := func(u uint32) {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: makeDummyKey4(u), Val: makeDummyValue(byte(u & 0xff))})
		require.NoError(t, err)
	}

	ins4(0x6a000000)
	ins4(0x69ca0000)
	ins4(0x69c90000)

	key := makeDummyKey4(0x69df0000)
	path, err := eng.LookupPath(m, rem.MerkleLookupArg{Key: key})
	require.NoError(t, err)
	var cpath proto.MerklePathCompressed
	err = path.Compress(&cpath)
	require.NoError(t, err)
	err = VerifyAbsence(&cpath, &key)
	require.NoError(t, err)
}

func lookupArg(k proto.MerkleTreeRFOutput) rem.MerkleLookupArg {
	return rem.MerkleLookupArg{
		Key: k,
	}
}

func TestSimpleInserts(t *testing.T) {
	d := NewTestDB()
	eng := NewEngine(d)
	m := newTestMetaContext()

	ins := func(b byte) {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: makeDummyKey(b), Val: makeDummyValue(b)})
		require.NoError(t, err)
	}
	ins4 := func(l uint32) {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: makeDummyKey4(l), Val: makeDummyValue4(l)})
		require.NoError(t, err)

	}

	ins(0x1)
	ins(0x2)
	path, err := eng.LookupPath(m, lookupArg(makeDummyKey(0x2)))
	require.NoError(t, err)
	require.NotNil(t, path.Leaf)

	require.Equal(t, proto.MerkleEpno(2), path.Epno)
	require.Equal(t, 1, len(path.Path))
	require.Equal(t, 6, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 7, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, makeDummyValue(0x2), path.Leaf.Leaf.Value)

	path, err = eng.LookupPath(m, lookupArg(makeDummyKey(0x1)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(2), path.Epno)
	require.Equal(t, 1, len(path.Path))
	require.Equal(t, 6, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 7, path.Path[0].KeyBitsMatched)
	require.Equal(t, false, path.Path[0].Next)
	require.Equal(t, makeDummyValue(0x1), path.Leaf.Leaf.Value)

	// Insert binary: 00011111
	ins(0x1f)
	path, err = eng.LookupPath(m, lookupArg(makeDummyKey(0x2)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(3), path.Epno)
	require.Equal(t, 2, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, false, path.Path[0].Next)
	require.Equal(t, 2, path.Path[1].Node.Prefix.BitCount)
	require.Equal(t, 4, path.Path[1].Node.Prefix.BitStart)
	require.Equal(t, 4, path.Path[1].KeyBitStart)
	require.Equal(t, 3, path.Path[1].KeyBitsMatched)
	require.Equal(t, true, path.Path[1].Next)
	require.Equal(t, makeDummyValue(0x2), path.Leaf.Leaf.Value)

	path, err = eng.LookupPath(m, lookupArg(makeDummyKey(0x1f)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(3), path.Epno)
	require.Equal(t, 1, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, makeDummyValue(0x1f), path.Leaf.Leaf.Value)

	// Insert binary: 00011110 11110000 00000000 00000000
	ins4(0x1EF00000)
	path, err = eng.LookupPath(m, lookupArg(makeDummyKey(0x1f)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(4), path.Epno)
	require.Equal(t, 2, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, 3, path.Path[1].Node.Prefix.BitCount)
	require.Equal(t, 4, path.Path[1].Node.Prefix.BitStart)
	require.Equal(t, 4, path.Path[1].KeyBitStart)
	require.Equal(t, 4, path.Path[1].KeyBitsMatched)
	require.Equal(t, true, path.Path[1].Next)
	require.Equal(t, makeDummyValue(0x1f), path.Leaf.Leaf.Value)

	path, err = eng.LookupPath(m, lookupArg(makeDummyKey4(0x1ef00000)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(4), path.Epno)
	require.Equal(t, 2, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, 3, path.Path[1].Node.Prefix.BitCount)
	require.Equal(t, 4, path.Path[1].Node.Prefix.BitStart)
	require.Equal(t, 4, path.Path[1].KeyBitStart)
	require.Equal(t, 4, path.Path[1].KeyBitsMatched)
	require.Equal(t, false, path.Path[1].Next)
	require.Equal(t, makeDummyValue4(0x1ef00000), path.Leaf.Leaf.Value)

	// Insert binary: 00011110 11110000 00001000 00000000
	ins4(0x1ef00800)
	path, err = eng.LookupPath(m, lookupArg(makeDummyKey4(0x1ef00000)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(5), path.Epno)
	require.Equal(t, 3, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, 3, path.Path[1].Node.Prefix.BitCount)
	require.Equal(t, 4, path.Path[1].Node.Prefix.BitStart)
	require.Equal(t, 4, path.Path[1].KeyBitStart)
	require.Equal(t, 4, path.Path[1].KeyBitsMatched)
	require.Equal(t, false, path.Path[1].Next)
	require.Equal(t, 12, path.Path[2].Node.Prefix.BitCount)
	require.Equal(t, 8, path.Path[2].Node.Prefix.BitStart)
	require.Equal(t, 8, path.Path[2].KeyBitStart)
	require.Equal(t, 13, path.Path[2].KeyBitsMatched)
	require.Equal(t, false, path.Path[2].Next)
	require.Equal(t, makeDummyValue4(0x1ef00000), path.Leaf.Leaf.Value)

	ins4(0x1ef00a00)
	path, err = eng.LookupPath(m, lookupArg(makeDummyKey4(0x1ef00800)))
	require.NoError(t, err)
	require.Equal(t, proto.MerkleEpno(6), path.Epno)
	require.Equal(t, 4, len(path.Path))
	require.Equal(t, 3, path.Path[0].Node.Prefix.BitCount)
	require.Equal(t, 0, path.Path[0].Node.Prefix.BitStart)
	require.Equal(t, 0, path.Path[0].KeyBitStart)
	require.Equal(t, 4, path.Path[0].KeyBitsMatched)
	require.Equal(t, true, path.Path[0].Next)
	require.Equal(t, 3, path.Path[1].Node.Prefix.BitCount)
	require.Equal(t, 4, path.Path[1].Node.Prefix.BitStart)
	require.Equal(t, 4, path.Path[1].KeyBitStart)
	require.Equal(t, 4, path.Path[1].KeyBitsMatched)
	require.Equal(t, false, path.Path[1].Next)
	require.Equal(t, 12, path.Path[2].Node.Prefix.BitCount)
	require.Equal(t, 8, path.Path[2].Node.Prefix.BitStart)
	require.Equal(t, 8, path.Path[2].KeyBitStart)
	require.Equal(t, 13, path.Path[2].KeyBitsMatched)
	require.Equal(t, true, path.Path[2].Next)
	require.Equal(t, 1, path.Path[3].Node.Prefix.BitCount)
	require.Equal(t, 21, path.Path[3].Node.Prefix.BitStart)
	require.Equal(t, 21, path.Path[3].KeyBitStart)
	require.Equal(t, 2, path.Path[3].KeyBitsMatched)
	require.Equal(t, false, path.Path[3].Next)
	require.Equal(t, makeDummyValue4(0x1ef00800), path.Leaf.Leaf.Value)

	path, err = eng.LookupPath(m, lookupArg(makeDummyKey4(0x1ef00801)))
	require.NoError(t, err)
	require.NotNil(t, path.Leaf)
	require.False(t, path.Leaf.Matches)
	require.NotEqual(t, makeDummyKey4(0x1ef00801), path.Leaf.Leaf.Key)
}

func randomFill(t *testing.T, b []byte) {
	_, err := cryptoRand.Read(b)
	require.NoError(t, err)
}

func TestSlowGetRacingFastGet(t *testing.T) {
	d := NewTestDB()
	eng := NewEngine(d)
	tmc := newTestMerkleClient(eng)
	m := newTestMetaContext()

	insLeaf := func() {
		var leaf proto.MerkleLeaf
		randomFill(t, leaf.Key[:])
		randomFill(t, leaf.Value[:])
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: leaf.Key, Val: leaf.Value})
		require.NoError(t, err)
	}

	insLeaves := func(n int) {
		for i := 0; i < n; i++ {
			insLeaf()
		}
	}

	lookup := func() *LookupPathRes {
		var key proto.MerkleTreeRFOutput
		randomFill(t, key[:])
		res, err := eng.LookupPath(m, lookupArg(key))
		require.NoError(t, err)
		require.True(t, res.Leaf == nil || !res.Leaf.Matches)
		return res
	}

	resToRoot := func(res *LookupPathRes) *proto.MerkleRoot {
		var cpath proto.MerklePathCompressed
		err := res.Compress(&cpath)
		require.NoError(t, err)
		return &cpath.Root
	}

	checkRoot := func(res *LookupPathRes, rollbackError bool) {
		r := resToRoot(res)
		err := CheckAndStoreLatestRoot(m.Ctx(), tmc, r)
		if !rollbackError {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.IsType(t, core.MerkleRollbackError{}, err)
		}
	}

	getLatestEpno := func() proto.MerkleEpno {
		latest, err := tmc.GetLatestRootFromCache(m.Ctx())
		require.NoError(t, err)
		return latest.V1().Epno
	}
	insLeaves(9)
	l0 := lookup()
	checkRoot(l0, false)

	insLeaves(3)
	l1 := lookup()
	s1 := NewSession(tmc)
	err := s1.Init(m.Ctx())
	require.NoError(t, err)
	insLeaves(24)
	l2 := lookup()
	checkRoot(l2, false)
	insLeaves(5)

	ep1 := getLatestEpno()

	// We should get a rollback error here, since the l2 lookup bumped the
	// merkle epno stored locally allthe way up to 26, but l1 is still at 2.
	checkRoot(l1, true)

	// This however should work fine.
	err = s1.Run(m.Ctx(), resToRoot(l1))
	require.NoError(t, err)

	ep2 := getLatestEpno()
	require.GreaterOrEqual(t, ep2, ep1)
}

func TestLotsOfInserts(t *testing.T) {
	n := 18000
	var leaves []proto.MerkleLeaf
	d := NewTestDB()
	eng := NewEngine(d)

	m := newTestMetaContext()
	for i := 0; i < n; i++ {
		var tmp proto.MerkleLeaf
		randomFill(t, tmp.Key[:])
		randomFill(t, tmp.Value[:])
		leaves = append(leaves, tmp)
	}

	for _, leaf := range leaves {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: leaf.Key, Val: leaf.Value})
		require.NoError(t, err)
	}

}

func TestRandomInserts(t *testing.T) {
	n := 2048
	var leaves []proto.MerkleLeaf
	d := NewTestDB()
	eng := NewEngine(d)
	tmc := newTestMerkleClient(eng)

	m := newTestMetaContext()
	for i := 0; i < n; i++ {
		var tmp proto.MerkleLeaf
		randomFill(t, tmp.Key[:])
		randomFill(t, tmp.Value[:])
		leaves = append(leaves, tmp)
	}

	checkBackPointersAt := []int{
		2, 5, 8, 124, 127, 128, 129, 505, 509, 1001, 1023, 1599,
	}
	checkPointersMap := make(map[int]bool)
	for _, i := range checkBackPointersAt {
		checkPointersMap[i] = true
	}

	for i, leaf := range leaves {
		err := eng.InsertKeyValue(m, InsertKeyValueArg{Key: leaf.Key, Val: leaf.Value})
		require.NoError(t, err)

		if checkPointersMap[i] {
			res, err := eng.LookupPath(m, lookupArg(leaf.Key))
			require.NoError(t, err)
			require.NotNil(t, res.Leaf)
			require.True(t, res.Leaf.Matches)
			require.Equal(t, leaf.Key, res.Leaf.Leaf.Key)
			require.Equal(t, leaf.Value, res.Leaf.Leaf.Value)

			var cpath proto.MerklePathCompressed
			err = res.Compress(&cpath)
			require.NoError(t, err)

			_, err = VerifyPresence(&cpath, &leaf.Key)
			require.NoError(t, err)
			err = CheckAndStoreLatestRoot(m.Ctx(), tmc, &cpath.Root)
			require.NoError(t, err)
		}
	}

	for _, leaf := range leaves {
		res, err := eng.LookupPath(m, lookupArg(leaf.Key))
		require.NoError(t, err)
		require.NotNil(t, res.Leaf)
		require.True(t, res.Leaf.Matches)
		require.Equal(t, leaf.Key, res.Leaf.Leaf.Key)
		require.Equal(t, leaf.Value, res.Leaf.Leaf.Value)

		var cpath proto.MerklePathCompressed
		err = res.Compress(&cpath)
		require.NoError(t, err)

		_, err = VerifyPresence(&cpath, &leaf.Key)
		require.NoError(t, err)
		_, err = eng.CheckKeyExists(m, leaf.Key)
		require.NoError(t, err)

		// Now verify absense works properly
		leaf.Key[5] ^= 0x8
		res, err = eng.LookupPath(m, lookupArg(leaf.Key))
		require.NoError(t, err)
		err = res.Compress(&cpath)
		require.NoError(t, err)

		err = VerifyAbsence(&cpath, &leaf.Key)
		require.NoError(t, err)
		_, err = VerifyPresence(&cpath, &leaf.Key)
		require.Error(t, err)
		require.Equal(t, core.MerkleVerifyError("server claimed key was not in tree"), err)

		_, err = eng.CheckKeyExists(m, leaf.Key)
		require.Error(t, err)
		require.Equal(t, core.MerkleLeafNotFoundError{}, err)
	}

	// Now check that the server can't "hide" an existing key by returning
	// another valid path that is just the wrong path.

	checkServerCannotHide := func(i int) {
		hiddenLeaf := leaves[i]
		for j, decoyLeaf := range leaves {
			if i == j {
				continue
			}
			res, err := eng.LookupPath(m, lookupArg(decoyLeaf.Key))
			require.NoError(t, err)
			require.NotNil(t, res.Leaf)

			var cpath proto.MerklePathCompressed
			err = res.Compress(&cpath)
			require.NoError(t, err)
			complete, err := cpath.Terminal.GetLeaf()
			require.NoError(t, err)
			require.True(t, complete)
			require.Nil(t, cpath.Terminal.True().FoundKey)
			_, err = VerifyPresence(&cpath, &decoyLeaf.Key)
			require.NoError(t, err)
			cpath.Terminal.F_1__.FoundKey = &decoyLeaf.Key
			err = VerifyAbsence(&cpath, &hiddenLeaf.Key)
			require.Error(t, err)
			require.Equal(t, core.MerkleVerifyError("failed to match root node hash"), err)
		}
	}

	for i := 0; i < 10; i++ {
		r := rand.Int() % len(leaves)
		checkServerCannotHide(r)
	}
}

func TestSegmentSplit(t *testing.T) {

	var vectors = []struct {
		input    Segment
		nbits    int
		left     Segment
		splitBit bool
		right    Segment
		err      error
	}{
		{
			input: Segment{
				Bytes:    []byte{0xfe, 0xc1},
				BitCount: 2,
				BitStart: 8,
			},
			nbits: 1,
			left: Segment{
				Bytes:    []byte{0xfe},
				BitStart: 8,
				BitCount: 1,
			},
			splitBit: true,
			right: Segment{
				Bytes:    []byte{0xfe, 0xc1},
				BitStart: 10,
				BitCount: 0,
			},
			err: nil,
		},
		{
			input: Segment{
				Bytes:    []byte{0xfe},
				BitCount: 1,
				BitStart: 8,
			},
			nbits: 0,
			left: Segment{
				Bytes:    []byte{0xfe},
				BitStart: 8,
				BitCount: 0,
			},
			splitBit: true,
			right: Segment{
				Bytes:    []byte{0xfe},
				BitStart: 9,
				BitCount: 0,
			},
			err: nil,
		},
		{
			input: Segment{
				Bytes:    []byte{0xfe},
				BitCount: 1,
				BitStart: 7,
			},
			nbits: 0,
			left: Segment{
				Bytes:    []byte{0xfe},
				BitStart: 7,
				BitCount: 0,
			},
			splitBit: false,
			right: Segment{
				Bytes:    []byte{},
				BitStart: 8,
				BitCount: 0,
			},
			err: nil,
		},
		{
			input: Segment{
				Bytes:    []byte{0x44, 0x8f, 0x8e, 0xe7},
				BitCount: 21,
				BitStart: 5,
			},
			nbits: 9,
			left: Segment{
				Bytes:    []byte{0x44, 0x8f},
				BitStart: 5,
				BitCount: 9,
			},
			splitBit: true,
			right: Segment{
				Bytes:    []byte{0x8f, 0x8e, 0xe7},
				BitCount: 11,
				BitStart: 15,
			},
			err: nil,
		},
	}

	for _, e := range vectors {
		l, b, r, err := e.input.Split(e.nbits)
		require.Equal(t, e.err, err)
		if err != nil {
			continue
		}
		require.Equal(t, e.left, *l)
		require.Equal(t, e.splitBit, b)
		require.Equal(t, e.right, *r)
	}

}
