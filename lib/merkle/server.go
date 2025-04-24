// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"context"
	"fmt"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// We store hashes in the DB as a byte which indicates if the hash pointing to a
// leaf or node, and then the 32 bytes of the standard hash.
type PrefixedHash struct {
	Typ  proto.MerkleNodeType
	Hash *proto.MerkleNodeHash
}

func (p *PrefixedHash) Bytes() []byte {
	ret := make([]byte, len(*p.Hash)+1)
	ret[0] = byte(p.Typ)
	copy(ret[1:], (*p.Hash)[:])
	return ret
}

type MetaContext interface {
	Ctx() context.Context
	Warnw(msg string, keysAndValues ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	ShortHostID() core.ShortHostID
	HostID() core.HostID
}

type Bookkeeping struct {
	BatchNo proto.MerkleBatchNo
	Pos     int
}

func (b Bookkeeping) Advance() *Bookkeeping {
	return &Bookkeeping{
		BatchNo: b.BatchNo + 1,
		Pos:     -1,
	}
}

func NewBookkeeping() *Bookkeeping {
	return &Bookkeeping{
		BatchNo: proto.MerkleBatchNo(1),
		Pos:     -1,
	}
}

// All of these storage abstractions have the notion of a "hostID" built in. If we're
// going to be storing multiple hosts in a single DB, which is probably a good idea,
// we need to handle that in the implementation of these various abstractions.

type StorageWriter interface {
	RunRetryTx(MetaContext, string, func(MetaContext, StorageTransactor) error) error
	RunRead(MetaContext, string, func(MetaContext, StorageReader) error) error
}

type StorageTransactor interface {
	StorageReader
	InsertRoot(m MetaContext, epno proto.MerkleEpno, time proto.Time,
		rootHash proto.MerkleRootHash, body []byte, rootNode *PrefixedHash,
		hct *proto.HostchainTail) error
	InsertNode(m MetaContext, hash *proto.MerkleNodeHash, segment Segment,
		left *PrefixedHash, right *PrefixedHash) error
	InsertLeaf(m MetaContext, hash proto.MerkleNodeHash,
		key proto.MerkleTreeRFOutput, val proto.StdHash,
		epno proto.MerkleEpno) error
	UpdateBookkeeping(m MetaContext, bk Bookkeeping) error
	UpdateBookkeepingForBatcher(MetaContext, proto.MerkleBatchNo) error
}

type Root struct {
	Epno     proto.MerkleEpno
	Body     []byte
	RootNode *PrefixedHash
	Sig      *proto.Signature
}

type StorageReader interface {
	SelectRootForTraversal(m MetaContext, signed bool, epno *proto.MerkleEpno) (root *Root, err error)
	SelectNode(m MetaContext, h *PrefixedHash) (*Node, error)
	SelectLeaf(m MetaContext, h *PrefixedHash) (*proto.MerkleLeaf, error)
	CheckLeafExists(m MetaContext, h proto.MerkleTreeRFOutput) (rem.MerkleExistsRes, error)
	SelectRootHashes(m MetaContext, lst []proto.MerkleEpno) ([]proto.MerkleRootHash, error)
	SelectCurrentRootHash(m MetaContext) (*proto.TreeRoot, error)
	SelectRoots(m MetaContext, lst []proto.MerkleEpno) ([]proto.MerkleRoot, error)
	SelectBookkeeping(m MetaContext) (*Bookkeeping, error)
	SelectCurrentHostchainTail(m MetaContext) (*proto.HostchainTail, error)
	ConfirmRoot(m MetaContext, root proto.TreeRoot) error
}

type Segment struct {
	Bytes    []byte
	BitStart int
	BitCount int
}

type LookupPathNode struct {
	Node           *Node
	Next           bool
	KeyBitStart    int
	KeyBitsMatched int // includes L&R pointer follows
}

func (n *LookupPathNode) OppositeHash() *proto.MerkleNodeHash {
	h := n.Node.Select(!n.Next)
	return h.Hash
}

type LookupLeaf struct {
	Leaf    *proto.MerkleLeaf
	Hash    *PrefixedHash
	Matches bool
}

type LookupPathRes struct {
	Epno     proto.MerkleEpno
	RootBody []byte
	Path     []LookupPathNode
	Leaf     *LookupLeaf
}

type LookupPathsRes struct {
	Epno     proto.MerkleEpno
	RootBody []byte
	Paths    [](*LookupPathSingle)
}

type LookupPathSingle struct {
	Path []LookupPathNode
	Leaf *LookupLeaf
}

type Engine struct {
	sync.RWMutex
	s StorageWriter
}

type NodeBuilder struct {
	Node      *Node
	protoNode *proto.MerkleInteriorNode
	hash      *proto.MerkleNodeHash
}

func (b *NodeBuilder) SetChild(pos bool, ph *PrefixedHash) {
	b.hash = nil
	b.protoNode = nil
	b.Node.SetChild(pos, ph)
}

type LeafBuilder struct {
	ProtoLeaf *proto.MerkleLeaf
	hash      *proto.MerkleNodeHash
}

func NewLeafBuilder(k proto.MerkleTreeRFOutput, v proto.StdHash) *LeafBuilder {
	return &LeafBuilder{
		ProtoLeaf: &proto.MerkleLeaf{
			Key:   k,
			Value: v,
		},
	}
}

type Hasher interface {
	Hash() (*proto.MerkleNodeHash, error)
}

func (l *LeafBuilder) Hash() (*proto.MerkleNodeHash, error) {
	if l.hash != nil {
		return l.hash, nil
	}
	leaf := proto.NewMerkleNodeWithLeaf(*l.ProtoLeaf)
	var ret proto.MerkleNodeHash
	err := HashNode(&leaf, &ret)
	if err != nil {
		return nil, err
	}
	l.hash = &ret
	return &ret, nil

}

func ImportPrefixedHashFromDB(b []byte) (*PrefixedHash, error) {
	var typ proto.MerkleNodeType
	if len(b) == 0 {
		return nil, nil
	}
	var h proto.MerkleNodeHash
	if len(b) != len(h)+1 {
		return nil, core.InternalError("read wronge length of node hash out of DB")
	}
	typ = proto.MerkleNodeType(b[0])

	switch typ {
	case proto.MerkleNodeType_Leaf:
	case proto.MerkleNodeType_Node:
	default:
		return nil, core.InternalError("unexpected hash prefix")
	}

	copy(h[:], b[1:])
	return &PrefixedHash{Typ: typ, Hash: &h}, nil
}

func (s *Segment) ExportToNode(n *proto.MerkleInteriorNode) {
	n.PrefixBitStart = uint64(s.BitStart)
	n.PrefixBitCount = uint64(s.BitCount)
	n.Prefix, _ = core.ShiftCopyAndClamp(s.Bytes, s.BitStart, s.BitCount)
}

func NewNodeBuilderFromDB(n *Node) *NodeBuilder {
	return &NodeBuilder{
		Node: n,
	}
}

func (b *NodeBuilder) BuildNode() *proto.MerkleInteriorNode {
	if b.protoNode != nil {
		return b.protoNode
	}
	ret := &proto.MerkleInteriorNode{
		Left:  *b.Node.Left.Hash,
		Right: *b.Node.Right.Hash,
	}
	b.Node.Prefix.ExportToNode(ret)
	b.protoNode = ret
	return ret
}

func (b *NodeBuilder) Hash() (*proto.MerkleNodeHash, error) {
	if b.hash != nil {
		return b.hash, nil
	}
	node := b.BuildNode()
	wrapper := proto.NewMerkleNodeWithNode(*node)
	var ret proto.MerkleNodeHash
	err := HashNode(&wrapper, &ret)
	if err != nil {
		return nil, err
	}
	b.hash = &ret
	return &ret, nil
}

func (s *Segment) Split(nbits int) (*Segment, bool, *Segment, error) {
	if nbits >= s.BitCount || nbits < 0 {
		return nil, false, nil, core.InternalError("attempt to slice a segment would overflow bounds")
	}

	bitSplit := s.BitStart + nbits
	offset := s.BitStart - s.BitStart&0x7

	leftBitEnd := bitSplit - offset
	splitBit := leftBitEnd
	rightBitStart := splitBit + 1

	splitByte := splitBit >> 3
	leftByteEnd := leftBitEnd >> 3
	rightByteStart := rightBitStart >> 3

	// The layout is:
	//
	// <.... lead bits (can ignore)...> <...left bits...> splitBit <...rightBits...> <...traiilng bits...(can ignore)...>
	//

	left := Segment{
		BitCount: nbits,
		BitStart: s.BitStart,
		Bytes:    s.Bytes[0:(leftByteEnd + 1)],
	}

	splitBitValue := (s.Bytes[splitByte] & (1 << (0x7 - (splitBit & 0x7)))) != 0

	right := Segment{
		BitCount: s.BitCount - nbits - 1,
		BitStart: rightBitStart + offset,
		Bytes:    s.Bytes[rightByteStart:],
	}

	return &left, splitBitValue, &right, nil
}

func (l *LookupPathNode) Split() (*Segment, bool, error) {
	top, splitBit, bottom, err := l.Node.Prefix.Split(l.KeyBitsMatched)
	if err != nil {
		return nil, false, err
	}
	l.Node.Prefix = *bottom
	return top, splitBit, nil
}

func (e *Engine) propagateUpdates(
	m MetaContext,
	path []LookupPathNode,
	outputPath []NodeBuilder,
) ([]NodeBuilder, error) {

	var prev *NodeBuilder
	if len(outputPath) > 0 {
		prev = &outputPath[len(outputPath)-1]
	}

	for i := len(path) - 1; i >= 0; i-- {
		if prev == nil {
			return nil, core.InternalError("expected output node in storeUpdatePath")
		}
		nb := NewNodeBuilderFromDB(path[i].Node)
		hash, err := prev.Hash()
		if err != nil {
			return nil, err
		}

		nb.SetChild(path[i].Next, &PrefixedHash{Typ: proto.MerkleNodeType_Node, Hash: hash})
		outputPath = append(outputPath, *nb)
		prev = nb
	}
	return outputPath, nil
}

func (e *Engine) storeUpdatedPath(
	m MetaContext,
	tx StorageTransactor,
	lookupRes *LookupPathRes,
	lb *LeafBuilder,
	outputPath []NodeBuilder,
	arg InsertKeyValueArg,
) error {

	epno := proto.MerkleEpnoFirst
	if lookupRes != nil {
		epno = lookupRes.Epno + 1
	}
	m.Infow("storeUpdatedPath", "shortHostID", m.ShortHostID(), "epno", epno)

	err := e.storeLeaf(m, tx, lb, epno)
	if err != nil {
		return err
	}

	var root Hasher
	root = lb
	rootTyp := proto.MerkleNodeType_Leaf

	for _, n := range outputPath {
		root = &n
		rootTyp = proto.MerkleNodeType_Node
		err = n.storeNode(m, tx)
		if err != nil {
			return err
		}
	}

	rootHash, err := root.Hash()
	if err != nil {
		return err
	}

	err = e.storeRoot(m, tx, epno, &PrefixedHash{Hash: rootHash, Typ: rootTyp}, arg.Time, arg.Hct)
	if err != nil {
		return err
	}

	if arg.Bk != nil {
		err = tx.UpdateBookkeeping(m, *arg.Bk)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) buildBackPointerHash(m MetaContext, tx StorageTransactor, epno proto.MerkleEpno) (*proto.MerkleBackPointerHash, error) {
	seq := MerkleBackpointerSequence(epno)
	var tmp proto.MerkleBackPointers
	if len(seq) > 0 {
		bps, err := tx.SelectRootHashes(m, seq)
		if err != nil {
			return nil, err
		}
		tmp = proto.MerkleBackPointers(make([]proto.MerkleBackPointer, len(seq)))
		for i, ep := range seq {
			tmp[i] = proto.MerkleBackPointer{
				Epno: ep,
				Hash: bps[i],
			}
		}
	} else {
		tmp = []proto.MerkleBackPointer{}
	}
	var ret proto.MerkleBackPointerHash
	err := HashBackPointers(&tmp, &ret)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func (e *Engine) StoreRoot(
	m MetaContext,
	time proto.Time,
	hct proto.HostchainTail,
	bk Bookkeeping,
) error {
	return e.s.RunRetryTx(m, "StoreRoot",
		func(m MetaContext, tx StorageTransactor) error {
			root, err := tx.SelectRootForTraversal(m, false, nil)
			if err != nil {
				return err
			}
			if root == nil {
				return core.MerkleNoRootError{}
			}
			err = e.storeRoot(m, tx, root.Epno+1, root.RootNode, time, &hct)
			if err != nil {
				return err
			}
			return tx.UpdateBookkeeping(m, bk)
		})
}

func (e *Engine) storeRoot(
	m MetaContext,
	tx StorageTransactor,
	epno proto.MerkleEpno,
	rootNode *PrefixedHash,
	time proto.Time,
	newHct *proto.HostchainTail,
) error {

	m.Infow("Engine::storeRoot",
		"shortHostID", m.ShortHostID(),
		"epno", epno,
		"RootNode.Hash",
		rootNode.Hash,
		"RootNode.Type",
		rootNode.Typ)

	bphash, err := e.buildBackPointerHash(m, tx, epno)
	if err != nil {
		return err
	}

	if time == 0 {
		time = proto.Now()
	}

	currHct, err := tx.SelectCurrentHostchainTail(m)
	if err != nil {
		return err
	}

	dupe := false

	if newHct != nil && currHct != nil {
		if currHct.Seqno > newHct.Seqno {
			return core.MerkleTreeError("hostchain tail is older than current")
		}
		if currHct.Seqno == newHct.Seqno {
			dupe = true
		}
	}
	storeHct := currHct
	if newHct != nil {
		storeHct = newHct
	}
	if storeHct == nil {
		storeHct = &proto.HostchainTail{}
	}
	if dupe {
		newHct = nil
	}

	r1 := proto.MerkleRootV1{
		Epno:         epno,
		Time:         time,
		RootNode:     *rootNode.Hash,
		BackPointers: *bphash,
		Hostchain:    *storeHct,
	}

	root := proto.NewMerkleRootWithV1(r1)
	var hash proto.MerkleRootHash
	err = HashRoot(&root, &hash)

	if err != nil {
		return err
	}
	raw, err := core.EncodeToBytes(&root)
	if err != nil {
		return err
	}
	err = tx.InsertRoot(m,
		r1.Epno,
		r1.Time,
		hash,
		raw,
		rootNode,
		newHct,
	)
	if err != nil {
		return err
	}
	return nil
}

func (n *NodeBuilder) Segment() Segment {
	return n.Node.Prefix
}

func (n *NodeBuilder) storeNode(m MetaContext, tx StorageTransactor) error {

	hash, err := n.Hash()
	if err != nil {
		return err
	}

	err = tx.InsertNode(
		m,
		hash,
		n.Segment(),
		n.Node.Left,
		n.Node.Right,
	)
	if err != nil {
		return err
	}

	return nil
}

func (e *Engine) storeLeaf(
	m MetaContext,
	tx StorageTransactor,
	lb *LeafBuilder,
	epno proto.MerkleEpno,
) error {
	hash, err := lb.Hash()
	if err != nil {
		return err
	}
	err = tx.InsertLeaf(
		m,
		*hash,
		lb.ProtoLeaf.Key,
		lb.ProtoLeaf.Value,
		epno,
	)
	if err != nil {
		return err
	}
	return nil
}

func (e *Engine) selectOrCreateBookkepingTryTx(
	m MetaContext,
	tx StorageTransactor,
) (
	*Bookkeeping,
	error,
) {
	e.Lock()
	defer e.Unlock()

	bk, err := tx.SelectBookkeeping(m)
	if err != nil {
		return nil, err
	}
	if bk != nil {
		return bk, nil
	}
	bk = NewBookkeeping()
	err = tx.UpdateBookkeeping(m, *bk)
	if err != nil {
		return nil, err
	}
	return bk, nil
}

func (e *Engine) insertKeyValueTryTx(
	m MetaContext,
	tx StorageTransactor,
	arg InsertKeyValueArg,
) error {
	e.Lock()
	defer e.Unlock()

	lookupRes, err := e.lookupPathWithLock(m, tx, rem.MerkleLookupArg{Key: arg.Key})

	// Insert are idempotent so if the key is already in the tree, it's not a problem.
	// But we have to make sure to update bookkeeping if it's needed, so we don't get stuck here.
	// Booking is otherwise updated in storeUpdatePath.
	if err == nil && lookupRes != nil && lookupRes.Leaf != nil && lookupRes.Leaf.Matches {
		m.Warnw("indexKeyValuTryTx", "warning", "key already exists in Merkle Tree", "key", arg.Key.Hex())
		if arg.Bk != nil {
			err = tx.UpdateBookkeeping(m, *arg.Bk)
			if err != nil {
				return err
			}
		}
		return nil
	}

	lb := NewLeafBuilder(arg.Key, arg.Val)

	// Rare case - first insert
	if _, ok := err.(core.MerkleNoRootError); ok && lookupRes == nil {
		return e.storeUpdatedPath(m, tx, nil, lb, nil, arg)
	}

	if err != nil {
		return err
	}

	newLeafHash, err := lb.Hash()
	if err != nil {
		return err
	}

	// The path of nodes we need to commit into the DB
	var outputPath []NodeBuilder

	// input Path
	path := lookupRes.Path

	// Here are the 3 cases we need to consider:
	//  0. Totally empty tree
	//  1. We traversed all the way down to a leaf but it was the wrong leaf,
	//     so we have to insert a node right above it with the appriopriate longest
	//     common prefix. In this case, we introduce a new prefix.
	//  2. We stop at an interior node where we don't match the "segment" of that node
	//     and hence we're going to have to split that segment in 2 pieces.
	//
	// Case 0 is not handled, since there's nothing to do

	if lookupRes.Leaf != nil {
		// Case 1 -- lookupRes.Leaf is not nil, but path can be 0 or non-0.

		bitsMatched := 0
		if len(path) > 0 {
			lastNode := path[len(path)-1]
			// Add the extra bit since we traversed a pointer down to the leaf.
			bitsMatched = lastNode.KeyBitStart + lastNode.KeyBitsMatched
		}
		prefix, numbits, splitBit, err := core.ComputePrefixMatch(arg.Key[:], lookupRes.Leaf.Leaf.Key[:], bitsMatched)
		if err != nil {
			return err
		}

		existingLeafHash := lookupRes.Leaf.Hash

		var left, right *proto.MerkleNodeHash

		if !splitBit {
			left = newLeafHash
			right = existingLeafHash.Hash
		} else {
			right = newLeafHash
			left = existingLeafHash.Hash
		}

		nb := NodeBuilder{
			Node: &Node{
				Prefix: Segment{
					Bytes:    prefix,
					BitStart: bitsMatched,
					BitCount: numbits,
				},
				Left: &PrefixedHash{
					Typ:  proto.MerkleNodeType_Leaf,
					Hash: left,
				},
				Right: &PrefixedHash{
					Typ:  proto.MerkleNodeType_Leaf,
					Hash: right,
				},
			},
		}
		outputPath = append(outputPath, nb)

	} else if len(path) > 0 {

		// Case 2
		i := len(path) - 1
		firstMiss := path[i]

		// Cut this part of the path off for when we walk back up to the root
		path = path[0:i]

		// We matched some of the segment, so split it into 2 pieces;
		// The bottom side of the split will be reflected in the "firstMiss"
		// LookupPathNode
		top, splitBit, err := firstMiss.Split()
		if err != nil {
			return err
		}

		pathBottom := NewNodeBuilderFromDB(firstMiss.Node)
		nodeHash, err := pathBottom.Hash()
		if err != nil {
			return err
		}
		outputPath = append(outputPath, *pathBottom)

		node := &PrefixedHash{
			Typ:  proto.MerkleNodeType_Node,
			Hash: nodeHash,
		}
		leaf := &PrefixedHash{
			Typ:  proto.MerkleNodeType_Leaf,
			Hash: newLeafHash,
		}

		var left, right *PrefixedHash
		if splitBit {
			right, left = node, leaf
		} else {
			left, right = node, leaf
		}

		nb := NodeBuilder{
			Node: &Node{
				Prefix: *top,
				Left:   left,
				Right:  right,
			},
		}
		outputPath = append(outputPath, nb)
	}

	outputPath, err = e.propagateUpdates(m, path, outputPath)
	if err != nil {
		return err
	}

	return e.storeUpdatedPath(m, tx, lookupRes, lb, outputPath, arg)
}

type InsertKeyValueArg struct {
	Key  proto.MerkleTreeRFOutput
	Val  proto.StdHash
	Bk   *Bookkeeping
	Time proto.Time
	Hct  *proto.HostchainTail
}

func (e *Engine) InsertKeyValue(
	m MetaContext,
	arg InsertKeyValueArg,
) error {
	return e.s.RunRetryTx(m, "merkle.Insert",
		func(m MetaContext, tx StorageTransactor) error {
			return e.insertKeyValueTryTx(m, tx, arg)
		})
}

func (e *Engine) UpdateBookkeeping(
	m MetaContext,
	bk Bookkeeping,
) error {
	return e.s.RunRetryTx(m, "merkle.UpdateBookkeeping",
		func(m MetaContext, tx StorageTransactor) error {
			return tx.UpdateBookkeeping(m, bk)
		})
}

func (e *Engine) UpdateBookkeepingForBatcher(
	m MetaContext,
	batchNo proto.MerkleBatchNo,
) error {
	return e.s.RunRetryTx(m, "merkle.UpdateBookkeepingForBatcher",
		func(m MetaContext, tx StorageTransactor) error {
			return tx.UpdateBookkeepingForBatcher(m, batchNo)
		})
}

func (e *Engine) SelectBookkeeping(
	m MetaContext,
) (*Bookkeeping, error) {
	var ret *Bookkeeping
	err := e.s.RunRead(m, "merkle.SelectBookkeeping",
		func(m MetaContext, r StorageReader) error {
			var err error
			ret, err = r.SelectBookkeeping(m)
			return err
		})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (e *Engine) SelectOrCreateBookkeeping(
	m MetaContext,
) (*Bookkeeping, error) {
	var ret *Bookkeeping
	err := e.s.RunRetryTx(m, "merkle.SelectOrCreateBookkeeping",
		func(m MetaContext, tx StorageTransactor) error {
			tmp, err := e.selectOrCreateBookkepingTryTx(m, tx)
			if err != nil {
				return err
			}
			ret = tmp
			return nil
		})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (e *Engine) LookupPath(
	m MetaContext,
	arg rem.MerkleLookupArg,
) (*LookupPathRes, error) {
	e.RLock()
	defer e.RUnlock()
	var ret *LookupPathRes
	err := e.s.RunRead(m, "merkle.LookupPath",
		func(m MetaContext, r StorageReader) error {
			var err error
			ret, err = e.lookupPathWithLock(m, r, arg)
			return err
		},
	)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (e *Engine) LookupPaths(
	m MetaContext,
	arg rem.MerkleMLookupArg,
) (*LookupPathsRes, error) {
	e.RLock()
	defer e.RUnlock()
	var ret *LookupPathsRes
	err := e.s.RunRead(m, "merkle.LookupPath",
		func(m MetaContext, r StorageReader) error {
			var err error
			ret, err = e.lookupPathsWithLock(m, r, arg)
			return err
		},
	)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type Node struct {
	Prefix Segment
	Left   *PrefixedHash
	Right  *PrefixedHash
}

func (n *Node) Select(b bool) *PrefixedHash {
	if b {
		return n.Right
	}
	return n.Left
}

func (n *Node) SetChild(b bool, ph *PrefixedHash) {
	if b {
		n.Right = ph
	} else {
		n.Left = ph
	}
}

func (e *Engine) lookupPathWithLockFromRoot(
	m MetaContext,
	db StorageReader,
	key proto.MerkleTreeRFOutput,
	currNode *PrefixedHash,
	leaf *PrefixedHash,
) (*LookupPathSingle, error) {
	var ret LookupPathSingle

	bitCursor := 0 // Points to the next bit to match (+1 of the last bit matched)

	for currNode != nil {

		node, err := db.SelectNode(m, currNode)
		if err != nil {
			m.Errorw("looupPathWithLockFromRoot",
				"err", err,
				"currNode.Typ", currNode.Typ,
				"currNode.Hash", currNode.Hash.Hex(),
			)
			return nil, err
		}

		bitsMatched := 0

		if node.Prefix.BitStart != bitCursor {
			return nil, core.MerkleTreeError(fmt.Sprintf("mismatch on path traversal bit location: %d != %d", bitCursor, node.Prefix.BitStart))
		}

		nodeMatchErr := core.AssertKeyMatch(key[:], node.Prefix.Bytes, node.Prefix.BitStart, node.Prefix.BitCount)
		var bitAt bool
		var nxt *PrefixedHash

		if nodeMatchErr == nil {
			bitsMatched = node.Prefix.BitCount
			bitAt, err = core.BitAt(key[:], bitCursor+bitsMatched)
			if err != nil {
				return &ret, err
			}
			nxt = node.Select(bitAt)

			// We just matched the pointer above at Select, so increment
			// the number of total bits matched by this node.
			bitsMatched++

		} else if bpme, ok := nodeMatchErr.(core.BitPrefixMatchError); ok {
			bitsMatched = int(bpme) - node.Prefix.BitStart
		} else {
			return nil, err
		}

		ret.Path = append(ret.Path, LookupPathNode{
			Node:           node,
			Next:           bitAt,
			KeyBitStart:    bitCursor,
			KeyBitsMatched: bitsMatched,
		})

		bitCursor += bitsMatched

		if nodeMatchErr != nil {
			return &ret, nil
		}

		if nxt.Typ == proto.MerkleNodeType_Leaf {
			leaf = nxt
			currNode = nil
		} else {
			currNode = nxt
		}
	}

	if leaf == nil {
		return &ret, nil
	}

	// We went to the end of the path and we may or may not find our leaf. We might just
	// find a leaf with a common prefix, in which case we need to insert a node above it.
	// Note this is likely the common case as we hit a steady state.

	pleaf, err := db.SelectLeaf(m, leaf)
	if err != nil {
		return nil, err
	}

	ret.Leaf = &LookupLeaf{
		Hash:    leaf,
		Leaf:    pleaf,
		Matches: key.Eq(pleaf.Key),
	}

	return &ret, nil
}

func (e *Engine) lookupPathWithLock(
	m MetaContext,
	db StorageReader,
	arg rem.MerkleLookupArg,
) (*LookupPathRes, error) {

	marg := rem.MerkleMLookupArg{
		Signed: arg.Signed,
		Root:   arg.Root,
		Keys:   []proto.MerkleTreeRFOutput{arg.Key},
	}

	mres, err := e.lookupPathsWithLock(m, db, marg)
	if err != nil {
		return nil, err
	}
	if len(mres.Paths) == 0 {
		return nil, nil
	}
	var ret LookupPathRes
	ret.RootBody = mres.RootBody
	ret.Epno = mres.Epno
	if path := mres.Paths[0]; path != nil {
		ret.Path = path.Path
		ret.Leaf = path.Leaf
	}
	return &ret, nil
}

func (e *Engine) lookupPathsWithLock(
	m MetaContext,
	db StorageReader,
	arg rem.MerkleMLookupArg,
) (*LookupPathsRes, error) {

	var ret LookupPathsRes

	root, err := db.SelectRootForTraversal(m, arg.Signed, arg.Root)
	if err != nil {
		return nil, err
	}

	var currNode *PrefixedHash
	var leaf *PrefixedHash

	if root != nil {
		ret.Epno = root.Epno
		ret.RootBody = root.Body
		currNode = root.RootNode

		// Rare case: only one item in the tree, and it's a leaf (of course).
		if root.RootNode.Typ == proto.MerkleNodeType_Leaf {
			leaf = currNode
			currNode = nil
		}
	}
	for _, key := range arg.Keys {
		sing, err := e.lookupPathWithLockFromRoot(m, db, key, currNode, leaf)
		if err != nil {
			return nil, err
		}
		ret.Paths = append(ret.Paths, sing)
	}

	return &ret, nil
}

func NewEngine(s StorageWriter) *Engine {
	return &Engine{s: s}
}

func (l *LookupPathRes) Compress(ret *proto.MerklePathCompressed) error {

	err := core.DecodeFromBytes(&ret.Root, l.RootBody)
	if err != nil {
		return err
	}

	if len(l.Path) == 0 {
		return core.MerkleVerifyError("empty path")
	}

	// we might need to slice off the end of the path, so do that to our
	// local slice, and not the one we got passed.
	ret.Path, ret.Terminal = compressPath(l.Path, l.Leaf)

	return nil
}

func (l *LookupPathsRes) Compress(ret *proto.MerklePathsCompressed) error {

	err := core.DecodeFromBytes(&ret.Root, l.RootBody)
	if err != nil {
		return err
	}

	for _, path := range l.Paths {
		if len(path.Path) == 0 {
			return core.MerkleVerifyError("empty path")
		}
		var pair proto.MerklePathCompressedPair
		pair.Path, pair.Terminal = compressPath(path.Path, path.Leaf)
		ret.Paths = append(ret.Paths, pair)
	}
	return nil
}

func compressPath(
	path []LookupPathNode,
	leaf *LookupLeaf,
) (
	proto.MerklePathCompressedBlob,
	proto.MerklePathTerminal,
) {
	var term proto.MerklePathTerminal

	// If we didn't match the full node (on a miss), then we need to record
	// the node that was there, so the receiever can reconstruct the root.
	last := path[len(path)-1]
	if last.KeyBitsMatched < last.Node.Prefix.BitCount {
		node := (&NodeBuilder{Node: last.Node}).BuildNode()
		term = proto.NewMerklePathTerminalWithFalse(
			proto.MerklePathIncomplete{
				NodeAtPrefixMiss: *node,
			},
		)
		path = path[0 : len(path)-1]
	}

	stepLen := len(proto.MerkleNodeHash{}) + 1
	outPath := make([]byte, len(path)*stepLen)
	curr := outPath
	for _, edge := range path {
		curr[0] = byte(edge.Node.Prefix.BitCount)
		hsh := edge.OppositeHash()
		copy(curr[1:], (*hsh)[:])
		curr = curr[stepLen:]
	}

	// Leaf might be nil if we fail the lookup in an internal node, which is very possible.
	if leaf != nil {
		complete := proto.MerklePathToLeaf{
			Leaf: leaf.Leaf.Value,
		}
		if !leaf.Matches {
			complete.FoundKey = &leaf.Leaf.Key
		}
		term = proto.NewMerklePathTerminalWithTrue(complete)
	}

	return outPath, term
}

func (e *Engine) GetCurrentSignedRoot(
	m MetaContext,
) (
	proto.SignedMerkleRoot,
	error,
) {
	var ret proto.SignedMerkleRoot
	err := e.s.RunRead(m, "getCurrentSignedRoot", func(m MetaContext, r StorageReader) error {
		root, err := r.SelectRootForTraversal(m, true, nil)
		if err != nil {
			return err
		}
		if root == nil {
			return core.MerkleTreeError("no root found")
		}
		if root.Sig == nil {
			return core.MerkleTreeError("no signature found")
		}
		ret.Sig = *root.Sig
		ret.Inner = root.Body
		return nil
	})
	return ret, err
}

func (e *Engine) ConfirmRoot(
	m MetaContext,
	root proto.TreeRoot,
) error {
	return e.s.RunRead(m, "confirmRoot", func(m MetaContext, tx StorageReader) error {
		return tx.ConfirmRoot(m, root)
	})
}

func (e *Engine) GetCurrentSignedRootEpno(
	m MetaContext,
) (
	proto.MerkleEpno,
	error,
) {
	var ret proto.MerkleEpno
	err := e.s.RunRead(m, "getCurrentSignedRoot", func(m MetaContext, r StorageReader) error {
		root, err := r.SelectRootForTraversal(m, true, nil)
		if err != nil {
			return err
		}
		if root == nil {
			return core.MerkleTreeError("no root found")
		}
		if root.Sig == nil {
			return core.MerkleTreeError("no signature found")
		}
		ret = root.Epno
		return nil
	})
	return ret, err
}

func (e *Engine) GetCurrentRoot(
	m MetaContext,
) (
	proto.MerkleRoot,
	error,
) {
	var ret proto.MerkleRoot
	err := e.s.RunRead(m, "getCurrentRoot", func(m MetaContext, r StorageReader) error {
		root, err := r.SelectRootForTraversal(m, false, nil)
		if err != nil {
			return err
		}
		if root == nil {
			return core.MerkleTreeError("no root found")
		}
		err = core.DecodeFromBytes(&ret, root.Body)
		if err != nil {
			return err
		}
		return nil
	})
	return ret, err
}

func (e *Engine) GetCurrentRootHash(
	m MetaContext,
) (
	*proto.TreeRoot,
	error,
) {
	var ret *proto.TreeRoot
	err := e.s.RunRead(m, "getCurrentRootHash", func(m MetaContext, r StorageReader) error {
		var err error
		ret, err = r.SelectCurrentRootHash(m)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (e *Engine) GetHistoricalRoots(
	m MetaContext,
	full []proto.MerkleEpno,
	hashes []proto.MerkleEpno,
) (
	[]proto.MerkleRoot,
	[]proto.MerkleRootHash,
	error,
) {
	var retHashes []proto.MerkleRootHash
	var retRoots []proto.MerkleRoot

	err := e.s.RunRead(m, "getHistoricalRoots", func(m MetaContext, r StorageReader) error {
		var err error
		retHashes, err = r.SelectRootHashes(m, hashes)
		if err != nil {
			return err
		}
		retRoots, err = r.SelectRoots(m, full)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return retRoots, retHashes, nil
}

func (e *Engine) CheckKeyExists(m MetaContext, arg proto.MerkleTreeRFOutput) (rem.MerkleExistsRes, error) {
	e.RLock()
	defer e.RUnlock()
	var res rem.MerkleExistsRes
	err := e.s.RunRead(m, "merkle.LookupPath",
		func(m MetaContext, r StorageReader) error {
			var err error
			res, err = r.CheckLeafExists(m, arg)
			return err

		},
	)
	return res, err
}
