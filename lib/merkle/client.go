// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"context"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func Verify(p *proto.MerklePathCompressed, key *proto.MerkleTreeRFOutput, present bool) (*proto.StdHash, error) {
	if present {
		return VerifyPresence(p, key)
	}
	return nil, VerifyAbsence(p, key)
}

func VerifyAbsence(p *proto.MerklePathCompressed, key *proto.MerkleTreeRFOutput) error {

	found, err := p.Terminal.KeyWasFound()
	if err != nil {
		return err
	}

	if found {
		return core.MerkleVerifyError("server claimed key was in tree")
	}

	return verifyPath(p, key)

}

func VerifyPresence(p *proto.MerklePathCompressed, key *proto.MerkleTreeRFOutput) (*proto.StdHash, error) {

	found, err := p.Terminal.KeyWasFound()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, core.MerkleVerifyError("server claimed key was not in tree")
	}
	err = verifyPath(p, key)
	if err != nil {
		return nil, err
	}
	which, err := p.Terminal.GetLeaf()
	if err != nil {
		return nil, err
	}
	if !which {
		return nil, core.MerkleVerifyError("expected a leaf at the end of the path")
	}
	leaf := p.Terminal.True().Leaf
	return &leaf, nil
}

func checkErrIsBitPrefxMatchError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(core.BitPrefixMatchError)
	return ok
}

func verifyPath(p *proto.MerklePathCompressed, key *proto.MerkleTreeRFOutput) error {

	bitCursor := 0
	edgeLen := 1 + len(proto.MerkleNodeHash{})
	path := make([]proto.MerkleInteriorNode, len(p.Path)/edgeLen)
	bytePath := p.Path
	keyBytes := (*key)[:]
	pathCursor := 0
	for len(bytePath) > 0 {
		if len(bytePath) < edgeLen {
			return core.MerkleVerifyError(fmt.Sprintf("bad path, needs to be a multiple of %d bytes", edgeLen))
		}
		prefixLen := int(bytePath[0])
		prfx := core.CopyAndClamp(keyBytes, bitCursor, prefixLen)
		if prfx == nil {
			return core.MerkleVerifyError("key bit offset overflow")
		}
		inode := proto.MerkleInteriorNode{
			PrefixBitStart: uint64(bitCursor),
			PrefixBitCount: uint64(prefixLen),
			Prefix:         prfx,
		}
		bitCursor += prefixLen
		bit, err := core.BitAt(keyBytes, bitCursor)
		if err != nil {
			return err
		}
		bitCursor++
		var tmp proto.MerkleNodeHash
		copy(tmp[:], bytePath[1:])
		inode.SetChild(!bit, &tmp)
		bytePath = bytePath[edgeLen:]
		path[pathCursor] = inode
		pathCursor++
	}

	var lastHash proto.MerkleNodeHash
	var foundKey *proto.MerkleTreeRFOutput

	complete, err := p.Terminal.GetLeaf()
	if err != nil {
		return err
	}

	if !complete {
		n := p.Terminal.False().NodeAtPrefixMiss

		err = core.AssertKeyMatch(keyBytes, n.Prefix, bitCursor, int(n.PrefixBitCount))
		if !checkErrIsBitPrefxMatchError(err) {
			return core.MerkleVerifyError("we matched up to last interior node but server claimed otherwise")
		}

		tmp := proto.NewMerkleNodeWithNode(n)
		err := HashNode(&tmp, &lastHash)
		if err != nil {
			return err
		}

	} else {

		tmp := proto.MerkleLeaf{
			Value: p.Terminal.True().Leaf,
		}
		foundKey = p.Terminal.True().FoundKey
		if foundKey != nil {
			tmp.Key = *foundKey
		} else {
			tmp.Key = *key
		}

		leaf := proto.NewMerkleNodeWithLeaf(tmp)

		err := HashNode(&leaf, &lastHash)
		if err != nil {
			return err
		}

	}

	for i := len(path) - 1; i >= 0; i-- {
		curr := path[i]
		curr.SetEmpty(&lastHash)
		node := proto.NewMerkleNodeWithNode(curr)
		err := HashNode(&node, &lastHash)
		if err != nil {
			return err
		}
	}

	v, err := p.Root.GetV()
	if err != nil {
		return err
	}
	if v != proto.MerkleRootVersion_V1 {
		return core.VersionNotSupportedError("got merkle root from the future")
	}
	rv1 := p.Root.V1()
	if !rv1.RootNode.Eq(&lastHash) {
		return core.MerkleVerifyError("failed to match root node hash")
	}

	if foundKey != nil {
		if foundKey.Eq(*key) {
			return core.MerkleVerifyError("found key was the same as our key, and it should not have been")
		}
		err := core.AssertKeyMatch((foundKey)[:], (*key)[:], 0, bitCursor)
		if err != nil {
			return err
		}
	}

	return nil
}

type ClientInterface interface {
	HostID() proto.HostID // each interface is local to a given HostID scope, return it needed
	GetRootHashFromCache(context.Context, proto.MerkleEpno) (*proto.MerkleRootHash, error)
	GetRootFromCache(context.Context, proto.MerkleEpno) (*proto.MerkleRoot, error)
	GetLatestRootFromCache(ctx context.Context) (*proto.MerkleRoot, error)
	Store(context.Context, proto.MerkleEpno, *proto.MerkleRootHash, *proto.MerkleRoot, bool) error
	GetRootsFromServer(context.Context, []proto.MerkleEpno, []proto.MerkleEpno) ([]proto.MerkleRoot, []proto.MerkleRootHash, error)
	GetLatestRootFromServer(context.Context) (proto.MerkleRoot, error)
}

type openedRoot struct {
	r  *proto.MerkleRoot
	v1 *proto.MerkleRootV1
	h  proto.MerkleRootHash
}

func (o *openedRoot) Epno() proto.MerkleEpno {
	return o.v1.Epno
}

func openRoot(r *proto.MerkleRoot) (*openedRoot, error) {
	v, err := r.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.MerkleRootVersion_V1 {
		return nil, core.VersionNotSupportedError("merkle root from the future")
	}
	rv1 := r.V1()

	ret := &openedRoot{r: r, v1: &rv1}

	err = HashRoot(r, &ret.h)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func getRootHashFromCache(ctx context.Context, c ClientInterface, e proto.MerkleEpno) (*proto.MerkleRootHash, error) {
	hash, err := c.GetRootHashFromCache(ctx, e)
	if err != nil {
		return nil, err
	}
	if hash != nil {
		return hash, nil
	}
	root, err := c.GetRootFromCache(ctx, e)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	var tmp proto.MerkleRootHash
	err = HashRoot(root, &tmp)
	if err != nil {
		return nil, err
	}
	return &tmp, nil
}

func computeBackPointers(
	e proto.MerkleEpno,
	hashes map[proto.MerkleEpno]*proto.MerkleRootHash,
	roots map[proto.MerkleEpno]*proto.MerkleRoot,
) (*proto.MerkleBackPointerHash, proto.MerkleBackPointers, error) {
	seq := MerkleBackpointerSequence(e)
	ret := proto.MerkleBackPointers(make([]proto.MerkleBackPointer, len(seq)))

	getHash := func(e proto.MerkleEpno) (*proto.MerkleRootHash, error) {
		hash := hashes[e]
		if hash != nil {
			return hash, nil
		}
		root := roots[e]
		if root == nil {
			return nil, nil
		}
		var tmp proto.MerkleRootHash
		err := HashRoot(root, &tmp)
		if err != nil {
			return nil, err
		}
		return &tmp, nil
	}

	for i, epno := range seq {
		hash, err := getHash(epno)
		if err != nil {
			return nil, nil, err
		}
		if hash == nil {
			return nil, nil, core.MerkleBackPointerVerifyError{Msg: "missing hash", Epno: epno}
		}
		ret[i] = proto.MerkleBackPointer{
			Epno: epno,
			Hash: *hash,
		}
	}
	var hash proto.MerkleBackPointerHash
	err := HashBackPointers(&ret, &hash)
	if err != nil {
		return nil, nil, err
	}

	return &hash, ret, nil
}

func CheckAndStoreLatestRoot(ctx context.Context, c ClientInterface, latest *proto.MerkleRoot) error {

	sess := NewSession(c)
	err := sess.Init(ctx)
	if err != nil {
		return err
	}
	err = sess.Run(ctx, latest)
	if err != nil {
		return err
	}
	return nil
}

func OpenMerkleRootNoSigCheck(b []byte) (proto.MerkleRootV1, error) {
	var ret proto.MerkleRootV1
	var tmp proto.MerkleRoot

	err := core.DecodeFromBytes(&tmp, b)
	if err != nil {
		return ret, err
	}
	v, err := tmp.GetV()
	if err != nil {
		return ret, err
	}
	if v != 1 {
		return ret, core.VersionNotSupportedError("merkle root from the future")
	}
	return tmp.V1(), nil
}

// Two threads checking the same merkle tree can race, and the winner might put down a root that
// comes after the loser. So we adopt a different race-free strategy:
//
//  1. Write down the current root at the start the server operation.
//  2. Do the server operation.
//  3. Assert that the merkle root is later than the root at the start.
//  4. Check the root against the new known latest merkle root. That could be either behdind or
//     in front of the root we just got back from the server, due to races.
//  5. Write down the root we just got either way to the local database. If it's the latest epno
//     we've seen, then bump the DB pointer to it.
type Session struct {
	rootAtStart *openedRoot
	isInit      bool
	ci          ClientInterface
}

func NewSession(ci ClientInterface) *Session {
	return &Session{ci: ci}
}

func (s *Session) HostID() proto.HostID { return s.ci.HostID() }

func (s *Session) loadLatestKnownRoot(ctx context.Context) (*openedRoot, error) {

	existing, err := s.ci.GetLatestRootFromCache(ctx)
	// Simple base case, early-out
	if _, ok := err.(core.MerkleNoRootError); ok || existing == nil {
		return nil, nil

	}
	if err != nil {
		return nil, err
	}
	ret, err := openRoot(existing)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *Session) Init(ctx context.Context) error {
	root, err := s.loadLatestKnownRoot(ctx)
	if err != nil {
		return err
	}
	s.rootAtStart = root
	s.isInit = true
	return nil
}

func (s *Session) InitWithRoot(ctx context.Context, mr *proto.MerkleRoot) error {
	root, err := openRoot(mr)
	if err != nil {
		return err
	}
	s.rootAtStart = root
	s.isInit = true
	return nil
}

func (s *Session) CheckHistoricalRoot(ctx context.Context, root *proto.MerkleRoot) error {
	oRoot, err := openRoot(root)
	if err != nil {
		return err
	}
	if oRoot.Epno() > s.rootAtStart.Epno() {
		return core.MerkleVerifyError("historical root was newer than the root we just got!")
	}
	if oRoot.Epno() == s.rootAtStart.Epno() {
		if !oRoot.h.Eq(&s.rootAtStart.h) {
			return core.MerkleVerifyError("historical root hash mismatch")
		}
		return nil
	}
	return s.checkSkipPointersFromAtoB(ctx, s.rootAtStart, oRoot)
}

func (s *Session) Run(ctx context.Context, latest *proto.MerkleRoot) error {

	if !s.isInit {
		return core.InternalError("must call Init() before Run()")
	}

	oLatest, err := openRoot(latest)
	if err != nil {
		return err
	}

	storeLatest := func(l *openedRoot) error {

		err := s.ci.Store(ctx, l.Epno(), &l.h, l.r, true)
		return err
	}

	existing, err := s.loadLatestKnownRoot(ctx)
	if err != nil {
		return err
	}

	// If we have no root, then we can just store the latest root and be done.
	if existing == nil {
		if s.rootAtStart != nil {
			return core.InternalError("merkle root was non-nil then nil!")
		}
		return storeLatest(oLatest)
	}

	if s.rootAtStart != nil && s.rootAtStart.Epno() > existing.Epno() {
		return core.InternalError("merkle root at start is newer than latest known root")
	}

	if s.rootAtStart != nil && s.rootAtStart.Epno() > oLatest.Epno() {
		return core.MerkleRollbackError{Have: s.rootAtStart.Epno(), Saw: oLatest.Epno()}
	}

	if oLatest.Epno() == existing.Epno() {
		if !oLatest.h.Eq(&existing.h) {
			return core.MerkleVerifyError(fmt.Sprintf("hash mismatch at epno %d", oLatest.Epno()))
		}
		return nil
	}

	right := oLatest
	left := existing
	// In the case of a race, where a fast Get raced a slow, the fast one will write down a
	// merkle root that is newer than what the server appears to return. That is fine, so long
	// as it's newer than the root at the start of the query (rootAtStart).
	if oLatest.Epno() < existing.Epno() {
		right = existing
		left = oLatest
	}

	// common case: check that the most recent root we have is pointed to by the one returned
	// by the server.
	err = s.checkSkipPointersFromAtoB(ctx, right, left)
	if err != nil {
		return err
	}
	return storeLatest(oLatest)
}

func (s *Session) checkSkipPointersFromAtoB(
	ctx context.Context,
	right *openedRoot,
	left *openedRoot,
) error {

	if right.Epno() <= left.Epno() {
		return core.InternalError("right epno is less than or equal to left epno")
	}

	allRootsMap := make(map[proto.MerkleEpno]*proto.MerkleRoot)
	allRootHashesMap := make(map[proto.MerkleEpno]*proto.MerkleRootHash)
	neededHashes := []proto.MerkleEpno{}
	neededRoots := []proto.MerkleEpno{}

	roots, hashes := MerkleCollectRoots(right.Epno(), left.Epno())

	// No need to rerequest what we just got, so load these in and don't rerequest them
	allRootsMap[right.Epno()] = right.r
	allRootsMap[left.Epno()] = left.r

	for _, epno := range roots {

		if allRootsMap[epno] != nil {
			continue
		}

		root, err := s.ci.GetRootFromCache(ctx, epno)
		if err != nil {
			return err
		}
		if root != nil {
			allRootsMap[epno] = root
		} else {
			neededRoots = append(neededRoots, epno)
		}
	}

	for _, epno := range hashes {
		hash, err := getRootHashFromCache(ctx, s.ci, epno)
		if err != nil {
			return err
		}
		if hash != nil {
			allRootHashesMap[epno] = hash
		} else {
			neededHashes = append(neededHashes, epno)
		}
	}

	var newRoots []proto.MerkleRoot
	var newHashes []proto.MerkleRootHash
	if len(neededHashes) > 0 || len(neededRoots) > 0 {
		var err error
		newRoots, newHashes, err = s.ci.GetRootsFromServer(ctx, neededRoots, neededHashes)
		if err != nil {
			return err
		}
	}

	for i, root := range newRoots {
		epno := neededRoots[i]
		tmp := root
		allRootsMap[epno] = &tmp
		hash, err := s.ci.GetRootHashFromCache(ctx, epno)
		if err != nil {
			return err
		}
		if hash != nil {
			var computed proto.MerkleRootHash
			err := HashRoot(&root, &computed)
			if err != nil {
				return err
			}
			if !computed.Eq(hash) {
				return core.MerkleBackPointerVerifyError{Msg: "cached merkle root hash isn't equal to root we just got", Epno: epno}
			}
		}
	}

	for i, hash := range newHashes {
		tmp := hash
		allRootHashesMap[neededHashes[i]] = &tmp
	}

	findBackPointer := func(backPointerSet proto.MerkleBackPointers, epno proto.MerkleEpno) *proto.MerkleRootHash {
		for _, e := range backPointerSet {
			if e.Epno == epno {
				return &e.Hash
			}
		}
		return nil
	}

	checkRootAgainstBackPointers := func(backPointerSet proto.MerkleBackPointers, epno proto.MerkleEpno, root *proto.MerkleRoot) error {
		if len(backPointerSet) == 0 {
			return nil
		}
		bp := findBackPointer(backPointerSet, epno)
		if bp == nil {
			return core.MerkleBackPointerVerifyError{Epno: epno, Msg: "missing backpointer"}
		}
		var rootHash proto.MerkleRootHash
		err := HashRoot(root, &rootHash)
		if err != nil {
			return err
		}
		if !rootHash.Eq(bp) {
			return core.MerkleBackPointerVerifyError{Msg: "backpointer mismatc", Epno: epno}
		}
		return nil
	}

	var backPointerSet proto.MerkleBackPointers
	for _, rootEpno := range roots {
		root := allRootsMap[rootEpno]
		if root == nil {
			return core.MerkleBackPointerVerifyError{Epno: rootEpno, Msg: "missing root"}
		}

		// First time through we don't check anything. Back pointer set is going to be empty since
		// nothing is presumabl back-pointing to the most current root.
		err := checkRootAgainstBackPointers(backPointerSet, rootEpno, root)
		if err != nil {
			return err
		}

		oRoot, err := openRoot(root)
		if err != nil {
			return err
		}
		if oRoot.Epno() != rootEpno {
			return core.MerkleBackPointerVerifyError{Msg: "got mismatched root", Epno: oRoot.Epno()}
		}
		var expectedBackPointerHash *proto.MerkleBackPointerHash
		expectedBackPointerHash, backPointerSet, err = computeBackPointers(rootEpno, allRootHashesMap, allRootsMap)
		if err != nil {
			return err
		}
		if !oRoot.v1.BackPointers.Eq(expectedBackPointerHash) {
			return core.MerkleBackPointerVerifyError{Epno: rootEpno, Msg: "bad backpointer hash"}
		}
	}

	err := checkRootAgainstBackPointers(backPointerSet, left.Epno(), left.r)
	if err != nil {
		return err
	}

	for i, root := range newRoots {
		epno := neededRoots[i]
		if epno != right.Epno() {
			err := s.ci.Store(ctx, epno, allRootHashesMap[epno], &root, false)
			if err != nil {
				return err
			}
		}
	}

	for i, hash := range newHashes {
		epno := neededHashes[i]
		if epno != right.Epno() {
			err := s.ci.Store(ctx, epno, &hash, nil, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
