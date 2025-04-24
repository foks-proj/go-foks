// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func InitTree(m MetaContext, storage StorageWriter) error {

	// And empty leaf has a 0 hash and a 0 value
	nilLeaf := proto.MerkleLeaf{}

	if !nilLeaf.Key.IsZero() || !nilLeaf.Value.IsZero() {
		return core.MerkleInitError("need zero-hashes for key and value for first node")
	}

	node := proto.NewMerkleNodeWithLeaf(nilLeaf)
	var hash proto.MerkleNodeHash
	err := HashNode(&node, &hash)
	if err != nil {
		return err
	}

	var bkp proto.MerkleBackPointers
	var bkpHash proto.MerkleBackPointerHash
	err = HashBackPointers(&bkp, &bkpHash)
	if err != nil {
		return err
	}

	r1 := proto.MerkleRootV1{
		Epno:         proto.MerkleEpnoFirst,
		Time:         proto.Now(),
		RootNode:     hash,
		BackPointers: bkpHash,
	}
	root := proto.NewMerkleRootWithV1(r1)
	var rootHash proto.MerkleRootHash
	err = HashRoot(&root, &rootHash)
	if err != nil {
		return err
	}
	raw, err := core.EncodeToBytes(&root)
	if err != nil {
		return err
	}

	phash := PrefixedHash{
		Typ:  proto.MerkleNodeType_Leaf,
		Hash: &hash,
	}

	err = storage.RunRetryTx(
		m,
		"init tree",
		func(m MetaContext, tx StorageTransactor) error {
			noRoot, err := tx.SelectRootForTraversal(m, false, nil)
			if !errors.Is(err, core.MerkleNoRootError{}) || noRoot != nil {
				return core.MerkleInitError("tree already initialized")
			}
			ph := PrefixedHash{
				Typ:  proto.MerkleNodeType_Leaf,
				Hash: &hash,
			}

			// The nil leaf might already exist if this is the second
			// instance of a merkle host on this DB, etc.
			_, err = tx.SelectLeaf(m, &ph)
			if err != nil && errors.Is(err, core.MerkleLeafNotFoundError{}) {
				err = tx.InsertLeaf(m, hash, nilLeaf.Key, nilLeaf.Value, r1.Epno)
				if err != nil {
					return err
				}
			}

			err = tx.InsertRoot(m, r1.Epno, r1.Time, rootHash, raw, &phash, nil)
			if err != nil {
				return err
			}
			return nil
		},
	)

	if err != nil {
		return err
	}

	return nil
}
