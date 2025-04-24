// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"sort"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func MerkleBackpointerSequence(e proto.MerkleEpno) []proto.MerkleEpno {
	cursor := proto.MerkleEpno(1)
	var ret []proto.MerkleEpno
	switch e {
	case proto.MerkleEpno(1), proto.MerkleEpno(0):
		return nil
	case proto.MerkleEpno(2):
		return []proto.MerkleEpno{1}
	case proto.MerkleEpno(3):
		return []proto.MerkleEpno{2, 1}
	case proto.MerkleEpno(4):
		return []proto.MerkleEpno{3, 2, 1}
	}
	for (e - cursor).IsValid() {
		ptr := e - cursor
		ret = append(ret, ptr)
		if (e & cursor) != 0 {
			break
		}
		cursor <<= 1
	}
	return ret
}

// Starting at start, and ending at finish, where start > end, output all of the
// roots in all of the nodes traversed, so that we can reconstruct the needed
// skip pointer hashes. The output here is log(x) * log(x) where x is the size
// of the start pointer. It's possible to generate the path in log(x) *
// log(log(x)) using binary search, but we still need to generate a list of all
// the sibbling pointers, so it's not worth it.
func MerkleCollectRoots(start, end proto.MerkleEpno) ([]proto.MerkleEpno, []proto.MerkleEpno) {

	path := []proto.MerkleEpno{}
	allRootsSet := make(map[proto.MerkleEpno]struct{})
	allSiblingsSet := make(map[proto.MerkleEpno]struct{})

	for start > end {
		path = append(path, start)
		allRootsSet[start] = struct{}{}
		seq := MerkleBackpointerSequence(start)
		for _, curr := range seq {
			if curr >= end {
				start = curr
			}
			if _, found := allRootsSet[curr]; !found {
				allSiblingsSet[curr] = struct{}{}
			}
		}
	}

	allSiblings := make([]proto.MerkleEpno, len(allSiblingsSet))
	i := 0
	for root := range allSiblingsSet {
		allSiblings[i] = root
		i++
	}

	sort.Slice(allSiblings, func(i, j int) bool { return allSiblings[i] > allSiblings[j] })

	return path, allSiblings
}

func KeyHash(out *proto.MerkleTreeRFOutput, inp proto.MerkleTreeRFInput) error {
	err := core.PrefixedHashInto(&inp, (*out)[:])
	if err != nil {
		return err
	}
	return nil
}

func NameToEntityID(
	p proto.Name,
	hostId proto.HostID,
) (proto.EntityID, error) {
	pi := proto.NameHashPreimage{
		Name:   p.Normalize(),
		HostId: hostId,
	}
	var s proto.StdHash
	err := core.PrefixedHashInto(&pi, s[:])
	if err != nil {
		return nil, err
	}
	ret, err := proto.EntityType_Name.MakeEntityID(s.Bytes())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func HashName(eid proto.EntityID, seqno proto.NameSeqno) (*proto.MerkleTreeRFOutput, error) {
	inp := proto.MerkleTreeRFInput{
		Seqno:    proto.Seqno(seqno),
		Entity:   eid,
		Ct:       proto.ChainType_Name,
		Location: nil,
	}
	var key proto.MerkleTreeRFOutput
	err := KeyHash(&key, inp)
	if err != nil {
		return nil, err
	}
	return &key, nil
}
