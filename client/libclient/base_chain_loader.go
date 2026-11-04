// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type ChainLoaderTesting struct {
	SkipMerkleLeafValueCheck bool
	SkipPrevCheck            bool
	SkipMerklePathCheck      bool
	SkipExistingLoad         bool
}

type BaseChainLoader struct {
	linkHashes   [](*proto.LinkHash)
	lastHash     *proto.LinkHash
	merkleLeaves []proto.MerkleLeaf
	fatalError   error
	testing      *ChainLoaderTesting
}

func (u *BaseChainLoader) queueFatalError(err error) {
	if err != nil && u.fatalError == nil {
		u.fatalError = err
	}
}

func (u *BaseChainLoader) SetTesting(t *ChainLoaderTesting) {
	u.testing = t
}

func (u *BaseChainLoader) MerkleKey(i proto.Seqno) *proto.MerkleTreeRFOutput {
	if int(i) >= len(u.merkleLeaves) {
		return nil
	}
	return &u.merkleLeaves[i].Key
}

func (b *BaseChainLoader) checkChain(
	m MetaContext,
	prev *proto.LinkHash,
	seqno proto.Seqno,
	links []proto.LinkOuter,
	chainerAtIndex func(n int) *proto.HidingChainer,
	which string,
	testing *ChainLoaderTesting,
) error {

	for i, link := range links {
		ch := chainerAtIndex(i)
		if ch == nil {
			// Should never happen
			return ChainLoaderGenericError("chainerAtIndex returned nil")
		}
		found := ch.Base.Seqno
		if found != seqno {
			return core.ChainLoaderError{
				Race: true,
				Err: core.CLBadSeqnoError{
					Which:    which,
					Expected: seqno,
					Actual:   found,
				},
			}
		}

		hsh, err := core.LinkHash(&link)
		if err != nil {
			return err
		}
		lpp := ch.Base.Prev
		b.linkHashes = append(b.linkHashes, hsh)

		if ((lpp == nil) != (prev == nil)) || (lpp != nil && !lpp.Eq(*prev)) {

			err := core.ChainLoaderError{
				Err: core.CLBadPrevError{
					Seqno:    seqno,
					Expected: prev,
					Actual:   lpp,
				},
			}

			if testing != nil && testing.SkipPrevCheck {
				b.queueFatalError(err)
			} else {
				return err
			}
		}

		if seqno.IsEldest() != (prev == nil) {
			// This case is largely covered by the above case, so we likely can't
			// trigger this error. Still, leave it in just to be sure.
			return ChainLoaderGenericError("prev==nil iff seqno==1")
		}
		prev = hsh
		seqno++
	}

	// We'll write this to disk for the next load, it will be loaded
	// is as the initial prev.
	b.lastHash = prev

	return nil
}

func (b *BaseChainLoader) checkMerklePaths(
	m MetaContext,
	eid proto.EntityID,
	typ proto.ChainType,
	locations []proto.TreeLocation,
	links []proto.LinkOuter,
	chainerAtIndex func(n int) *proto.HidingChainer,
	merklePaths proto.MerklePathsCompressed,
	ntlc *proto.TreeLocationCommitment,
	seqno proto.Seqno,
	loc0 *proto.TreeLocation, // for some chains, the 0ths tree location is set by another chain
	offset int,
	which string,
	testing *ChainLoaderTesting,
) error {

	// The first few are username links, the rest are UID
	// links.
	paths := merklePaths.Paths[offset:]
	l := len(paths)

	if l != len(links)+1 {
		return core.ChainLoaderError{
			Err: core.CLBadCountError{
				Which:    "merkle-paths",
				Expected: len(links) + 1,
				Actual:   l,
			},
		}
	}

	neededLocations := l
	if ntlc == nil {
		neededLocations--
	}

	if neededLocations != len(locations) {
		return core.ChainLoaderError{
			Err: core.CLBadCountError{
				Which:    "locations",
				Expected: neededLocations,
				Actual:   len(locations),
			},
		}
	}

	locIndex := 0
	for i := 0; i < l; i++ {

		inp := proto.MerkleTreeRFInput{
			Seqno:  seqno,
			Entity: eid,
			Ct:     typ,
		}

		switch {
		case ntlc != nil:
			loc := locations[locIndex]
			locIndex++
			err := core.VerifyTreeLocationCommitment(loc, *ntlc)
			if err != nil {
				return core.ChainLoaderError{
					Err: core.CLBadTreeLocationError{
						Err:   err,
						Seqno: seqno,
					},
				}
			}
			inp.Location = &loc
		case loc0 != nil:
			// commitment on loc0 is computed slightly differently, so do that in the caller.
			inp.Location = loc0
		case typ.IsPartyType() && seqno.IsEldest():
			// noop, this is fine
		default:
			// this error should not be possible
			return core.InternalError("unexpected nil value for next tree location commitment")
		}

		var key proto.MerkleTreeRFOutput
		err := merkle.KeyHash(&key, inp)
		if err != nil {
			return err
		}
		last := (i == l-1)

		// Need to add back in the username offset here
		pathTriple := merklePaths.Select(i + offset)
		leaf, err := merkle.Verify(&pathTriple, &key, !last)
		if err != nil {
			return core.ChainLoaderError{
				Race: true,
				Err: core.CLBadMerklePathError{
					Err:   err,
					Which: which,
					Seqno: seqno,
				},
			}
		}

		if last {
			continue
		}

		ch := chainerAtIndex(i)
		if ch == nil {
			// Should never happen
			return core.InternalError("chainerAtIndex returned nil")
		}

		ntlc = &ch.NextLocationCommitment
		if leaf == nil {
			return core.InternalError("unexpected nil leaf")
		}

		if !leaf.Eq(b.linkHashes[i].ToStdHash()) {
			err := core.ChainLoaderError{
				Err: core.CLBadMerkleLeafValueError{
					Which: which,
					Seqno: seqno,
				},
			}
			if testing != nil && testing.SkipMerkleLeafValueCheck {
				b.queueFatalError(err)
			} else {
				return err
			}
		}

		// Hold onto these to ensure propoer ordering between two different chains.
		b.merkleLeaves = append(b.merkleLeaves, proto.MerkleLeaf{Key: key, Value: *leaf})

		seqno++
	}
	return nil
}

func (b *BaseChainLoader) runMany(m MetaContext, runOnce func(m MetaContext) error, resetState func()) error {
	var err error

	params, err := m.G().MerkleRaceConfig()
	if err != nil {
		return err
	}

	n := params.Cfg.NumRetries
	wait := params.Cfg.Wait

	for i := 0; true; i++ {

		err = runOnce(m)
		if err == nil || i >= n {
			return err
		}

		if clerr, ok := err.(core.ChainLoaderError); !ok || !clerr.Race {
			return err
		}
		m.Warnw("BaseChainLoader::Run",
			"retry", "merkle race",
			"err", err.Error(),
			"wait", wait,
			"iter", i,
		)
		if resetState != nil {
			resetState()
		}

		// If an Eracer is present (likely during a test), we'll synchronously wait for it before
		// moving on to the next iteration. Otherwise, we'll just do a regular timed backoff.
		if params.Eracer != nil {
			err := params.Eracer(m.Ctx(), err)
			if err != nil {
				return err
			}
		} else {
			// Never wait past the caller's deadline. A plain sleep kept a
			// bounded caller (an app cold start restoring its user) stuck for
			// the rest of the backoff after its deadline had passed. The
			// context error is a transport error, so the caller's offline
			// fallbacks take over instead of seeing a retry-exhausted race.
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-m.Ctx().Done():
				timer.Stop()
				return m.Ctx().Err()
			}
			wait *= 2
		}
	}
	panic("unreachable")
}

func (b *BaseChainLoader) checkNameLoad(
	m MetaContext,
	party proto.PartyID,
	hostId proto.HostID,
	commitments []proto.Commitment,
	names []rem.NameCommitmentAndKey,
	existing *proto.NameAndSeqnoBundle,
	proposed proto.NameUtf8,
	numNamePathsSupplied int,
	paths proto.MerklePathsCompressed,
) (
	proto.NameSeqno,
	error,
) {
	var ret proto.NameSeqno // last seqno we verified
	if len(commitments) != len(names) {
		return ret, core.ChainLoaderError{
			Err: core.CLBadCountError{
				Which:    "names",
				Expected: len(commitments),
				Actual:   len(names),
			},
		}
	}

	// First check all the username commitments. The sigchain has the commitment,
	// the server supplies the random key and the preimage.
	var last *rem.NameCommitment
	for i, unc := range commitments {
		un := names[i]
		err := core.OpenCommitment(&un.Unc, &un.Key, &unc)
		if err != nil {
			return ret, core.ChainLoaderError{
				Err: core.ULOpenCommitmentError{
					Which: "username",
					Idx:   i,
					Err:   err,
				},
			}
		}
		last = &un.Unc
	}

	nn, err := core.NormalizeName(proposed)
	if err != nil {
		return ret, core.ChainLoaderError{Err: err}
	}

	// We need a username merkle check if either it's a first time load, or it's an
	// existing load by the normalize userrname doesn't match what we previously had.
	needUsernameMerkleCheck := (existing == nil || (existing.B.Name != nn))

	if last == nil && needUsernameMerkleCheck {
		return ret, core.LinkError("no username commitment found in chain, and one was needed")
	}

	if last != nil && last.Name != nn {
		return ret, ChainLoaderGenericError("username commitment does not match supplied username")
	}

	seqno := proto.FirstNameSeqno
	if !needUsernameMerkleCheck {
		seqno = existing.S + 1
	}

	neid, err := merkle.NameToEntityID(nn, hostId)
	if err != nil {
		return ret, err
	}

	if numNamePathsSupplied == 0 {
		return ret, ChainLoaderGenericError("need at least one username link to prove absense of updates")
	}
	if needUsernameMerkleCheck && numNamePathsSupplied < 2 {
		return ret, ChainLoaderGenericError("need at least two username links to establish a username")
	}

	// If no new links, then just using the existing seqno, and return after we
	// verify no further links.
	if existing != nil {
		ret = existing.S
	}

	for i := 0; i < numNamePathsSupplied; i++ {

		// The last time through we verify absense, not presense
		last := (i == numNamePathsSupplied-1)

		// The pennultimate time through we verify the leaf value matches our UID. Prior
		// to that we verify the path but do not verify the leaf.
		penultimate := (i == numNamePathsSupplied-2)

		h, err := merkle.HashName(neid, seqno)
		if err != nil {
			return ret, err
		}
		pathTriple := paths.Select(i)
		leaf, err := merkle.Verify(&pathTriple, h, !last)

		if err != nil {
			err = core.ChainLoaderError{
				Err: core.CLBadMerklePathError{
					Seqno: proto.Seqno(i),
					Which: "username",
					Err:   err,
				},
			}
			if b.testing != nil && b.testing.SkipMerklePathCheck {
				// We'd love to test the leaf check just below, so
				// need to, in test, buffer this error, and charge forward.
				// But we also need the leaf that merkle.Verify won't return
				// because it errored.
				b.queueFatalError(err)
				typ, err := pathTriple.Terminal.GetLeaf()
				if err == nil && typ {
					tmp := pathTriple.Terminal.True().Leaf
					leaf = &tmp
				}
			} else {
				return ret, err
			}
		}

		if last {
			continue
		}

		if leaf == nil {
			return ret, core.InternalError("expected a leaf at end of username path")
		}

		// set to the last seqno we got and verified.
		ret = seqno

		if !penultimate {
			continue
		}

		v := rem.NewEntityIDMerkleValueWithV1(party.EntityID())
		ph, err := core.PrefixedHash(&v)
		if err != nil {
			return ret, err
		}
		if !ph.Eq(*leaf) {
			return ret, core.ChainLoaderError{
				Err: core.CLBadMerkleLeafValueError{
					Seqno: proto.Seqno(i),
					Which: "username",
				},
			}
		}
		seqno++
	}

	return ret, nil
}
