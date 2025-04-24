// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func findKey(state *proto.HostchainState, typ proto.EntityType) *proto.KeyAtSeqno {
	for i := len(state.Keys) - 1; i >= 0; i-- {
		k := state.Keys[i]
		if k.Eid.Type() == typ {
			return &k
		}
	}
	return nil
}

func findCert(state *proto.HostchainState) *proto.HostTLSCAAtSeqno {
	for i := len(state.Cas) - 1; i >= 0; i -= 1 {
		k := state.Cas[i]
		return &k
	}
	return nil
}

func initHostchainTest(t *testing.T) (
	m shared.MetaContext,
	dir core.Path,
	hk *shared.HostChain,
	cleanup func(),
) {
	m = testMetaContext()
	dir, err := core.MkdirTemp("hostkeys")
	require.NoError(t, err)
	vhid, err := proto.RandomID16er[proto.VHostID]()
	require.NoError(t, err)
	hk = shared.NewHostChain().WithVHostID(*vhid)

	// NOTE! We're making a second host that's going to play against the same
	// services as the first. This means we have a *virtual host* situation,
	// and we have to set up the relationship properly, otherwise, we'll get
	// security failures below. The hostname of the vhost is throwaway
	// here so just specify whatever.
	rd, err := core.RandomDomain()
	require.NoError(t, err)
	hk = hk.WithParentVanity(m.G().HostChain(), proto.Hostname(rd))

	err = hk.Forge(m, dir)
	require.NoError(t, err)

	cleanup = func() {
		_ = dir.RemoveAll()
	}
	return m, dir, hk, cleanup
}

func TestNewHostchain(t *testing.T) {
	m, dir, hk, cleanup := initHostchainTest(t)
	defer cleanup()

	var err error

	links := hk.Links()
	require.Equal(t, 1, len(links))

	hc := core.NewHostchain()
	hc, err = hc.Play(links[0])
	require.NoError(t, err)
	exp, err := hc.Export()
	require.NoError(t, err)
	require.Equal(t, proto.Seqno(1), exp.Seqno)
	require.Equal(t, 3, len(exp.Keys))
	require.False(t, exp.Host.IsZero())

	msk := findKey(&exp, proto.EntityType_HostMerkleSigner)
	require.NotNil(t, msk)
	err = hk.Revoke(m, []proto.EntityID{msk.Eid})
	require.NoError(t, err)
	links = hk.Links()
	require.Equal(t, 2, len(links))

	// Now make sure that we can play this update on the client-side.
	// Process the revoke and make sure that our state is updated.
	hc, err = hc.Play(links[1])
	require.NoError(t, err)
	exp, err = hc.Export()
	require.NoError(t, err)
	msk = findKey(&exp, proto.EntityType_HostMerkleSigner)
	require.Nil(t, msk)
	require.Equal(t, proto.Seqno(2), exp.Seqno)
	require.Equal(t, 2, len(exp.Keys))
	require.False(t, exp.Host.IsZero())

	// Now rotate the MetadataUpdate key
	typ := proto.EntityType_HostMetadataSigner
	mdsk := findKey(&exp, typ)
	require.NotNil(t, mdsk)
	fn := dir.JoinStrings("host.mds2.key")
	err = hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links = hk.Links()
	require.Equal(t, 3, len(links))
	hc, err = hc.Play(links[2])
	require.NoError(t, err)
	exp, err = hc.Export()
	require.NoError(t, err)
	mdskNew := findKey(&exp, typ)
	require.NotNil(t, mdskNew)
	require.Equal(t, proto.Seqno(3), exp.Seqno)
	require.Equal(t, 3, len(exp.Keys))
	require.False(t, exp.Host.IsZero())
	require.False(t, mdskNew.Eid.Eq(mdsk.Eid))

	// Now rotate the host key
	typ = proto.EntityType_Host
	oldHostKey := findKey(&exp, typ)
	require.NotNil(t, oldHostKey)
	fn = dir.JoinStrings("host2.key")
	err = hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links = hk.Links()
	require.Equal(t, 4, len(links))
	hc, err = hc.Play(links[3])
	require.NoError(t, err)
	exp, err = hc.Export()
	require.NoError(t, err)
	newHostKey := findKey(&exp, typ)
	require.NotNil(t, newHostKey)
	require.Equal(t, proto.Seqno(4), exp.Seqno)
	require.Equal(t, 4, len(exp.Keys))
	require.False(t, exp.Host.IsZero())
	require.False(t, oldHostKey.Eid.Eq(newHostKey.Eid))

	// now revoke the TLSCA
	tlsca := findCert(&exp)
	require.NotNil(t, tlsca)
	eid := tlsca.Ca.Id.EntityID()
	err = hk.Revoke(m, []proto.EntityID{eid})
	require.NoError(t, err)
	links = hk.Links()
	require.Equal(t, 5, len(links))
	hc, err = hc.Play(links[4])
	require.NoError(t, err)

	// now revoke the original host key, to make sure we can properly rotate them.
	oldHostEid := oldHostKey.Eid
	err = hk.Revoke(m, []proto.EntityID{oldHostEid})
	require.NoError(t, err)
	links = hk.Links()
	require.Equal(t, 6, len(links))
	hc, err = hc.Play(links[5])
	require.NoError(t, err)

	// new make sure that we can still sign updates even though we have a revoked eldest key (should be able to
	// sign no problem with the new key).
	fn = dir.JoinStrings("host.tlsca2.key")
	typ = proto.EntityType_HostTLSCA
	err = hk.NewKey(m, fn, typ)
	require.NoError(t, err)
	links = hk.Links()
	require.Equal(t, 7, len(links))
	hc, err = hc.Play(links[6])
	require.NoError(t, err)
}

func TestEvilHostchainFakeHostKey(t *testing.T) {
	m, dir, hk, cleanup := initHostchainTest(t)
	defer cleanup()

	fn := dir.JoinStrings("fake.key")
	fake, err := shared.NewHostKeyGenerate(m.Ctx(), fn, proto.EntityType_Host)
	require.NoError(t, err)
	feid, err := fake.EntityID()
	require.NoError(t, err)
	fhid, err := feid.ToHostID()
	require.NoError(t, err)
	et := shared.EvilHostChainTester{
		MutateLink: func(ch *proto.HostchainChange) {
			ch.Signer = fhid
		},
		MutateSigners: func(signers []core.Signer) []core.Signer {
			// remove the last signer
			signers = signers[0 : len(signers)-1]
			signers = append(signers, fake)
			return signers
		},
	}
	hk = hk.WithEvilTester(&et)
	fn = dir.JoinStrings("host2.key")
	typ := proto.EntityType_Host
	err = hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links := hk.Links()
	require.Equal(t, 2, len(links))
	hc := core.NewHostchain()
	hc, err = hc.Play(links[0])
	require.NoError(t, err)
	_, err = hc.Play(links[1])
	require.Error(t, err)
	require.Equal(t, core.HostchainError("existing host signing key not found"), err)
}

func TestEvilHostchainBadChainerHash(t *testing.T) {
	m, dir, hk, cleanup := initHostchainTest(t)
	defer cleanup()

	er := shared.EvilHostChainTester{
		MutateLink: func(ch *proto.HostchainChange) {
			ch.Chainer.Prev[4] ^= 0x4
		},
	}
	hk = hk.WithEvilTester(&er)
	fn := dir.JoinStrings("host2.key")
	typ := proto.EntityType_Host
	err := hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links := hk.Links()
	require.Equal(t, 2, len(links))
	hc := core.NewHostchain()
	hc, err = hc.Play(links[0])
	require.NoError(t, err)
	_, err = hc.Play(links[1])
	require.Error(t, err)
	require.Equal(t, core.HostchainError("prev did not match tail"), err)
}

func TestEvilHostchainBadChainerSeqno(t *testing.T) {
	m, dir, hk, cleanup := initHostchainTest(t)
	defer cleanup()

	er := shared.EvilHostChainTester{
		MutateLink: func(ch *proto.HostchainChange) {
			ch.Chainer.Seqno += 1
		},
	}
	hk = hk.WithEvilTester(&er)
	fn := dir.JoinStrings("host2.key")
	typ := proto.EntityType_Host
	err := hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links := hk.Links()
	require.Equal(t, 2, len(links))
	hc := core.NewHostchain()
	hc, err = hc.Play(links[0])
	require.NoError(t, err)
	_, err = hc.Play(links[1])
	require.Error(t, err)
	require.Equal(t, core.HostchainError("seqno must be exactly 1 greater than previous"), err)
}

func TestEvilHostchainUseRevoked(t *testing.T) {
	m, dir, hk, cleanup := initHostchainTest(t)
	defer cleanup()

	fn := dir.JoinStrings("host2.key")
	typ := proto.EntityType_Host
	err := hk.NewKey(m, fn, typ)
	require.NoError(t, err)
	newk := hk.Key(typ)
	require.NotNil(t, newk)
	eid, err := newk.EntityID()
	require.NoError(t, err)
	fhid, err := eid.ToHostID()
	require.NoError(t, err)

	// now revoke the key
	err = hk.Revoke(m, []proto.EntityID{*eid})
	require.NoError(t, err)

	fn = dir.JoinStrings("host3.key")
	er := shared.EvilHostChainTester{
		MutateLink: func(ch *proto.HostchainChange) {
			ch.Signer = fhid
		},
		MutateSigners: func(signers []core.Signer) []core.Signer {
			// remove the last signer
			signers = signers[0 : len(signers)-1]
			signers = append(signers, newk)
			return signers
		},
	}
	hk = hk.WithEvilTester(&er)

	// now try to use the revoked key
	err = hk.NewKey(m, fn, typ)
	require.NoError(t, err)

	links := hk.Links()
	require.Equal(t, 4, len(links))
	hc := core.NewHostchain()
	for i := 0; i < 3; i++ {
		hc, err = hc.Play(links[i])
		require.NoError(t, err)
	}
	_, err = hc.Play(links[3])
	require.Error(t, err)
	require.Equal(t, core.HostchainError("revoked key used"), err)
}

func TestPublicZone(t *testing.T) {
	m := testMetaContext()
	hkc := m.G().HostChain()
	key := hkc.Key(proto.EntityType_HostMetadataSigner)
	require.NotNil(t, key)
	err := shared.StorePublicZone(m, *key)
	require.NoError(t, err)
	z, err := shared.LoadPublicZone(m)
	require.NoError(t, err)
	var pz proto.PublicZone
	err = core.DecodeFromBytes(&pz, z.Inner)
	require.NoError(t, err)

	require.NotEqual(t, 0, len(pz.Services.MerkleQuery))
	require.NotEqual(t, 0, len(pz.Services.Reg))
	require.NotEqual(t, 0, len(pz.Services.User))
}
