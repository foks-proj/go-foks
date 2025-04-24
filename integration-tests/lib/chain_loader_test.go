// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func getCurrentTreeRoot(t *testing.T, m shared.MetaContext) proto.TreeRoot {
	return getCurrentTreeRootWithHostID(t, m, nil)
}

func getCurrentTreeRootWithHostID(t *testing.T, m shared.MetaContext, hid *proto.HostID) proto.TreeRoot {
	mcli, err := m.MerkleCli()
	require.NoError(t, err)
	root, err := mcli.GetCurrentRoot(m.Ctx(), hid)
	require.NoError(t, err)
	var hsh proto.MerkleRootHash
	err = merkle.HashRoot(&root, &hsh)
	require.NoError(t, err)
	v, err := root.GetV()
	require.NoError(t, err)
	require.Equal(t, v, proto.MerkleRootVersion_V1)
	return proto.TreeRoot{
		Epno: root.V1().Epno,
		Hash: hsh,
	}
}

func getCurrentSignedTreeRoot(t *testing.T, m shared.MetaContext) proto.TreeRoot {
	return getCurrentSignedTreeRootWithHostID(t, m, nil)
}

func getCurrentSignedTreeRootWithHostID(t *testing.T, m shared.MetaContext, hid *proto.HostID) proto.TreeRoot {
	mcli, err := m.MerkleCli()
	require.NoError(t, err)
	res, err := mcli.GetCurrentRootSigned(m.Ctx(), hid)
	require.NoError(t, err)
	mr, err := res.Inner.AllocAndDecode(core.DecoderFactory{})
	require.NoError(t, err)
	var hsh proto.MerkleRootHash
	err = merkle.HashRoot(mr, &hsh)
	require.NoError(t, err)
	v, err := mr.GetV()
	require.NoError(t, err)
	require.Equal(t, v, proto.MerkleRootVersion_V1)
	return proto.TreeRoot{
		Epno: mr.V1().Epno,
		Hash: hsh,
	}
}

func (u *TestUser) makeSettingsLink(
	t *testing.T,
	m shared.MetaContext,
	dev core.PrivateSuiter,
	gen proto.PassphraseGeneration,
	salt *proto.PassphraseSalt,
) *core.MakeLinkRes {
	seqno := proto.ChainEldestSeqno
	var prev *proto.LinkHash
	if u.uscl != nil {
		seqno = u.uscl.seqno + 1
		prev = &u.uscl.hash
	}
	tmp, _ := makeSettingsLink(
		t, m, u, seqno, prev, dev, gen, salt,
	)
	var ret proto.LinkHash
	err := core.LinkHashInto(tmp.Link, ret[:])
	require.NoError(t, err)
	u.uscl = &userSettingsChainTail{
		seqno: seqno,
		hash:  ret,
	}
	return tmp
}

func makeSettingsLink(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	dev core.PrivateSuiter,
	gen proto.PassphraseGeneration,
	salt *proto.PassphraseSalt,
) (*core.MakeLinkRes, proto.TreeRoot) {

	p0 := proto.NewGenericLinkPayloadWithUsersettings(
		proto.NewUserSettingsLinkWithPassphrase(
			proto.PassphraseInfo{
				Gen:  gen,
				Salt: salt,
			},
		),
	)
	tr := getCurrentTreeRoot(t, m)

	mlr, err := core.MakeGenericLink(
		u.FQE().Entity,
		u.FQE().Host,
		dev,
		p0,
		seqno,
		prev,
		tr,
	)
	require.NoError(t, err)

	return mlr, tr
}

func makeAndPostSettingsLink(
	t *testing.T,
	m shared.MetaContext,
	u *TestUser,
	ucli *rem.UserClient,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	dev core.PrivateSuiter,
	gen proto.PassphraseGeneration,
	salt *proto.PassphraseSalt,
) (proto.LinkHash, proto.TreeRoot) {

	mlr, tr := makeSettingsLink(t, m, u, seqno, prev, dev, gen, salt)

	var ret proto.LinkHash
	err := core.LinkHashInto(mlr.Link, ret[:])
	require.NoError(t, err)

	err = ucli.PostGenericLink(m.Ctx(), rem.PostGenericLinkArg{
		Link:             *mlr.Link,
		NextTreeLocation: *mlr.NextTreeLocation,
	})
	require.NoError(t, err)
	common.PokeMerklePipelineInTest(t, m)
	return ret, tr
}

func TestUserSettingsChain(t *testing.T) {

	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	ma := tew.NewClientMetaContext(t, a)

	dnCased := proto.DeviceName("Yôyödyne 4K L+")
	tr := getCurrentTreeRoot(t, m)
	yoyo := a.ProvisionNewDeviceWithOpts(t, a.eldest, string(dnCased), proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)

	ucli, closeFn := a.newUserCertAndClient(t, m.Ctx())
	defer closeFn()

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, a)

	err := ucli.SetPassphrase(m.Ctx(), arg)
	require.NoError(t, err)

	s := proto.ChainEldestSeqno
	var prev *proto.LinkHash
	doSettingsLink := func(dev core.PrivateSuiter, ppgen proto.PassphraseGeneration, salt *proto.PassphraseSalt) {
		newPrev, _ := makeAndPostSettingsLink(
			t, m, a, ucli,
			s, prev, dev, ppgen, salt,
		)
		s++
		prev = &newPrev
	}

	doSettingsLink(yoyo, ppe.gen, &ppe.salt)

	earlyRoot := getCurrentTreeRoot(t, m)

	for i := 0; i < 2; i++ {
		cppArg := ppe.changePassphrase(t, a)
		err = ucli.ChangePassphrase(m.Ctx(), cppArg)
		require.NoError(t, err)
		doSettingsLink(yoyo, ppe.gen, nil)
	}

	au := ma.G().ActiveUser()
	require.NotNil(t, au)

	runLoader := func() {
		usl := libclient.NewUserSettingsLoader(au)
		res, err := usl.Run(ma)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.NotNil(t, res.Payload.Usersettings())
		require.Equal(t, res.Payload.Usersettings().Passphrase.Gen, ppe.gen)
	}

	runLoader()

	doSettingsLink(yoyo, ppe.gen, nil)
	tr = getCurrentTreeRoot(t, m)
	bobo := a.ProvisionNewDeviceWithOpts(t, yoyo, "bobobut", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)
	tr = getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, bobo, yoyo, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	cppArg := ppe.changePassphrase(t, a)
	err = ucli.ChangePassphrase(m.Ctx(), cppArg)
	require.NoError(t, err)
	doSettingsLink(bobo, ppe.gen, nil)
	tew.DirectMerklePokeForLeafCheck(t)

	runLoader()

	// This is a bad link, since the root we've captured predates links we've signed with bobo
	// (just above). We expect a failure here when we rerun the chain.
	err = a.AttemptRevokeDeviceWithTreeRoot(t, a.eldest, bobo, &earlyRoot)
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "too old"}, err)
}

func TestUserRevokeWithRootTooOld(t *testing.T) {

	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)
	tr := getCurrentTreeRoot(t, m)
	angelo := a.ProvisionNewDeviceWithOpts(t, a.eldest, "angelo", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)
	bingo := a.ProvisionNewDeviceWithOpts(t, angelo, "bingo", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, a)
	ucli, closeFn := a.newUserCertAndClient(t, m.Ctx())
	defer closeFn()
	err := ucli.SetPassphrase(m.Ctx(), arg)
	require.NoError(t, err)

	_, oldRoot := makeAndPostSettingsLink(
		t, m, a, ucli,
		proto.ChainEldestSeqno, nil, angelo, ppe.gen, &ppe.salt,
	)
	tew.DirectMerklePokeForLeafCheck(t)
	tr = getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, bingo, angelo, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	ma := tew.NewClientMetaContext(t, a)
	au := ma.G().ActiveUser()
	require.NotNil(t, au)
	usl := libclient.NewUserSettingsLoader(au)
	usl.SetTesting(&libclient.UserSettingsLoaderTesting{
		Base: libclient.ChainLoaderTesting{},
		MutateUserWrapperHook: func(uw *libclient.UserWrapper) {
			eid, err := angelo.EntityID()
			require.NoError(t, err)
			feid, err := eid.Fixed()
			require.NoError(t, err)
			fqe := proto.FQEntityFixed{
				Entity: feid,
				Host:   a.FQE().Host,
			}
			uw.DevInfo[fqe][0].Revoked.Chain.Root = oldRoot
		},
	})
	_, err = usl.Run(ma)
	require.Error(t, err)

	cle, ok := err.(core.ChainLoaderError)
	require.True(t, ok)
	vpe, ok := cle.Err.(core.CLBadMerkleVerifyPresenceError)
	require.True(t, ok)
	require.Equal(t, vpe.Epno, oldRoot.Epno)
	expected := usl.GenericChainLoader().MerkleKey(0)
	require.NotNil(t, expected)
	require.Equal(t, *expected, vpe.Key)

}
