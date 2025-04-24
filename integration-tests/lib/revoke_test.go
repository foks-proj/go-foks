// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestProvisionAndRevokeTriggers(t *testing.T) {

	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)

	beta := a.ProvisionNewDevice(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	betaId, err := beta.EntityID()
	require.NoError(t, err)

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	var pe int
	err = db.QueryRow(m.Ctx(),
		`SELECT provision_epno FROM device_keys
		 WHERE short_host_id=$1 AND verify_key=$2 AND uid=$3`,
		int(m.ShortHostID()),
		betaId.ExportToDB(),
		a.FQUser().Uid.ExportToDB(),
	).Scan(&pe)
	require.NoError(t, err)
	require.GreaterOrEqual(t, int(pe), int(tr.Epno))

	a.RevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	var x, y int
	err = db.QueryRow(m.Ctx(),
		`SELECT revoke_header_epno, revoke_tree_epno
		 FROM revoked_device_keys
 		 WHERE short_host_id=$1 AND verify_key=$2 AND uid=$3`,
		int(m.ShortHostID()),
		betaId.ExportToDB(),
		a.FQUser().Uid.ExportToDB(),
	).Scan(&x, &y)
	require.NoError(t, err)
	require.Greater(t, y, x)
	require.Greater(t, 2, 1)
	require.GreaterOrEqual(t, int(x), int(tr.Epno))
}

func TestRevokeProvisionRace(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)
	beta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)

	tr = getCurrentTreeRoot(t, m)

	ucli, closeFn := a.newUserCertAndClient(t, m.Ctx())
	defer closeFn()

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, a)

	err := ucli.SetPassphrase(m.Ctx(), arg)
	require.NoError(t, err)

	srvch := tew.UserSrv().TestStopPostGenericLink.Init()
	runRevoke := func() {
		retCh := <-srvch
		a.RevokeDevice(t, a.eldest, beta)
		retCh <- struct{}{}
	}

	mlr, _ := makeSettingsLink(t, m, a, proto.ChainEldestSeqno, nil, beta,
		ppe.gen, &ppe.salt)

	go runRevoke()

	err = ucli.PostGenericLink(m.Ctx(), rem.PostGenericLinkArg{
		Link:             *mlr.Link,
		NextTreeLocation: *mlr.NextTreeLocation,
	})
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "key locked"}, err)
}

func TestRevokeFailsWhenSigsInFlight(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)
	beta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)
	tr = getCurrentTreeRoot(t, m)
	a.ProvisionNewDeviceWithOpts(t, beta, "gamma 3.3g", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})

	// Can't revoke eldest since the work of it signing beta into the chain is still in flight.
	tr = getCurrentTreeRoot(t, m)
	err := a.AttemptRevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "work inflight"}, err)

	ctx := m.Ctx()
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBuilderSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)

	// Even though the revoke is happening after the provision, it is still based on a tree
	// that is old, since it doesn't contain the provision link.  This is because,
	// in this test, the revoker process never got to sign the link.
	tr = getCurrentSignedTreeRoot(t, m)
	err = a.AttemptRevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "too old"}, err)

	err = tew.MerkleSignerSrv().Poke(ctx)
	require.NoError(t, err)

	tr = getCurrentSignedTreeRoot(t, m)
	err = a.AttemptRevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	require.NoError(t, err)
}

func TestRevokeAndReuse(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)
	beta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)
	beta25519, ok := beta.(*core.PrivateSuite25519)
	require.True(t, ok)
	seed := beta25519.Seed()
	betaEid, err := beta.EntityID()
	require.NoError(t, err)

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, a)
	ucli, closeFn := a.newUserCertAndClient(t, m.Ctx())
	defer closeFn()
	err = ucli.SetPassphrase(m.Ctx(), arg)
	require.NoError(t, err)

	prev, _ := makeAndPostSettingsLink(
		t, m, a, ucli,
		proto.ChainEldestSeqno, nil, beta, ppe.gen, &ppe.salt,
	)
	tew.DirectMerklePokeForLeafCheck(t)

	tr = getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	tr = getCurrentTreeRoot(t, m)
	newBeta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr, Seed: &seed})
	tew.DirectMerklePokeForLeafCheck(t)
	newBetaEid, err := newBeta.EntityID()
	require.NoError(t, err)
	require.Equal(t, betaEid, newBetaEid)

	cppArg := ppe.changePassphrase(t, a)
	err = ucli.ChangePassphrase(m.Ctx(), cppArg)
	require.NoError(t, err)

	makeAndPostSettingsLink(
		t, m, a, ucli,
		proto.Seqno(2), &prev, newBeta, ppe.gen, &ppe.salt,
	)
	tew.DirectMerklePokeForLeafCheck(t)

	tr = getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, a.eldest, newBeta, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	// Now check the user loader handles this. It should!
	ma := tew.NewClientMetaContext(t, a)
	au := ma.G().ActiveUser()
	usl := libclient.NewUserSettingsLoader(au)
	res, err := usl.Run(ma)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Payload.Usersettings().Passphrase)
	require.Equal(t, res.Payload.Usersettings().Passphrase.Gen, ppe.gen)
}

func runMerkleActivePoker(t *testing.T, tew *TestEnvWrapper) func() {
	activePoker := common.NewLoopUntilStop(func() {
		time.Sleep(10 * time.Millisecond)
		tew.DirectMerklePoke(t)
	})
	go activePoker.Run()
	return func() {
		activePoker.Stop()
	}
}

func testRevokeMgr(t *testing.T) (
	func(),
	*TestEnvWrapper,
	*TestUser,
	shared.MetaContext,
	libclient.MetaContext,
) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)
	beta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)

	ma := tew.NewClientMetaContext(t, a)
	ma.G().Cfg().TestSetMerkleRaceRetryConfig(libclient.MerkleRaceRetryConfig{
		NumRetries: 10,
		Wait:       2 * time.Millisecond,
	})
	au := ma.G().ActiveUser()
	fqu := au.FQU()
	host := fqu.HostID
	betaPublic, err := beta.Publicize(&host)
	require.NoError(t, err)

	stopper := runMerkleActivePoker(t, tew)

	err = libclient.Revoke(ma, au, betaPublic.GetEntityID())
	require.NoError(t, err)
	a.userSeqno++

	uw, err := libclient.LoadMe(ma, au)
	require.NoError(t, err)
	a.prev = &uw.Prot().LastHash
	sk := uw.StalePUKs()
	require.True(t, sk.IsEmpty())

	return stopper, tew, a, m, ma
}

func (u *TestUser) SetPassphrase(t *testing.T, m shared.MetaContext, dev core.PrivateSuiter) proto.Passphrase {
	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, u)
	ucli, closeFn := u.newUserCertAndClient(t, m.Ctx())
	defer closeFn()
	mlres := u.makeSettingsLink(t, m, dev, proto.FirstPassphraseGeneration, &ppe.salt)
	arg.UserSettingsLink = &rem.PostGenericLinkArg{
		Link:             *mlres.Link,
		NextTreeLocation: *mlres.NextTreeLocation,
	}
	err := ucli.SetPassphrase(m.Ctx(), arg)
	require.NoError(t, err)
	return ppe.pp
}

func TestRevokeMgrHappyPath(t *testing.T) {
	stopper, _, _, _, _ := testRevokeMgr(t)
	stopper()
}

func TestRevokeBadDevice(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePoke(t)
	mc := tew.NewClientMetaContextWithEracer(t, bluey)
	au := mc.G().ActiveUser()
	fqu := au.FQU()
	dev, err := bluey.eldest.Publicize(&fqu.HostID)
	require.NoError(t, err)
	eid := dev.GetEntityID()
	eid[4] ^= 0x1
	err = libclient.Revoke(mc, mc.G().ActiveUser(), eid)
	require.Error(t, err)
	require.Equal(t, core.KeyNotFoundError{Which: "device"}, err)
}

func TestSelfRevoke(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	m := tew.MetaContext()
	tew.DirectMerklePoke(t)
	mc := tew.NewClientMetaContextWithEracer(t, bluey)
	au := mc.G().ActiveUser()
	fqu := au.FQU()
	host := fqu.HostID

	// store a secret for bluey on this device, since we'll
	// be accessing the secret store when we rotate PUKs later.
	storeSecret(t, mc, bluey, bluey.eldest)

	tr := getCurrentTreeRoot(t, m)
	beta := bluey.ProvisionNewDeviceWithOpts(t, bluey.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePoke(t)
	tew.DirectMerklePoke(t)
	bluey.SetPassphrase(t, m, beta)
	mcBeta := tew.NewClientMetaContextWithDevice(t, bluey, beta)
	mcBeta.G().Cfg().TestSetMerkleRaceRetryConfig(libclient.MerkleRaceRetryConfig{
		NumRetries: 10,
		Wait:       2 * time.Millisecond,
	})

	// important to speed things up, since it takes several merkle iterations to fully
	// process a revoke.
	stopper := runMerkleActivePoker(t, tew)
	defer stopper()

	betaPublic, err := beta.Publicize(&host)
	require.NoError(t, err)

	// Self-revoke for the newly provisioned beta device
	err = libclient.Revoke(mcBeta, mcBeta.G().ActiveUser(), betaPublic.GetEntityID())
	require.NoError(t, err)

	//  Now we need to load the user in our other thread. Note the ordering of key use
	// versus revocation is not the usual in the case of a self-revoke.
	mc.G().Cfg().TestSetMerkleRaceRetryConfig(libclient.MerkleRaceRetryConfig{
		NumRetries: 10,
		Wait:       2 * time.Millisecond,
	})
	uw, err := libclient.LoadMe(mc, au)
	require.NoError(t, err)
	staleKeys := uw.StalePUKs()
	require.False(t, staleKeys.IsEmpty())
	require.Equal(t, 1, len(uw.ActiveDevices()))

	err = libclient.RotatePUKs(mc, au, staleKeys)
	require.NoError(t, err)
	uw, err = libclient.LoadMe(mc, au)
	require.NoError(t, err)
	staleKeys = uw.StalePUKs()
	require.True(t, staleKeys.IsEmpty())
}
