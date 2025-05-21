// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

type TestEnvWrapper struct {
	*common.TestEnv
	shutdownFns []func()
}

func (w TestEnvWrapper) NewTestUserFakeRoot(t *testing.T) *TestUser {
	return w.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: false})
}

func (w TestEnvWrapper) NewTestUser(t *testing.T) *TestUser {
	return w.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
}

func (w TestEnvWrapper) NewTestUserOpts(t *testing.T, opts *TestUserOpts) *TestUser {
	if opts == nil {
		opts = &TestUserOpts{RealTreeRoot: true}
	}
	m := w.MetaContext()
	rcli, closeFn, err := newRegClientFromEnv(m, w.TestEnv)
	require.NoError(t, err)
	defer closeFn()
	return GenerateNewTestUserWithRegCli(t, w.TestEnv, rcli, opts)
}

func (w TestEnvWrapper) NewTestUserYubi(t *testing.T) *TestUser {
	m := w.MetaContext()
	rcli, closeFn, err := newRegClientFromEnv(m, w.TestEnv)
	require.NoError(t, err)
	defer closeFn()
	return GenerateNewTestUserYubiWithRegCli(t, w.TestEnv, rcli)
}

func ForkNewTestEnvWrapper(t *testing.T) *TestEnvWrapper {
	return ForkNewTestEnvWrapperWithOpts(t, common.SetupOpts{})
}

func ForkNewTestEnvWrapperWithOpts(t *testing.T, opts common.SetupOpts) *TestEnvWrapper {
	env := globalTestEnv.Fork(t, opts)
	return &TestEnvWrapper{TestEnv: env}
}

func (w *TestEnvWrapper) pushShutdownHook(f func()) {
	w.shutdownFns = append(w.shutdownFns, f)
}

func (w *TestEnvWrapper) userCli(t *testing.T, u *TestUser) *rem.UserClient {
	cert := u.ClientCert(t)
	cli, closeFn, err := newUserClientFromEnv(w.MetaContext(), cert, w.TestEnv, u.vhost)
	require.NoError(t, err)
	w.pushShutdownHook(closeFn)
	return cli
}

func (w *TestEnvWrapper) regCli(t *testing.T) *rem.RegClient {
	cli, closeFn, err := newRegClientFromEnv(w.MetaContext(), w.TestEnv)
	require.NoError(t, err)
	w.pushShutdownHook(closeFn)
	return cli
}

func (w *TestEnvWrapper) DirectMerklePoke(t *testing.T) {
	err := w.TestEnv.DirectMerklePoke()
	require.NoError(t, err)
}

func (w *TestEnvWrapper) Shutdown() {
	for _, f := range w.shutdownFns {
		f()
	}
	_ = w.TestEnv.Shutdown()
}

var _testEnvBetaLock sync.Mutex
var _testEnvBeta *TestEnvWrapper

// Test Env Beta is a global test environment that is forked once for each test suite run,
// and indepedent of the test environment that depends on stepwise merkle timing.
// Note this is all probably backwards. We should run all tests on a shared TestEnvironment,
// and only the Merkle pipeline tests should have sandboxed environments.
//
// Note that we've extended testEnvBeta to also give us virtual domains:
//
//	a.foo.com, b.foo.com, c.foo.com, d.foo.com and e.foo.com (e which is set to "open" user viewership)
//
// Where foo.com is a random domain, such as: d-e38e23.io
func testEnvBeta(t *testing.T) *TestEnvWrapper {
	_testEnvBetaLock.Lock()
	defer _testEnvBetaLock.Unlock()

	if _testEnvBeta != nil {
		return _testEnvBeta
	}

	domain := RandomDomain(t)
	primary := proto.Hostname("pri." + domain)
	hns := []proto.Hostname{
		primary,
		proto.Hostname("127.0.0.1"),
		proto.Hostname("localhost"),
		proto.Hostname("::1"),
	}
	n := 5
	for i := 0; i < n; i++ {
		hn := common.VHostnameI(t, i, n, domain)
		hns = append(hns, hn)
	}
	ret := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			WildcardVhostDomain: domain,
			Hostnames: &common.Hostnames{
				Probe: hns,
			},
			NVHosts:         n,
			PrimaryHostname: primary,
		},
	)
	ret.SetHostname(primary)
	pushShutdownHook(func() error {
		ret.Shutdown()
		return nil
	})
	_testEnvBeta = ret

	ret.DirectMerklePokeInTest(t)
	ret.BeaconRegister(t)
	return ret
}

func TestSimpleUserLoads(t *testing.T) {

	// Since we need to poke merkle, fork the environment so we don't pollute merkle tests.
	// Maybe we should rethink this at some point, but for now....
	tew := testEnvBeta(t)

	a := tew.NewTestUserFakeRoot(t)
	b := tew.NewTestUserFakeRoot(t)
	c := tew.NewTestUserFakeRoot(t)

	tew.DirectMerklePoke(t)

	bcli := tew.userCli(t, b)
	acli := tew.userCli(t, a)

	grantViewPermission(t, *acli, a.uid, b.uid)
	m := tew.MetaContext()
	res, err := bcli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   a.uid,
		Start: proto.ChainEldestSeqno,
	})
	foundKey := func(m proto.MerklePathTerminal, expected bool) {
		got, err := m.FoundKey()
		require.NoError(t, err)
		require.Equal(t, expected, got)
	}
	checkRes := func(res rem.UserChain, ndn int) {
		require.NoError(t, err)
		require.Equal(t, 1, len(res.Links))
		require.Equal(t, 1, len(res.Usernames))
		require.Equal(t, 1, len(res.Locations))
		require.Equal(t, 4, len(res.Merkle.Paths))
		require.Equal(t, uint64(2), res.NumUsernameLinks)
		require.Equal(t, ndn, len(res.DeviceNames))

		foundKey(res.Merkle.Paths[0].Terminal, true)
		foundKey(res.Merkle.Paths[1].Terminal, false)
		foundKey(res.Merkle.Paths[2].Terminal, true)
		foundKey(res.Merkle.Paths[3].Terminal, false)
	}
	checkRes(res, 0)

	tok, err := acli.GrantRemoteViewPermissionForUser(m.Ctx(),
		rem.GrantRemoteViewPermissionPayload{
			Viewee: a.uid.ToPartyID(),
			Viewer: b.FQUser().FQParty(),
		},
	)
	require.NoError(t, err)

	rcli := tew.regCli(t)
	res, err = rcli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   a.uid,
		Auth:  rem.NewLoadUserChainAuthWithToken(tok),
		Start: proto.ChainEldestSeqno,
	})
	require.NoError(t, err)
	checkRes(res, 0)
	require.Equal(t, a.name, res.UsernameUtf8)

	_, err = rcli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   a.uid,
		Start: proto.ChainEldestSeqno,
	})
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)

	ccli := tew.userCli(t, c)
	_, err = ccli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   a.uid,
		Start: proto.ChainEldestSeqno,
	})
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)

	// self-load should work
	res, err = bcli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   b.uid,
		Start: proto.ChainEldestSeqno,
	})
	require.NoError(t, err)
	checkRes(res, 1)

	// If we start at link 2, we should just get 0 new links, and 2 merkle paths,
	// showing that the UID and username chains are up-to-date.
	res, err = bcli.LoadUserChain(m.Ctx(), rem.LoadUserChainArg{
		Uid:   b.uid,
		Start: 2,
		Username: &rem.NameSeqnoPair{
			N: b.UsernameNormalized(t),
			S: 2,
		}})
	require.NoError(t, err)
	require.Equal(t, uint64(1), res.NumUsernameLinks)
	require.Equal(t, 0, len(res.Links))
	require.Equal(t, 2, len(res.Merkle.Paths))
	foundKey(res.Merkle.Paths[0].Terminal, false)
	foundKey(res.Merkle.Paths[1].Terminal, false)

}

func (w *TestEnvWrapper) NewClientMetaContext(t *testing.T, u *TestUser) libclient.MetaContext {
	return w.NewClientMetaContextWithDevice(t, u, u.devices[0])
}

func (w *TestEnvWrapper) NewClientMetaContextWithEracer(t *testing.T, u *TestUser) libclient.MetaContext {
	ret := w.NewClientMetaContextWithDevice(t, u, u.devices[0])
	ret.G().SetMerkleEracer(func(_ context.Context, _ error) error {
		return w.TestEnv.DirectMerklePoke()
	})
	return ret
}

func (w *TestEnvWrapper) NewClientMetaContextWithDevice(t *testing.T, u *TestUser, d core.PrivateSuiter) libclient.MetaContext {
	cm := libclient.NewMetaContextMain()
	tmp, err := os.MkdirTemp("", "foks_agent_test_")
	require.NoError(t, err)
	w.pushShutdownHook(func() {
		err := os.RemoveAll(tmp)
		require.NoError(t, err)
	})

	// Make sure that the test env and the client's meta data
	// refer to the same Yubi dispatch.
	cm.G().SetYubiDispatch(w.YubiDisp(t))

	cm.G().Cfg().TestSetHomeCLIFlag(tmp)
	cm.G().Cfg().TestSetLogTargets("stdout", "stderr")
	err = cm.Configure()
	require.NoError(t, err)

	// No need to retry in test, since we can just poke merkle
	cm.G().Cfg().TestDisableMerkleRaceRetry()

	// Don't encrypt local keys
	cm.G().Cfg().TestDisableSecretKeyEncryption()

	// Allow for KV retries
	cm.G().Cfg().TestEnableKVRetry()

	// Disable things like auto-config file creation
	cm.G().Cfg().TestSetTestingMode()

	m := w.MetaContext()

	// copy some configuration params over from server config
	// to client config.
	rootCAs, rootCAsString, err := m.G().Config().ProbeRootCAs(m.Ctx())
	require.NoError(t, err)
	cm.G().Cfg().TestSetProbeRootCAs(rootCAsString)

	_, beaconAddr, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Beacon)
	require.NoError(t, err)
	cm.G().Cfg().TestSetHostsBeacon(string(beaconAddr))

	cn := m.G().CnameResolver()
	cm.G().SetCnameResolver(cn)

	PokeMerklePipelineInTest(t, m)

	_, probeAddr, _, err := m.G().ListenParams(m.Ctx(), proto.ServerType_Probe)
	require.NoError(t, err)
	if u.vhost != nil {
		probeAddr, err = probeAddr.WithHostname(u.vhost.Hostname)
		require.NoError(t, err)
	}
	probe, err := cm.Probe(chains.ProbeArg{
		Timeout: time.Hour,
		RootCAs: rootCAs,
		Addr:    probeAddr,
		Fresh:   true,
		HostID:  u.host,
	})
	require.NoError(t, err)

	addUserToGlobalContext(t, cm, u, d, probe)

	return cm
}

func storeSecret(t *testing.T, cm libclient.MetaContext, u *TestUser, d core.PrivateSuiter) {
	ps25519, ok := d.(*core.PrivateSuite25519)
	require.True(t, ok)
	seed := ps25519.Seed()
	did, err := ps25519.DeviceID()
	require.NoError(t, err)
	tok, err := core.NewPermissionToken()
	require.NoError(t, err)

	row := lcl.LabeledSecretKeyBundle{
		Fqur: proto.FQUserAndRole{
			Fqu:  u.FQUser(),
			Role: proto.OwnerRole,
		},
		KeyID:   did,
		SelfTok: tok,
		Bundle: lcl.NewStoredSecretKeyBundleWithPlaintext(
			lcl.NewSecretKeyBundleWithV1(
				seed,
			),
		),
	}

	err = cm.G().SecretStore().Put(row)
	require.NoError(t, err)
	err = cm.G().SecretStore().Save(cm.Ctx())
	require.NoError(t, err)
}

func addUserToGlobalContext(
	t *testing.T,
	cm libclient.MetaContext,
	u *TestUser,
	d core.PrivateSuiter,
	probe *chains.Probe,
) {
	keyId, err := d.EntityID()
	require.NoError(t, err)
	uc := &libclient.UserContext{
		Info: proto.UserInfo{
			Fqu: u.FQUser(),
			Username: proto.NameBundle{
				NameUtf8: u.name,
				Name:     u.UsernameNormalized(t),
			},
			Role: proto.OwnerRole,
			Key:  keyId,
		},
	}
	uc.PrivKeys.SetDevkey(d)
	uc.SetHomeServer(probe)
	yi, err := d.ExportToYubiKeyInfo(cm.Ctx())
	require.NoError(t, err)
	if yi != nil {
		uc.Info.YubiInfo = yi
	}
	err = libclient.SetActiveUser(cm, uc)
	require.NoError(t, err)
	ui := uc.Info
	require.NoError(t, err)

	var ltx libclient.LocalDbTx
	err = ltx.PutUser(ui, false)
	require.NoError(t, err)
	err = ltx.Exec(cm)
	require.NoError(t, err)
}

type devicePair struct {
	status proto.DeviceStatus
	eid    proto.EntityID
}

func entityID(t *testing.T, ps core.PrivateSuiter) proto.EntityID {
	eid, err := ps.EntityID()
	require.NoError(t, err)
	return eid
}

func TestUserLoaderClientHappyPaths(t *testing.T) {

	tew := testEnvBeta(t)
	m := tew.MetaContext()

	a := tew.NewTestUserFakeRoot(t)
	ma := tew.NewClientMetaContext(t, a)
	lures1, err := libclient.LoadUser(ma, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeSelf})
	require.NoError(t, err)

	checkDeviceNamesMatch := func(u *TestUser, devlist []proto.DeviceInfo) {
		found := make(map[proto.DeviceLabel]bool)
		for _, d := range devlist {
			require.NotNil(t, d.Dn)
			require.False(t, found[d.Dn.Label])
			found[d.Dn.Label] = true
			_, ok := u.deviceLabels[d.Dn.Label]
			require.True(t, ok)
		}
		require.Equal(t, len(a.deviceLabels), len(devlist))
	}

	require.Equal(t, proto.NameSeqno(1), lures1.Prot().Username.S)
	require.Equal(t, 1, len(lures1.Prot().Puks))
	require.NotNil(t, lures1.Prot().Devices[0].Dn)
	checkDeviceNamesMatch(a, lures1.Prot().Devices)

	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	dnCased := proto.DeviceName("Yôyödyne 4K L+")
	yoyo := a.ProvisionNewDevice(t, a.eldest, string(dnCased), proto.DeviceType_Computer, role)
	PokeMerklePipelineInTest(t, m)

	lures2, err := libclient.LoadUser(ma, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeSelf})
	require.NoError(t, err)
	require.Equal(t, proto.NameSeqno(1), lures2.Prot().Username.S)
	require.Equal(t, 1, len(lures2.Prot().Puks))
	checkDeviceNamesMatch(a, lures2.Prot().Devices)
	require.Equal(t, dnCased, lures2.Prot().Devices[1].Dn.Name)
	require.Equal(t, proto.DeviceNameNormalized("yoyodyne 4k l+"), lures2.Prot().Devices[1].Dn.Label.Name)

	// Now b loads a's chain, should not get any device names back
	b := tew.NewTestUserFakeRoot(t)
	mb := tew.NewClientMetaContext(t, b)
	acli := tew.userCli(t, a)
	grantViewPermission(t, *acli, a.uid, b.uid)
	require.NoError(t, err)

	lures3, err := libclient.LoadUser(mb, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeOthers})
	require.NoError(t, err)
	for _, d := range lures3.Prot().Devices {
		require.Nil(t, d.Dn)
	}
	require.Equal(t, proto.NameSeqno(1), lures2.Prot().Username.S)
	require.Equal(t, 2, len(lures2.Prot().Devices))
	require.Equal(t, 1, len(lures2.Prot().Puks))

	expectedDevices := []devicePair{
		{proto.DeviceStatus_REVOKED, entityID(t, a.eldest)},
		{proto.DeviceStatus_ACTIVE, entityID(t, yoyo)},
	}

	checkDevicesAgainstExpected := func(want []devicePair, got []proto.DeviceInfo) {
		require.Equal(t, len(want), len(got))
		for i, d := range got {
			require.Equal(t, expectedDevices[i].status, d.Status)
			require.Equal(t, expectedDevices[i].eid, d.Key.Member.Id.Entity)
		}
	}
	tew.DirectMerklePoke(t)

	// Now check that we can revoke a devie and it gets marked as
	// revoked in the next user load.
	a.RevokeDevice(t, yoyo, a.eldest)
	PokeMerklePipelineInTest(t, m)
	lures4, err := libclient.LoadUser(ma, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeSelf})
	require.NoError(t, err)
	devs := lures4.Prot().Devices
	checkDevicesAgainstExpected(expectedDevices, devs)

	// Now check that we can provision a new device with the existing
	// device.
	bobo := a.ProvisionNewDevice(t, a.devices[0], "bobo", proto.DeviceType_Computer, role)
	PokeMerklePipelineInTest(t, m)
	lures5, err := libclient.LoadUser(ma, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeSelf})
	require.NoError(t, err)
	expectedDevices = append(expectedDevices, devicePair{proto.DeviceStatus_ACTIVE, entityID(t, bobo)})
	checkDevicesAgainstExpected(expectedDevices, lures5.Prot().Devices)

	// c shows up at the very end and should still be able to play
	// a's chain from the start.
	c := tew.NewTestUserFakeRoot(t)
	mc := tew.NewClientMetaContext(t, c)
	grantViewPermission(t, *acli, a.uid, c.uid)
	require.NoError(t, err)
	lures6, err := libclient.LoadUser(mc, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeOthers})
	require.NoError(t, err)
	checkDevicesAgainstExpected(expectedDevices, lures6.Prot().Devices)
}

func TestUserLoadChangeUsername(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)

	ma := tew.NewClientMetaContext(t, a)
	PokeMerklePipelineInTest(t, m)

	b := tew.NewTestUserFakeRoot(t)
	acli := tew.userCli(t, a)
	mb := tew.NewClientMetaContext(t, b)
	grantViewPermission(t, *acli, a.uid, b.uid)
	bres1, err := libclient.LoadUser(mb, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeOthers})
	require.NoError(t, err)
	require.Equal(t, a.UsernameNormalized(t), bres1.Prot().Username.B.Name)

	newUsername := changeUsername(m.Ctx(), t, a)
	PokeMerklePipelineInTest(t, m)

	// Simplest test -- load the self user and all chagnes at once.
	lures1, err := libclient.LoadUser(ma, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeSelf})
	require.NoError(t, err)
	require.Equal(t, newUsername, lures1.Prot().Username.B.NameUtf8)

	// Slightly more complicated --- load as user B and also get part of it
	// up front, and part of it in second get.
	bres2, err := libclient.LoadUser(mb, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeOthers})
	require.NoError(t, err)
	require.Equal(t, newUsername, bres2.Prot().Username.B.NameUtf8)

	// Check a second load still works even if no changes
	bres2, err = libclient.LoadUser(mb, libclient.LoadUserArg{Uid: a.uid, LoadMode: libclient.LoadModeOthers})
	require.NoError(t, err)
	require.Equal(t, newUsername, bres2.Prot().Username.B.NameUtf8)
}

func storePrivateKey(t *testing.T, m libclient.MetaContext) {
	au := m.G().ActiveUser()
	require.NotNil(t, au)
	k := au.PrivKeys.GetDevkey()
	k25519, ok := k.(*core.PrivateSuite25519)
	require.True(t, ok)
	require.NotNil(t, k)
	did, err := k25519.DeviceID()
	require.NoError(t, err)
	tok, err := core.NewPermissionToken()
	require.NoError(t, err)

	row := lcl.LabeledSecretKeyBundle{
		Fqur: proto.FQUserAndRole{
			Fqu:  au.Info.Fqu,
			Role: au.Info.Role,
		},
		KeyID:   did,
		SelfTok: tok,
		Bundle: lcl.NewStoredSecretKeyBundleWithPlaintext(
			lcl.NewSecretKeyBundleWithV1(
				k25519.Seed(),
			),
		),
	}

	err = m.G().SecretStore().Put(row)
	require.NoError(t, err)
	err = m.G().SecretStore().Save(m.Ctx())
	require.NoError(t, err)
}

func checkActiveUser(t *testing.T, u *libclient.UserContext) {
	require.NotNil(t, u)
	require.NotNil(t, u.PrivKeys.GetDevkey())
	require.NotZero(t, len(u.PrivKeys.GetPUKs()))
}

func TestLoadActiveUser(t *testing.T) {
	tew := testEnvBeta(t)
	a := tew.NewTestUserFakeRoot(t)
	ma := tew.NewClientMetaContext(t, a)
	storePrivateKey(t, ma)
	ma.G().ClearSecrets()
	err := ma.G().LoadActiveUser(ma.Ctx(), libclient.LoadActiveUserOpts{})
	require.NoError(t, err)
	au := ma.G().ActiveUser()
	checkActiveUser(t, au)
	inf, err := au.Export()
	require.NoError(t, err)
	fmt.Printf("%+v\n", inf.Info.Username)
}

func TestLoadActiveUserYubi(t *testing.T) {
	tew := testEnvBeta(t)
	a := tew.NewTestUserYubi(t)
	ma := tew.NewClientMetaContext(t, a)
	// unlike the previous we don't store a secret key
	// since it's a yubikey and there's no secret
	// to store!
	ma.G().ClearSecrets()
	err := ma.G().LoadActiveUser(
		ma.Ctx(),
		libclient.LoadActiveUserOpts{ForceYubiUnlock: true},
	)
	require.NoError(t, err)
	au := ma.G().ActiveUser()
	checkActiveUser(t, au)

	// Now check that we can do an explicit unlock with YubiUnlock,
	// then populate the PUKs, and that everything loads OK.
	ma.G().ClearSecrets()
	err = ma.G().LoadActiveUser(
		ma.Ctx(),
		libclient.LoadActiveUserOpts{},
	)
	require.NoError(t, err)
	au = ma.G().ActiveUser()
	err = au.YubiUnlock(ma)
	require.NoError(t, err)
	err = au.PopulateWithDevkey(ma)
	require.NoError(t, err)
	checkActiveUser(t, au)
}

func TestAllUsers(t *testing.T) {

	// Make user A with a yubikey, add to in-memory user list
	tew := testEnvBeta(t)
	a := tew.NewTestUserYubi(t)
	ma := tew.NewClientMetaContext(t, a)

	// Make a second user on the same context, add to in-memory user list
	// via some surgery.
	b := tew.NewTestUserFakeRoot(t)
	ac := ma.G().ActiveUser()
	require.NotNil(t, ac)
	probe := ac.HomeServer()
	require.NotNil(t, probe)
	dev := b.devices[0]
	storeSecret(t, ma, b, dev)
	addUserToGlobalContext(t, ma, b, dev, probe)

	// We need to register this hostID on our local beacon server so our
	// attempts to lookup hostname in repair work below.
	tew.BeaconRegister(t)

	loadAllFromDb := func() []proto.UserInfo {
		v, err := libclient.LoadAllUsersFromDB(ma)
		require.NoError(t, err)
		return v
	}

	// Both users should show up in all users loader
	aul := libclient.NewAllUserLoader()
	err := aul.Run(ma)
	require.NoError(t, err)
	all := aul.Users()
	require.Equal(t, 2, len(all))
	v := loadAllFromDb()
	require.Equal(t, 2, len(v))

	// Now nuke the DB and make sure we get 0 users
	err = ma.G().DbNuke(ma.Ctx(), libclient.DbTypeHard)
	require.NoError(t, err)
	v = loadAllFromDb()
	require.Equal(t, 0, len(v))

	// Recovery will only recover the user stored in the secret store, which is user B.
	aul = libclient.NewAllUserLoader()
	err = aul.Run(ma)
	require.NoError(t, err)
	all = aul.Users()
	require.Equal(t, 1, len(all))
	require.Equal(t, all[0].Fqu, b.FQUser())
	// hostname lookup via beacon should work too
	require.Equal(t, all[0].HostAddr.Hostname(), common.TestExtHostname(t, tew.MetaContext()))
	require.True(t, all[0].Username.Name.IsZero()) // still nil, we need to run a repair operation on it

	// Confirm the "repair" operation rewrote the DB.
	v = loadAllFromDb()
	require.NoError(t, err)
	require.Equal(t, 1, len(v))
	require.Equal(t, v[0].Fqu, b.FQUser())
	require.True(t, v[0].Username.Name.IsZero()) // Repair doesn't lookup username though

}

func TestRevokesThenUserLoad(t *testing.T) {

	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	dnCased := proto.DeviceName("Yôyödyne 4K L+ 2.1.4a")
	yoyo := a.ProvisionNewDevice(t, a.eldest, string(dnCased), proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)

	bobo := a.ProvisionNewDevice(t, yoyo, "bobobutt", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	tr := getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, bobo, yoyo, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	tr = getCurrentTreeRoot(t, m)
	a.RevokeDeviceWithTreeRoot(t, bobo, a.eldest, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	ma := tew.NewClientMetaContextWithDevice(t, a, bobo)
	_, err := libclient.LoadMe(ma, ma.G().ActiveUser())
	require.NoError(t, err)
}

func TestDevicesDoNotPileUpOnMerkleRace(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	a := tew.NewTestUser(t)
	ma := tew.NewClientMetaContextWithDevice(t, a, a.eldest)
	_, err := libclient.LoadMe(ma, ma.G().ActiveUser())
	require.NoError(t, err)
	a.ProvisionNewDevice(t, a.eldest, "bobobutt", proto.DeviceType_Computer, proto.OwnerRole)

	wantedErr := core.ChainLoaderError{
		Race: true,
		Err: core.CLBadMerklePathError{
			Err:   core.MerkleVerifyError("server claimed key was not in tree"),
			Which: "uid",
			Seqno: 2,
		},
	}
	tries := 0

	// Allow the user loader to race twice. On the 3rd attempt, we'll poke
	// the merkle apparatus, so the next attempt will pass. Once that happens,
	// we check that devices didn't pile up inside the user loader.
	eracer := func(_ context.Context, e error) error {
		require.Equal(t, wantedErr, e)
		if tries == 2 {
			tew.DirectMerklePoke(t)
		}
		if tries > 2 {
			return core.InternalError("didn't expect more than 3 retries")
		}
		tries++
		return nil
	}

	ma.G().SetMerkleEracer(eracer)

	obj, err := libclient.LoadMe(ma, ma.G().ActiveUser())
	require.NoError(t, err)
	require.Equal(t, 2, len(obj.Prot().Devices))

}

func TestUsernameLookup(t *testing.T) {
	tew := testEnvBeta(t)
	tew.DirectMerklePokeInTest(t)
	a := tew.NewTestUser(t)
	ma := tew.NewClientMetaContextWithDevice(t, a, a.eldest)

	_, err := libclient.LoadMe(ma, ma.G().ActiveUser())
	require.NoError(t, err)

	nname, err := core.NormalizeName(a.name)
	require.NoError(t, err)

	uid, err := libclient.LookupUIDFromDB(ma, a.host, nname)
	require.NoError(t, err)
	require.NotNil(t, uid)
	require.Equal(t, a.uid, *uid)

	uid, err = libclient.LookupUIDFromDB(ma, a.host, nname+"xxx")
	require.Error(t, err)
	require.Nil(t, uid)
	require.Equal(t, core.RowNotFoundError{}, err)
}

func TestReloadByUsername(t *testing.T) {
	tew := testEnvBeta(t)
	a := tew.NewTestUser(t)
	b := tew.NewTestUser(t)
	tew.DirectMerklePoke(t)

	bcli := tew.userCli(t, b)
	grantViewPermission(t, *bcli, b.uid, a.uid)
	ma := tew.NewClientMetaContext(t, a)

	for i := 0; i < 2; i++ {
		_, err := libclient.LoadUser(ma, libclient.LoadUserArg{Username: b.name, LoadMode: libclient.LoadModeOthers})
		require.NoError(t, err)
	}
}
