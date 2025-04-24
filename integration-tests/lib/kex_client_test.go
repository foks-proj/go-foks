// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

type testKex struct {
	u                *TestUser
	ucli             *rem.UserClient
	kexcli           *rem.KexClient
	mySessionCh      chan proto.KexSecret
	theirSessionCh   chan proto.KexSecret
	secretInputErrCh chan error
	newPuk           *core.SharedPrivateSuite25519
	rk               core.RoleKey
	cdnHook          func(ctx context.Context, d *proto.DeviceLabelAndName) error
}

var _ libclient.KexInterfacer = (*testKex)(nil)
var _ libclient.KexUIer = (*testKex)(nil)
var _ libclient.KexLocalKeyer = (*testKex)(nil)
var _ libclient.KexNewDeviceKeyer = (*testKex)(nil)

func (k *testKex) StoreNewDeviceKey(
	ctx context.Context,
	q proto.FQUserAndRole,
	p *lcl.KexPPE,
	tok proto.PermissionToken,
) error {
	return nil
}

func (k *testKex) GetKexPPE(ctx context.Context) (*lcl.KexPPE, error) {
	return nil, nil
}

func (k *testKex) FillChainer(ctx context.Context, c *proto.BaseChainer) error {
	c.Prev = k.u.prev
	c.Seqno = k.u.userSeqno
	c.Root = proto.TreeRoot{}
	c.Root.Epno = k.u.rootEpno
	c.Root.Hash = core.RandomMerkleRootHash()
	c.Time = proto.Now()
	return nil
}
func (k *testKex) GetOrGeneratePUK(ctx context.Context, rk core.RoleKey) (core.SharedPrivateSuiter, bool, error) {
	puk, found := k.u.puks[rk]
	if found {
		return &puk, false, nil
	}
	pukSs := core.RandomSecretSeed32()
	newPuk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_User,
		rk.Export(),
		pukSs,
		proto.Generation(0),
		k.u.host,
	)
	if err != nil {
		return nil, false, err
	}
	k.newPuk = newPuk
	k.rk = rk
	return newPuk, true, nil
}

func (k *testKex) GetAllDevicesForRole(ctx context.Context, newDeviceRoleKey core.RoleKey) ([]core.PublicBoxer, error) {

	var ret []core.PublicBoxer
	newDeviceRole := newDeviceRoleKey.Export()

	for _, d := range k.u.devices {
		lt, err := d.GetRole().LessThan(newDeviceRole)
		if err != nil {
			return nil, err
		}
		if !lt {
			pub, err := d.Publicize(nil)
			if err != nil {
				return nil, err
			}
			ret = append(ret, pub)
		}
	}

	return ret, nil
}

func (k *testKex) CheckDeviceName(ctx context.Context, d *proto.DeviceLabelAndName) error {
	if k.cdnHook != nil {
		return k.cdnHook(ctx, d)
	}
	for k.u.deviceLabels[d.Label] {
		d.Label.Serial++
	}
	return nil
}

func (k *testKex) GetSessionFromUI(ctx context.Context) (proto.KexSecret, func(context.Context, error), error) {
	var err error
	var secret proto.KexSecret
	select {
	case secret = <-k.theirSessionCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	fmt.Printf("returning secret from UI -> %v\n", secret)
	return secret, func(ctx context.Context, err error) {
		k.secretInputErrCh <- err
	}, err
}
func (k *testKex) SendSessionToUI(ctx context.Context, s proto.KexSecret) error {
	k.mySessionCh <- s
	return nil
}
func (k *testKex) EndSessionExchange(context.Context, error) error {
	return nil
}
func (k *testKex) UI() libclient.KexUIer {
	return k
}

func (k *testKex) Keyer() libclient.KexLocalKeyer {
	return k
}

func (k *testKex) Server(ctx context.Context) (libclient.KexServer, error) {
	return k.ucli, nil
}

func (k *testKex) Router() libclient.KexRouter {
	return k.kexcli
}

func newTestKex(
	u *TestUser,
	ucli *rem.UserClient,
	kexcli *rem.KexClient,
) *testKex {
	return &testKex{
		u:                u,
		ucli:             ucli,
		kexcli:           kexcli,
		mySessionCh:      make(chan proto.KexSecret, 1),
		theirSessionCh:   make(chan proto.KexSecret, 1),
		secretInputErrCh: make(chan error, 1),
	}
}

func TestKexProvisionXDriving(t *testing.T) {

	ctx := context.Background()
	u, cleanup, kiX, kiY, X, Y := setupKexTest(t, ctx)
	defer cleanup()
	waitFn := runBoth(t, ctx, X, Y)

	secret := <-kiX.mySessionCh
	kiY.theirSessionCh <- secret

	waitFn()

	u.deviceLabels[X.DeviceLabelAndName().Label] = true
	priv, ok := Y.MyKey().(*core.PrivateSuite25519)
	require.True(t, ok)
	u.devices = append(u.devices, priv)
	u.userSeqno++
	u.rootEpno++

	var hash proto.LinkHash
	err := core.LinkHashInto(X.Link(), hash[:])
	require.NoError(t, err)
	u.prev = &hash
	if kiX.newPuk != nil {
		u.puks[kiX.rk] = *kiX.newPuk
	}
}

func runKex(t *testing.T, ctx context.Context, k libclient.KexActor, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		err := libclient.RunKex(ctx, k, time.Minute)
		require.NoError(t, err)
		wg.Done()
	}()
}

func runBoth(t *testing.T, ctx context.Context, X libclient.KexActor, Y libclient.KexActor) func() {
	var wg sync.WaitGroup
	run := func(k libclient.KexActor) { runKex(t, ctx, k, &wg) }
	run(X)
	run(Y)
	return func() {
		wg.Wait()
	}
}

func setupKexTest(t *testing.T, ctx context.Context) (
	*TestUser, func(), *testKex, *testKex,
	*libclient.KexProvisioner, *libclient.KexProvisionee,
) {
	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := newUserClient(ctx, crt)
	require.NoError(t, err)
	kexcli, kexCloseFn, err := newKexClient(ctx)
	require.NoError(t, err)

	kiX := newTestKex(u, ucli, kexcli)
	kiY := newTestKex(u, nil, kexcli)

	X := libclient.NewKexProvisioner(kiX, u.uid, u.host,
		proto.NewRoleDefault(proto.RoleType_OWNER),
		u.eldest)

	ss := core.RandomSecretSeed32()
	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	newkey, err := core.NewPrivateSuite25519(proto.EntityType_Device, role, ss, u.host)
	require.NoError(t, err)

	dn := proto.DeviceName("galaxy")
	dnn, err := core.NormalizeDeviceName(dn)
	require.NoError(t, err)

	dln := proto.DeviceLabelAndName{
		Name: dn,
		Label: proto.DeviceLabel{
			DeviceType: proto.DeviceType_Mobile,
			Name:       dnn,
			Serial:     proto.FirstDeviceSerial,
		},
	}

	Y := libclient.NewKexProvisionee(kiY, kiY, dln, newkey)
	cleanup := core.Compose(userCloseFn, kexCloseFn)

	return u, cleanup, kiX, kiY, X, Y
}

func TestKexBadSecretInputOnX(t *testing.T) {

	ctx := context.Background()
	_, cleanup, kiX, kiY, X, Y := setupKexTest(t, ctx)
	defer cleanup()
	waitFn := runBoth(t, ctx, X, Y)

	secret := <-kiY.mySessionCh
	secret[0] ^= 0x01
	kiX.theirSessionCh <- secret

	err := <-kiX.secretInputErrCh
	require.Error(t, err)
	require.IsType(t, core.KexBadSecretError{}, err)
	secret[0] ^= 0x01
	kiX.theirSessionCh <- secret

	waitFn()
}

func TestKexBadSecretInputOnY(t *testing.T) {

	ctx := context.Background()
	_, cleanup, kiX, kiY, X, Y := setupKexTest(t, ctx)
	defer cleanup()
	waitFn := runBoth(t, ctx, X, Y)

	secret := <-kiX.mySessionCh
	secret[0] ^= 0x01
	kiY.theirSessionCh <- secret

	err := <-kiY.secretInputErrCh
	require.Error(t, err)
	require.IsType(t, core.KexBadSecretError{}, err)
	secret[0] ^= 0x01
	kiY.theirSessionCh <- secret

	waitFn()
}

func TestKexProvisionYDriving(t *testing.T) {

	ctx := context.Background()
	_, cleanup, kiX, kiY, X, Y := setupKexTest(t, ctx)
	defer cleanup()
	waitFn := runBoth(t, ctx, X, Y)

	secret := <-kiY.mySessionCh
	kiX.theirSessionCh <- secret

	waitFn()
}

func testErrors(t *testing.T, xDrives bool, xErrors bool) {

	var intentionalError = errors.New("intentional error")
	ctx := context.Background()
	_, cleanup, kiX, kiY, X, Y := setupKexTest(t, ctx)

	if xErrors {
		kiX.cdnHook = func(ctx context.Context, d *proto.DeviceLabelAndName) error {
			return intentionalError
		}
	} else {
		Y.TestErrorHook = func() error { return intentionalError }
	}

	defer cleanup()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		err := libclient.RunKex(ctx, X, time.Minute)
		require.Error(t, err)
		if xErrors {
			require.Equal(t, intentionalError, err)
		} else {
			require.Equal(t, core.KexWrapperError{Err: intentionalError}, err)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		err := libclient.RunKex(ctx, Y, time.Minute)
		require.Error(t, err)
		if xErrors {
			require.Equal(t, core.KexWrapperError{Err: intentionalError}, err)
		} else {
			require.Equal(t, intentionalError, err)
		}
		wg.Done()
	}()

	if xDrives {
		secret := <-kiX.mySessionCh
		kiY.theirSessionCh <- secret
	} else {
		secret := <-kiY.mySessionCh
		kiX.theirSessionCh <- secret
	}

	wg.Wait()
}

func TestKexProvisionXDrivingXErrors(t *testing.T) { testErrors(t, true, true) }
func TestKexProvisionXDrivingYErrors(t *testing.T) { testErrors(t, true, false) }
func TestKexProvisionYDrivingYErrors(t *testing.T) { testErrors(t, false, false) }
func TestKexProvisionYDrivingXErrors(t *testing.T) { testErrors(t, false, true) }
