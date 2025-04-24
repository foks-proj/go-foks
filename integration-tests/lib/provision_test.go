// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"sort"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func (u *TestUser) RevokeDevice(t *testing.T, signer core.PrivateSuiter, target core.PrivateSuiter) {
	err := u.AttemptRevokeDevice(t, signer, target)
	require.NoError(t, err)
}

func (u *TestUser) AttemptRevokeDevice(t *testing.T, signer core.PrivateSuiter, target core.PrivateSuiter) error {
	return u.AttemptRevokeDeviceWithTreeRoot(t, signer, target, nil)
}

func (u *TestUser) RevokeDeviceWithTreeRoot(t *testing.T, signer core.PrivateSuiter, target core.PrivateSuiter, rootp *proto.TreeRoot) {
	err := u.AttemptRevokeDeviceWithTreeRoot(t, signer, target, rootp)
	require.NoError(t, err)
}

func (u *TestUser) AttemptRevokeDeviceWithTreeRoot(
	t *testing.T,
	signer core.PrivateSuiter,
	target core.PrivateSuiter,
	rootp *proto.TreeRoot,
) error {

	var hepks proto.HEPKSet

	ctx := context.Background()

	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := u.newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()

	targetRole, err := core.ImportRole(target.GetRole())
	require.NoError(t, err)
	selfRevoke, err := core.PrivateSuiterEqual(signer, target)
	require.NoError(t, err)

	arg := rem.RevokeDeviceArg{}

	newPuks := make(map[core.RoleKey]core.SharedPrivateSuite25519)
	var newPukList []core.SharedPrivateSuite25519
	for rk, puk := range u.puks {
		if targetRole.LessThan(rk) || selfRevoke {
			newPuks[rk] = puk
			continue
		}
		ss := core.RandomSecretSeed32()
		newPuk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_PUKVerify,
			puk.Role,
			ss,
			puk.Md.Gen+1,
			u.host,
		)
		require.NoError(t, err)
		newPuks[rk] = *newPuk
		newPukList = append(newPukList, *newPuk)

		collectHEPK(t, &hepks, newPuk)
	}

	// Can only make seed chain after we know our new PUKs
	for role, puk := range u.puks {
		// If a <1,-5> device gets revoked, no need to rotate the <3,0> keys.
		// Recall <1,-5> is a member with -5 viz level, while <3,0> is an owner device
		if targetRole.LessThan(role) || selfRevoke {
			continue
		}
		newPuk := newPuks[role]
		require.NotNil(t, newPuk)

		sbox := newPuk.SecretBoxKey()
		fqe := proto.FQEntity{
			Entity: u.uid.EntityID(),
			Host:   u.host,
		}
		sks := puk.ExportToBoxCleartext(fqe)
		sb, err := core.SealIntoSecretBox(&sks, &sbox)
		require.NoError(t, err)

		// Fake the ciphertexts and nonces for now, server won't check
		scb := proto.SeedChainBox{
			Gen:  puk.Md.Gen,
			Role: puk.Role,
			Box:  *sb,
		}
		arg.SeedChain = append(arg.SeedChain, scb)
	}

	sort.Slice(newPukList, func(i, j int) bool {
		lt, err := newPukList[i].Role.LessThan(newPukList[j].Role)
		require.NoError(t, err)
		return lt
	})

	var newPukListInterface []core.SharedPrivateSuiter
	for _, puk := range newPukList {
		tmp := puk
		newPukListInterface = append(newPukListInterface, &tmp)
	}

	skb, err := core.NewSharedKeyBoxer(u.host, signer)
	require.NoError(t, err)

	for _, dev := range u.devices {
		// Skip the device we're revoking
		eq, err := core.PrivateSuiterEqual(dev, target)
		require.NoError(t, err)
		if eq || selfRevoke {
			continue
		}
		for rk, puk := range newPuks {
			drk, err := core.ImportRole(dev.GetRole())
			require.NoError(t, err)
			if drk.LessThan(rk) || targetRole.LessThan(rk) {
				continue
			}
			devPub, err := dev.Publicize(&u.host)
			require.NoError(t, err)
			err = skb.Box(&puk, devPub)
			require.NoError(t, err)
		}
	}

	tmp, err := skb.Finish()
	require.NoError(t, err)
	arg.PukBoxes = *tmp
	arg.Hepks = hepks

	targetPublic, err := target.Publicize(&u.host)
	require.NoError(t, err)

	var root proto.TreeRoot
	if rootp != nil {
		root = *rootp
	} else {
		root = u.NextRoot()
	}

	mlr, err := core.MakeRevokeLink(
		u.uid,
		u.host,
		signer,
		targetPublic,
		newPukListInterface,
		u.userSeqno,
		*u.prev,
		root,
	)
	link := mlr.Link
	arg.Link = *link
	arg.NextTreeLocation = *mlr.NextTreeLocation
	require.NoError(t, err)
	err = ucli.RevokeDevice(ctx, arg)
	if err != nil {
		return err
	}

	u.puks = newPuks
	u.userSeqno++
	b, err := core.LinkHash(link)
	require.NoError(t, err)
	u.prev = b
	u.addPuksToMatrix(t)

	// Now reomve the revoked device from the device list
	newDevices := []core.PrivateSuiter{}
	for _, dev := range u.devices {
		eq, err := core.PrivateSuiterEqual(dev, target)
		require.NoError(t, err)
		if !eq {
			tmp := dev
			newDevices = append(newDevices, tmp)
		}
	}
	u.devices = newDevices
	u.addPuksToMatrix(t)

	return nil
}

func (u *TestUser) ProvisionNewDevice(t *testing.T, provisioner core.PrivateSuiter, name string, typ proto.DeviceType, role proto.Role) core.PrivateSuiter {
	return u.ProvisionNewDeviceWithOpts(t, provisioner, name, typ, role, nil)
}

type ProvisionOpts struct {
	TreeRoot        *proto.TreeRoot
	Seed            *proto.SecretSeed32
	ReturnPostError bool
	PostError       error
}

func (u *TestUser) ProvisionNewDeviceWithOpts(
	t *testing.T,
	provisioner core.PrivateSuiter,
	name string,
	typ proto.DeviceType,
	role proto.Role,
	opts *ProvisionOpts,
) core.PrivateSuiter {

	ctx := context.Background()
	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := u.newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()

	var hepks proto.HEPKSet

	var ss proto.SecretSeed32
	if opts != nil && opts.Seed != nil {
		ss = *opts.Seed
	} else {
		ss = core.RandomSecretSeed32()
	}
	newDevice, err := core.NewPrivateSuite25519(proto.EntityType_Device, role, ss, u.host)
	require.NoError(t, err)

	collectHEPK(t, &hepks, newDevice)

	var root proto.TreeRoot

	if opts != nil && opts.TreeRoot != nil {
		root = *opts.TreeRoot
	} else {
		root = proto.TreeRoot{
			Epno: u.rootEpno,
			Hash: core.RandomMerkleRootHash(),
		}
		u.rootEpno++
	}

	dn := proto.DeviceName(name)
	dnn, err := core.NormalizeDeviceName(dn)
	require.NoError(t, err)

	dln := proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			DeviceType: typ,
			Name:       dnn,
			Serial:     proto.FirstDeviceSerial,
		},
		Name: dn,
	}

	signer := provisioner
	existingDevice, err := signer.Publicize(&u.host)
	require.NoError(t, err)

	roleRk, err := core.ImportRole(role)
	require.NoError(t, err)

	var newUserKey core.SharedPrivateSuiter

	puk, found := u.puks[*roleRk]

	skb, err := core.NewSharedKeyBoxer(u.host, signer)
	require.NoError(t, err)

	boxPUK := func(puk *core.SharedPrivateSuite25519, dev core.PrivateSuiter) {
		devPub, err := dev.Publicize(&u.host)
		require.NoError(t, err)
		err = skb.Box(puk, devPub)
		require.NoError(t, err)
	}

	if found {
		// If found, then all we need to do is to box for the new device
		boxPUK(&puk, newDevice)

	} else {

		// If not found, we need to post new public keys and then box for all devices that are equal to
		// or lower than this role
		pukSs := core.RandomSecretSeed32()
		puk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_User,
			role,
			pukSs,
			proto.FirstGeneration,
			u.host,
		)
		newUserKey = puk

		collectHEPK(t, &hepks, puk)

		require.NoError(t, err)
		allDevices := []core.PrivateSuiter{newDevice}
		for _, d := range u.devices {
			lt, err := d.GetRole().LessThan(role)
			require.NoError(t, err)
			if !lt {
				tmp := d
				allDevices = append(allDevices, tmp)
			}
		}
		for _, dev := range allDevices {
			boxPUK(puk, dev)
		}
		u.puks[*roleRk] = *puk
	}

	mlr, err := core.MakeProvisionLink(
		u.uid,
		u.host,
		existingDevice,
		newDevice,
		role,
		newUserKey,
		dln.Label,
		u.userSeqno,
		*u.prev,
		root,
		nil,
	)
	u.userSeqno++
	require.NoError(t, err)
	link := mlr.Link

	link, err = core.CountersignProvisionLink(link, signer)
	require.NoError(t, err)
	pukBoxes, err := skb.Finish()
	require.NoError(t, err)

	tok, err := core.NewPermissionToken()
	require.NoError(t, err)

	b, err := core.LinkHash(link)
	require.NoError(t, err)

	err = ucli.ProvisionDevice(ctx, rem.ProvisionDeviceArg{
		Link: *link,
		Dlnc: rem.DeviceLabelNameAndCommitmentKey{
			Dln:           dln,
			CommitmentKey: *mlr.DevNameCommitmentKey,
		},
		PukBoxes:         *pukBoxes,
		NextTreeLocation: *mlr.NextTreeLocation,
		SelfToken:        tok,
		Hepks:            hepks,
	})

	if err != nil && opts != nil && opts.ReturnPostError {
		opts.PostError = err
		return nil
	}

	require.NoError(t, err)
	u.prev = b
	u.devices = append(u.devices, newDevice)
	u.deviceLabels[dln.Label] = true
	u.addPuksToMatrix(t)

	return newDevice
}

var ownerRK = core.RoleKey{Typ: proto.RoleType_OWNER}

func makeDeviceLabelAndName(
	t *testing.T,
	n string,
	typ proto.DeviceType,
) proto.DeviceLabelAndName {
	dn := proto.DeviceName(n)
	dnn, err := core.NormalizeDeviceName(dn)
	require.NoError(t, err)
	return proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			DeviceType: typ,
			Name:       dnn,
			Serial:     proto.FirstDeviceSerial,
		},
		Name: dn,
	}
}

func TestProvision(t *testing.T) {

	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	ctx := context.Background()
	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()

	ss := core.RandomSecretSeed32()
	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	newDevice, err := core.NewPrivateSuite25519(proto.EntityType_Device, role, ss, u.host)
	require.NoError(t, err)

	hepk, err := newDevice.ExportHEPK()
	require.NoError(t, err)

	var hepks proto.HEPKSet
	hepks.Push(*hepk)

	root := proto.TreeRoot{
		Epno: 1001,
		Hash: core.RandomMerkleRootHash(),
	}
	dln := makeDeviceLabelAndName(t, "galaxy", proto.DeviceType_Mobile)

	existingDevice, err := u.eldest.Publicize(&u.host)
	require.NoError(t, err)
	puk, found := u.puks[ownerRK]
	require.True(t, found)

	skb, err := core.NewSharedKeyBoxer(u.host, u.eldest)
	require.NoError(t, err)
	newDevicePub, err := newDevice.Publicize(&u.host)
	require.NoError(t, err)
	err = skb.Box(&puk, newDevicePub)
	require.NoError(t, err)
	pukBoxes, err := skb.Finish()
	require.NoError(t, err)

	seqno := proto.ChainEldestSeqno + 1

	mlr, err := core.MakeProvisionLink(
		u.uid,
		u.host,
		existingDevice,
		newDevice,
		role,
		nil,
		dln.Label,
		seqno,
		*u.prev,
		root,
		nil,
	)
	require.NoError(t, err)
	link := mlr.Link
	seqno++

	link, err = core.CountersignProvisionLink(link, u.eldest)
	require.NoError(t, err)

	tok, err := core.NewPermissionToken()
	require.NoError(t, err)

	err = ucli.ProvisionDevice(ctx, rem.ProvisionDeviceArg{
		Link: *link,
		Dlnc: rem.DeviceLabelNameAndCommitmentKey{
			Dln:           dln,
			CommitmentKey: *mlr.DevNameCommitmentKey,
		},
		PukBoxes:         *pukBoxes,
		NextTreeLocation: *mlr.NextTreeLocation,
		SelfToken:        tok,
		Hepks:            hepks,
	})
	require.NoError(t, err)

	prev, err := core.LinkHash(link)
	require.NoError(t, err)

	u.devices = append(u.devices, newDevice)

	// Now make a "reader" device at a lower level. Note that
	// we are going to have to send up 3 boxes here, one for all
	// 3 existing devices.
	ss2 := core.RandomSecretSeed32()
	botRole := proto.NewRoleWithMember(-5)
	newDeviceBot, err := core.NewPrivateSuite25519(proto.EntityType_Device, botRole, ss2, u.host)
	require.NoError(t, err)
	pukSs := core.RandomSecretSeed32()
	botPuk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_User,
		botRole,
		pukSs,
		proto.FirstGeneration,
		u.host,
	)
	require.NoError(t, err)

	hepk, err = newDeviceBot.ExportHEPK()
	require.NoError(t, err)
	hepks.Push(*hepk)

	hepk, err = botPuk.ExportHEPK()
	require.NoError(t, err)
	hepks.Push(*hepk)

	skb, err = core.NewSharedKeyBoxer(u.host, newDevice)
	require.NoError(t, err)

	devices := []core.PrivateSuiter{u.eldest, newDevice, newDeviceBot}
	for _, dev := range devices {
		pub, err := dev.Publicize(&u.host)
		require.NoError(t, err)
		err = skb.Box(botPuk, pub)
		require.NoError(t, err)
	}
	boxes, err := skb.Finish()
	require.NoError(t, err)

	newDevicePublic, err := newDevice.Publicize(&u.host)
	require.NoError(t, err)

	makeArg := func() rem.ProvisionDeviceArg {

		mlr, err := core.MakeProvisionLink(
			u.uid,
			u.host,
			newDevicePublic,
			newDeviceBot,
			botRole,
			botPuk,
			dln.Label,
			seqno,
			*prev,
			root,
			nil,
		)
		require.NoError(t, err)
		link := mlr.Link

		link, err = core.CountersignProvisionLink(link, newDevice)
		require.NoError(t, err)

		// the correct arg, but let's test some failure cases
		ret := rem.ProvisionDeviceArg{
			Link: *link,
			Dlnc: rem.DeviceLabelNameAndCommitmentKey{
				Dln:           dln,
				CommitmentKey: *mlr.DevNameCommitmentKey,
			},
			PukBoxes:         *boxes,
			NextTreeLocation: *mlr.NextTreeLocation,
			Hepks:            hepks,
		}
		tok, err := core.NewPermissionToken()
		require.NoError(t, err)
		ret.SelfToken = tok
		dln.Label.Serial++
		return ret
	}

	(*prev)[0] ^= 0x4
	arg := makeArg()
	err = ucli.ProvisionDevice(ctx, arg)
	require.Error(t, err)
	require.Equal(t, core.PrevError("wrong prev hash"), err)

	(*prev)[0] ^= 0x4
	arg = makeArg()

	// not enough boxes
	allBoxes := boxes.Boxes
	boxes.Boxes = allBoxes[1:]
	arg.PukBoxes = *boxes
	err = ucli.ProvisionDevice(ctx, arg)
	require.Error(t, err)
	require.IsType(t, core.BoxError(""), err)
	require.Contains(t, err.Error(), "box missing for device")

	// too many boxes
	newBoxes := append([]proto.SharedKeyBox{allBoxes[0]}, allBoxes...)
	boxes.Boxes = newBoxes
	arg.PukBoxes = *boxes
	err = ucli.ProvisionDevice(ctx, arg)
	require.Error(t, err)
	require.IsType(t, core.BoxError(""), err)
	require.Contains(t, err.Error(), "repeated box")

	boxes.Boxes = allBoxes
	arg.PukBoxes = *boxes
	err = ucli.ProvisionDevice(ctx, arg)
	require.NoError(t, err)
}

func TestProvisionLibrary(t *testing.T) {
	u := GenerateNewTestUser(t)
	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	foobar := u.ProvisionNewDevice(t, u.eldest, "foobar", proto.DeviceType_Computer, role)
	boobar := u.ProvisionNewDevice(t, foobar, "boobar", proto.DeviceType_Computer, role)
	u.ProvisionNewDevice(t, boobar, "yoyobox", proto.DeviceType_Computer, role)
	u.ProvisionNewDevice(t, u.eldest, "doom", proto.DeviceType_Computer, role)
}

func TestSimpleRevoke(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)
	role := proto.NewRoleDefault(proto.RoleType_OWNER)

	foobar := u.ProvisionNewDevice(t, u.eldest, "foobar", proto.DeviceType_Computer, role)
	tew.DirectMerklePokeForLeafCheck(t)
	boobar := u.ProvisionNewDevice(t, foobar, "boobar", proto.DeviceType_Computer, role)
	tew.DirectMerklePokeForLeafCheck(t)
	u.RevokeDevice(t, foobar, u.eldest)
	tew.DirectMerklePokeForLeafCheck(t)
	u.RevokeDevice(t, boobar, foobar)
	err := u.AttemptRevokeDevice(t, boobar, boobar)
	require.Error(t, err)
	require.Equal(t, core.RevokeError("cannot revoke last owner device"), err)
}

func TestMultiLevelProvision(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	owner := proto.NewRoleDefault(proto.RoleType_OWNER)
	reader := proto.NewRoleWithMember(-4)
	lowly := proto.NewRoleWithMember(-8)
	king := u.ProvisionNewDevice(t, u.eldest, "king", proto.DeviceType_Computer, owner)
	tew.DirectMerklePokeForLeafCheck(t)
	chief := u.ProvisionNewDevice(t, king, "chief", proto.DeviceType_Computer, reader)
	tew.DirectMerklePokeForLeafCheck(t)
	u.RevokeDevice(t, king, u.eldest)
	tew.DirectMerklePokeForLeafCheck(t)
	u.ProvisionNewDevice(t, king, "lowly", proto.DeviceType_Computer, lowly)
	tew.DirectMerklePokeForLeafCheck(t)
	u.RevokeDevice(t, king, chief)
}
