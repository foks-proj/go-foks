// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func newYubi(t *testing.T, disp *Dispatch, role proto.Role, hid proto.HostID) *KeySuiteHybrid {
	return disp.NextTestKey(context.Background(), t, role, hid)
}

func newDevice(t *testing.T, role proto.Role, hid proto.HostID) *core.PrivateSuite25519 {
	sx := core.RandomSecretSeed32()
	x, err := core.NewPrivateSuite25519(proto.EntityType_Device, role, sx, hid)
	require.NoError(t, err)
	return x
}

func TestBoxUnboxDevYubi(t *testing.T)  { testBoxUnbox(t, false, true) }
func TestBoxUnboxYubiDev(t *testing.T)  { testBoxUnbox(t, true, false) }
func TestBoxUnboxYubiYubi(t *testing.T) { testBoxUnbox(t, true, true) }
func TestBoxUnboxDevDev(t *testing.T)   { testBoxUnbox(t, false, false) }

type boxUnboxState struct {
	ss   proto.SecretSeed32
	x    core.PrivateSuiter
	y    core.PrivateSuiter
	xPub core.PublicSuiter
	yPub core.PublicSuiter
	tmp  *proto.TempDHKeySigned
	set  *proto.BoxSetID
	sbs  *proto.SharedKeyBoxSet
	disp *Dispatch
}

func (s *boxUnboxState) cleanup() {
}

func setupBoxUnbox(t *testing.T, xIsYubi bool, yIsYubi bool) *boxUnboxState {

	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	hostID := core.RandomHostID()

	disp, err := AllocDispatchTest()
	require.NoError(t, err)

	alloc := func(isYubi bool) core.PrivateSuiter {
		if isYubi {
			return newYubi(t, disp, role, hostID)
		}
		return newDevice(t, role, hostID)
	}
	x := alloc(xIsYubi)
	y := alloc(yIsYubi)

	ss := core.RandomSecretSeed32()
	newPuk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_User,
		role,
		ss,
		0,
		hostID,
	)
	require.NoError(t, err)

	yPub, err := y.Publicize(&hostID)
	require.NoError(t, err)
	xPub, err := x.Publicize(&hostID)
	require.NoError(t, err)

	sbs, err := core.BoxOne(hostID, newPuk, x, yPub)
	require.NoError(t, err)

	var tmp *proto.TempDHKeySigned
	var setId *proto.BoxSetID

	if xIsYubi != yIsYubi {
		tmp = sbs.TempDHKeySigned
		setId = &sbs.Id
	}
	state := boxUnboxState{
		ss:   ss,
		x:    x,
		y:    y,
		xPub: xPub,
		yPub: yPub,
		tmp:  tmp,
		set:  setId,
		sbs:  sbs,
		disp: disp,
	}
	return &state
}

func testBoxUnbox(t *testing.T, xIsYubi bool, yIsYubi bool) {
	s := setupBoxUnbox(t, xIsYubi, yIsYubi)
	defer s.cleanup()

	// Now unbox it
	var sks proto.SharedKeySeed
	err := core.OpenBoxInSet(&sks, s.sbs.Boxes[0].Box, s.tmp, s.set, s.xPub, s.y)
	require.NoError(t, err)
	require.Equal(t, s.ss, sks.Seed)
}

func TestBoxUnboxDevYubiBadBox(t *testing.T) {
	s := setupBoxUnbox(t, false, true)
	defer s.cleanup()

	// First test a bad sig over the temporary key breaks the decryption
	tmp := *s.tmp
	tmp.Sig.F_0__[8] ^= 0x01
	var sks proto.SharedKeySeed
	err := core.OpenBoxInSet(&sks, s.sbs.Boxes[0].Box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.VerifyError(""), err)
	tmp.Sig.F_0__[8] ^= 0x01

	// Also try to break the DH key, but it should still fail the sig verification
	tmp = *s.tmp
	tmp.TempDHKey.Key.F_1__.Bytes()[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, s.sbs.Boxes[0].Box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	tmp.TempDHKey.Key.F_1__.Bytes()[4] ^= 0x01

	// Break the nonce for the inner secret box
	tmp = *s.tmp
	box := s.sbs.Boxes[0].Box
	box.F_2__.F_1__.Sbox.F_0__.Nonce[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.Sbox.F_0__.Nonce[4] ^= 0x01

	// Break the ciphertext for the inner secret box
	box.F_2__.F_1__.Sbox.F_0__.Ciphertext[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.Sbox.F_0__.Ciphertext[4] ^= 0x01

	// Break the KEM ciphertext
	box.F_2__.F_1__.KemCtext[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.KemCtext[4] ^= 0x01
}

func TestBoxUnboxYubiDevBadBox(t *testing.T) {
	s := setupBoxUnbox(t, true, false)
	defer s.cleanup()

	// First test a bad sig over the temporary key breaks the decryption
	tmp := *s.tmp
	tmp.Sig.F_1__.Bytes()[8] ^= 0x01
	var sks proto.SharedKeySeed
	err := core.OpenBoxInSet(&sks, s.sbs.Boxes[0].Box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.VerifyError(""), err)
	tmp.Sig.F_1__.Bytes()[8] ^= 0x01

	// Also try to break the DH key, but it should still fail the sig verification
	tmp = *s.tmp
	tmp.TempDHKey.Key.F_0__[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, s.sbs.Boxes[0].Box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	tmp.TempDHKey.Key.F_0__[4] ^= 0x01

	// Break the nonce for the inner secret box
	tmp = *s.tmp
	box := s.sbs.Boxes[0].Box
	box.F_2__.F_1__.Sbox.F_0__.Nonce[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.Sbox.F_0__.Nonce[4] ^= 0x01

	// Break the ciphertext for the inner secret box
	box.F_2__.F_1__.Sbox.F_0__.Ciphertext[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.Sbox.F_0__.Ciphertext[4] ^= 0x01

	// Break the KEM ciphertext
	box.F_2__.F_1__.KemCtext[4] ^= 0x01
	err = core.OpenBoxInSet(&sks, box, &tmp, s.set, s.xPub, s.y)
	require.Error(t, err)
	require.IsType(t, core.DecryptionError{}, err)
	box.F_2__.F_1__.KemCtext[4] ^= 0x01
}
