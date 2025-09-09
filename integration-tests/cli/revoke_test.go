// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func testRevokeSetup(
	t *testing.T,
	withPassphrase bool,
) (
	*testAgent,
	*testAgent,
	proto.Passphrase,
) {

	ao := agentOpts{}
	if withPassphrase {
		ao.defaultKeyEncryptionMode = "passphrase"
	}
	x := newTestAgentWithOpts(t, ao)
	x.runAgent(t)

	y := newTestAgentWithOpts(t, ao)
	y.runAgent(t)

	pp := core.RandomPassphrase()

	runProvisionOnAgents(
		t,
		provOpts{
			enterHespOnX: true,
			x:            x,
			y:            y,
			signupHook: func(x *mockSignupUI) *mockSignupUI {
				if withPassphrase {
					x.passphrase = pp
				}
				return x
			},
		},
	)
	return x, y, pp
}

func testRevokeHappyPath(t *testing.T, withPassphrase bool) {

	x, y, pp := testRevokeSetup(t, withPassphrase)
	defer x.stop(t)
	defer y.stop(t)

	yInfo := getActiveUser(t, y)
	yKey, err := yInfo.Key.StringErr()
	require.NoError(t, err)

	stopper := runMerkleActivePoker(t)
	defer stopper()
	userX := getActiveUser(t, x)

	// Revoke y's key.
	x.runCmd(t, nil, "key", "revoke", yKey)

	// test tha y has troubles authenticating
	y.runCmd(t, nil, "test", "clear-user-state")
	err = y.runCmdErr(nil, "user", "load-me")
	require.Error(t, err)
	require.Equal(t, core.ChainLoaderError{Err: core.AuthError{}, Race: false}, err)

	var ss lcl.SecretStore
	y.runCmdToJSON(t, &ss, "test", "dump-secret-store")
	v, err := ss.GetV()
	require.NoError(t, err)
	require.Equal(t, lcl.SecretStoreVersion_V2, v)
	v2 := ss.V2()
	require.Equal(t, 1, len(v2.Keys))
	require.Equal(t, yInfo.Key, v2.Keys[0].KeyID.EntityID())

	y.runCmd(t, nil, "test", "trigger-bg-user-job")
	y.runCmdToJSON(t, &ss, "test", "dump-secret-store")
	v, err = ss.GetV()
	require.NoError(t, err)
	require.Equal(t, lcl.SecretStoreVersion_V2, v)
	v2 = ss.V2()
	require.Equal(t, 0, len(v2.Keys))

	// Revoke y's key again?.
	err = x.runCmdErr(nil, "key", "revoke", yKey)
	require.Error(t, err)
	require.Equal(t, core.RevokeError("device already revoked"), err)

	if !withPassphrase {
		return
	}

	x.stop(t)
	x.runAgent(t)
	verifyPassphraseLockedThenUnlock(t, x, userX, pp, 2)

}

func TestRevokeHappyPathWithoutPassphrase(t *testing.T) {
	testRevokeHappyPath(t, false)
}

func TestRevokeHappyPathWithPassphrase(t *testing.T) {
	testRevokeHappyPath(t, true)
}

// X sets a passphrase.
// X provisions Y
// X provisions Z
// X revokes Y
// Z rotates passphrase
func TestRevokeThreeWayWithPassphraseRotation(t *testing.T) {

	x, y, pp := testRevokeSetup(t, true)
	defer x.stop(t)
	defer y.stop(t)

	ao := agentOpts{defaultKeyEncryptionMode: "passphrase"}
	z := newTestAgentWithOpts(t, ao)
	z.runAgent(t)

	userX := getActiveUser(t, x)
	stopper := runMerkleActivePoker(t)
	defer stopper()

	runProvisionOnAgents(
		t,
		provOpts{
			enterHespOnX: true,
			x:            x,
			y:            z,
			noSignup:     true,
			nameY:        proto.DeviceName("Cobra Kai C3.3c"),
		},
	)
	yInfo := getActiveUser(t, y)
	yKey, err := yInfo.Key.StringErr()
	require.NoError(t, err)

	// Revoke y's key.
	x.runCmd(t, nil, "key", "revoke", yKey)

	// Force the background cleaner job on Z.
	z.runCmd(t, nil, "test", "trigger-bg-user-job")

	// Now Z should be rotate onto the new passhrase generation
	z.stop(t)
	z.runAgent(t)
	verifyPassphraseLockedThenUnlock(t, z, userX, pp, 2)
}

// Sign up user A on X
// Sign up user B on X
// Provision user A on Y
// Revoke user B on device X from Y
// Test that user B is deleted from X
// Test that user A is still there
func TestRevokeAndSelfDelete(t *testing.T) {
	testRevokeAndSelfDeleteOptionalFlush(t, false)
}

func TestRevokeAndSelfDeleteWithflush(t *testing.T) {
	testRevokeAndSelfDeleteOptionalFlush(t, true)
}

func testRevokeAndSelfDeleteOptionalFlush(t *testing.T, doFlush bool) {

	beaconRegister(t)
	x := newTestAgentWithOpts(t, agentOpts{})
	x.runAgent(t)
	defer x.stop(t)

	dn := proto.DeviceName("User A on Device X should be retained")
	signupUI := newMockSignupUI().withDeviceKey().withDeviceName(dn)
	uis := libclient.UIs{
		Signup:   signupUI,
		Terminal: &terminalUI{},
	}

	x.runCmdWithUIs(t, uis, "--simple-ui", "signup")
	stopper := runMerkleActivePoker(t)
	defer stopper()
	userAonX := getActiveUser(t, x)
	fmt.Printf("%+v\n", userAonX)

	y := newTestAgentWithOpts(t, agentOpts{defaultKeyEncryptionMode: "passphrase"})
	y.runAgent(t)

	pp := core.RandomPassphrase()

	runProvisionOnAgents(
		t,
		provOpts{
			enterHespOnX: true,
			x:            x,
			y:            y,
			signupHook: func(x *mockSignupUI) *mockSignupUI {
				x.passphrase = pp
				return x
			},
		},
	)

	userBonX := getActiveUser(t, x)
	bxKey, err := userBonX.Key.StringErr()
	require.NoError(t, err)

	// Revoke user B's key on device X
	y.runCmd(t, nil, "key", "revoke", bxKey)

	if doFlush {
		// Force background cleaner on device X
		x.runCmd(t, nil, "test", "clear-user-state")
	}

	// Force background cleaner on device X
	x.runCmd(t, nil, "test", "trigger-bg-user-job")

	var status lcl.AgentStatus
	x.runCmdToJSON(t, &status, "status")

	require.Equal(t, 1, len(status.Users))
	require.Equal(t, userAonX.Info.Fqu, status.Users[0].Info.Fqu)
	require.False(t, status.Users[0].Info.Active)
}

// User A signs up via Yubi, then self-provisions a real device, then
// switches to the yubi, then revokes the real device. The user should no
// longer show up in `user list` as a real device after the revoke.
func TestSelfProvisionThenRevoke(t *testing.T) {

	beaconRegister(t)
	a := newTestAgentWithOpts(t, agentOpts{})
	a.runAgent(t)
	defer a.stop(t)
	var signupUI mockSignupUI
	var terminalUI terminalUI
	uis := libclient.UIs{
		Signup:   &signupUI,
		Terminal: &terminalUI,
	}
	stopper := runMerkleActivePoker(t)
	defer stopper()

	a.runCmdWithUIs(t, uis, "--simple-ui", "signup")

	aInfoYubi := getActiveUser(t, a)
	aStr := fquString(t, aInfoYubi.Info, false, false)

	dn := proto.DeviceName("zodobomb 3.14+")
	a.runCmd(t, nil, "key", "dev", "perm", "--name", string(dn))

	findDevice := func() bool {
		var klres lcl.KeyListRes
		args := []string{"key", "list"}
		a.runCmdToJSON(t, &klres, args...)
		for _, d := range klres.AllUsers {
			if d.Info.KeyGenus == proto.KeyGenus_Device {
				return true
			}
		}
		return false
	}

	require.True(t, findDevice())

	aInfoDev := getActiveUser(t, a)
	yubiDev, err := aInfoYubi.Key.StringErr()
	require.NoError(t, err)
	a.runCmd(t, nil, "key", "switch", "-u", aStr, "--key-id", yubiDev)

	dev, err := aInfoDev.Key.StringErr()
	require.NoError(t, err)

	a.runCmd(t, nil, "key", "revoke", dev)

	require.False(t, findDevice())
}

func TestYubiNewThenRevoke(t *testing.T) {
	beaconRegister(t)
	a := newTestAgentWithOpts(t, agentOpts{})
	a.runAgent(t)
	defer a.stop(t)
	var signupUI mockSignupUI
	uis := libclient.UIs{
		Signup: signupUI.withDeviceKey(),
	}
	stopper := runMerkleActivePoker(t)
	defer stopper()

	a.runCmdWithUIs(t, uis, "--simple-ui", "signup")

	var cardList []proto.YubiCardID
	a.runCmdToJSON(t, &cardList, "yubi", "ls")
	require.True(t, len(cardList) > 0)
	serial := cardList[0].Serial

	itoa := func(i any) string { return fmt.Sprintf("%d", i) }

	var lysRes lcl.ListYubiSlotsRes
	a.runCmdToJSON(t, &lysRes, "yubi", "ls", "--serial", itoa(serial))
	require.Greater(t, len(lysRes.Device.Keys), 1)

	// To conserve key slots, we just reuse the PQ slot from the first
	// key in-use key  we find.
	var slot, pqSlot proto.YubiSlot
	for _, s := range lysRes.Device.Keys {
		if !usedKeySlots[s.Slot] && slot == 0 {
			slot = s.Slot
			usedKeySlots[s.Slot] = true
		} else if pqSlot == 0 {
			pqSlot = s.Slot
		}
		if pqSlot != 0 && slot != 0 {
			break
		}
	}

	require.True(t, slot != 0 && pqSlot != 0)
	merklePoke(t)

	a.runCmd(t, nil, "yubi", "new", "--serial", itoa(serial),
		"--slot", itoa(slot),
		"--pq-slot", itoa(pqSlot),
		"--name", "zoombomb 3.14+")

	merklePoke(t)
	var ret lcl.KeyListRes
	var found proto.EntityID
	a.runCmdToJSON(t, &ret, "key", "list", "--json")
	for _, k := range ret.CurrUserAllKeys {
		id := k.Di.Key.Member.Id.Entity
		if id.Type() == proto.EntityType_Yubi {
			found = id
			break
		}
	}
	dev, err := found.StringErr()
	require.NoError(t, err)

	a.runCmd(t, nil, "key", "revoke", dev)
}

// The observed sequence of operations for Bug 8 was:
// 1. Provision with yubi
// 2. Self-provision device
// 3. Make backup
// 4. Revoke backup
func TestIssue8(t *testing.T) {
	if libyubi.GetRealForce() {
		t.Skip("skipping test in real mode to save yubi slots")
	}
	stopper := runMerkleActivePoker(t)
	defer stopper()

	ua := makeFreshUserWithAgent(t)
	ag := ua.agent
	defer ua.stop(t)
	newDevName := proto.DeviceName("d1")
	ag.runCmd(t, nil, "key", "dev", "perm", "--name", string(newDevName), "--role", "o")
	ag.runCmd(t, nil, "backup", "new")
	var klres lcl.KeyListRes
	ag.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 3, len(klres.CurrUserAllKeys))

	var bkp proto.EntityID

	for _, d := range klres.CurrUserAllKeys {
		if d.Di.Dn.Label.DeviceType == proto.DeviceType_Backup {
			d := d
			bkp = d.Di.Key.Member.Id.Entity
			break
		}
	}
	require.NotNil(t, bkp)
	bkpS, err := bkp.StringErr()
	require.NoError(t, err)
	ag.runCmd(t, nil, "key", "revoke", bkpS)
}

// 1. Signup on device x
// 2. provision device y
// 3. self-revoke device y on y
// 4. restart agent on y
// ----
// While we are here, do 3 more things:
// 1. Confirm that the PUK didn't get rotated (on X)
// 2. Poke a background job (on X)
// 3. Confirm rotation (on X)
func TestIssue92(t *testing.T) {

	opts := agentOpts{}
	x := newTestAgentWithOpts(t, opts)
	y := newTestAgentWithOpts(t, opts)
	x.runAgent(t)
	y.runAgent(t)

	defer func() {
		x.stop(t)
		y.stop(t)
	}()

	runProvisionOnAgents(t, provOpts{x: x, y: y})
	yInfo := getActiveUser(t, y)
	yKey, err := yInfo.Key.StringErr()
	require.NoError(t, err)

	stopper := runMerkleActivePoker(t)
	defer stopper()

	// ensure we find the key in the macos keychain

	// Revoke y's key.
	y.runCmd(t, nil, "key", "revoke", yKey)

	y.stop(t)
	y.runAgent(t)

	maxPUKGen := func(t *testing.T, a *testAgent) proto.Generation {
		var res lcl.UserMetadataAndSigchainState
		a.runCmdToJSON(t, &res, "user", "load-me")
		var maxGen proto.Generation
		for _, puk := range res.State.Puks {
			if puk.Gen > maxGen {
				maxGen = puk.Gen
			}
		}
		return maxGen
	}

	// First assert that no rotation happened on self-revoke
	mpg := maxPUKGen(t, x)
	require.Equal(t, mpg, proto.Generation(1))

	x.runCmd(t, nil, "test", "trigger-bg-user-job")

	mpg = maxPUKGen(t, x)
	require.Equal(t, mpg, proto.Generation(2))

}
