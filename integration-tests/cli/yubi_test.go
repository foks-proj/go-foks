// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestYubiSetPIN(t *testing.T) {
	if libyubi.GetRealForce() {
		t.Skip("test changes PIN and PUK on Yubi, so not doing it a real key")
	}
	var bob userAgentBundle
	bob.init(t, true)
	merklePoke(t)
	b := bob.agent
	defer b.stop(t)

	status := b.status(t)
	require.Equal(t, 1, len(status.Users))
	eldest := status.Users[0].Key
	username := status.Users[0].Info.Username.Name

	var cardList []proto.YubiCardID
	b.runCmdToJSON(t, &cardList, "yubi", "ls")

	itoa := func(i any) string { return fmt.Sprintf("%d", i) }

	require.True(t, len(cardList) > 0)
	serial := cardList[0].Serial
	var res lcl.SetOrGetManagementKeyRes
	b.runCmdToJSON(t, &res,
		"yubi", "set-pin",
		"--serial", itoa(serial),
		"--new-pin", "121212",
		"--new-puk", "23232323",
	)
	require.True(t, res.WasMade)
	err := b.runCmdErr(nil,
		"yubi", "set-pin",
		"--serial", itoa(serial),
		"--new-pin", "121212",
		"--new-puk", "23232323",
	)
	require.Error(t, err)
	require.Equal(t, core.YubiAuthError{Retries: 2}, err)
	goodPin := proto.YubiPIN("343434")

	var res2 lcl.SetOrGetManagementKeyRes
	b.runCmdToJSON(t, &res2,
		"yubi", "set-pin",
		"--serial", itoa(serial),
		"--current-pin", "121212",
		"--new-pin", goodPin.String(),
		"--new-puk", "56565656",
		"--current-puk", "23232323",
	)
	require.False(t, res2.WasMade)
	require.Equal(t, res.Key, res2.Key)
	mk := res2.Key

	// check that pin unlock with the wrong key fails
	err = b.runCmdErr(nil,
		"yubi", "unlock",
		"--pin", "343438",
	)
	require.Error(t, err)
	require.Equal(t, core.YubiAuthError{Retries: 2}, err)

	// check that pin unlock with the right key works
	runPinUnlock := func() {
		b.runCmd(t, nil, "yubi", "unlock", "--pin", goodPin.String())
	}
	runPinUnlock()

	var lysRes lcl.ListYubiSlotsRes
	b.runCmdToJSON(t, &lysRes, "yubi", "ls", "--serial", itoa(serial))
	require.Greater(t, len(lysRes.Device.EmptySlots), 1)

	// clear out stored secrets, now we should fail to make a new key
	// because we don't have a management key loaded into memory.
	clear := func() {
		bob.agent.g.YubiDispatch().ClearSecrets()
	}
	clear()

	slots := lysRes.Device.EmptySlots
	require.Greater(t, len(slots), 3)

	err = b.runCmdErr(nil, "yubi", "new", "--serial", itoa(serial),
		"--slot", itoa(slots[0]), "--pq-slot", itoa(slots[1]), "--name", "zoombomb 3.14+")
	require.Error(t, err)
	require.Equal(t, core.YubiAuthError{Retries: 0}, err)

	// should work once we supply the managemnt key
	runPinUnlock()
	b.runCmd(t, nil, "yubi", "new", "--serial", itoa(serial),
		"--slot", itoa(slots[0]), "--pq-slot", itoa(slots[1]), "--name", "zoombomb 3.14+")
	merklePoke(t)

	// now make a pin-protected key
	b.runCmd(t, nil, "yubi", "new",
		"--serial", itoa(serial),
		"--slot", itoa(slots[2]),
		"--pq-slot", itoa(slots[3]),
		"--name", "zoombomb 3.1415+",
		"--pin", goodPin.String(),
		"--lock-with-pin",
	)
	merklePoke(t)

	// now make this new key the active key
	b.runCmd(t, nil, "yubi", "use", "--serial", itoa(serial), "--slot", itoa(slots[2]))

	clear()
	// clear out all PUKs
	b.runCmd(t, nil, "key", "lock")

	au := getActiveUser(t, b)
	require.False(t, userIsUnlocked(*au))
	require.IsType(t, core.YubiLockedError{}, core.StatusToError(au.LockStatus))

	err = b.runCmdErr(nil,
		"yubi", "unlock",
	)
	require.Error(t, err)
	require.Equal(t, core.YubiPINRequredError{}, err)

	runPinUnlock()

	au = getActiveUser(t, b)
	require.True(t, userIsUnlocked(*au))
	require.IsType(t, nil, core.StatusToError(au.LockStatus))

	failPinUnlock := func(i int) {
		err := b.runCmdErr(nil, "yubi", "unlock", "--pin", "898989")
		require.Error(t, err)
		require.Equal(t, core.YubiAuthError{Retries: i}, err)
	}

	breakIt := func() {

		for i := 2; i >= 0; i-- {
			failPinUnlock(i)
		}
		failPinUnlock(0)

		// Should still fail even if we supply the right PIN!
		err = b.runCmdErr(nil, "yubi", "unlock", "--pin", goodPin.String())
		require.Error(t, err)
		require.Equal(t, core.YubiAuthError{Retries: 0}, err)

	}

	breakIt()

	fixIt := func(withKey bool) {
		args := []string{
			"yubi", "recover",
			"--serial", itoa(serial),
			"--new-pin", goodPin.String(),
			"--new-puk", "00000000",
		}
		if withKey {
			args = append(args, "--management-key", mk.String())
		}
		b.runCmd(t, nil,
			args...,
		)
	}

	fixIt(true)
	runPinUnlock()

	// Now make it a permanent device, and switch onto that device.
	stopper := runMerkleActivePoker(t)
	defer stopper()
	b.runCmd(t, nil, "key", "dev", "perm", "--name", "device B.2")

	fixIt(false)
	estr, err := eldest.StringErr()
	require.NoError(t, err)
	b.runCmd(t, nil, "key", "switch", "-u", username.String(), "--key-id", estr)
	runPinUnlock()
}
