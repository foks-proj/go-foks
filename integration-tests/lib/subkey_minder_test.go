// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/stretchr/testify/require"
)

func TestSubkeyMinder(t *testing.T) {
	tew := testEnvBeta(t)
	sm := tew.MetaContext()
	a := tew.NewTestUserYubi(t)
	tew.DirectMerklePoke(t)
	cm, clean := makeCliMetaContext(t)
	tew.pushShutdownHook(clean)
	probe := makeProbe(t, tew.TestEnv, sm, cm, false)

	// First time should hit server, next time should hit local DB.
	// This just tests the subkey minder, but doesn't do much with the
	// subkey yielded from the test...
	for i := 0; i < 2; i++ {
		priv, err := libclient.LoadSubkey(cm, a.uid, probe, a.eldest)
		require.NoError(t, err)
		require.NotNil(t, priv)
	}

	// now test that we can use and load the subkey in context
	uc := a.exportToUserContext(t)
	uc.SetHomeServer(probe)
	cli, err := uc.UserClient(cm)
	require.NoError(t, err)
	_, err = cli.Ping(cm.Ctx())
	require.NoError(t, err)
}
