// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestPUKMinder(t *testing.T) {
	tew := testEnvBeta(t)
	sm := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePoke(t)
	cm, clean := makeCliMetaContext(t)
	tew.pushShutdownHook(clean)
	uc := a.exportToUserContext(t)
	probe := makeProbe(t, tew.TestEnv, sm, cm, false)
	uc.SetHomeServer(probe)
	pm := libclient.NewPUKMinder(uc)
	set, err := pm.GetPUKSetForRole(cm, proto.OwnerRole)
	require.NoError(t, err)
	curr := set.Current()
	require.NotNil(t, curr)
	require.Equal(t, proto.FirstGeneration, curr.Metadata().Gen)

	// Now churn the sigchain and PUKs a bit
	rabbit := a.ProvisionNewDevice(t, a.eldest, "rabbit", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePoke(t)
	chipmunk := a.ProvisionNewDevice(t, rabbit, "chipmunk", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	a.RevokeDevice(t, chipmunk, rabbit)
	tew.DirectMerklePoke(t)

	// Reload should give gen=1 PUK
	pm.RefreshUser()
	set, err = pm.GetPUKSetForRole(cm, proto.OwnerRole)
	require.NoError(t, err)
	curr = set.Current()
	require.NotNil(t, curr)
	require.Equal(t, proto.Generation(2), curr.Metadata().Gen)

}
