// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestBadSigningKey(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	a := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)

	// Create device Beta and then revoke it.
	tr := getCurrentTreeRoot(t, m)
	beta := a.ProvisionNewDeviceWithOpts(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole,
		&ProvisionOpts{TreeRoot: &tr})
	tew.DirectMerklePokeForLeafCheck(t)
	err := a.AttemptRevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	require.NoError(t, err)

	tr = getCurrentTreeRoot(t, m)
	opts := &ProvisionOpts{
		TreeRoot:        &tr,
		ReturnPostError: true,
	}
	gamma := a.ProvisionNewDeviceWithOpts(t, beta, "gamma 3.3c", proto.DeviceType_Computer, proto.OwnerRole, opts)
	require.Nil(t, gamma)
	require.Error(t, opts.PostError)
	require.Equal(t, core.ValidationError("signing key wasn't a current device"), opts.PostError)
}
