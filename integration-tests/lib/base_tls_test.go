// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestInternalCA(t *testing.T) {
	te := testEnvBeta(t)
	m := te.MetaContext()
	g := m.G()

	// Last writer wins on this field, which is slightly weird.
	typ := g.GetServerType()
	require.Equal(t, proto.ServerType_Autocert, typ)
	acli, clean, err := g.AutocertCli(m.Ctx())
	require.NoError(t, err)
	defer clean()

	err = acli.Poke(m.Ctx())
	require.NoError(t, err)
}

func TestExternalCAAgainstVHosts(t *testing.T) {

	tew := testEnvBeta(t)
	vHostID := tew.VHostMakeI(t, 2)
	require.NotNil(t, vHostID)
	alice := tew.NewTestUserAtVHost(t, vHostID)
	ucli := tew.userCli(t, alice)
	_, err := ucli.Ping(context.Background())
	require.NoError(t, err)

	mc := tew.NewClientMetaContext(t, alice)
	ucli, err = mc.G().ActiveUser().UserClient(mc)
	require.NoError(t, err)
	_, err = ucli.Ping(mc.Ctx())
	require.NoError(t, err)
}
