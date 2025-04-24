// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestSelfSecret(t *testing.T) {

	bg := context.Background()
	disp, err := AllocDispatchTest()
	require.NoError(t, err)

	var secrets []proto.SecretSeed32
	for i := 0; i < 2; i++ {
		core := disp.nextTestKeyCore(bg, t)
		require.NotNil(t, core)
		secret, err := core.GenerateSelfSecret(bg)
		require.NoError(t, err)
		require.NotNil(t, secret)
		secrets = append(secrets, *secret)
	}
	require.NotEqual(t, secrets[0], secrets[1])
}
