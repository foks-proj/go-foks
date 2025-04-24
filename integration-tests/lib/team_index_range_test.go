// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestTeamIndexRangeUpdate(t *testing.T) {
	tew := testEnvBeta(t)
	bob := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	t0 := tew.makeTeamForOwner(t, bob)
	m := tew.MetaContext()

	rng := func(s string) core.RationalRange {
		r, err := core.ParseRationalRange(s)
		require.NoError(t, err)
		return *r
	}

	tryChange := func(s string) error {
		nr := rng(s)

		_, err := t0.makeChangesFull(
			t,
			m,
			bob,
			nil,
			nil,
			makeChangesKnobs{
				md: []proto.ChangeMetadata{
					proto.NewChangeMetadataWithTeamindexrange(
						nr.Export(),
					),
				},
			},
		)
		return err
	}
	err := tryChange("00.01-10")
	require.Error(t, err)
	noIncludeErr := core.TeamError("previous range does not include new range")
	dupeErr := core.TeamError("index range is the same as the previous")
	require.Error(t, err)
	require.Equal(t, noIncludeErr, err)

	err = tryChange("01-30")
	require.NoError(t, err)
	tew.DirectMerklePokeInTest(t)
	err = tryChange("04-10.00ff")
	require.NoError(t, err)
	err = tryChange("04-10.00ff")
	require.Error(t, err)
	require.Equal(t, dupeErr, err)
	tew.DirectMerklePokeInTest(t)
	err = tryChange("03-10")
	require.Error(t, err)
	require.Equal(t, noIncludeErr, err)

	mu := tew.NewClientMetaContext(t, bob)
	_, tw, err := libclient.LoadTeamReturnLoader(mu, libclient.LoadTeamArg{
		Team:    t0.FQTeam(t),
		As:      bob.FQUser().FQParty(),
		Keys:    bob.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.Equal(t, rng("04-10.00ff").Export(), tw.Prot().Tir)

}
