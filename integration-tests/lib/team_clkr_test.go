// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestSingleTeamCLKR(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	A := tew.makeTeamForOwner(t, u)

	cpu2 := u.ProvisionNewDevice(t, u.eldest, "cpu2", proto.DeviceType_Computer, proto.OwnerRole)
	mu := tew.NewClientMetaContextWithDevice(t, u, u.eldest)

	mu.Infow("TestSimpleCLKR", "user", u.FQE(), "team", A.FQTeam(t), "label", "A")
	au := mu.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)

	loadTeam := func() {
		puks, err := mu.G().ActiveUser().RefreshPUKs(mu)
		require.NoError(t, err)
		_, err = libclient.LoadTeam(mu,
			libclient.LoadTeamArg{
				As:      au.FQParty(),
				Team:    A.FQTeam(t),
				Keys:    puks,
				SrcRole: proto.OwnerRole,
			},
		)
		require.NoError(t, err)
	}
	loadTeam()

	mu.Infow("TestSimpleCLKR", "stage", "no-op CLKR")

	clkr := libclient.NewCLKR(tmm, libclient.CLKROpts{})
	err := clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 0, len(clkr.Rekeys()))

	tew.DirectMerklePokeInTest(t)
	u.RevokeDevice(t, u.eldest, cpu2)
	tew.DirectMerklePokeInTest(t)

	clkr = libclient.NewCLKR(tmm, tew.clkrOpts(t))
	err = clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 1, len(clkr.Rekeys()))

	mu.Infow("TestSimpleCLKR", "stage", "success")

	loadTeam()
}

func (tew *TestEnvWrapper) clkrOpts(t *testing.T) libclient.CLKROpts {
	return libclient.CLKROpts{
		WaitFn: func(_ context.Context) error {
			tew.DirectMerklePokeInTest(t)
			return nil
		},
		WaitForMerkleRefresh: func(_ context.Context) error {
			tew.DirectMerklePokeInTest(t)
			return nil
		},
	}
}

// TestSimpleDiamondGraphCLKR sets up a team graph that looks like this:
//
// u -> A -> C
// u -> B -> C
//
// Here an edge from x to y means "x is a member of y".  Just to keep
// things simple, everything is an admin of everything else.
// The order of operations will be:
//
// 1. u,v are created
// 2. u makes A and B
// 3. v makes C
// 4. v adds A and B to C
// 3. u adds a device, and we ensure that CLKR is a noop
// 4. u revokes that device, and we ensure all teams rotate.
//
// For now this test is pretty simple, in that it doesn't involve multiple
// hosts, or teams we don't have permission to rotate.
func TestSimpleDiamondGraphCLKR(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUser(t)
	v := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()
	A := tew.makeTeamForOwner(t, u)

	A.setIndexRange(t, m, u, index0)
	B := tew.makeTeamForOwner(t, u)
	B.setIndexRange(t, m, u, index0)
	C := tew.makeTeamForOwner(t, v)
	C.setIndexRange(t, m, v, index1)

	tew.DirectMerklePokeInTest(t)
	tew.DirectMerklePokeInTest(t)
	C.absorb(A.hepks)
	C.absorb(B.hepks)

	// Add A and B as admins to C, making u transitively an admin of C.
	runLocalJoinSequenceForTeam(t, m, C, A, v, u, proto.AdminRole, proto.AdminRole)
	tew.DirectMerklePokeInTest(t)
	runLocalJoinSequenceForTeam(t, m, C, B, v, u, proto.AdminRole, proto.AdminRole)
	tew.DirectMerklePokeInTest(t)

	cpu2 := u.ProvisionNewDevice(t, u.eldest, "cpu2", proto.DeviceType_Computer, proto.OwnerRole)
	mu := tew.NewClientMetaContextWithDevice(t, u, u.eldest)

	mu = mu.WithLogTag("testrun")
	mu.Infow("TestSimpleCLKR", "user", u.FQE(), "team", A.FQTeam(t), "label", "A")
	mu.Infow("TestSimpleCLKR", "user", u.FQE(), "team", B.FQTeam(t), "label", "B")
	mu.Infow("TestSimpleCLKR", "user", v.FQE(), "team", C.FQTeam(t), "label", "C")

	au := mu.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)

	mu.Infow("TestSimpleCLKR", "stage", "no-op CLKR")

	clkr := libclient.NewCLKR(tmm, libclient.CLKROpts{})
	err := clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 0, len(clkr.Rekeys()))

	tew.DirectMerklePokeInTest(t)
	u.RevokeDevice(t, u.eldest, cpu2)
	tew.DirectMerklePokeInTest(t)

	mu.Infow("TestSimpleCLKR", "stage", "rotate CLKR")

	clkr = libclient.NewCLKR(tmm, tew.clkrOpts(t))

	err = clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 3, len(clkr.Rekeys()))

	mu.Infow("TestSimpleCLKR", "stage", "success")
}

func TestLongChainCLKR(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUser(t)
	v := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()
	A := tew.makeTeamForOwner(t, v)

	A.setIndexRange(t, m, v, index0)
	B := tew.makeTeamForOwner(t, v)
	B.setIndexRange(t, m, v, index1)
	C := tew.makeTeamForOwner(t, v)
	C.setIndexRange(t, m, v, index2)

	tew.DirectMerklePokeInTest(t)
	tew.DirectMerklePokeInTest(t)
	B.absorb(A.hepks)
	C.absorb(B.hepks)

	// v adds A to B as an admin
	runLocalJoinSequenceForTeam(t, m, B, A, v, v, proto.AdminRole, proto.AdminRole)
	tew.DirectMerklePokeInTest(t)

	// v adds B to C as an admin
	runLocalJoinSequenceForTeam(t, m, C, B, v, v, proto.AdminRole, proto.AdminRole)
	tew.DirectMerklePokeInTest(t)

	// v Adds u to A as an admin
	runLocalJoinSequenceForUser(t, m, A, v, u, proto.AdminRole, nil)
	tew.DirectMerklePokeInTest(t)

	cpu2 := u.ProvisionNewDevice(t, u.eldest, "cpu2", proto.DeviceType_Computer, proto.OwnerRole)
	mu := tew.NewClientMetaContextWithDevice(t, u, u.eldest)

	mu = mu.WithLogTag("testrun")
	mu.Infow("TestSimpleCLKR",
		"user.v", v.FQE(),
		"user.v", u.FQE(),
		"team.A", A.FQTeam(t),
		"team.B", B.FQTeam(t),
		"team.C", C.FQTeam(t),
	)

	au := mu.G().ActiveUser()
	require.NotNil(t, au)
	tmm := libclient.NewTeamMinder(au)

	mu.Infow("TestSimpleCLKR", "stage", "no-op CLKR")

	clkr := libclient.NewCLKR(tmm, libclient.CLKROpts{})
	err := clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 0, len(clkr.Rekeys()))

	tew.DirectMerklePokeInTest(t)
	u.RevokeDevice(t, u.eldest, cpu2)
	tew.DirectMerklePokeInTest(t)

	mu.Infow("TestSimpleCLKR", "stage", "rotate CLKR")

	clkr = libclient.NewCLKR(tmm, tew.clkrOpts(t))

	err = clkr.Run(mu)
	require.NoError(t, err)
	require.Equal(t, 3, len(clkr.Rekeys()))

	mu.Infow("TestSimpleCLKR", "stage", "success")
}
