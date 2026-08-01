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
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}

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

// TestMixedRoleCLKR checks that CLKR refreshes a member's keys without
// changing that member's role.
//
// In the other CLKR tests here, the actor's role already equals the role of
// every member CLKR actually rekeys, so a rekey that stamped the actor's role
// onto each member it touched would pass all of them.
//
// Here v owns the team and u is a member at the default viz level. u revokes a
// device, which rolls u's PUK and is the condition CLKR keys off of; then v's
// CLKR run picks u up. u must come back at the role they started with.
func TestMixedRoleCLKR(t *testing.T) {
	tew := testEnvBeta(t)
	v := tew.NewTestUser(t)
	u := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()
	A := tew.makeTeamForOwner(t, v)
	readerRole := proto.NewRoleWithMember(0)

	runLocalJoinSequenceForUser(t, m, A, v, u, readerRole, nil)
	tew.DirectMerklePokeInTest(t)

	// Roll u's PUK, so that CLKR has something to do.
	// The double poke is required, not belt-and-braces: provision_epno is
	// written by the batcher pass *after* the one that stages the leaf, and
	// RevokeDevice rejects a signer whose provision_epno is still NULL.
	cpu2 := u.ProvisionNewDevice(t, u.eldest, "cpu2", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectDoubleMerklePokeInTest(t)
	u.RevokeDevice(t, u.eldest, cpu2)
	tew.DirectMerklePokeInTest(t)

	// v, the owner, runs the background rekey.
	mv := tew.NewClientMetaContextWithDevice(t, v, v.eldest)
	mv = mv.WithLogTag("testrun")
	av := mv.G().ActiveUser()
	require.NotNil(t, av)
	tmm := libclient.NewTeamMinder(av)

	clkr := libclient.NewCLKR(tmm, tew.clkrOpts(t))
	err := clkr.Run(mv)
	require.NoError(t, err)
	require.Equal(t, 1, len(clkr.Rekeys()))

	twr, err := libclient.LoadTeam(mv, libclient.LoadTeamArg{
		Team:            A.FQTeam(t),
		As:              v.FQUser().FQParty(),
		SrcRole:         proto.OwnerRole,
		Keys:            v.KeySeq(t, proto.OwnerRole),
		LoadMembersFull: true,
	})
	require.NoError(t, err)
	x, err := twr.ExportToRoster()
	require.NoError(t, err)

	require.Len(t, x.Members, 2)
	roles := make(map[proto.NameUtf8]proto.Role)
	for _, mem := range x.Members {
		roles[mem.Mem.Name] = mem.DstRole
	}
	require.Equal(t, proto.OwnerRole, roles[v.name], "owner's role should be untouched")
	require.Equal(t, readerRole, roles[u.name], "CLKR must not change the role of the member it rekeys")
}

// TestAdminCLKRSkipsStaleHigherRoleMember covers the other half of the same
// hunk: an admin cannot submit a change for a member who outranks it, because
// checkChangesLocked rejects the whole change set, and visitAllTeams returns on
// the first team error. So a single stale owner used to abort the sweep for
// every remaining team. The admin should now rekey what it may and leave the
// owner to an owner-run CLKR.
func TestAdminCLKRSkipsStaleHigherRoleMember(t *testing.T) {
	tew := testEnvBeta(t)
	v := tew.NewTestUser(t)
	w := tew.NewTestUser(t)
	u := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()
	A := tew.makeTeamForOwner(t, v)
	A.setIndexRange(t, m, v, index0)
	readerRole := proto.NewRoleWithMember(0)
	tew.DirectDoubleMerklePokeInTest(t)

	runLocalJoinSequenceForUser(t, m, A, v, w, proto.AdminRole, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	runLocalJoinSequenceForUser(t, m, A, v, u, readerRole, nil)
	tew.DirectDoubleMerklePokeInTest(t)

	// w, an admin, is the one who will run the background rekey.
	mw := tew.NewClientMetaContextWithDevice(t, w, w.eldest)
	mw = mw.WithLogTag("testrun")
	aw := mw.G().ActiveUser()
	require.NotNil(t, aw)
	tmm := libclient.NewTeamMinder(aw)
	tmm.TestHooks = &libclient.TeamMinderTestHooks{
		PostChainHook: func() error {
			tew.DirectDoubleMerklePokeInTest(t)
			return nil
		},
	}

	clkr := libclient.NewCLKR(tmm, libclient.CLKROpts{})
	err := clkr.Run(mw)
	require.NoError(t, err)
	require.Equal(t, 0, len(clkr.Rekeys()))

	// Both the owner and the reader go stale, so the admin's sweep sees one
	// member it may not touch and one it may.
	rollPUK := func(x *TestUser, dev string) {
		d := x.ProvisionNewDevice(t, x.eldest, dev, proto.DeviceType_Computer, proto.OwnerRole)
		tew.DirectDoubleMerklePokeInTest(t)
		x.RevokeDevice(t, x.eldest, d)
		tew.DirectMerklePokeInTest(t)
	}
	rollPUK(v, "vcpu2")
	rollPUK(u, "ucpu2")

	clkr = libclient.NewCLKR(tmm, tew.clkrOpts(t))
	err = clkr.Run(mw)
	require.NoError(t, err, "a stale owner must not abort an admin's sweep")
	require.Equal(t, 1, len(clkr.Rekeys()))

	twr, err := libclient.LoadTeam(mw, libclient.LoadTeamArg{
		Team:            A.FQTeam(t),
		As:              w.FQUser().FQParty(),
		SrcRole:         proto.OwnerRole,
		Keys:            w.KeySeq(t, proto.OwnerRole),
		LoadMembersFull: true,
	})
	require.NoError(t, err)
	x, err := twr.ExportToRoster()
	require.NoError(t, err)

	require.Len(t, x.Members, 3)
	roles := make(map[proto.NameUtf8]proto.Role)
	for _, mem := range x.Members {
		roles[mem.Mem.Name] = mem.DstRole
	}
	require.Equal(t, proto.OwnerRole, roles[v.name], "the skipped owner keeps their role")
	require.Equal(t, proto.AdminRole, roles[w.name], "the actor keeps their role")
	require.Equal(t, readerRole, roles[u.name], "CLKR must not change the role of the member it rekeys")
}
