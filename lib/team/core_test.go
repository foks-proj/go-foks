// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func testFQE(t *testing.T, h, u byte) MemberID {
	var ret proto.FQEntityFixed
	ret.Host[0] = byte(proto.EntityType_Host)
	ret.Host[32] = h
	ret.Entity[0] = byte(proto.EntityType_User)
	ret.Entity[33] = u
	return MemberID{
		Fqe:     ret,
		SrcRole: core.OwnerRole,
	}
}

func testFQEWithSrcRole(t *testing.T, h byte, u byte, r proto.Role) MemberID {
	ret := testFQE(t, h, u)
	rk, err := core.ImportRole(r)
	require.NoError(t, err)
	ret.SrcRole = *rk
	return ret
}

func TestTeamAlgebra1(t *testing.T) {

	alice := testFQE(t, 1, 1)
	bob := testFQE(t, 1, 2)
	char := testFQE(t, 1, 3)
	dee := testFQE(t, 1, 10)
	boto := testFQE(t, 1, 11)
	bozo := testFQE(t, 2, 12)

	owner := core.RoleKey{Typ: proto.RoleType_OWNER}
	none := core.RoleKey{Typ: proto.RoleType_NONE}
	admin := core.RoleKey{Typ: proto.RoleType_ADMIN}
	reader := core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: proto.VizLevel(0)}
	bot := core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: proto.VizLevel(-10)}

	roster := NewRosterCore()
	roster.Add(alice, owner, 0, 0, 0)
	roster.Add(bob, owner, 1, 0, 0)
	roster.Add(char, admin, 1, 0, 0)
	roster.Add(dee, reader, 2, 0, 0)
	roster.Add(boto, bot, 3, 0, 0)
	roster.Add(bozo, bot, 3, 0, 0)

	keys := make(KeyGens)
	keys[owner] = 2
	keys[admin] = 3
	keys[reader] = 4
	keys[bot] = 5

	// 1. Remove an admin (char), check for rotations below.
	chng := Change{Member: char, Info: MemberInfo{Role: none}}
	rPost, sched, err := Gameplan(alice, roster, keys, []Change{chng})
	require.Equal(t, roster.Len()-1, rPost.Len())
	require.NoError(t, err)
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      bot,
				Gen:       6,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, dee, boto, bozo},
			},
			{
				Role:      reader,
				Gen:       5,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, dee},
			},
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{char},
	}, *sched)

	// 2. Add an admin (gigi).
	gigi := testFQE(t, 1, 30)
	chng = Change{Member: gigi, Info: MemberInfo{Role: admin, Gen: 30}}
	rPost, sched, err = Gameplan(alice, roster, keys, []Change{chng})
	require.NoError(t, err)
	require.Equal(t, roster.Len()+1, rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      bot,
				Gen:       5,
				NewKeyGen: false,
				Members:   []MemberID{gigi},
			},
			{
				Role:      reader,
				Gen:       4,
				NewKeyGen: false,
				Members:   []MemberID{gigi},
			},
			{
				Role:      admin,
				Gen:       3,
				NewKeyGen: false,
				Members:   []MemberID{gigi},
			},
		},
		Additions: []MemberID{gigi},
		Removals:  []MemberID{},
	}, *sched)

	// 3. Add a level (superreaders).
	superreader := core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: proto.VizLevel(10)}
	superdude := testFQE(t, 3, 31)
	chng = Change{Member: superdude, Info: MemberInfo{Role: superreader, Gen: 31}}
	rPost, sched, err = Gameplan(alice, roster, keys, []Change{chng})
	require.Equal(t, roster.Len()+1, rPost.Len())
	require.NoError(t, err)
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      bot,
				Gen:       5,
				NewKeyGen: false,
				Members:   []MemberID{superdude},
			},
			{
				Role:      reader,
				Gen:       4,
				NewKeyGen: false,
				Members:   []MemberID{superdude},
			},
			{
				Role:      superreader,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char, superdude},
			},
		},
		Additions: []MemberID{superdude},
		Removals:  []MemberID{},
	}, *sched)

	// 4. downgrade a user from owner to admin. Note, there is no need to rotate the
	// admin, reader, or bot keys since the bob still gets these keys! Subtle!
	chng = Change{Member: bob, Info: MemberInfo{Role: admin, Gen: 1}}
	rPost, sched, err = Gameplan(alice, roster, keys, []Change{chng})
	require.NoError(t, err)
	require.Equal(t, roster.Len(), rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      owner,
				Gen:       3,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{},
	}, *sched)

	// 5. An admin (Bob) does a key rotation. Here we need to rotate the whole kit
	// and kaboodle.
	chng = Change{Member: bob, Info: MemberInfo{Role: admin, Gen: 2}}
	rPost, sched, err = Gameplan(bob, roster, keys, []Change{chng})
	require.NoError(t, err)
	require.Equal(t, roster.Len(), rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      bot,
				Gen:       6,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char, dee, boto, bozo},
			},
			{
				Role:      reader,
				Gen:       5,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char, dee},
			},
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char},
			},
			{
				Role:      owner,
				Gen:       3,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{},
	}, *sched)

	// 6. An admin (char) is demoted to a reader, and simultaneously we get a
	// a key rotation.
	chng = Change{Member: char, Info: MemberInfo{Role: reader, Gen: 2}}
	rPost, sched, err = Gameplan(char, roster, keys, []Change{chng})
	require.NoError(t, err)
	require.Equal(t, roster.Len(), rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      bot,
				Gen:       6,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char, dee, boto, bozo},
			},
			{
				Role:      reader,
				Gen:       5,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, char, dee},
			},
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{},
	}, *sched)

	// 7. upgrade a user and downgrade a user in the same swoop. Char and Dee swap
	// places as admins and readers. Only the admin key needs to be updated.
	changes := ChangeSet{
		{Member: char, Info: MemberInfo{Role: reader, Gen: 1}},
		{Member: dee, Info: MemberInfo{Role: admin, Gen: 2}},
	}
	rPost, sched, err = Gameplan(alice, roster, keys, changes)
	require.NoError(t, err)
	require.Equal(t, roster.Len(), rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{alice, bob, dee},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{},
	}, *sched)

	// 8. Upgrade + downgrade, and shoot past each othera
	changes = ChangeSet{
		{Member: boto, Info: MemberInfo{Role: owner, Gen: 3}},
		{Member: bob, Info: MemberInfo{Role: bot, Gen: 1}},
	}
	rPost, sched, err = Gameplan(alice, roster, keys, changes)
	require.NoError(t, err)
	require.Equal(t, roster.Len(), rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      reader,
				Gen:       5,
				NewKeyGen: true,
				Members:   []MemberID{alice, char, dee, boto},
			},
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{alice, char, boto},
			},
			{
				Role:      owner,
				Gen:       3,
				NewKeyGen: true,
				Members:   []MemberID{alice, boto},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{},
	}, *sched)

	// 9 create a new team
	changes = ChangeSet{
		{Member: alice, Info: MemberInfo{Role: owner, Gen: 0}},
		{Member: boto, Info: MemberInfo{Role: bot, Gen: 10}},
	}
	rPost, sched, err = Gameplan(alice, nil, nil, changes)
	require.NoError(t, err)
	require.Equal(t, 2, rPost.Len())
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      core.KVMinRole,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice, boto},
			},
			{
				Role:      bot,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice, boto},
			},
			{
				Role:      reader,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
			{
				Role:      admin,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
			{
				Role:      owner,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
		},
		Additions: []MemberID{alice, boto},
		Removals:  []MemberID{},
	}, *sched)

	// 10. test that you can't add a remote user as an admin or owner.
	changes = ChangeSet{
		{Member: bozo, Info: MemberInfo{Role: owner, Gen: 10}},
	}
	_, _, err = Gameplan(alice, roster, keys, changes)
	require.Error(t, err)
	require.IsType(t, core.TeamRosterError(""), err)
	require.Contains(t, err.Error(), "only local members can be admins or above")

	// 11. test that you can add a user twice with different roles
	aliceLow := alice
	aliceLow.SrcRole = reader
	changes = ChangeSet{
		{Member: alice, Info: MemberInfo{Role: owner, Gen: 10}},
		{Member: aliceLow, Info: MemberInfo{Role: reader, Gen: 10}},
	}
	_, sched, err = Gameplan(alice, nil, nil, changes)
	require.NoError(t, err)
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      core.KVMinRole,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{aliceLow, alice},
			},
			{
				Role:      reader,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{aliceLow, alice},
			},
			{
				Role:      admin,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
			{
				Role:      owner,
				Gen:       1,
				NewKeyGen: true,
				Members:   []MemberID{alice},
			},
		},
		Additions: []MemberID{aliceLow, alice},
		Removals:  []MemberID{},
	}, *sched)

}

func TestMultipleSrcRoles(t *testing.T) {
	aliceOwner := testFQEWithSrcRole(t, 1, 1, proto.OwnerRole)
	aliceAdmin := testFQEWithSrcRole(t, 1, 1, proto.AdminRole)
	bob := testFQE(t, 1, 2)

	owner := core.OwnerRole
	none := core.RoleKey{Typ: proto.RoleType_NONE}
	admin := core.AdminRole
	reader := core.RoleKey{Typ: proto.RoleType_MEMBER, Lev: proto.VizLevel(0)}

	roster := NewRosterCore()
	roster.Add(bob, owner, 0, 0, 0)
	roster.Add(aliceOwner, admin, 1, 0, 0)
	roster.Add(aliceAdmin, reader, 0, 0, 0)

	keys := make(KeyGens)
	keys[owner] = 2
	keys[admin] = 3
	keys[reader] = 4

	// 1. Remove aliceOwner, but leave in aliceAdmin
	chng := Change{Member: aliceOwner, Info: MemberInfo{Role: none}}
	rPost, sched, err := Gameplan(bob, roster, keys, []Change{chng})
	require.Equal(t, roster.Len()-1, rPost.Len())
	require.NoError(t, err)
	require.Equal(t, KeySchedule{
		Items: []KeyScheduleItem{
			{
				Role:      reader,
				Gen:       5,
				NewKeyGen: true,
				Members:   []MemberID{aliceAdmin, bob},
			},
			{
				Role:      admin,
				Gen:       4,
				NewKeyGen: true,
				Members:   []MemberID{bob},
			},
		},
		Additions: []MemberID{},
		Removals:  []MemberID{aliceOwner},
	}, *sched)

}
