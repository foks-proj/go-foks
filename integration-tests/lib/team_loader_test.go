// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func TestServerSimpleTeamLoadHappyPath(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	tew.DirectDoubleMerklePokeInTest(t)
	team := tew.makeTeamForOwner(t, u)
	tok := makeVOBearerTokenForUser(t, team, u, nil)
	m := tew.MetaContext()
	tcli, closer := u.newTeamLoaderClient(t, m.Ctx(), true)
	defer closer()

	// Local load
	ch, err := tcli.LoadTeamChain(m.Ctx(), rem.LoadTeamChainArg{
		Team:  team.FQTeam(t),
		Tok:   rem.NewTokenVariantWithTeamvobearer(tok),
		Start: proto.ChainEldestSeqno,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(ch.Links))
	require.Equal(t, 1, len(ch.Teamnames))
	require.Equal(t, uint64(2), ch.NumTeamnameLinks)
	require.Equal(t, 4, len(ch.Merkle.Paths))
	require.Equal(t, 4, len(ch.Boxes))
	require.Equal(t, 0, len(ch.Boxes[0].SeedChain))

	mem := proto.NewRoleWithMember(0)
	vHostID := tew.VHostMakeI(t, 0)
	x := tew.NewTestUserAtVHost(t, vHostID)
	runRemoteJoinSequenceForUser(t, m, team, x, u, mem)
	xtok := makeVOBearerTokenForUser(t, team, x, nil)
	xtcli, xcloser := x.newTeamLoaderClient(t, m.Ctx(), false)
	defer xcloser()

	// Remote user load
	ch, err = xtcli.LoadTeamChain(m.Ctx(), rem.LoadTeamChainArg{
		Team:  team.FQTeam(t),
		Tok:   rem.NewTokenVariantWithTeamvobearer(xtok),
		Start: proto.ChainEldestSeqno,
	})
	require.NoError(t, err)
	require.Equal(t, 2, len(ch.Links))
	require.Equal(t, 1, len(ch.Teamnames))
	require.Equal(t, uint64(2), ch.NumTeamnameLinks)
	require.Equal(t, 5, len(ch.Merkle.Paths))
	require.Equal(t, 2, len(ch.Boxes))
	require.Equal(t, 0, len(ch.Boxes[0].SeedChain))
}

func TestClientSimpleTeamLoadHappyPath(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, u)
	mu := tew.NewClientMetaContext(t, u)

	_, _, err := libclient.LoadTeamReturnLoader(mu, libclient.LoadTeamArg{
		Team:    tm.FQTeam(t),
		As:      u.FQUser().FQParty(),
		Keys:    u.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
}

func TestClientSimpleTeamByNameLoadHappyPath(t *testing.T) {
	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, u)
	mu := tew.NewClientMetaContext(t, u)

	_, tw, err := libclient.LoadTeamReturnLoader(mu, libclient.LoadTeamArg{
		Team: proto.FQTeam{
			Host: tm.host,
		},
		As:      u.FQUser().FQParty(),
		Keys:    u.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
		Name:    proto.NameUtf8(tm.nm),
	})
	require.NoError(t, err)
	require.Equal(t, tw.Prot().Fqt.Team, tm.FQTeam(t).Team)
}

func TestClientTeamLoaderPTKRotations(t *testing.T) {
	tew := testEnvBeta(t)
	var v []*TestUser
	n := 5
	for i := 0; i < n; i++ {
		v = append(v, tew.NewTestUserFakeRoot(t))
	}
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, v[0])
	m := tew.MetaContext()

	var mrs []proto.MemberRole
	for _, u := range v[1:] {
		mrs = append(mrs, u.toMemberRole(t, proto.AdminRole, tm.hepks))
	}
	tm.makeChanges(t, m, v[0], mrs, nil)
	rmMember := func(i int) {
		tm.makeChanges(t, m, v[0], []proto.MemberRole{
			v[i].toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), tm.hepks),
		}, nil)
	}
	rmMember(1)
	tew.DirectDoubleMerklePokeInTest(t)
	owner := v[0]
	mo := tew.NewClientMetaContext(t, owner)

	freshLoad := func() *libclient.TeamLoader {
		loader, _, err := libclient.LoadTeamReturnLoader(mo, libclient.LoadTeamArg{
			Team:    tm.FQTeam(t),
			As:      owner.FQUser().FQParty(),
			Keys:    owner.KeySeq(t, proto.OwnerRole),
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
		require.NotNil(t, loader)
		return loader
	}
	loader := freshLoad()

	_, err := loader.Run(mo)
	require.NoError(t, err)
	rmMember(2)
	rmMember(3)
	tew.DirectDoubleMerklePokeInTest(t)
	_, err = loader.Run(mo)
	require.NoError(t, err)

	loader = freshLoad()
	require.NotNil(t, loader.Existing())

	rmMember(4)
	tew.DirectDoubleMerklePokeInTest(t)

	loader = freshLoad()
	require.NotNil(t, loader.Existing())
}

func TestRotatePTKOnPUKRotation(t *testing.T) {
	tew := testEnvBeta(t)
	biden := tew.NewTestUserFakeRoot(t)
	aoc := tew.NewTestUserFakeRoot(t)

	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, biden)
	m := tew.MetaContext()

	tm.makeChanges(t, m, biden, []proto.MemberRole{
		aoc.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)

	freshLoad := func(who *TestUser) *libclient.TeamLoader {
		mc := tew.NewClientMetaContext(t, who)
		loader, _, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
			Team:    tm.FQTeam(t),
			As:      who.FQUser().FQParty(),
			Keys:    who.KeySeq(t, proto.OwnerRole),
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
		require.NotNil(t, loader)
		return loader
	}
	freshLoad(biden)
	freshLoad(aoc)

	// Force a rotation via revoke
	beta := aoc.ProvisionNewDevice(t, aoc.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	tr := getCurrentTreeRoot(t, m)
	aoc.RevokeDeviceWithTreeRoot(t, aoc.eldest, beta, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	// rotate em
	tm.makeChanges(t, m, biden, []proto.MemberRole{
		aoc.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	freshLoad(biden)
	freshLoad(aoc)
}

func TestCreateWithRotatedPUK(t *testing.T) {
	tew := testEnvBeta(t)
	clinton := tew.NewTestUserFakeRoot(t)
	newt := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)
	beta := clinton.ProvisionNewDevice(t, clinton.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	m := tew.MetaContext()
	tr := getCurrentTreeRoot(t, m)
	clinton.RevokeDeviceWithTreeRoot(t, clinton.eldest, beta, &tr)
	tm := tew.makeTeamForOwner(t, clinton)
	freshLoad := func(who *TestUser) *libclient.TeamLoader {
		mc := tew.NewClientMetaContext(t, who)
		loader, _, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
			Team:    tm.FQTeam(t),
			As:      who.FQUser().FQParty(),
			Keys:    who.KeySeq(t, proto.OwnerRole),
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
		require.NotNil(t, loader)
		return loader
	}
	freshLoad(clinton)
	tm.makeChanges(t, m, clinton, []proto.MemberRole{
		newt.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks),
	}, nil)
	tew.DirectDoubleMerklePokeInTest(t)
	freshLoad(clinton)
	freshLoad(newt)
}

var index3 = core.NewRationalRange(
	proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x80}},
		High: proto.Rational{Infinity: true},
	},
)

var index2 = core.NewRationalRange(
	proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x40}},
		High: proto.Rational{Base: []byte{0x70}},
	},
)

var index1 = core.NewRationalRange(
	proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x20}},
		High: proto.Rational{Base: []byte{0x30}},
	},
)

var index0 = core.NewRationalRange(
	proto.RationalRange{
		Low:  proto.Rational{Base: []byte{0x1}},
		High: proto.Rational{Base: []byte{0x10}},
	},
)

func TestLoadTeamAsTeam(t *testing.T) {
	tew := testEnvBeta(t)
	nirvana := tew.NewTestUserFakeRoot(t)
	tew.DirectMerklePokeForLeafCheck(t)
	t1 := tew.makeTeamForOwner(t, nirvana)
	tew.DirectDoubleMerklePokeInTest(t)
	t2 := tew.makeTeamForOwner(t, nirvana)
	tew.DirectDoubleMerklePokeInTest(t)
	m := tew.MetaContext()
	readerRole := proto.NewRoleWithMember(0)
	bot := tew.NewTestUserFakeRoot(t)

	t1.setIndexRange(t, m, nirvana, index3)
	t2.setIndexRange(t, m, nirvana, index0)
	tew.DirectMerklePokeInTest(t)

	// Load the admins of t2 as members (level 0) in team t1
	mr := t2.toMemberRole(t, proto.AdminRole, readerRole)

	// send t2's full HEPK over to t1
	t1.absorb(t2.hepks)

	t1.makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{mr},
		nil,
	)
	mc := tew.NewClientMetaContext(t, nirvana)

	loader, _, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
		Team:    t1.FQTeam(t),
		As:      nirvana.FQUser().FQParty(),
		Keys:    nirvana.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, loader)

	loader, _, err = libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
		Team:    t1.FQTeam(t),
		As:      t2.FQTeam(t).FQParty(),
		Keys:    t2.KeySeq(t, proto.AdminRole),
		SrcRole: proto.AdminRole,
	})
	require.NoError(t, err)
	require.NotNil(t, loader)

	// Now try to load in the readers of t2 as bots (level -10) in team t1
	botRole := proto.NewRoleWithMember(-10)
	t2.makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{bot.toMemberRole(t, botRole, t2.hepks)},
		nil,
	)
	mr = t2.toMemberRole(t, readerRole, botRole)
	t1.makeChanges(
		t,
		m,
		nirvana,
		[]proto.MemberRole{mr},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	// Also make sure the load back from disk still works.
	loader, _, err = libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
		Team:    t1.FQTeam(t),
		As:      t2.FQTeam(t).FQParty(),
		Keys:    t2.KeySeq(t, readerRole),
		SrcRole: readerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, loader)
}

func TestLoadRemovalKey(t *testing.T) {
	tew := testEnvBeta(t)
	abe := tew.NewTestUser(t)
	bella := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, abe)
	m := tew.MetaContext()
	tm.makeChanges(t, m, abe, []proto.MemberRole{
		bella.toMemberRole(t, proto.AdminRole, tm.hepks),
	}, nil)
	tew.DirectMerklePoke(t)
	mc := tew.NewClientMetaContext(t, bella)
	wrp, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:    tm.FQTeam(t),
		As:      bella.FQUser().FQParty(),
		Keys:    bella.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, wrp)
	require.NotNil(t, wrp.RemovalKey())
}

// bluey creats t0 on h0
// coco creats t1 on h1
// t0 is added to t1 as a member.
// t1 should be able to load t0 to get its PTKs, but obviously no privs (or other secret materials)
func TestTeamRemotePermissionTokenPublicLoad(t *testing.T) {
	tew := testEnvBeta(t)

	// This registers (host ID of the base env) -> 127.0.0.1
	// This situation isn't ideal, and we should consider not allowing
	// registration of IP adddresses. But for now, it will enable the
	// operation of this test below, since we need to lookup by hostID
	// in the team load.
	tew.BeaconRegister(t)
	bluey := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)
	m := tew.MetaContext()
	tew.DirectDoubleMerklePokeInTest(t)
	t0 := tew.makeTeamForOwner(t, bluey)
	t1 := tew.makeTeamForOwner(t, coco)
	mem := proto.NewRoleWithMember(0)

	t1.setIndexRange(t, m, coco, index3)
	t0.setIndexRange(t, m, bluey, index0)

	tok := runRemoteJoinSequenceForTeam(t, m, t1, t0, coco, bluey, proto.AdminRole, mem)
	tew.DirectMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, coco)
	twr, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team: t0.FQTeam(t),
		As:   t1.FQTeam(t).FQParty(),
		Tok:  &tok,
	})
	require.NoError(t, err)

	// Still have public PTKs for owner, admin, and member, and kv-min
	kr := twr.KeyRing().All()
	require.Equal(t, 4, len(kr))
	for _, rk := range []core.RoleKey{core.OwnerRole, core.AdminRole, core.MemberRole, core.KVMinRole} {
		kfr := twr.KeyRing().KeysForRole(rk)
		require.NotNil(t, kfr)
		require.False(t, kfr.HasPrivates())
		require.Equal(t, 1, kfr.PublicGens())
	}
}

// bluey creates t0 on h0
// coco creats t1 on h1
// snickers is a user on h0
// muffin is a user on h1
// socks is a user on h1
// socks create t2 on h1
// coco adds t0, t2, snickers and muffin to t1 as members.
// coco loads t1
func TestTeamLoadMembers(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	snickers := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)
	muffin := tew.NewTestUserAtVHost(t, vHostID)
	socks := tew.NewTestUserAtVHost(t, vHostID)
	tew.DirectDoubleMerklePokeInTest(t)
	snickers.ProvisionNewDevice(t, snickers.eldest, "steam deck", proto.DeviceType_Computer, proto.OwnerRole)

	t0 := tew.makeTeamForOwner(t, bluey)
	t1 := tew.makeTeamForOwner(t, coco)
	t2 := tew.makeTeamForOwner(t, socks)
	tew.DirectMerklePokeInTest(t)
	m := tew.MetaContext()

	muffinRole := proto.NewRoleWithMember(-1)
	t2Role := proto.NewRoleWithMember(-2)
	snickersRole := proto.NewRoleWithMember(-3)
	t0Role := proto.NewRoleWithMember(-4)

	t1.setIndexRange(t, m, coco, index3)
	t2.setIndexRange(t, m, socks, index0)
	t0.setIndexRange(t, m, bluey, index0)
	tew.DirectDoubleMerklePokeInTest(t)

	// All join possibilities in the 2x2
	runLocalJoinSequenceForUser(t, m, t1, coco, muffin, muffinRole, nil)
	tew.DirectMerklePokeInTest(t)
	runLocalJoinSequenceForTeam(t, m, t1, t2, coco, socks, proto.AdminRole, t2Role)
	tew.DirectMerklePokeInTest(t)
	runRemoteJoinSequenceForUser(t, m, t1, snickers, coco, snickersRole)
	tew.DirectMerklePokeInTest(t)
	runRemoteJoinSequenceForTeam(t, m, t1, t0, coco, bluey, proto.AdminRole, t0Role)
	tew.DirectMerklePokeInTest(t)

	t2.makeChanges(t,
		m,
		socks,
		[]proto.MemberRole{
			muffin.toMemberRole(t, proto.AdminRole, t2.hepks),
		},
		nil,
	)
	tew.DirectMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, coco)
	twr, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:        t1.FQTeam(t),
		As:          coco.FQUser().FQParty(),
		SrcRole:     proto.OwnerRole,
		Keys:        coco.KeySeq(t, proto.OwnerRole),
		LoadMembers: true,
	})
	require.NoError(t, err)
	x, err := twr.ExportToRoster()
	require.NoError(t, err)

	cocoHost := tew.VHostnameI(t, 0)
	blueyHost := tew.Hostname()

	expected := []struct {
		role       proto.Role
		name       proto.NameUtf8
		hostname   proto.Hostname
		numMembers int64
	}{
		{proto.OwnerRole, coco.name, cocoHost, 1},
		{muffinRole, muffin.name, cocoHost, 1},
		{t2Role, t2.nm, cocoHost, 2},
		{snickersRole, snickers.name, blueyHost, 2},
		{t0Role, t0.nm, blueyHost, 1},
	}

	// 4 members and 1 owner
	require.Equal(t, len(expected), len(x.Members))

	for i, e := range expected {
		require.Equal(t, e.role, x.Members[i].DstRole)
		require.Equal(t, e.name, x.Members[i].Mem.Name)
		require.Equal(t, e.hostname, x.Members[i].Mem.Host)
		require.Equal(t, e.numMembers, x.Members[i].NumMembers)
	}
}

func TestSimpleVhostAction(t *testing.T) {
	tew := testEnvBeta(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)
	tew.DirectDoubleMerklePokeInTest(t)
	t1 := tew.makeTeamForOwner(t, coco)
	tew.DirectMerklePokeInTest(t)
	mc := tew.NewClientMetaContext(t, coco)
	_, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:    t1.FQTeam(t),
		As:      coco.FQUser().FQParty(),
		SrcRole: proto.OwnerRole,
		Keys:    coco.KeySeq(t, proto.OwnerRole),
	})
	require.NoError(t, err)
}

// In v0.0.20 and above, it is possible to load the other members of a team
// even if you are just a member/0 or above. so test this.
func TestTeamLoadMembersAsNonAdmin(t *testing.T) {
	tew := testEnvBeta(t)
	pikachu := tew.NewTestUserOpts(t, &TestUserOpts{UsernamePrefix: "pika"})
	charmander := tew.NewTestUserOpts(t, &TestUserOpts{UsernamePrefix: "char"})
	sprigatito := tew.NewTestUserOpts(t, &TestUserOpts{UsernamePrefix: "sprig"})
	tew.DirectDoubleMerklePokeInTest(t)

	t0 := tew.makeTeamForOwner(t, pikachu)
	m := tew.MetaContext()
	tew.DirectMerklePokeInTest(t)

	role := proto.DefaultRole
	runLocalJoinSequenceForUser(t, m, t0, pikachu, charmander, role, nil)
	tew.DirectMerklePokeInTest(t)
	runLocalJoinSequenceForUser(t, m, t0, pikachu, sprigatito, role, nil)
	tew.DirectMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, sprigatito)
	twr, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:        t0.FQTeam(t),
		As:          sprigatito.FQUser().FQParty(),
		SrcRole:     proto.OwnerRole,
		Keys:        sprigatito.KeySeq(t, proto.OwnerRole),
		LoadMembers: true,
	})
	require.NoError(t, err)
	x, err := twr.ExportToRoster()
	require.NoError(t, err)
	fmt.Printf("Members: %v\n", x.Members)

	expected := map[proto.NameUtf8]struct {
		role proto.Role
		uid  proto.UID
	}{
		charmander.name: {
			role: role,
			uid:  charmander.uid,
		},
		sprigatito.name: {
			role: role,
			uid:  sprigatito.uid,
		},
		pikachu.name: {
			role: proto.OwnerRole,
			uid:  pikachu.uid,
		},
	}
	require.Equal(t, len(expected), len(x.Members))
	for _, m := range x.Members {
		e, ok := expected[m.Mem.Name]
		require.True(t, ok, "unexpected member %s", m.Mem.Name)
		require.Equal(t, e.role, m.DstRole)
		require.True(t, m.Mem.Fqp.Party.IsUser())
		uid, err := m.Mem.Fqp.Party.UID()
		require.NoError(t, err)
		require.Equal(t, e.uid, uid, "unexpected UID for member %s", m.Mem.Name)
	}

}
