// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func testFQEInHostScope(t *testing.T, teamHost byte, memberHost byte, u byte) proto.FQEntityInHostScope {
	var ret proto.FQEntityInHostScope
	ret.Entity = make(proto.EntityID, 33)
	ret.Entity[0] = byte(proto.EntityType_User)
	ret.Entity[32] = u
	if teamHost != memberHost {
		ret.Host = &proto.HostID{}
		ret.Host[0] = byte(proto.EntityType_Host)
		ret.Host[32] = memberHost
	}
	return ret
}

func testMember(
	t *testing.T,
	teamHost byte,
	memberHost byte,
	u byte,
	q proto.Seqno,
	s proto.Role,
	d proto.Role,
	g proto.Generation,
	includeRemovalKey bool,
) proto.MemberRoleSeqno {

	fqe := testFQEInHostScope(t, teamHost, memberHost, u)

	tmk := proto.TeamMemberKeys{
		Gen: g,
	}
	tmk.HepkFp[0] = 0xe0
	tmk.HepkFp[31] = u
	tmk.VerifyKey = make(proto.EntityID, 33)
	tmk.VerifyKey[0] = byte(proto.EntityType_PUKVerify)
	tmk.VerifyKey[32] = u
	if includeRemovalKey {
		var comm proto.KeyCommitment
		comm[0] = 0xe2
		comm[31] = u
		tmk.Trkc = &comm
	}

	ret := proto.MemberRoleSeqno{
		Seqno: q,
		Mr: proto.MemberRole{
			DstRole: d,
			Member: proto.Member{
				Id:      fqe,
				SrcRole: s,
				Keys:    proto.NewMemberKeysWithTeam(tmk),
			},
		},
	}
	return ret
}

func TestTeamKeys(t *testing.T) {

	var hostID proto.HostID
	hostID[0] = byte(proto.EntityType_Host)
	hostID[32] = 0x11

	owner := testMember(t, 0x11, 0x11, 0x1, 0, proto.OwnerRole, proto.OwnerRole, 0, true)
	alice := testMember(t, 0x11, 0x11, 0x2, 0, proto.OwnerRole, proto.AdminRole, 1, true)

	op, err := owner.Mr.Member.Id.Entity.ToPartyID()
	require.NoError(t, err)

	roster := NewEmptyRoster()
	ko := proto.KeyOwner{
		Party:   op,
		SrcRole: proto.OwnerRole,
	}

	roster, _, err = roster.Gameplan(
		ko,
		hostID,
		[]proto.MemberRoleSeqno{owner, alice},
		owner.Mr.Member.Keys.Team().VerifyKey,
		nil,
	)
	require.NoError(t, err)
	aliceID, err := MemberRoleToMemberID(&alice.Mr, hostID)
	require.NoError(t, err)

	// Keep the commitment hanging around, since we're going to blast over it
	comm := *alice.Mr.Member.Keys.Team().Trkc

	check := func() {
		aliceRoster := roster.Mks.Members[*aliceID]
		require.NotNil(t, aliceRoster.Trkc)
		require.Equal(t, comm, *aliceRoster.Trkc)
	}
	check()

	update := func() {
		roster, _, err = roster.Gameplan(
			ko,
			hostID,
			[]proto.MemberRoleSeqno{alice},
			owner.Mr.Member.Keys.Team().VerifyKey,
			nil,
		)
		require.NoError(t, err)
	}
	// Now zero this out, as we do on subseqent updates
	alice.Mr.Member.Keys.F_2__.Trkc = nil
	alice.Mr.DstRole = proto.DefaultRole

	// We're going to test what happens if we mess with Alice's role a few times, but
	// before we do that, first test that passing the wrong signing key causes the
	// operation to fail.
	_, _, err = roster.Gameplan(
		ko,
		hostID,
		[]proto.MemberRoleSeqno{alice},
		alice.Mr.Member.Keys.Team().VerifyKey,
		nil,
	)
	require.Error(t, err)
	require.Equal(t, core.TeamError("member verify key mismatch"), err)

	// Propagate happens after one update
	update()
	check()

	// and a second update
	alice.Mr.DstRole = proto.OwnerRole
	update()
	check()

}
