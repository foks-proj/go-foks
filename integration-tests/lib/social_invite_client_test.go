// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// The inviter's seed box is sealed to the PUK generation current at create
// time. A device revoke rotates the PUK; listing afterwards must still open
// the box, with the older generation the seed chain hands to the current key.
func TestSocialInviteListAfterPUKRotation(t *testing.T) {
	tew := testEnvBeta(t)
	alice := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, alice)
	res, err := libclient.SocialInviteCreate(mc, lcl.SocialInviteCreateArg{
		Team: *tm.ToFQTeamParsed(t),
		Text: "hi",
	})
	require.NoError(t, err)

	beta := alice.ProvisionNewDevice(t, alice.eldest, "beta", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)
	alice.RevokeDevice(t, alice.eldest, beta)
	tew.DirectMerklePokeForLeafCheck(t)

	mc = tew.NewClientMetaContext(t, alice)
	puks, err := mc.G().ActiveUser().RefreshPUKs(mc)
	require.NoError(t, err)
	require.Equal(t, proto.Generation(2), puks.Current().Metadata().Gen)

	rows, err := libclient.SocialInviteList(mc)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, res.Id, rows[0].Id)
	require.Equal(t, res.Seed, rows[0].Seed)
	require.Len(t, rows[0].Msgs, 1)
	require.Equal(t, "hi", rows[0].Msgs[0].Text)
}

// Replying to a decided invitation fails in the client, before the grant: a
// team that has already declined must not gain view of whoever replies next.
func TestSocialInviteReplyToDecidedGrantsNothing(t *testing.T) {
	tew := testEnvBeta(t)
	alice := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)

	ma := tew.NewClientMetaContext(t, alice)
	res, err := libclient.SocialInviteCreate(ma, lcl.SocialInviteCreateArg{
		Team: *tm.ToFQTeamParsed(t),
		Text: "hi",
	})
	require.NoError(t, err)

	bob := tew.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
	carol := tew.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
	tew.DirectDoubleMerklePokeInTest(t)

	mb := tew.NewClientMetaContext(t, bob)
	require.NoError(t, libclient.SocialInviteReply(mb, lcl.SocialInviteReplyArg{
		Seed: res.Seed, InReplyTo: 1, Text: "it's me",
	}))
	require.NoError(t, libclient.SocialInviteClose(ma, lcl.SocialInviteCloseArg{
		Id: res.Id, St: proto.SocialInviteState_Declined,
	}))

	mcar := tew.NewClientMetaContext(t, carol)
	err = libclient.SocialInviteReply(mcar, lcl.SocialInviteReplyArg{
		Seed: res.Seed, InReplyTo: 1, Text: "me too",
	})
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	m := tew.MetaContext()
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	var n int
	err = db.QueryRow(m.Ctx(),
		`SELECT COUNT(*) FROM local_view_permissions
		 WHERE short_host_id=$1 AND viewer_eid=$2 AND target_eid=$3`,
		m.ShortHostID().ExportToDB(), tid.ExportToDB(), carol.uid.ExportToDB(),
	).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}
