// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Adding a member through a shared team on a closed-viewership host (fork;
// SECO dm-direct-add).
//
// On a closed host a team can only load a user who granted it view
// permission, and that grant normally comes with the user's RSVP. A team the
// adder and the new member already share holds such a grant (the member gave
// it when they joined), so TeamAdd with LoadVia loads the member through that
// team's view token instead of the target team's, and adds them with no RSVP.
package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// loadViaScene: alice owns community c, which bob joined through the 3-way
// invite flow (so c may load bob); alice also owns a fresh team tt that has no
// view permission on bob.
type loadViaScene struct {
	tew        *TestEnvWrapper
	alice, bob *TestUser
	c, tt      *teamObj
	cFqt, tFqt proto.FQTeamParsed
	tid        proto.TeamID
	ma, mb     libclient.MetaContext
	tma, tmb   *libclient.TeamMinder
}

func setupLoadViaScene(t *testing.T) *loadViaScene {
	tew := testEnvBeta(t)
	s := &loadViaScene{tew: tew}
	s.alice = tew.NewTestUser(t)
	s.bob = tew.NewTestUserOpts(t, &TestUserOpts{RealTreeRoot: true})
	tew.DirectDoubleMerklePokeInTest(t)

	s.c = tew.makeTeamForOwner(t, s.alice)
	tew.DirectDoubleMerklePokeInTest(t)
	s.c.setIndexRange(t, tew.MetaContext(), s.alice, index0)
	tew.DirectDoubleMerklePokeInTest(t)
	s.cFqt = *s.c.ToFQTeamParsed(t)

	s.ma, s.tma = tew.teamMinderFor(t, s.alice)
	s.mb, s.tmb = tew.teamMinderFor(t, s.bob)

	inv, err := s.tma.CreateInvite(s.ma, s.cFqt)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)
	_, err = s.tmb.AcceptInvite(s.mb, lcl.TeamAcceptInviteArg{I: *inv})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)
	inbox, err := s.tma.TeamInbox(s.ma, s.cFqt)
	require.NoError(t, err)
	require.Len(t, inbox.Rows, 1)
	err = s.tma.TeamAdmit(s.ma, lcl.TeamAdmitArg{
		Team:    s.cFqt,
		Members: []lcl.TokRole{{Tok: inbox.Rows[0].Tok, Role: proto.DefaultRole}},
	})
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	s.tt = tew.makeTeamForOwner(t, s.alice)
	tew.DirectDoubleMerklePokeInTest(t)
	s.tFqt = *s.tt.ToFQTeamParsed(t)
	s.tid, err = s.tt.id.ToTeamID()
	require.NoError(t, err)
	return s
}

func (s *loadViaScene) add(t *testing.T, via *proto.FQTeamParsed, who *TestUser) error {
	err := s.tma.Add(s.ma, lcl.TeamAddArg{
		Team:    s.tFqt,
		Members: []lcl.FQPartyParsedAndRole{byUID(who)},
		LoadVia: via,
	})
	if err == nil {
		s.tew.DirectDoubleMerklePokeInTest(t)
	}
	return err
}

func (s *loadViaScene) rosterNames(t *testing.T) []string {
	roster, err := s.tma.ListTeamRoster(s.ma, s.tFqt)
	require.NoError(t, err)
	var ret []string
	for _, mem := range roster.Members {
		ret = append(ret, string(mem.Mem.Name))
	}
	return ret
}

// Without LoadVia the closed host refuses, because tt cannot load bob; through
// c, which bob joined, the add goes through and bob's own listing finds tt
// without bob doing anything first.
func TestTeamAddLoadViaSharedTeam(t *testing.T) {
	s := setupLoadViaScene(t)

	err := s.add(t, nil, s.bob)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no view permission")

	require.NoError(t, s.add(t, &s.cFqt, s.bob))

	membs, err := s.tmb.ListMemberships(s.mb, nil)
	require.NoError(t, err)
	var names []proto.NameUtf8
	for _, tm := range membs.Teams {
		names = append(names, tm.Team.Name)
	}
	require.Contains(t, names, s.tt.nm)
}

// A via team the member never joined holds no permission on them.
func TestTeamAddLoadViaTeamMemberNeverJoined(t *testing.T) {
	s := setupLoadViaScene(t)
	other := s.tew.makeTeamForOwner(t, s.alice)
	s.tew.DirectDoubleMerklePokeInTest(t)
	err := s.add(t, other.ToFQTeamParsed(t), s.bob)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no view permission")
}

// The adder must be able to load the via team at all.
func TestTeamAddLoadViaTeamAdderNotIn(t *testing.T) {
	s := setupLoadViaScene(t)
	carol := s.tew.NewTestUser(t)
	s.tew.DirectDoubleMerklePokeInTest(t)
	carols := s.tew.makeTeamForOwner(t, carol)
	s.tew.DirectDoubleMerklePokeInTest(t)
	require.Error(t, s.add(t, carols.ToFQTeamParsed(t), s.bob))
}

// The member is added before the team's first channel exists, so the
// channel-creation fan-out includes them: a delivery row and a push row from
// the first message (dm-direct-add D4). Everything the adder and the member do
// next works before the member grants tt view permission on themself; the
// adder's roster only shows the member's name once they have.
func TestTeamAddLoadViaFirstMessagePushes(t *testing.T) {
	s := setupLoadViaScene(t)
	require.NoError(t, s.add(t, &s.cFqt, s.bob))

	alice := newPrivActor(t, s.tew, s.alice)
	bob := newPrivActor(t, s.tew, s.bob)
	tCfg := team.WrapNamedPtr(&s.tFqt)

	// Before bob's grant: alice's roster lists bob unnamed.
	require.Contains(t, s.rosterNames(t), "")

	nm, err := core.RandomDomain()
	require.NoError(t, err)
	chid, err := alice.minder.MakeChannelWithOpts(alice.m, tCfg, proto.RTAppID_Chat,
		proto.RTChannelName("dm-"+nm), "",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		librt.MakeChannelOpts{}, nil)
	require.NoError(t, err)
	_, err = alice.minder.Send(alice.m, tCfg, proto.RTAppID_Chat,
		lcl.NewRTChannelSpecifierWithId(*chid), []byte("hello"))
	require.NoError(t, err)

	sc := &privScene{tew: s.tew}
	require.Equal(t, 1, sc.rtdbCount(t,
		`SELECT count(*) FROM user_channels WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
		s.tew.MetaContext().ShortHostID(), chid.Short().Int64(), s.bob.uid.ExportToDB()))
	require.Equal(t, 1, sc.pushRowsFor(t, *chid, bob))

	// Bob reads it through librt, as the app's wake path and the iOS
	// notification extension do.
	view, err := bob.minder.InboxView(bob.m, proto.RTAppID_Chat, false)
	require.NoError(t, err)
	found := false
	for _, r := range view.Rows {
		found = found || r.Ch.ParentTeam.Eq(s.tid)
	}
	require.True(t, found, "bob's inbox renders the new team's row")
	page, err := bob.minder.GetThreadPage(bob.m, tCfg, proto.RTAppID_Chat,
		lcl.NewRTChannelSpecifierWithId(*chid), 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Msgs, 1)

	// KV on tt works for both of them too.
	actingAs := team.WrapNamed(proto.FQTeamParsed{Team: proto.NewParsedTeamWithFalse(s.tid)})
	cfg := lcl.KVConfig{
		ActingAs: actingAs,
		Roles:    proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		MkdirP:   true,
	}
	mka := libkv.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.alice))
	kva := libkv.NewMinderWithCacheSettings(mka.G().ActiveUser(), libclient.CacheSettings{})
	path := proto.KVPath("/dm/seed")
	buf := writeRandomFileWithConfig(t, kva, mka, path, 100, cfg, 0)
	mkb := libkv.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.bob))
	kvb := libkv.NewMinderWithCacheSettings(mkb.G().ActiveUser(), libclient.CacheSettings{})
	got, err := kvb.GetFile(mkb, lcl.KVConfig{ActingAs: actingAs}, path)
	require.NoError(t, err)
	require.Equal(t, buf, []byte(got.Chunk.Chunk))

	// Bob grants tt view permission on himself; alice's roster names him.
	_, err = s.tew.userCli(t, s.bob).GrantLocalViewPermissionForUser(
		s.tew.MetaContext().Ctx(),
		rem.GrantLocalViewPermissionPayload{
			Viewee: s.bob.uid.ToPartyID(),
			Viewer: s.tid.ToPartyID(),
		})
	require.NoError(t, err)
	require.NotContains(t, s.rosterNames(t), "")
}
