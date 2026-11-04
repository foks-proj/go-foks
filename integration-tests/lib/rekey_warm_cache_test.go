// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

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
	"github.com/stretchr/testify/require"
)

// rekeyWarmCacheTest is a team of an owner, a reader and a member who gets
// removed. The reader's client loads the team before the removal and keeps it
// cached for the whole test (FOKS_TEAM_CACHE_TIMEOUT=1h), so content sealed
// under the post-removal key generation reaches it with a key ring that is one
// generation behind. A removal does not touch the reader's own team_members
// row, so its view bearer token stays valid and the stale-token refresh never
// runs: only the key lookup can notice the ring is behind.
type rekeyWarmCacheTest struct {
	tew    *TestEnvWrapper
	tm     *teamObj
	owner  *TestUser
	reader *TestUser
	gone   *TestUser
}

func setupRekeyWarmCacheTest(t *testing.T) *rekeyWarmCacheTest {
	t.Setenv("FOKS_TEAM_CACHE_TIMEOUT", "1h")
	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	reader := tew.NewTestUser(t)
	gone := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, owner)
	tm.makeChanges(
		t, tew.MetaContext(), owner,
		[]proto.MemberRole{
			reader.toMemberRole(t, proto.AdminRole, tm.hepks),
			gone.toMemberRole(t, proto.AdminRole, tm.hepks),
		},
		nil,
	)
	return &rekeyWarmCacheTest{tew: tew, tm: tm, owner: owner, reader: reader, gone: gone}
}

// removeGone removes the third member, which rotates the team's keys.
func (s *rekeyWarmCacheTest) removeGone(t *testing.T) {
	s.tm.makeChanges(t, s.tew.MetaContext(), s.owner, []proto.MemberRole{
		s.gone.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), s.tm.hepks),
	}, nil)
	s.tew.DirectDoubleMerklePokeInTest(t)
}

func TestKVReadAfterRekeyWithWarmTeamCache(t *testing.T) {
	s := setupRekeyWarmCacheTest(t)

	cs := libclient.CacheSettings{UseMem: true, UseDisk: true}
	cfg := lcl.KVConfig{
		ActingAs: team.WrapNamed(proto.FQTeamParsed{
			Team: proto.NewParsedTeamWithFalse(s.tm.FQTeam(t).Team),
		}),
		Roles: proto.RolePairOpt{Read: &proto.AdminRole, Write: &proto.AdminRole},
	}
	putCfg := cfg
	putCfg.MkdirP = true
	putCfg.OverwriteOk = true
	prfx, err := core.RandomDomain()
	require.NoError(t, err)
	path := func(p string) proto.KVPath { return proto.KVPath("/" + prfx + p) }

	put := func(mc libkv.MetaContext, kvm *libkv.Minder, p, data string) {
		_, err := kvm.PutFileFirst(mc, putCfg, path(p), []byte(data), true)
		require.NoError(t, err)
	}
	get := func(mc libkv.MetaContext, kvm *libkv.Minder, p string) (string, error) {
		res, err := kvm.GetFile(mc, cfg, path(p))
		if err != nil {
			return "", err
		}
		return string(res.Chunk.Chunk), nil
	}

	oMc := libkv.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.owner))
	oKvm := libkv.NewMinderWithCacheSettings(oMc.G().ActiveUser(), cs)
	rMc := libkv.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.reader))
	rKvm := libkv.NewMinderWithCacheSettings(rMc.G().ActiveUser(), cs)

	// The reader loads the team (and its key ring) before the removal.
	put(oMc, oKvm, "/before.txt", "before")
	got, err := get(rMc, rKvm, "/before.txt")
	require.NoError(t, err)
	require.Equal(t, "before", got)

	s.removeGone(t)

	// A fresh owner client knows the new generation and seals under it.
	o2Mc := libkv.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.owner))
	o2Kvm := libkv.NewMinderWithCacheSettings(o2Mc.G().ActiveUser(), cs)
	put(o2Mc, o2Kvm, "/after.txt", "after")

	// The reader's ring is a generation behind; the read must still succeed.
	got, err = get(rMc, rKvm, "/after.txt")
	require.NoError(t, err)
	require.Equal(t, "after", got)
}

func TestRTReadAfterRekeyWithWarmTeamCache(t *testing.T) {
	s := setupRekeyWarmCacheTest(t)
	fqt := s.tm.ToFQTeamParsed(t)
	ch := proto.RTChannelName("rekey")

	oMc := librt.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.owner))
	owner := librt.NewMinder(oMc.G().ActiveUser())
	rMc := librt.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.reader))
	reader := librt.NewMinder(rMc.G().ActiveUser())

	_, err := owner.MakeChannel(oMc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch, "rekey",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)
	_, err = owner.Send(oMc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(ch), []byte("before"))
	require.NoError(t, err)

	// The reader loads the team (and its key ring) before the removal.
	msgs, err := reader.GetMsgs(rMc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(ch), []proto.RTMsgSeq{1})
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	s.removeGone(t)

	// A fresh owner client knows the new generation and seals under it.
	o2Mc := librt.NewMetaContext(s.tew.NewClientMetaContextWithEracer(t, s.owner))
	owner2 := librt.NewMinder(o2Mc.G().ActiveUser())
	_, err = owner2.Send(o2Mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(ch), []byte("after"))
	require.NoError(t, err)

	// The reader's ring is a generation behind; the read must still succeed.
	msgs, err = reader.GetMsgs(rMc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(ch), []proto.RTMsgSeq{2})
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "after", string(msgs[0].Body))
}
