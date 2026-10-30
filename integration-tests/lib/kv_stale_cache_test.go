// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

type kvStaleCacheTeamTest struct {
	prfx    string
	aMc     libkv.MetaContext
	aKvm    *libkv.Minder
	bMc     libkv.MetaContext
	bKvm    *libkv.Minder
	putCfg  lcl.KVConfig
	readCfg lcl.KVConfig
}

// Two members of one team, each with a caching KV minder, writing and reading
// the same team KV.
func setupKVStaleCacheTeamTest(t *testing.T) *kvStaleCacheTeamTest {
	tew := testEnvBeta(t)
	a := tew.NewTestUser(t)
	b := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, a)
	tm.makeChanges(
		t, tew.MetaContext(), a,
		[]proto.MemberRole{b.toMemberRole(t, proto.AdminRole, tm.hepks)},
		nil,
	)

	aMc := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, a))
	bMc := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, b))
	cs := libclient.CacheSettings{UseMem: true, UseDisk: true}

	cfg := lcl.KVConfig{
		ActingAs: team.WrapNamed(proto.FQTeamParsed{
			Team: proto.NewParsedTeamWithFalse(tm.FQTeam(t).Team),
		}),
		Roles: proto.RolePairOpt{
			Read:  &proto.AdminRole,
			Write: &proto.AdminRole,
		},
	}
	putCfg := cfg
	putCfg.MkdirP = true
	putCfg.OverwriteOk = true

	prfx, err := core.RandomDomain()
	require.NoError(t, err)

	return &kvStaleCacheTeamTest{
		prfx:    prfx,
		aMc:     aMc,
		aKvm:    libkv.NewMinderWithCacheSettings(aMc.G().ActiveUser(), cs),
		bMc:     bMc,
		bKvm:    libkv.NewMinderWithCacheSettings(bMc.G().ActiveUser(), cs),
		putCfg:  putCfg,
		readCfg: cfg,
	}
}

func (s *kvStaleCacheTeamTest) path(p string) proto.KVPath {
	return proto.KVPath("/" + s.prfx + p)
}

func (s *kvStaleCacheTeamTest) put(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder, p string, data string) {
	_, err := kvm.PutFileFirst(mc, s.putCfg, s.path(p), []byte(data), true)
	require.NoError(t, err)
}

func (s *kvStaleCacheTeamTest) get(mc libkv.MetaContext, kvm *libkv.Minder, p string) (string, error) {
	res, err := kvm.GetFile(mc, s.readCfg, s.path(p))
	if err != nil {
		return "", err
	}
	return string(res.Chunk.Chunk), nil
}

// A writes and caches a file, B overwrites it, A reads it back. The cache
// race loop has to notice A's cached dirent is stale and serve B's write.
func TestKVStaleCacheOverwriteByOtherMember(t *testing.T) {
	s := setupKVStaleCacheTeamTest(t)
	p := "/docs/note.txt"

	s.put(t, s.aMc, s.aKvm, p, "v1")
	got, err := s.get(s.aMc, s.aKvm, p)
	require.NoError(t, err)
	require.Equal(t, "v1", got)

	s.put(t, s.bMc, s.bKvm, p, "v2")
	got, err = s.get(s.aMc, s.aKvm, p)
	require.NoError(t, err)
	require.Equal(t, "v2", got)
}

// The cache race loop's first attempt makes a server lookup whose
// precondition passes, and only after that reads a stale cached entry. The
// lookup is for a symlink A has never seen; everything behind the symlink is
// in A's cache, and the file at the end of it was overwritten by B.
//
// Before the fix, the successful lookup dropped the party from the request's
// cache-access record, so when the closing cache check came back stale,
// clearCaches found no party, cleared nothing, and the loop replayed the same
// stale read until it ran out of retries.
func TestKVStaleCacheAfterFreshServerLookup(t *testing.T) {
	s := setupKVStaleCacheTeamTest(t)
	p := "/a/b/c.txt"

	s.put(t, s.aMc, s.aKvm, p, "v1")
	got, err := s.get(s.aMc, s.aKvm, p)
	require.NoError(t, err)
	require.Equal(t, "v1", got)

	symCfg := s.putCfg
	symCfg.OverwriteOk = false
	_, err = s.bKvm.Symlink(s.bMc, symCfg, s.path("/l"), s.path("/a/b"))
	require.NoError(t, err)
	s.put(t, s.bMc, s.bKvm, p, "v2")

	got, err = s.get(s.aMc, s.aKvm, "/l/c.txt")
	require.NoError(t, err)
	require.Equal(t, "v2", got)
}

// B removes a file that A has cached, A reads the removal (and caches the
// tombstone), then B writes the file again. A's next read must see the new
// file: a "no such file" answered from a cached tombstone has to be checked
// with the server like any other cache-derived result.
func TestKVStaleCacheTombstoneThenRecreate(t *testing.T) {
	s := setupKVStaleCacheTeamTest(t)
	p := "/docs/note.txt"

	s.put(t, s.aMc, s.aKvm, p, "v1")
	got, err := s.get(s.aMc, s.aKvm, p)
	require.NoError(t, err)
	require.Equal(t, "v1", got)

	err = s.bKvm.Unlink(s.bMc, s.readCfg, s.path(p))
	require.NoError(t, err)
	_, err = s.get(s.aMc, s.aKvm, p)
	require.True(t, core.IsKVNoentError(err), "want noent, got %v", err)

	s.put(t, s.bMc, s.bKvm, p, "v2")
	got, err = s.get(s.aMc, s.aKvm, p)
	require.NoError(t, err)
	require.Equal(t, "v2", got)
}
