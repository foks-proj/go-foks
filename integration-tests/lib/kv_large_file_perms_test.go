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
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// largeFileRoleFixture builds a team whose KV tree is readable at the default
// role but whose file is admin-only, so the file is the only thing between a
// low-role member and the bytes. It returns the team, the low-role member, the
// path and the file's ID (which that member can legitimately learn from the
// dirent, since the directory is readable to them).
type largeFileRoleFixture struct {
	tew    *TestEnvWrapper
	tm     *teamObj
	owner  *TestUser
	reader *TestUser
	admin  *TestUser
	path   proto.KVPath
	fileID proto.FileID
}

// kvMinderFor opens a cache-free KV minder for one of the fixture's users.
func (f *largeFileRoleFixture) kvMinderFor(
	t *testing.T,
	u *TestUser,
) (libkv.MetaContext, *libkv.Minder, lcl.KVConfig) {
	m := libkv.NewMetaContext(f.tew.NewClientMetaContextWithEracer(t, u))
	kvm := libkv.NewMinderWithCacheSettings(m.G().ActiveUser(), libclient.CacheSettings{})
	cfg := lcl.KVConfig{
		ActingAs: team.WrapNamed(proto.FQTeamParsed{
			Team: proto.NewParsedTeamWithFalse(f.tm.FQTeam(t).Team),
		}),
	}
	return m, kvm, cfg
}

func setupLargeFileRoleFixture(t *testing.T) *largeFileRoleFixture {
	tew := testEnvBeta(t)

	owner := tew.NewTestUser(t)
	reader := tew.NewTestUser(t)
	admin := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, owner)
	tm.makeChanges(
		t, tew.MetaContext(), owner,
		[]proto.MemberRole{
			reader.toMemberRole(t, proto.DefaultRole, tm.hepks),
			admin.toMemberRole(t, proto.AdminRole, tm.hepks),
		}, nil,
	)

	actingAs := team.WrapNamed(proto.FQTeamParsed{
		Team: proto.NewParsedTeamWithFalse(tm.FQTeam(t).Team),
	})
	dirCfg := lcl.KVConfig{
		ActingAs: actingAs,
		Roles:    proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		MkdirP:   true,
	}
	fileCfg := lcl.KVConfig{
		ActingAs: actingAs,
		Roles:    proto.RolePairOpt{Read: &proto.AdminRole, Write: &proto.AdminRole},
	}

	root, err := core.RandomDomain()
	require.NoError(t, err)
	dir := proto.KVPath("/" + root + "/shared")
	path := dir + "/secret.bin"

	mOwner := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, owner))
	kvOwner := libkv.NewMinderWithCacheSettings(mOwner.G().ActiveUser(), libclient.CacheSettings{})

	_, err = kvOwner.Mkdir(mOwner, dirCfg, dir)
	require.NoError(t, err)

	// Several chunks, so the file is a large file with a non-final first chunk.
	buf := writeRandomFileWithConfig(t, kvOwner, mOwner, path, 3*testChunkSize, fileCfg, 0)
	require.NotEmpty(t, buf)

	gfr, err := kvOwner.GetFile(mOwner, fileCfg, path)
	require.NoError(t, err)
	require.NotNil(t, gfr.Id)
	require.False(t, gfr.Chunk.Final)

	return &largeFileRoleFixture{
		tew: tew, tm: tm, owner: owner, reader: reader, admin: admin,
		path: path, fileID: *gfr.Id,
	}
}

// rawFor opens a raw KV-store client and team auth for one of the fixture's
// users, for the paths libkv will not issue on its own.
func (f *largeFileRoleFixture) rawFor(
	t *testing.T,
	u *TestUser,
) (libclient.MetaContext, rem.KVStoreClient, rem.KVAuth) {
	m := f.tew.NewClientMetaContext(t, u)
	cli := kvStoreClientForUser(t, f.tew, u)
	// srcRole nil means OwnerRole: the role the member holds over their OWN
	// party, which is what team_members records and what the token check joins
	// on. The team role the server authorizes with comes from the membership
	// row, not from this argument.
	tok := makeVOBearerTokenForUser(t, f.tm, u, nil)
	return m, cli, rem.NewKVAuthWithTeam(tok)
}

func wantLargeFilePermErr() error {
	return core.KVPermssionError{
		KVPermError: proto.KVPermError{
			Op:       proto.KVOp_Read,
			Resource: proto.KVNodeType_File,
		},
	}
}

// TestLargeFileReadRoleEnforcedOnGetNode pins the check in
// loadLargeFileMetadata, which hands back the file's key box. It used to read
// the file's read role out of large_file_key, copy it into the response, and
// never compare it to the caller.
func TestLargeFileReadRoleEnforcedOnGetNode(t *testing.T) {
	f := setupLargeFileRoleFixture(t)

	mReader, kvReader, cfg := f.kvMinderFor(t, f.reader)

	_, err := kvReader.GetFile(mReader, cfg, f.path)
	require.Error(t, err)
	require.Equal(t, wantLargeFilePermErr(), err)
}

// TestLargeFileReadRoleEnforcedOnGetChunk pins the check in getChunk, which
// serves raw ciphertext addressed by file ID with no directory context. It used
// to accept a role and ignore it entirely.
//
// This drives the RPC directly rather than going through libkv. libkv's
// GetFileChunk loads the file's metadata first (client/libkv/getfile.go), so
// once loadLargeFileMetadata is checked the chunk RPC is never reached through
// that route -- and a test that went through it would pass with getChunk's own
// check removed, pinning nothing. The server may not rely on a client choosing
// to ask for metadata first.
func TestLargeFileReadRoleEnforcedOnGetChunk(t *testing.T) {
	f := setupLargeFileRoleFixture(t)

	m, cli, auth := f.rawFor(t, f.reader)

	_, err := cli.KvGetEncryptedChunk(m.Ctx(), rem.KvGetEncryptedChunkArg{
		Auth:   auth,
		Id:     f.fileID,
		Offset: proto.Offset(testChunkSize),
	})
	require.Error(t, err)
	require.Equal(t, wantLargeFilePermErr(), err)
}

// TestLargeFileReadRoleAllowsEqualRole covers the at-or-above boundary at
// equality, which the two denial tests cannot reach: their only successful
// reader is the team owner, and Owner is strictly above the file's Admin read
// role. Without this, tightening the check to strictly-above would lock every
// admin out of every admin-role large file and still pass the suite.
func TestLargeFileReadRoleAllowsEqualRole(t *testing.T) {
	f := setupLargeFileRoleFixture(t)

	mAdmin, kvAdmin, cfg := f.kvMinderFor(t, f.admin)

	gfr, err := kvAdmin.GetFile(mAdmin, cfg, f.path)
	require.NoError(t, err)
	require.NotNil(t, gfr.Id)
	require.Equal(t, f.fileID, *gfr.Id)

	// And the chunk path, which authorizes separately from the metadata path.
	chnk, err := kvAdmin.GetFileChunk(mAdmin, cfg, f.fileID, proto.Offset(testChunkSize))
	require.NoError(t, err)
	require.NotEmpty(t, chnk.Chunk)
}

// TestLargeFileStatusNotDisclosedBelowRole pins the ORDER of the check in
// loadLargeFileMetadata: it must run before the status switch, not after.
//
// The switch answers KVUploadInProgressError for an uploading file and
// KVNoentError for a dead one. Returned ahead of the permission check, those
// tell a caller under the file's read role whether a file they may not read is
// mid-upload, deleted, or live -- and, since a missing file answers
// NotFoundError, whether it exists at all. A caller below the read role must
// get the same permission error whatever the file is doing.
func TestLargeFileStatusNotDisclosedBelowRole(t *testing.T) {
	f := setupLargeFileRoleFixture(t)

	// Start an upload at admin read role and never finalize it: with no
	// UploadFinal the row stays in 'uploading' for the rest of the test.
	mOwner, ownerCli, ownerAuth := f.rawFor(t, f.owner)

	var fid proto.FileID
	require.NoError(t, core.RandomFill(fid[:]))

	// The server rejects a non-final chunk under kv.MinEncryptedChunkSize; the
	// bytes are never decrypted here, only stored.
	chunk := make([]byte, 256)
	require.NoError(t, core.RandomFill(chunk))

	err := ownerCli.KvFileUploadInit(mOwner.Ctx(), rem.KvFileUploadInitArg{
		Auth:   ownerAuth,
		FileID: fid,
		Md: proto.LargeFileMetadata{
			Rg:   proto.RoleAndGen{Role: proto.AdminRole, Gen: proto.FirstGeneration},
			Vers: proto.KVVersion(1),
		},
		Chunk: proto.UploadChunk{
			Data:   proto.NaclCiphertext(chunk),
			Offset: proto.Offset(0),
			Final:  nil,
		},
	})
	require.NoError(t, err)

	mReader, readerCli, readerAuth := f.rawFor(t, f.reader)
	_, err = readerCli.KvGetNode(mReader.Ctx(), rem.KvGetNodeArg{
		Auth: readerAuth,
		Id:   fid.KVNodeID(),
	})
	require.Error(t, err)
	require.Equal(t, wantLargeFilePermErr(), err,
		"an uploading file must answer a below-role caller exactly as a live one does")

	// The admin, who may read it, still learns the real state.
	mAdmin, adminCli, adminAuth := f.rawFor(t, f.admin)
	_, err = adminCli.KvGetNode(mAdmin.Ctx(), rem.KvGetNodeArg{
		Auth: adminAuth,
		Id:   fid.KVNodeID(),
	})
	require.Equal(t, core.KVUploadInProgressError{}, err)
}
