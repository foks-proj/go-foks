// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"io"
	"slices"
	"testing"

	"github.com/foks-proj/go-foks/client/libgit"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage"
	"github.com/stretchr/testify/require"
)

func newRandomObject(t *testing.T, typ plumbing.ObjectType, sz int) plumbing.EncodedObject {
	ret := plumbing.MemoryObject{}
	ret.SetType(typ)
	buf := make([]byte, sz)
	err := core.RandomFill(buf)
	require.NoError(t, err)
	_, err = ret.Write(buf)
	require.NoError(t, err)
	return &ret
}

type gitTestUser struct {
	u    *TestUser
	mc   libkv.MetaContext
	kvm  *libkv.Minder
	stor *libgit.Storage
}

func (tew *TestEnvWrapper) newGitTestUser(t *testing.T) *gitTestUser {
	tu := tew.NewTestUser(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, tu))
	kvm := libkv.NewMinder(mc.G().ActiveUser())
	return &gitTestUser{u: tu, mc: mc, kvm: kvm}
}

func (u *gitTestUser) makeStorage(
	t *testing.T,
	fqt proto.FQTeamParsed,
	repo proto.GitRepo,
	opts libgit.StorageOpts,
) *libgit.Storage {
	stor := libgit.NewStorage(u.mc.G(), u.kvm, nil, &fqt, repo, opts)
	u.stor = stor
	return stor
}

func TestGitStorageObjects(t *testing.T) {
	tew := testEnvBeta(t)

	bluey := tew.newGitTestUser(t)
	coco := tew.newGitTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	heelers := tew.makeTeamForOwner(t, bluey.u)

	m := tew.MetaContext()
	heelers.makeChanges(
		t, m, bluey.u,
		[]proto.MemberRole{
			coco.u.toMemberRole(t, proto.AdminRole, heelers.hepks),
		}, nil,
	)
	fqt := heelers.FQTeam(t).ToFQTeamParsed()
	opts := libgit.StorageOpts{ListPageSize: 3}

	var allObjs []plumbing.EncodedObject

	nro := func(typ plumbing.ObjectType, sz int) plumbing.EncodedObject {
		obj := newRandomObject(t, typ, sz)
		allObjs = append(allObjs, obj)
		return obj
	}

	repo := proto.GitRepo("keepey-uppey")
	bluey.makeStorage(t, fqt, repo, opts)

	obj := nro(plumbing.BlobObject, 4096)
	hash, err := bluey.stor.SetEncodedObject(obj)
	require.NoError(t, err)

	coco.makeStorage(t, fqt, repo, opts)
	obj2, err := coco.stor.EncodedObject(plumbing.BlobObject, hash)

	require.NoError(t, err)
	require.Equal(t, obj.Hash(), obj2.Hash())

	err = bluey.stor.HasEncodedObject(hash)
	require.NoError(t, err)
	hash[2] ^= 0x01
	err = bluey.stor.HasEncodedObject(hash)
	require.Error(t, err)
	require.Equal(t, plumbing.ErrObjectNotFound, err)

	for i := 0; i < 10; i++ {
		obj := nro(plumbing.BlobObject, 1024*i+i+3)
		_, err := bluey.stor.SetEncodedObject(obj)
		require.NoError(t, err)
	}

	iter, err := coco.stor.IterEncodedObjects(plumbing.BlobObject)
	require.NoError(t, err)
	var iteredObjs []plumbing.EncodedObject
	for {
		obj, err := iter.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		iteredObjs = append(iteredObjs, obj)
	}
	flatten := func(v []plumbing.EncodedObject) []string {
		tmp := core.Map(v, func(obj plumbing.EncodedObject) string { return obj.Hash().String() })
		slices.Sort(tmp)
		return tmp
	}
	require.Equal(t, flatten(allObjs), flatten(iteredObjs))
}

func TestConditionalPut(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)

	mc := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	kvm := libkv.NewMinder(mc.G().ActiveUser())

	path := proto.KVPath("/a/b")
	writeRandomFileWithConfig(t, kvm, mc, path, 1024, lcl.KVConfig{MkdirP: true}, 0)
	gfr, err := kvm.GetFile(mc, lcl.KVConfig{}, path)
	require.NoError(t, err)
	v := gfr.De.Version
	require.Equal(t, proto.KVVersion(1), v)

	// If we get the version right, it should work
	cfg := lcl.KVConfig{OverwriteOk: true, AssertVersion: &v}
	writeRandomFileWithConfig(t, kvm, mc, path, 1024, cfg, 0)

	// Doing it a second time should fail, since we have the old version number
	_, err = kvm.PutFileFirst(mc, cfg, path, []byte{1}, false)
	require.Error(t, err)
	require.Equal(t, core.KVRaceError("dirent"), err)
	v++

	// But if we bump the version number, it should check out
	_, err = kvm.PutFileFirst(mc, cfg, path, []byte{1}, false)
	require.NoError(t, err)

}

func TestGitStorageReferences(t *testing.T) {

	tew := testEnvBeta(t)

	var users []*gitTestUser
	for i := 0; i < 2; i++ {
		users = append(users, tew.newGitTestUser(t))
	}
	x, y := users[0], users[1]

	var allObjs []plumbing.EncodedObject
	var allRefs []*plumbing.Reference

	nrr := func(typ string, sz int) *plumbing.Reference {
		obj := newRandomObject(t, plumbing.BlobObject, sz)
		allObjs = append(allObjs, obj)
		hsh := obj.Hash()
		ref := plumbing.NewHashReference(plumbing.ReferenceName("refs/"+typ+"/r"+hsh.String()[0:8]), hsh)
		allRefs = append(allRefs, ref)
		return ref
	}

	tm := tew.makeTeamForOwner(t, x.u)

	m := tew.MetaContext()
	tm.makeChanges(
		t, m, x.u,
		[]proto.MemberRole{
			y.u.toMemberRole(t, proto.AdminRole, tm.hepks),
		}, nil,
	)
	fqt := tm.FQTeam(t).ToFQTeamParsed()
	opts := libgit.StorageOpts{ListPageSize: 3}
	repo := proto.GitRepo("repo")

	x.makeStorage(t, fqt, repo, opts)
	y.makeStorage(t, fqt, repo, opts)

	for i := 0; i < 20; i++ {
		typ := "heads"
		if i%5 == 0 {
			typ = "tags"
		} else if i%5 == 1 {
			typ = "remotes"
		}
		r := nrr(typ, 1024+i)
		err := x.stor.SetReference(r)
		require.NoError(t, err)
	}
	for _, r := range allRefs {
		r2, err := y.stor.Reference(r.Name())
		require.NoError(t, err)
		require.Equal(t, r.Hash(), r2.Hash())
	}

	r0a, r1 := allRefs[0], allRefs[1]
	r0b := plumbing.NewHashReference(r0a.Name(), r1.Hash())
	err := y.stor.CheckAndSetReference(r0b, r0a)
	require.NoError(t, err)
	r0c := plumbing.NewHashReference(r0a.Name(), allRefs[2].Hash())
	err = y.stor.CheckAndSetReference(r0c, r0a)
	require.Error(t, err)
	require.Equal(t, storage.ErrReferenceHasChanged, err)
	allRefs[0] = r0b

	_, err = y.stor.Reference(plumbing.ReferenceName("refs/heads/dawg"))
	require.Error(t, err)
	require.Equal(t, plumbing.ErrReferenceNotFound, err)

	iter, err := y.stor.IterReferences()
	require.NoError(t, err)
	var iteredRefs []*plumbing.Reference
	err = iter.ForEach(func(r *plumbing.Reference) error {
		iteredRefs = append(iteredRefs, r)
		return nil
	})
	require.NoError(t, err)

	flatten := func(v []*plumbing.Reference) []string {
		tmp := core.Map(v, func(r *plumbing.Reference) string { return r.Name().String() + "----" + r.Hash().String() })
		slices.Sort(tmp)
		return tmp
	}
	require.Equal(t, flatten(allRefs), flatten(iteredRefs))
}
