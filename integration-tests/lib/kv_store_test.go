// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func writeRandomFile(
	t *testing.T,
	kvm *libkv.Minder,
	mc libkv.MetaContext,
	path proto.KVPath,
	sz int,
) []byte {
	return writeRandomFileWithConfig(t, kvm, mc, path, sz, lcl.KVConfig{}, 0)
}

const testChunkSize = 128 * 1024

func writeRandomFileWithConfig(
	t *testing.T,
	kvm *libkv.Minder,
	mc libkv.MetaContext,
	path proto.KVPath,
	sz int,
	cfg lcl.KVConfig,
	chnkSz int,
) []byte {
	buf, err := writeRandomFileWithConfigAndErr(kvm, mc, path, sz, cfg, chnkSz)
	require.NoError(t, err)
	return buf
}

func writeRandomFileWithConfigAndErr(
	kvm *libkv.Minder,
	mc libkv.MetaContext,
	path proto.KVPath,
	sz int,
	cfg lcl.KVConfig,
	chnkSz int,
) ([]byte, error) {

	if chnkSz == 0 {
		chnkSz = testChunkSize
	}

	buf := make([]byte, sz)
	err := core.RandomFill(buf)
	if err != nil {
		return nil, err
	}

	off := 0
	var nid *proto.KVNodeID
	var last bool
	for off < len(buf) {
		end := off + chnkSz
		if end >= len(buf) {
			end = len(buf)
			last = true
		}
		b := buf[off:end]
		if off == 0 {
			fnode, err := kvm.PutFileFirst(mc, cfg, path, b, last)
			if err != nil {
				return nil, err
			}
			if fnode == nil {
				return nil, core.InternalError("fnode is nil")
			}
			nid = &fnode.NodeID
		} else {
			// Keep in mind that in the case of a smallFile, this won't work, since a SmllFileID isn't a fileID
			fid, err := nid.ToFileID()
			if err != nil {
				return nil, err
			}
			err = kvm.PutFileChunk(mc, cfg, *fid, b, proto.Offset(off), last)
			time.Sleep(time.Millisecond)
			if err != nil {
				return nil, err
			}
		}
		off = end
	}
	return buf, nil
}

func readFile(
	t *testing.T,
	kvm *libkv.Minder,
	mc libkv.MetaContext,
	path proto.KVPath,
	data []byte,
) {
	readFileWithConfig(t, kvm, mc, path, data, lcl.KVConfig{}, 0)
}

func readFileWithConfig(
	t *testing.T,
	kvm *libkv.Minder,
	mc libkv.MetaContext,
	path proto.KVPath,
	data []byte,
	cfg lcl.KVConfig,
	chnkSz int,
) {
	var readBuf bytes.Buffer
	gfr, err := kvm.GetFile(mc, cfg, proto.KVPath(path))
	require.NoError(t, err)
	require.NotNil(t, gfr)

	n, err := readBuf.Write(gfr.Chunk.Chunk)
	require.NoError(t, err)

	chkEq := func() {
		require.Equal(t, len(data), readBuf.Len())
		require.Equal(t, data, readBuf.Bytes())
	}

	if gfr.Chunk.Final {
		chkEq()
		return
	}
	if chnkSz == 0 {
		chnkSz = testChunkSize
	}

	require.NotNil(t, gfr.Id)
	require.Equal(t, n, chnkSz)

	offset := proto.Offset(n)

	for {
		chnk, err := kvm.GetFileChunk(mc, cfg, *gfr.Id, offset)
		require.NoError(t, err)
		require.NotNil(t, chnk)
		n, err := readBuf.Write(chnk.Chunk)
		require.NoError(t, err)
		offset += proto.Offset(n)
		if chnk.Final {
			break
		}
	}

	chkEq()
}

func TestKVStoreUserSimpleOps(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContext(t, bluey))

	test := func(cs libkv.CacheSettings) {
		nm, err := core.RandomDomain()
		require.NoError(t, err)
		kvm := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), cs)
		mk := func(p string) {
			dirid, err := kvm.Mkdir(mc, lcl.KVConfig{MkdirP: true}, proto.KVPath(p))
			require.NoError(t, err)
			fmt.Printf("mkdir %s -> %v\n", p, dirid)
			require.NotNil(t, dirid)
		}
		p1 := "/" + nm + "/foo bar/biz.zle/snizźlę"
		mk(p1)
		mk("/" + nm + "/foo bar/yodle")
		p2 := p1 + "/beastie/boyz"
		mk(p2)
		f := p2 + "/foo.txt"
		txt := "What hath god wrought?"

		fnode, err := kvm.PutFileFirst(mc, lcl.KVConfig{}, proto.KVPath(f), []byte(txt), true)
		require.NoError(t, err)
		require.NotNil(t, fnode)

		f2 := p2 + "/big.txt"
		buf := writeRandomFile(t, kvm, mc, proto.KVPath(f2), 5*testChunkSize/2)

		// Now get the file we just put.
		readFile(t, kvm, mc, proto.KVPath(f2), buf)
	}

	test(libkv.CacheSettings{})
	test(libkv.CacheSettings{UseMem: false, UseDisk: true})
	test(libkv.CacheSettings{UseMem: true, UseDisk: true})

}

func TestKVStoreTeamSimple(t *testing.T) {
	tew := testEnvBeta(t)

	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	coco := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, bluey)
	m := tew.MetaContext()
	mc := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	tm.makeChanges(
		t, m, bluey,
		[]proto.MemberRole{
			bingo.toMemberRole(t, proto.AdminRole, tm.hepks),
			coco.toMemberRole(t, proto.DefaultRole, tm.hepks),
		}, nil,
	)
	mBingo := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bingo))

	cfg := lcl.KVConfig{
		ActingAs: &proto.FQTeamParsed{
			Team: proto.NewParsedTeamWithFalse(tm.FQTeam(t).Team),
		},
		Roles: proto.RolePairOpt{
			Read:  &proto.AdminRole,
			Write: &proto.AdminRole,
		},
	}

	testFn := func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) (proto.KVPath, []byte) {
		root, err := core.RandomDomain()
		require.NoError(t, err)
		p1 := proto.KVPath("/" + root + "/a/b/c.txt")

		tmpCfg := cfg
		tmpCfg.MkdirP = true
		buf := writeRandomFileWithConfig(t, kvm, mc, p1, 6*testChunkSize/5, tmpCfg, 0)
		readFileWithConfig(t, kvm, mc, p1, buf, cfg, 0)
		return p1, buf
	}

	test := func(cs libkv.CacheSettings) (proto.KVPath, []byte) {
		kvm := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), cs)
		return testFn(t, mc, kvm)
	}

	test(libkv.CacheSettings{})
	test(libkv.CacheSettings{UseMem: false, UseDisk: true})
	pLast, bLast := test(libkv.CacheSettings{UseMem: true, UseDisk: true})

	kvmBingo := libkv.NewMinderWithCacheSettings(mBingo.G().ActiveUser(), libkv.CacheSettings{})
	readFileWithConfig(t, kvmBingo, mBingo, pLast, bLast, cfg, 0)

	mCoco := libkv.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	kvmCoco := libkv.NewMinderWithCacheSettings(mCoco.G().ActiveUser(), libkv.CacheSettings{})
	_, err := kvmCoco.GetFile(mCoco, cfg, pLast)

	// simple permission denied test -- should fail on the FS root, since we made it with
	// admin/admin perms. We shoudl build more tests her later
	require.Error(t, err)
	require.Equal(t, core.KVPermssionError{KVPermError: proto.KVPermError{Op: proto.KVOp_Read, Resource: proto.KVNodeType_Dir}}, err)
}

func kvTestAllCacheOptions(t *testing.T, testFn func(*testing.T, libkv.MetaContext, *libkv.Minder)) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContext(t, bluey))

	test := func(cs libkv.CacheSettings) {
		kvm := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), cs)
		testFn(t, mc, kvm)
	}

	test(libkv.CacheSettings{})
	test(libkv.CacheSettings{UseMem: false, UseDisk: true})
	test(libkv.CacheSettings{UseMem: true, UseDisk: true})
}

func makeSmallFile(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder, path proto.KVPath, data string) *libkv.PutFileRes {
	fnode, err := kvm.PutFileFirst(mc, lcl.KVConfig{MkdirP: true}, path, []byte(data), true)
	require.NoError(t, err)
	require.NotNil(t, fnode)
	return fnode
}

func overwriteSmallFile(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder, path proto.KVPath, data string) *libkv.PutFileRes {
	fnode, err := kvm.PutFileFirst(mc, lcl.KVConfig{MkdirP: true, OverwriteOk: true}, path, []byte(data), true)
	require.NoError(t, err)
	require.NotNil(t, fnode)
	return fnode
}

func makeSymlink(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder, path proto.KVPath, target proto.KVPath) {
	fnode, err := kvm.Symlink(mc, lcl.KVConfig{MkdirP: true}, path, target)
	require.NoError(t, err)
	require.NotNil(t, fnode)
}

func TestSmallFile(t *testing.T) {
	kvTestAllCacheOptions(t, func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) {
		nm, err := core.RandomDomain()
		require.NoError(t, err)
		p1 := "/" + nm + "/a/f1.txt"
		f1 := p1 + "/f1.txt"
		data1 := "f1 data here to collect data"
		makeSmallFile(t, mc, kvm, proto.KVPath(f1), data1)
		readFile(t, kvm, mc, proto.KVPath(f1), []byte(data1))
	})
}

func TestSmallFileUsage(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContext(t, bluey))
	kvm := libkv.NewMinder(mc.G().ActiveUser())
	nm, err := core.RandomDomain()
	require.NoError(t, err)
	p1 := "/" + nm + "/a/f1.txt"
	f1 := p1 + "/f1.txt"
	data1 := "f1 data here to collect data"
	makeSmallFile(t, mc, kvm, proto.KVPath(f1), data1)
	usage, err := kvm.GetUsage(mc, lcl.KVConfig{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), usage.Large.Base.Num)
	require.Equal(t, proto.Size(0), usage.Large.Base.Sum)
	require.Equal(t, uint64(1), usage.Small.Num)
	require.Equal(t, proto.Size(80), usage.Small.Sum)
}

func TestReadlink(t *testing.T) {
	kvTestAllCacheOptions(t, func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) {
		nm, err := core.RandomDomain()
		require.NoError(t, err)
		f1 := "/" + nm + "/f1.txt"
		data1 := "f1 data here to collect data"
		makeSmallFile(t, mc, kvm, proto.KVPath(f1), data1)
		s1 := "/" + nm + "/s1.txt"
		makeSymlink(t, mc, kvm, proto.KVPath(s1), proto.KVPath("f1.txt"))
		readFile(t, kvm, mc, proto.KVPath(s1), []byte(data1))
		lnk, err := kvm.Readlink(mc, lcl.KVConfig{}, proto.KVPath(s1))
		require.NoError(t, err)
		require.Equal(t, proto.KVPath("f1.txt"), *lnk)
	})
}

func TestSymlinks(t *testing.T) {
	kvTestAllCacheOptions(t, func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) {
		nm, err := core.RandomDomain()
		require.NoError(t, err)
		p1 := "/" + nm + "/a/b/c/d"
		f1 := p1 + "/f1.txt"
		data1 := "f1 data here to collect data"
		makeSmallFile(t, mc, kvm, proto.KVPath(f1), data1)
		p2 := "/" + nm + "/a/b/x/y/z"

		// symlink of directories along the path
		makeSymlink(t, mc, kvm, proto.KVPath(p2), proto.KVPath("../../c/d"))
		f2 := p2 + "/f2.txt"
		data2 := "f2 data here to collect data"
		f1s1 := p2 + "/f1.txt"
		makeSmallFile(t, mc, kvm, proto.KVPath(f2), data2)
		readFile(t, kvm, mc, proto.KVPath(f2), []byte(data2))
		readFile(t, kvm, mc, proto.KVPath(f1s1), []byte(data1))

		// symlink of file to file
		f1s2 := p2 + "/f1s2.txt"
		makeSymlink(t, mc, kvm, proto.KVPath(f1s2), proto.KVPath("f1.txt"))
		readFile(t, kvm, mc, proto.KVPath(f1s2), []byte(data1))

		f1s3 := p2 + "/f1s3.txt"
		makeSymlink(t, mc, kvm, proto.KVPath(f1s3), proto.KVPath("./f1.txt"))
		readFile(t, kvm, mc, proto.KVPath(f1s3), []byte(data1))

		f1s4 := p2 + "/f1s4.txt"
		makeSymlink(t, mc, kvm, proto.KVPath(f1s4), proto.KVPath("../d/f1.txt"))
		readFile(t, kvm, mc, proto.KVPath(f1s4), []byte(data1))

		f1s5 := p2 + "/f1s5.txt"
		makeSymlink(t, mc, kvm, proto.KVPath(f1s5), proto.KVPath("404.txt"))
		_, err = kvm.GetFile(mc, lcl.KVConfig{}, proto.KVPath(f1s5))
		require.Error(t, err)
		require.IsType(t, core.KVNoentError{}, err)

		lnk, err := kvm.Readlink(mc, lcl.KVConfig{}, proto.KVPath(f1s4))
		require.NoError(t, err)
		require.Equal(t, proto.KVPath("../d/f1.txt"), *lnk)

	})
}

func TestMv(t *testing.T) {
	kvTestAllCacheOptions(t, func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) {

		testNotFound := func(p proto.KVPath) {
			_, err := kvm.GetFile(mc, lcl.KVConfig{}, p)
			require.Error(t, err)
			require.IsType(t, core.KVNoentError{}, err)
		}

		nm, err := core.RandomDomain()
		require.NoError(t, err)

		// case 1: mv /foo/a.txt /foo/b.txt (files)
		p1 := proto.KVPath("/" + nm + "/foo/a.txt")
		f1 := "a.txt is a great file"
		makeSmallFile(t, mc, kvm, p1, f1)
		readFile(t, kvm, mc, p1, []byte(f1))

		p2 := proto.KVPath("/" + nm + "/foo/b.txt")
		err = kvm.Mv(mc, lcl.KVConfig{}, p1, p2)
		require.NoError(t, err)
		readFile(t, kvm, mc, p2, []byte(f1))
		testNotFound(p1)

		// case 2: mv /foo/b.txt /c/ (file to dir)
		d1 := proto.KVPath("/" + nm + "/c/")
		_, err = kvm.Mkdir(mc, lcl.KVConfig{}, d1)
		require.NoError(t, err)
		p3 := proto.KVPath(d1 + "b.txt")
		err = kvm.Mv(mc, lcl.KVConfig{MkdirP: true}, p2, d1)
		require.NoError(t, err)
		readFile(t, kvm, mc, p3, []byte(f1))
		testNotFound(p2)

		// Case 3: mv /c/b.txt /d/e.txt (move file and rename all at once)
		d2 := proto.KVPath("/" + nm + "/d/")
		_, err = kvm.Mkdir(mc, lcl.KVConfig{}, d2)
		require.NoError(t, err)
		p4 := proto.KVPath(d2 + "e.txt")
		err = kvm.Mv(mc, lcl.KVConfig{}, p3, p4)
		require.NoError(t, err)
		readFile(t, kvm, mc, p4, []byte(f1))
		testNotFound(p3)

		// Case 4:
		//  mkdir /a/b
		//  ln -s /a/b /a/l
		//  mv /d/e.txt /a/l
		dirAb := proto.KVPath("/" + nm + "/a/b/")
		_, err = kvm.Mkdir(mc, lcl.KVConfig{MkdirP: true}, dirAb)
		require.NoError(t, err)
		lnkL := proto.KVPath("/" + nm + "/a/l")
		_, err = kvm.Symlink(mc, lcl.KVConfig{}, lnkL, dirAb)
		require.NoError(t, err)
		err = kvm.Mv(mc, lcl.KVConfig{}, p4, lnkL)
		require.NoError(t, err)
		readFile(t, kvm, mc, proto.KVPath(dirAb+"e.txt"), []byte(f1))
		readFile(t, kvm, mc, proto.KVPath(lnkL+"/e.txt"), []byte(f1))

		// Case 4: overwrite a symlink with a move
		xDat := "x.txt is a good file"
		xPath := proto.KVPath("/" + nm + "/x.txt")
		lnk2 := proto.KVPath("/" + nm + "/l2")
		yDat := "y.txt is the best file"
		yPath := proto.KVPath("/" + nm + "/y.txt")
		makeSmallFile(t, mc, kvm, xPath, xDat)
		makeSmallFile(t, mc, kvm, yPath, yDat)
		readFile(t, kvm, mc, xPath, []byte(xDat))
		readFile(t, kvm, mc, yPath, []byte(yDat))
		_, err = kvm.Symlink(mc, lcl.KVConfig{}, lnk2, xPath)
		require.NoError(t, err)
		err = kvm.Mv(mc, lcl.KVConfig{}, yPath, lnk2)
		require.NoError(t, err)
		readFile(t, kvm, mc, lnk2, []byte(yDat))
		readFile(t, kvm, mc, xPath, []byte(xDat)) // check that the file pointed to didn't change

		// Case 5: rename a symlink
		lnk3 := proto.KVPath("/" + nm + "/l3")
		lnk4 := proto.KVPath("/" + nm + "/l4")
		_, err = kvm.Symlink(mc, lcl.KVConfig{}, lnk3, xPath)
		require.NoError(t, err)
		err = kvm.Mv(mc, lcl.KVConfig{}, lnk3, lnk4)
		require.NoError(t, err)
		readFile(t, kvm, mc, lnk4, []byte(xDat))
		testNotFound(lnk3)
	})
}

func TestMv2(t *testing.T) {

	kvTestAllCacheOptions(t, func(t *testing.T, mc libkv.MetaContext, kvm *libkv.Minder) {

		var nm string

		reset := func() {
			var err error
			nm, err = core.RandomDomain()
			require.NoError(t, err)
		}

		pathify := func(s string) proto.KVPath {
			return proto.KVPath("/" + nm + s)
		}

		mkdir := func(s string) {
			_, err := kvm.Mkdir(mc, lcl.KVConfig{MkdirP: true}, pathify(s))
			require.NoError(t, err)
		}

		mv := func(s1, s2 string) {
			err := kvm.Mv(mc, lcl.KVConfig{}, pathify(s1), pathify(s2))
			require.NoError(t, err)
		}

		ln := func(s1, s2 string) {
			_, err := kvm.Symlink(mc, lcl.KVConfig{}, pathify(s1), pathify(s2))
			require.NoError(t, err)
		}

		stat := func(s string, typ proto.KVNodeType) {
			nofollow := (typ == proto.KVNodeType_Symlink)
			st, err := kvm.Stat(mc, lcl.KVConfig{NoFollow: nofollow}, pathify(s))
			if typ == proto.KVNodeType_None {
				require.Error(t, err)
				require.IsType(t, core.KVNoentError{}, err)
				return
			}
			require.NoError(t, err)
			stType, err := st.V.GetT()
			require.NoError(t, err)
			require.Equal(t, typ, stType)
		}

		echo := func(data string, s string) {
			makeSmallFile(t, mc, kvm, pathify(s), data)
		}

		cat := func(s string, data string) {
			readFile(t, kvm, mc, pathify(s), []byte(data))
		}

		reset()

		// case 1:
		//    mkdir -p /a/c /b
		//	  mv /a /b
		//    stat /b/a/c
		mkdir("/a/c")
		mkdir("/b")
		mv("/a", "/b")
		stat("/b/a", proto.KVNodeType_Dir)
		stat("/b/a/c", proto.KVNodeType_Dir)
		stat("/a", proto.KVNodeType_None)
		stat("/a/c", proto.KVNodeType_None)

		// case 2:
		//	echo xx > a
		//  mkdir b
		//  ln -s b c
		//  mv a c
		//  cat c/a
		//  cat b/a
		reset()
		echo("xx", "/a")
		mkdir("/b")
		ln("/c", "/b")
		mv("/a", "/c")
		cat("/c/a", "xx")
		cat("/b/a", "xx")

		// case 3:
		//  echo xx > a
		// 	echo yy > b
		//  ln -s a c
		//  mv b c
		//  stat c
		//	cat c | diff <(echo "xx")
		//  cat a | diff <(echo "yy")
		reset()
		echo("xx", "/a")
		echo("yy", "/b")
		ln("/c", "/a")
		mv("/b", "/c")
		stat("/c", proto.KVNodeType_SmallFile)
		cat("/c", "yy")
		cat("/a", "xx")

	})
}

func TestSimpleOverwrite(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContext(t, bluey))
	kvm := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), libkv.CacheSettings{UseDisk: true})
	nm, err := core.RandomDomain()
	require.NoError(t, err)
	f1 := proto.KVPath("/" + nm + "/foo.txt")
	makeSmallFile(t, mc, kvm, f1, "aa")
	overwriteSmallFile(t, mc, kvm, f1, "bb")

}

type kvTestDevice struct {
	mc     libkv.MetaContext
	kvm    *libkv.Minder
	parent *multiDeviceTest
}

type multiDeviceTest struct {
	tew  *TestEnvWrapper
	user *TestUser
	dev  []*kvTestDevice
	prfx string
}

func (m *kvTestDevice) pathify(s string) proto.KVPath {
	return proto.KVPath("/" + m.parent.prfx + s)
}

func (m *kvTestDevice) mkdir(t *testing.T, s string) {
	_, err := m.kvm.Mkdir(m.mc, lcl.KVConfig{MkdirP: true}, m.pathify(s))
	require.NoError(t, err)
}

func (m *kvTestDevice) unlink(t *testing.T, s string) {
	err := m.kvm.Unlink(m.mc, lcl.KVConfig{Recursive: true}, m.pathify(s))
	require.NoError(t, err)
}
func (m *kvTestDevice) unlinkErr(s string) error {
	err := m.kvm.Unlink(m.mc, lcl.KVConfig{}, m.pathify(s))
	return err
}

func (m *kvTestDevice) echo(t *testing.T, data string, path string) proto.KVPath {
	apath := m.pathify(path)
	overwriteSmallFile(t, m.mc, m.kvm, apath, data)
	return apath
}

func (m *kvTestDevice) echoReturnDirent(t *testing.T, data string, path string) (proto.KVPath, *libkv.Dirent) {
	apath := m.pathify(path)
	pfr := overwriteSmallFile(t, m.mc, m.kvm, apath, data)
	return apath, pfr.Dirent
}

func (m *kvTestDevice) cat(t *testing.T, path string, data string) {
	readFile(t, m.kvm, m.mc, m.pathify(path), []byte(data))
}

func (m *kvTestDevice) mv(t *testing.T, src, dst string) {
	err := m.kvm.Mv(m.mc, lcl.KVConfig{}, m.pathify(src), m.pathify(dst))
	require.NoError(t, err)
}

func (m *kvTestDevice) ln(t *testing.T, s1 string, s2 string) {
	_, err := m.kvm.Symlink(m.mc, lcl.KVConfig{}, m.pathify(s1), m.pathify(s2))
	require.NoError(t, err)
}

func (m *kvTestDevice) statErr(t *testing.T, s string, exp error) {
	_, err := m.kvm.Stat(m.mc, lcl.KVConfig{}, m.pathify(s))
	require.Error(t, err)
	require.Equal(t, exp, err)
}

func (r *multiDeviceTest) reset(t *testing.T) {
	prfx, err := core.RandomDomain()
	require.NoError(t, err)
	r.prfx = prfx
}

func setupMultiDeviceTest(t *testing.T, n int, cs libkv.CacheSettings) *multiDeviceTest {
	tew := testEnvBeta(t)
	user := tew.NewTestUser(t)
	d0 := user.eldest
	for i := 1; i < n; i++ {
		tmp := user.ProvisionNewDevice(t, d0, fmt.Sprintf("phone-%d", i), proto.DeviceType_Computer, proto.OwnerRole)
		require.NotNil(t, tmp)
	}
	tew.DirectMerklePokeInTest(t)

	prfx, err := core.RandomDomain()
	require.NoError(t, err)

	ret := &multiDeviceTest{
		tew:  tew,
		user: user,
		prfx: prfx,
	}

	for _, d := range user.devices {
		mc := tew.NewClientMetaContextWithDevice(t, user, d)
		kvmc := libkv.NewMetaContext(mc)
		minder := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), cs)
		ret.dev = append(ret.dev, &kvTestDevice{mc: kvmc, kvm: minder, parent: ret})
	}
	return ret
}

func TestCacheInvalidations(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 2, libkv.CacheSettings{UseMem: true, UseDisk: true})
	x, y := mdt.dev[0], mdt.dev[1]
	x.mkdir(t, "/a/b")
	path := "/a/b/c.txt"
	x.echo(t, "xx", path)
	y.cat(t, path, "xx")
	x.echo(t, "yy", path)
	x.cat(t, path, "yy")
	y.cat(t, path, "yy")

	// it used to be a file and then it becomes a directory
	x.echo(t, "aa", "/a/b/d")
	x.cat(t, "/a/b/d", "aa")
	y.cat(t, "/a/b/d", "aa")
	x.mv(t, "/a/b/d", "/a/b/e")
	x.mkdir(t, "/a/b/d")
	x.echo(t, "bb", "/a/b/d/f")
	x.cat(t, "/a/b/d/f", "bb")
	y.cat(t, "/a/b/d/f", "bb")

	// It used to be a directory and it's replaced with a file
	mdt.reset(t)
	x.mkdir(t, "/a/b")
	x.echo(t, "aa", "/a/b/c")
	x.cat(t, "/a/b/c", "aa")
	y.cat(t, "/a/b/c", "aa")
	x.mv(t, "/a/b", "/a/d")
	x.echo(t, "bb", "/a/b")
	x.cat(t, "/a/b", "bb")
	y.cat(t, "/a/b", "bb")
}

func TestSymlinkLoop(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 2, libkv.CacheSettings{UseMem: true, UseDisk: true})
	x, y := mdt.dev[0], mdt.dev[1]
	x.mkdir(t, "/a")
	x.ln(t, "/a/b", "/a/c")
	x.ln(t, "/a/c", "/a/b")

	x.statErr(t, "/a/b/x", core.KVPathTooDeepError{})
	y.statErr(t, "/a/b/x", core.KVPathTooDeepError{})

	x.unlink(t, "/a/b")
	x.mkdir(t, "/a/b")
	x.echo(t, "aa", "/a/b/c")
	x.cat(t, "/a/b/c", "aa")
	y.cat(t, "/a/b/c", "aa")
}

func TestList(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	mc := dev.mc
	dev.mkdir(t, "/a")
	var files []string
	for i := 0; i < 10; i++ {
		path := dev.echo(t, fmt.Sprintf("data%d", i), fmt.Sprintf("/a/f%d.txt", i))
		files = append(files, string(path))
	}
	slices.Sort(files)

	var gotFiles []string
	nxt := proto.NewKVListPaginationWithNone()
	ls, err := dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/a"), nil,
		rem.KVListOpts{Start: nxt, Num: 5})
	require.NoError(t, err)
	parent := ls.Parent
	require.NotNil(t, ls.Nxt)
	for _, f := range ls.Ents {
		gotFiles = append(gotFiles, string(parent)+string(f.Name))
	}
	ls, err = dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/a"), &ls.Nxt.Id,
		rem.KVListOpts{Start: ls.Nxt.Nxt, Num: 6})
	require.NoError(t, err)
	require.Nil(t, ls.Nxt)
	for _, f := range ls.Ents {
		gotFiles = append(gotFiles, string(parent)+string(f.Name))
	}
	slices.Sort(gotFiles)
	require.Equal(t, files, gotFiles)

	_, err = dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/a/404"), nil,
		rem.KVListOpts{Start: nxt, Num: 5})
	require.Error(t, err)
	require.Equal(t, core.KVNoentError{}, err)

	_, err = dev.kvm.List(mc, lcl.KVConfig{}, proto.KVPath(files[0]), nil,
		rem.KVListOpts{Start: nxt, Num: 5})
	require.Error(t, err)
	require.Equal(t, core.KVTypeError("not a directory"), err)
}

func TestLocks(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 2, libkv.CacheSettings{UseMem: true, UseDisk: true})
	x, y := mdt.dev[0], mdt.dev[1]

	x.mkdir(t, "/a")
	_, de := x.echoReturnDirent(t, "file contents aa bb aa bb", "/a/b")

	lock, err := x.kvm.AcquireLock(x.mc, lcl.KVConfig{}, de.IDPair(), 0)
	require.NoError(t, err)

	err = lock.Release(x.mc)
	require.NoError(t, err)

	lock, err = y.kvm.AcquireLock(y.mc, lcl.KVConfig{}, de.IDPair(), 0)
	require.NoError(t, err)

	_, err = x.kvm.AcquireLock(x.mc, lcl.KVConfig{}, de.IDPair(), 0)
	require.Error(t, err)
	require.Equal(t, core.KVLockAlreadyHeldError{}, err)

	err = lock.Release(y.mc)
	require.NoError(t, err)

	lock, err = x.kvm.AcquireLock(x.mc, lcl.KVConfig{}, de.IDPair(), 0)
	require.NoError(t, err)

	err = lock.Release(x.mc)
	require.NoError(t, err)

	lock, err = x.kvm.AcquireLock(x.mc, lcl.KVConfig{}, de.IDPair(), 0)
	require.NoError(t, err)

	lockOverride, err := y.kvm.AcquireLock(y.mc, lcl.KVConfig{}, de.IDPair(), time.Millisecond)
	require.NoError(t, err)

	err = lockOverride.Release(y.mc)
	require.NoError(t, err)

	err = lock.Release(x.mc)
	require.Error(t, err)
	require.Equal(t, core.KVLockTimeoutError{}, err)
}

func TestSmallFileRightAtSmallFileBoundary(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectMerklePokeInTest(t)
	mc := libkv.NewMetaContext(tew.NewClientMetaContext(t, bluey))
	kvm := libkv.NewMinderWithCacheSettings(mc.G().ActiveUser(), libkv.CacheSettings{})

	_, err := kvm.Mkdir(mc, lcl.KVConfig{MkdirP: true}, proto.KVPath("/a"))
	require.NoError(t, err)
	var files [][]byte

	base := 2035
	n := 20
	for i := 0; i < n; i++ {
		fn := fmt.Sprintf("/a/f%d", i)
		dat := writeRandomFile(t, kvm, mc, proto.KVPath(fn), base+i)
		files = append(files, dat)
	}
	for i := 0; i < n; i++ {
		fn := fmt.Sprintf("/a/f%d", i)
		readFile(t, kvm, mc, proto.KVPath(fn), files[i])
	}
}

func TestListByMtime(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	mc := dev.mc
	dev.mkdir(t, "/a")
	var files []string
	for i := 0; i < 10; i++ {
		path := dev.echo(t, fmt.Sprintf("data%d", i), fmt.Sprintf("/a/f%d.txt", i))
		files = append(files, string(path))
	}

	var gotFiles []string
	nxt := proto.NewKVListPaginationWithTime(0)
	ls, err := dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/a"), nil,
		rem.KVListOpts{Start: nxt, Num: 5})
	require.NoError(t, err)
	parent := ls.Parent
	require.NotNil(t, ls.Nxt)
	for _, f := range ls.Ents {
		gotFiles = append(gotFiles, string(parent)+string(f.Name))
	}
	// Do this so we don't repeat the last entry (which normally happens).
	*ls.Nxt.Nxt.F_2__++
	ls, err = dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/a"), &ls.Nxt.Id,
		rem.KVListOpts{Start: ls.Nxt.Nxt, Num: 6})
	require.NoError(t, err)
	require.Nil(t, ls.Nxt)
	for _, f := range ls.Ents {
		gotFiles = append(gotFiles, string(parent)+string(f.Name))
	}
	require.Equal(t, files, gotFiles)
}

func TestListCache(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	dev.mkdir(t, "/a")
	dev.mkdir(t, "/b")
	mc := dev.mc
	ls, err := dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/"), nil,
		rem.KVListOpts{Num: 6})
	require.NoError(t, err)
	require.Equal(t, 2, len(ls.Ents))
	dev.mv(t, "/a", "/b/a")
	ls, err = dev.kvm.List(mc, lcl.KVConfig{}, dev.pathify("/"), nil,
		rem.KVListOpts{Num: 6})
	require.NoError(t, err)
	require.Equal(t, 1, len(ls.Ents))
	require.Equal(t, "b", string(ls.Ents[0].Name))
}

func TestUnlink(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	dev.mkdir(t, "/a")
	dev.echo(t, "aa", "/a/b")
	dev.unlink(t, "/a/b")
	dev.statErr(t, "/a/b", core.KVNoentError{Path: "b"})
	err := dev.unlinkErr("/a/b")
	require.Error(t, err)
	require.Equal(t, core.KVNoentError{Path: "b"}, err)
	dev.mkdir(t, "/a/c")
	dev.unlink(t, "/a/c")
	dev.statErr(t, "/a/c", core.KVNoentError{Path: "c"})
	err = dev.unlinkErr("/a/c")
	require.Error(t, err)
	require.Equal(t, core.KVNoentError{Path: "c"}, err)
}

func TestChangeChunkSize(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	file := dev.pathify("r.txt")
	dat := writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, 10777, lcl.KVConfig{}, 4096)
	readFileWithConfig(t, dev.kvm, dev.mc, file, dat, lcl.KVConfig{}, 4096)
}
