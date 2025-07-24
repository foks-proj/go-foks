// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func testWriteFile(t *testing.T, path string, s string) {
	inh, err := os.Create(path)
	require.NoError(t, err)
	_, err = inh.WriteString(s)
	require.NoError(t, err)
	err = inh.Close()
	require.NoError(t, err)
}

func TestKVStoreSimplePutGet(t *testing.T) {

	randomString := func() string {
		var dat [32]byte
		err := core.RandomFill(dat[:])
		require.NoError(t, err)
		return core.B62Encode(dat[:])
	}

	readFile := func(path string) string {
		outh, err := os.Open(path)
		require.NoError(t, err)
		dat, err := io.ReadAll(outh)
		require.NoError(t, err)
		err = outh.Close()
		require.NoError(t, err)
		return string(dat)
	}
	writeFile := func(path, s string) {
		testWriteFile(t, path, s)
	}

	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	path := "/aaa"
	s := randomString()

	b := bob.agent

	// stdout
	b.runCmd(t, nil, "kv", "put", path, s)
	dat2 := b.runCmdToBytes(t, "kv", "get", path, "-")
	require.Equal(t, s, string(dat2))

	dir := os.TempDir()
	prfx := randomString()[0:10]

	in := filepath.Join(dir, prfx+".in")
	out := filepath.Join(dir, prfx+".out")

	writeFile(in, s)

	path2 := "/bbb"
	b.runCmd(t, nil, "kv", "put", "-f", path2, in)
	b.runCmd(t, nil, "kv", "get", path2, out)

	s2 := readFile(out)
	require.Equal(t, s, s2)

	// Now do the same thing, but on behalf o a team...
	// First try stdout
	tm := "t-" + strings.ToLower(randomString()[0:10])
	merklePoke(t)
	var res lcl.TeamCreateRes
	b.runCmdToJSON(t, &res, "team", "create", tm)
	merklePoke(t)
	path3 := "/ttt"
	s = randomString()
	b.runCmd(t, nil, "kv", "put", "-t", tm, path3, s)
	dat2 = b.runCmdToBytes(t, "kv", "get", "-t", tm, path3, "-")
	require.Equal(t, s, string(dat2))

	path4 := "/uuuu"

	b.runCmd(t, nil, "kv", "mv", "-t", tm, path3, path4)
	dat2 = b.runCmdToBytes(t, "kv", "get", "-t", tm, path4, "-")
	require.Equal(t, s, string(dat2))

	b.runCmd(t, nil, "kv", "mkdir", "-p", "/a/b/c")
	s = randomString()
	b.runCmd(t, nil, "kv", "put", "/a/b/c/d.txt", s)
	s = randomString()
	b.runCmd(t, nil, "kv", "put", "/a/b/c/e.txt", s)

	// test out the rm call
	b.runCmd(t, nil, "kv", "rm", "/a/b/c/d.txt")
	err := b.runCmdErr(nil, "kv", "ls", "/a/b/c/d.txt")
	require.Error(t, err)
	require.Equal(t, core.KVNoentError{Path: proto.KVPath("d.txt")}, err)
	err = b.runCmdErr(nil, "kv", "rm", "/a/b/c")
	require.Error(t, err)
	require.Equal(t, core.KVRmdirNeedRecursiveError{}, err)
	b.runCmd(t, nil, "kv", "rm", "-R", "/a/b/c")
	err = b.runCmdErr(nil, "kv", "ls", "/a/b/c")
	require.Error(t, err)
	require.Equal(t, core.KVNoentError{Path: proto.KVPath("c")}, err)

}
func fsRandomString(t *testing.T, n int) string {
	if n == 0 {
		var c [1]byte
		err := core.RandomFill(c[:])
		require.NoError(t, err)
		n = int(c[0]%128 + 2)
	}
	dat := make([]byte, n)
	err := core.RandomFill(dat[:])
	require.NoError(t, err)
	return core.B62Encode(dat[:])
}

func TestKVList(t *testing.T) {

	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	parentPath := "/" + fsRandomString(t, 8)
	b := bob.agent
	b.runCmd(t, nil, "kv", "mkdir", "-p", parentPath)

	var paths []string

	for i := 0; i < 8; i++ {
		dat := fsRandomString(t, 0)
		name := fsRandomString(t, 24)
		path := parentPath + "/" + name
		paths = append(paths, path)
		b.runCmd(t, nil, "kv", "put", path, dat)
	}
	slices.Sort(paths)

	var got []string
	var res lcl.CliKVListRes
	b.runCmdToJSON(t, &res, "kv", "ls", parentPath)
	for _, item := range res.Ents {
		got = append(got, string(res.Parent)+string(item.Name))
	}
	slices.Sort(got)
	require.Equal(t, paths, got)
}

func TestKVListRoot(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	rs := fsRandomString(t, 8)
	parentPath := "/" + rs
	b := bob.agent
	b.runCmd(t, nil, "kv", "mkdir", "-p", parentPath)

	var ret lcl.CliKVListRes
	b.runCmdToJSON(t, &ret, "kv", "ls", "/")
	require.Len(t, ret.Ents, 1)
	require.Equal(t, ret.Ents[0].Name, proto.KVPathComponent(rs))
	require.True(t, ret.Ents[0].Value.IsDir())
}

func TestMakeRootOnFirstWrite(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	rs := fsRandomString(t, 8)
	path := "/" + rs
	b := bob.agent
	b.runCmd(t, nil, "kv", "put", path, "foooo")
}

func TestMkdirRoot(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	b := bob.agent
	b.runCmd(t, nil, "kv", "mkdir", "/")
	err := b.runCmdErr(nil, "kv", "mkdir", "/")
	require.Error(t, err)
	require.Equal(t, core.KVExistsError{}, err)
	b.runCmd(t, nil, "kv", "put", "/aaa", "foooo")
}

func TestKVTestPut404(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	rs := fsRandomString(t, 8)
	parentPath := "/" + rs
	b := bob.agent
	err := b.runCmdErr(nil, "kv", "put", parentPath+"/xxx", "foooo")
	require.Error(t, err)
	require.Equal(t, core.KVNoentOnWriteError{Path: proto.KVPath(parentPath)}, err)
}
