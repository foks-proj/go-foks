// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestGitRefs(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 3, libkv.CacheSettings{UseMem: true, UseDisk: true})
	x, y, z := mdt.dev[0], mdt.dev[1], mdt.dev[2]
	parent := "/app/git/redbulls/"
	heads := parent + "refs/heads"
	fn := func(s string) string { return heads + "/" + s }
	x.mkdir(t, heads)
	x.echo(t, "a1", fn("a"))
	x.echo(t, "b1", fn("b"))
	err := x.kvm.PutGitRef(x.mc, lcl.KVConfig{}, y.pathify(parent), proto.KVPath("refs/heads/max/c/beta"), "c1")
	require.NoError(t, err)

	expected := []proto.GitRef{
		{Name: proto.KVPath("refs/heads/a"), Value: "a1"},
		{Name: proto.KVPath("refs/heads/b"), Value: "b1"},
		{Name: proto.KVPath("refs/heads/max/c/beta"), Value: "c1"},
	}

	res, err := y.kvm.ExploreGitRefs(y.mc, lcl.KVConfig{}, y.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)

	gr, vers, err := y.kvm.GetGitRef(y.mc, lcl.KVConfig{}, y.pathify(parent), proto.KVPath("refs/heads/max/c/beta"))
	require.NoError(t, err)
	require.Equal(t, "c1", gr)
	require.Equal(t, proto.KVVersion(1), vers)

	x.echo(t, "d1", fn("d"))
	expected = append(expected,
		proto.GitRef{Name: proto.KVPath("refs/heads/d"), Value: "d1"},
	)

	res, err = y.kvm.ExploreGitRefs(y.mc, lcl.KVConfig{}, y.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)

	x.echo(t, "a2", fn("a"))
	expected = expected[1:]
	expected = append(expected,
		proto.GitRef{Name: proto.KVPath("refs/heads/a"), Value: "a2"},
	)

	res, err = y.kvm.ExploreGitRefs(y.mc, lcl.KVConfig{}, y.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)

	x.unlink(t, fn("b"))
	x.echo(t, "e1", fn("e"))

	expected = expected[1:]
	expected = append(expected,
		proto.GitRef{Name: proto.KVPath("refs/heads/e"), Value: "e1"},
	)

	res, err = y.kvm.ExploreGitRefs(y.mc, lcl.KVConfig{}, y.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)

	res, err = z.kvm.ExploreGitRefs(z.mc, lcl.KVConfig{}, z.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)

	err = z.kvm.UnlinkGitRef(z.mc, lcl.KVConfig{}, z.pathify(parent), proto.KVPath("refs/heads/e"))
	require.NoError(t, err)
	expected = expected[:len(expected)-1]
	res, err = x.kvm.ExploreGitRefs(x.mc, lcl.KVConfig{}, x.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, expected, res)
}

func TestGitRefsHEAD(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	x := mdt.dev[0]
	parent := "/app/git/nycfc/"
	x.mkdir(t, parent)
	err := x.kvm.PutGitRef(x.mc, lcl.KVConfig{}, x.pathify(parent), proto.KVPath("HEAD"), "h1")
	require.NoError(t, err)

	res, err := x.kvm.ExploreGitRefs(x.mc, lcl.KVConfig{}, x.pathify(parent), &libkv.ExploreGitRefsOpts{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, []proto.GitRef{
		{Name: proto.KVPath("HEAD"), Value: "h1"},
	}, res)

	gr, vers, err := x.kvm.GetGitRef(x.mc, lcl.KVConfig{}, x.pathify(parent), proto.KVPath("HEAD"))
	require.NoError(t, err)
	require.Equal(t, "h1", gr)
	require.Equal(t, proto.KVVersion(1), vers)
}
