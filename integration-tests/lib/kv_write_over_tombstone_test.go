// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
)

// A removed name takes a write -- put, mkdir -p, mv -- from any device, not
// only from one whose dirent cache holds the tombstone. x and y write; z only
// reads, so each read fetches the rewritten dirent from the server and checks
// its MACs.
func TestWriteOverTombstone(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 3, libclient.CacheSettings{UseMem: true, UseDisk: true})
	x, y, z := mdt.dev[0], mdt.dev[1], mdt.dev[2]

	run := func(name string, f func(t *testing.T)) {
		mdt.reset(t)
		t.Run(name, f)
	}

	run("put from the removing device", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		x.unlink(t, "/a/f")
		x.echo(t, "v2", "/a/f")
		z.cat(t, "/a/f", "v2")
	})

	run("put from a device that never saw the name", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		x.unlink(t, "/a/f")
		y.echo(t, "v2", "/a/f")
		z.cat(t, "/a/f", "v2")
	})

	run("put from a device holding the live dirent", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		y.cat(t, "/a/f", "v1")
		x.unlink(t, "/a/f")
		y.echo(t, "v2", "/a/f")
		z.cat(t, "/a/f", "v2")
	})

	run("mkdir -p through a removed directory", func(t *testing.T) {
		x.echo(t, "v1", "/a/b/f")
		x.unlink(t, "/a/b")
		y.echo(t, "v2", "/a/b/g")
		z.cat(t, "/a/b/g", "v2")
	})

	run("mv a file onto a removed name", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		x.unlink(t, "/a/f")
		x.echo(t, "v2", "/a/g")
		y.mv(t, "/a/g", "/a/f")
		z.cat(t, "/a/f", "v2")
	})

	run("mv a directory onto a removed name", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		x.unlink(t, "/a/f")
		x.echo(t, "v2", "/a/d/h")
		y.mv(t, "/a/d", "/a/f")
		z.cat(t, "/a/f/h", "v2")
	})

	// A symlink to a removed file behaves like one to a name that never
	// existed: the move writes through the link, which lives in another
	// directory under another key.
	run("mv onto a symlink to a removed file", func(t *testing.T) {
		x.echo(t, "v1", "/b/t")
		x.mkdir(t, "/a")
		x.ln(t, "/a/s", "/b/t")
		x.unlink(t, "/b/t")
		x.echo(t, "v2", "/a/g")
		y.mv(t, "/a/g", "/a/s")
		z.cat(t, "/a/s", "v2")
		z.cat(t, "/b/t", "v2")
	})

	run("a read of a removed name finds nothing", func(t *testing.T) {
		x.echo(t, "v1", "/a/f")
		x.unlink(t, "/a/f")
		z.statErr(t, "/a/f", core.KVNoentError{Path: z.pathify("/a/f")})
	})
}
