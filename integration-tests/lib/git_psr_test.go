// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libgit"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/stretchr/testify/require"
)

type rawIndexAndPack struct {
	remhelp.RawIndex
	pack []byte
}

func newRawIndexAndPack(t *testing.T, i int) rawIndexAndPack {
	dat := make([]byte, 100)
	err := core.RandomFill(dat)
	require.NoError(t, err)
	dat[0] = byte(i)
	sum := sha1.Sum(dat)
	hex := hex.EncodeToString(sum[:])
	pack := make([]byte, 200)
	err = core.RandomFill(pack)
	require.NoError(t, err)
	pack[0] = byte(i)
	return rawIndexAndPack{
		RawIndex: remhelp.RawIndex{
			Name:  remhelp.IndexName(hex),
			Data:  dat,
			CTime: time.Now(),
		},
		pack: pack,
	}
}

func (r *rawIndexAndPack) packReader() io.Reader {
	return bytes.NewReader(r.pack)
}

func (r *rawIndexAndPack) idxReader() io.Reader {
	return bytes.NewReader(r.Data)
}

func TestPSR(t *testing.T) {
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
	repo := proto.GitRepo("keepey-uppey")
	storage := bluey.makeStorage(t, fqt, repo, opts)
	psr := storage.NewPackSyncRemote()
	ctx := context.Background()

	// We're going to filter out indices we've already seen,
	// since there is a small chance of a race due to the microsecond
	// overlap of the two indices.
	seen := make(map[remhelp.IndexName]bool)
	filter := func(raw []remhelp.RawIndex) []remhelp.RawIndex {
		ret := []remhelp.RawIndex{}
		for _, r := range raw {
			if !seen[r.Name] {
				seen[r.Name] = true
				ret = append(ret, r)
			}
		}
		return ret
	}

	raw, err := psr.FetchNewIndices(ctx, time.Time{})
	raw = filter(raw)
	require.NoError(t, err)
	require.Equal(t, 0, len(raw))

	var rips []rawIndexAndPack

	rip := newRawIndexAndPack(t, 0)
	rips = append(rips, rip)

	push := func(rip *rawIndexAndPack) {
		err = psr.PushPackData(ctx, rip.Name, rip.packReader())
		require.NoError(t, err)
		err = psr.PushPackIndex(ctx, rip.Name, rip.idxReader())
		require.NoError(t, err)
	}

	push(&rip)

	pre := time.Now()
	raw, err = psr.FetchNewIndices(ctx, time.Time{})
	require.NoError(t, err)
	raw = filter(raw)
	require.Equal(t, 1, len(raw))

	require.Equal(t, rips[0].Name, raw[0].Name)
	require.Equal(t, rips[0].Data, raw[0].Data)

	rip1 := newRawIndexAndPack(t, 1)
	push(&rip1)
	rips = append(rips, rip1)
	raw, err = psr.FetchNewIndices(ctx, pre)
	raw = filter(raw)
	require.NoError(t, err)
	require.Equal(t, 1, len(raw))

	require.Equal(t, rip1.Name, raw[0].Name)
	require.Equal(t, rip1.Data, raw[0].Data)

	pre = time.Now()
	for i := 2; i < 20; i++ {
		rip := newRawIndexAndPack(t, i)
		push(&rip)
		rips = append(rips, rip)
	}
	newRips := rips[2:]

	raw, err = psr.FetchNewIndices(ctx, pre)
	raw = filter(raw)
	require.NoError(t, err)
	require.Equal(t, len(newRips), len(raw))

	for i, rip := range newRips {
		require.Equal(t, rip.Name, raw[i].Name)
		require.Equal(t, rip.Data, raw[i].Data)
	}

	var buf bytes.Buffer
	err = psr.FetchPackData(ctx, newRips[0].Name, &buf)
	require.NoError(t, err)
	require.Equal(t, newRips[0].pack, buf.Bytes())
}
