// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/stretchr/testify/require"
)

func randomGitProtocol(t *testing.T) string {
	buf := make([]byte, 6)
	err := core.RandomFill(buf)
	require.NoError(t, err)
	return "x" + core.Base36Encoding.EncodeToString(buf)
}

func TestSimplePushFetch(t *testing.T) {
	prot := randomGitProtocol(t)
	te, err := remhelp.NewTestEnv()
	require.NoError(t, err)
	err = te.InitWithDesc(remhelp.GitRepoDesc{
		ProtName: prot,
		RepoName: "xxxx",
	})
	require.NoError(t, err)
	defer func() {
		_ = te.Cleanup()
	}()
	sr := te.NewScratchRepo(t)

	sr.Mkdir(t, "a/b")
	sr.Mkdir(t, "c")
	sr.WriteFile(t, "a/b/1", "11111")
	sr.WriteFile(t, "a/2", "2222")
	sr.WriteFile(t, "c/3", "3333")

	sr.Git(t, "init")

	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "initial commit")
	sr.WriteFile(t, "a/4", "444444")
	sr.Git(t, "add", "a/4")
	sr.Git(t, "commit", "-m", "add a/4")
	sr.Git(t, "remote", "add", "origin", sr.Origin())
	sr.Git(t, "push", "-vvvv", "origin", "main")
}
