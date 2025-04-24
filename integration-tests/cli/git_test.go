// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/stretchr/testify/require"
)

type gitTestEnv struct {
	*remhelp.TestEnv
	path     string
	hostname proto.Hostname
	tvh      *common.TestVHost
}

func (g *gitTestEnv) socket() string {
	return filepath.Join(g.Dir, "foks.sock")
}

func (g *gitTestEnv) newAgentAndUser(t *testing.T) *userAgentBundle {
	rn, err := core.RandomBase36String(8)
	require.NoError(t, err)
	hostname := "git-" + rn
	tvh := globalTestEnv.VHostInit(t, hostname)
	return g.newAgentAndUserWithVHost(t, tvh)
}

func (g *gitTestEnv) newAgentAndUserWithVHost(t *testing.T, tvh *common.TestVHost) *userAgentBundle {
	var ret userAgentBundle
	g.tvh = tvh
	ret.initFuncAndAgentOpts(
		t,
		func(u *mockSignupUI) *mockSignupUI {
			return u.withDeviceKey().withServer(tvh.ProbeAddr)
		},
		agentOpts{
			socketFile: g.socket(),
			dnsAliases: []proto.Hostname{tvh.Hostname},
		})
	var st lcl.AgentStatus
	ret.agent.runCmdToJSON(t, &st, "status")
	require.Equal(t, len(st.Users), 1)
	uinfo := st.Users[0].Info
	hn := uinfo.HostAddr.Hostname()
	un := uinfo.Username.NameUtf8
	rn, err := core.RandomBase36String(8)
	require.NoError(t, err)
	g.TestEnv.Desc = remhelp.GitRepoDesc{
		ProtName: "foks",
		Host:     string(hn),
		As:       string(un),
		RepoName: rn,
	}
	g.hostname = hn
	return &ret
}

func (g *gitTestEnv) SetActAs(s string) {
	g.TestEnv.Desc.As = s
}

func (g *gitTestEnv) setenv() {
	if g.EnvIsSet {
		return
	}
	os.Setenv("FOKS_SOCKET_FILE", g.socket())
	g.path = os.Getenv("PATH")
	os.Setenv("PATH", fmt.Sprintf("%s:%s", g.Bin, g.path))
	g.EnvIsSet = true
}

func (g *gitTestEnv) restoreEnv() {
	os.Unsetenv("FOKS_SOCKET_FILE")
	os.Setenv("PATH", g.path)
}

var tapMu sync.Mutex
var tapPath string

func compileTap(t *testing.T) string {
	tapMu.Lock()
	defer tapMu.Unlock()
	if tapPath != "" {
		return tapPath
	}
	cd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(cd)
	}()

	tmpDir := os.TempDir()
	tapBinPath := filepath.Join(tmpDir, "foks_test_tap")
	err = os.MkdirAll(tapBinPath, 0755)
	require.NoError(t, err)

	goBinPrev := os.Getenv("GOBIN")
	os.Setenv("GOBIN", tapBinPath)
	defer os.Setenv("GOBIN", goBinPrev)

	err = os.Chdir("../../client/foks")
	require.NoError(t, err)
	goBinaryPath, err := exec.LookPath("go")
	require.NoError(t, err)

	now := time.Now()
	fmt.Printf("+ build foks binary\n")
	err = remhelp.EasyExec(goBinaryPath, "install")
	dur := time.Since(now)
	fmt.Printf("- build foks binary (%s)\n", dur)
	require.NoError(t, err)

	tapPath = filepath.Join(tapBinPath, "foks")
	return tapPath
}

func (g *gitTestEnv) InstallTap(t *testing.T) {
	tapPath := compileTap(t)
	err := os.MkdirAll(g.Bin, 0755)
	require.NoError(t, err)
	err = remhelp.EasyExec("cp", tapPath, filepath.Join(g.Bin, "git-remote-foks"))
	require.NoError(t, err)
}

func newGitTestEnv(t *testing.T) (*gitTestEnv, func()) {
	base, err := remhelp.NewTestEnvWithPrefix("foks_integration_cli_test_")
	require.NoError(t, err)
	ret := &gitTestEnv{TestEnv: base}
	ret.InstallTap(t)
	ret.setenv()
	return ret, func() {
		ret.restoreEnv()
		os.RemoveAll(ret.Dir)
	}
}

func TestGitSimplePushFetch(t *testing.T) {
	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Mkdir(t, "a/b")
	sr.WriteFile(t, "a/b/1", "11111")
	sr.WriteFile(t, "a/2", "2222")
	sr.Mkdir(t, "booo")
	sr.WriteFile(t, "booo/f3.txt", "3333")

	big := make([]byte, 1024*1024)
	err := core.RandomFill(big)
	require.NoError(t, err)
	sr.WriteFileBinary(t, "biggie", big)

	sr.Git(t, "init")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "initial commit")
	sr.Git(t, "remote", "add", "origin", sr.Origin())

	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)

	sr.Git(t, "push", "-vvvv", "origin", "main")

	sr2 := gte.NewScratchRepo(t)
	sr2.Git(t, "clone", sr.Origin(), ".")
	sr2.ReadFile(t, "a/b/1", "11111")
	sr2.ReadFile(t, "a/2", "2222")
	sr2.ReadFile(t, "booo/f3.txt", "3333")
	sr2.ReadFileBinary(t, "biggie", big)

	// switch to branch b1, make a change to a/b/1, and then push it
	sr.Git(t, "checkout", "-b", "b1")
	sr.WriteFile(t, "a/b/1", "b1 1")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "b1 1")
	sr.Git(t, "push", "origin", "b1")

	// over in checkout2, we fetch the branch that checkout1 just pushed
	sr2.Git(t, "fetch", "origin", "b1")
	sr2.Git(t, "checkout", "b1")
	sr2.ReadFile(t, "a/b/1", "b1 1")

	// checkout1 makes another change to to the file and pushes
	sr.WriteFile(t, "a/b/1", "b1 2")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "b1 2")
	sr.Git(t, "push", "origin", "b1")

	// checkout2 makes a parallel change to the same file
	sr2.WriteFile(t, "a/b/1", "b1 3")
	sr2.Git(t, "add", ".")
	sr2.Git(t, "commit", "-m", "b1 3")

	// should fail without the force
	err = sr2.GitWithErr(t, "push", "origin", "b1")
	require.Error(t, err)
	require.IsType(t, &remhelp.GitError{}, err)
	// should succeed with it
	sr2.Git(t, "push", "-f", "origin", "b1")

	// hard reset should fix it
	sr.Git(t, "fetch", "origin", "b1")
	sr.Git(t, "reset", "--hard", "origin/b1")
	sr.ReadFile(t, "a/b/1", "b1 3")
}

func TestGitTeamSimplePushFetch(t *testing.T) {
	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	x := gte.newAgentAndUser(t)
	r, err := core.RandomBase36String(10)
	require.NoError(t, err)

	tm := "t-" + strings.ToLower(r)
	merklePoke(t)
	merklePoke(t)
	var res lcl.TeamCreateRes
	x.agent.runCmdToJSON(t, &res, "team", "create", tm)
	merklePoke(t)

	tmPrefixed := fmt.Sprintf("t:%s", tm)
	fqt := fmt.Sprintf("%s@%s", tmPrefixed, gte.hostname)
	gte.SetActAs(tmPrefixed)

	sr := gte.NewScratchRepo(t)

	sr.Mkdir(t, "a/b")
	sr.WriteFile(t, "a/b/1", "11111")
	sr.WriteFile(t, "a/2", "2222")

	sr.Git(t, "init")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "initial commit")
	sr.Git(t, "remote", "add", "origin", sr.Origin())

	merklePoke(t)
	x.agent.runCmd(t, nil, "git", "create", "--team", fqt, gte.Desc.RepoName)

	sr.Git(t, "push", "-vvvv", "origin", "main")

	// x is going to invite y into the team tm with permissions member/0
	var res3 proto.TeamInvite
	x.agent.runCmdToJSON(t, &res3, "team", "invite", tm)
	inviteStr, err := team.ExportTeamInvite(res3)
	require.NoError(t, err)

	gte2, cleanup := newGitTestEnv(t)
	defer cleanup()
	y := gte2.newAgentAndUserWithVHost(t, gte.tvh)
	merklePoke(t)
	merklePoke(t)

	y.agent.runCmd(t, nil, "team", "accept", inviteStr)

	var inb lcl.TeamInbox
	x.agent.runCmdToJSON(t, &inb, "team", "inbox", tm)
	require.Equal(t, 1, len(inb.Rows))
	x.agent.runCmd(t, nil, "team", "admit", tm, string(inb.Rows[0].Tok.String())+"/m/0")
	merklePoke(t)

	sr2 := gte2.NewScratchRepo(t)
	sr2.Git(t, "clone", sr.Origin(), ".")
	sr2.ReadFile(t, "a/b/1", "11111")
	sr2.ReadFile(t, "a/2", "2222")
}

func TestGitSimplePushFetchPack(t *testing.T) {
	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Git(t, "init")
	mk := func(low, hi int) {
		for i := low; i < hi; i++ {
			sr.WriteFile(t, fmt.Sprintf("f-%d", i), fmt.Sprintf("%d%d", i, i))
		}
		sr.Git(t, "add", ".")
		sr.Git(t, "commit", "-m", "files")
		sr.Git(t, "repack")
	}
	for j := 0; j < 10; j++ {
		mk(j*3, (j+1)*3)
	}

	sr.Git(t, "remote", "add", "origin", sr.Origin())

	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)

	sr.Git(t, "push", "-vvvv", "origin", "main")

	sr2 := gte.NewScratchRepo(t)
	sr2.Git(t, "clone", sr.Origin(), ".")
}

func TestGitMainVsMaster(t *testing.T) {

	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Git(t, "init")
	sr.Git(t, "branch", "-m", "master")

	sr.WriteFile(t, "f1", "11111")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "f1")
	sr.Git(t, "remote", "add", "origin", sr.Origin())

	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)
	sr.Git(t, "push", "-u", "origin", "master")

	sr.WriteFile(t, "f2", "22222")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "f2")
	sr.Git(t, "push", "origin", "master")

	sr2 := gte.NewScratchRepo(t)
	sr2.Git(t, "clone", sr.Origin(), ".")

	// test repro -> this fails! -- now let's fix
	sr2.ReadFile(t, "f1", "11111")
}

func TestGitForcePush(t *testing.T) {

	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Git(t, "init")
	sr.Git(t, "checkout", "-b", "b1")
	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)

	sr.WriteFile(t, "f1", "11111")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "c1")
	sr.Git(t, "remote", "add", "origin", sr.Origin())
	sr.Git(t, "push", "origin", "b1")
	sr.Git(t, "commit", "--amend", "-m", "c2")

	// should fail because it's not a fast-forward push
	err := sr.GitWithErr(t, "push", "origin", "b1")
	require.Error(t, err)

	// should work, but See Issue #83
	sr.Git(t, "push", "-f", "origin", "b1")
}

func TestGitDeleteRemoteBranch(t *testing.T) {

	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Git(t, "init")
	sr.Git(t, "checkout", "-b", "b1")
	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)

	sr.WriteFile(t, "f1", "11111")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "c1")
	sr.Git(t, "remote", "add", "origin", sr.Origin())
	sr.Git(t, "push", "origin", "b1")

	sr.Git(t, "push", "origin", ":b1")
}

func TestOneArgClone(t *testing.T) {
	gte, cleanup := newGitTestEnv(t)
	defer cleanup()
	au := gte.newAgentAndUser(t)
	sr := gte.NewScratchRepo(t)

	sr.Git(t, "init")
	merklePoke(t)
	au.agent.runCmd(t, nil, "git", "create", gte.Desc.RepoName)

	sr.WriteFile(t, "f1", "11111")
	sr.Git(t, "add", ".")
	sr.Git(t, "commit", "-m", "c1")
	sr.Git(t, "remote", "add", "origin", sr.Origin())
	sr.Git(t, "push", "origin", "main")

	sr2 := gte.NewScratchRepo(t)
	sr2.Git(t, "clone", sr.Origin())
}
