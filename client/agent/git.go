// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"slices"
	"strings"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libgit"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type GitTermLog struct {
	xp  rpc.Transporter
	cli lcl.GitHelperLogClient
}

func NewGitTermLog(xp rpc.Transporter) *GitTermLog {
	return &GitTermLog{
		xp: xp,
		cli: lcl.GitHelperLogClient{
			Cli:            rpc.NewClient(xp, nil, nil),
			ErrorUnwrapper: core.StatusToError,
		},
	}
}

func (c *GitTermLog) Log(ctx context.Context, t remhelp.TermLogLine) {
	msg := []lcl.LogLine{
		{
			Msg:            t.Msg,
			Newline:        (t.Opts&remhelp.TermLogNoNewline == 0),
			CarriageReturn: (t.Opts&remhelp.TermLogCr != 0),
		},
	}
	_ = c.cli.GitLog(ctx, msg)
}

var _ remhelp.TermLogger = (*GitTermLog)(nil)

func (c *AgentConn) GitInit(ctx context.Context, arg lcl.GitInitArg) error {
	c.gitMu.Lock()
	defer c.gitMu.Unlock()

	mctx := c.MetaContext(ctx)

	if c.git != nil {
		return core.GitGenericError("double init")
	}
	lcd, err := remhelp.NewLocalCheckDirFromWorkingDirAndGitDir(
		remhelp.LocalPath(arg.Wd.String()),
		remhelp.LocalPath(arg.GitDir.String()),
	)
	if err != nil {
		return err
	}

	git := libgit.NewAgent(arg.Argv, lcd, NewGitTermLog(c.xp))

	err = git.Init(mctx)
	if err != nil {
		return err
	}
	c.git = git

	return nil
}

func (c *AgentConn) GitOp(ctx context.Context, line string) (lcl.GitOpRes, error) {
	var zed lcl.GitOpRes

	c.gitMu.Lock()
	git := c.git
	c.gitMu.Unlock()

	if git == nil {
		return zed, core.GitGenericError("not initialized")
	}

	res, err := git.PumpInRPC(ctx, line)
	if err != nil {
		return zed, err
	}

	return lcl.GitOpRes{Lines: res}, nil
}

func (c *AgentConn) GitCreate(
	ctx context.Context,
	arg lcl.GitCreateArg,
) (proto.GitURL, error) {

	var zed proto.GitURL
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return zed, err
	}
	nm, err := libgit.NormalizedRepoName(string(arg.Nm))
	if err != nil {
		return zed, err
	}
	gp := libgit.NewGitPath(nm)
	top := gp.Path()
	refs := gp.RefsPath()

	_, err = tm.Stat(m, arg.Cfg, top)
	if err == nil {
		return zed, core.KVExistsError{}
	}
	if core.IsKVNoentError(err) {
		err = nil
	}
	if err != nil {
		return zed, err
	}
	arg.Cfg.MkdirP = true
	_, err = tm.Mkdir(m, arg.Cfg, refs)
	if err != nil {
		return zed, err
	}

	fqpp, err := libclient.ActivePartyNamed(m.MetaContext, arg.Cfg.ActingAs)
	if err != nil {
		return zed, err
	}

	url := proto.GitURL{
		Proto: proto.GitProtoType_Foks,
		Fqp:   *fqpp,
		Repo:  arg.Nm,
	}
	return url, nil
}

func (c *AgentConn) GitLs(ctx context.Context, cfg lcl.KVConfig) ([]proto.GitURL, error) {
	m, tm, err := c.kvInit(ctx, cfg)
	if err != nil {
		return nil, err
	}
	path := proto.KVPathAbs(libgit.GitPathPrefix...)
	var did *proto.DirID
	var ret []proto.GitURL
	var strt proto.KVListPagination
	var eof bool

	fqpp, err := libclient.ActivePartyNamed(m.MetaContext, cfg.ActingAs)
	if err != nil {
		return nil, err
	}

	listSome := func() error {
		opts := rem.KVListOpts{
			Num:   128,
			Start: strt,
		}

		ls, err := tm.List(m, cfg, path, did, opts)
		if err != nil {
			return err
		}
		for _, ent := range ls.Ents {
			if !ent.Value.IsDir() {
				continue
			}
			ret = append(ret, proto.GitURL{
				Proto: proto.GitProtoType_Foks,
				Fqp:   *fqpp,
				Repo:  proto.GitRepo(ent.Name),
			})
		}
		if ls.Nxt != nil {
			did = &ls.Nxt.Id
			strt = ls.Nxt.Nxt
		} else {
			eof = true
		}
		return nil
	}

	for !eof {
		err := listSome()
		if err != nil {
			return nil, err
		}
	}

	slices.SortFunc(ret, func(a, b proto.GitURL) int {
		return strings.Compare(string(a.Repo), string(b.Repo))
	})

	return ret, nil
}

var _ lcl.GitHelperInterface = (*AgentConn)(nil)
var _ lcl.GitInterface = (*AgentConn)(nil)
