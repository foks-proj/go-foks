// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libterm"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/spf13/cobra"
)

var gitOpts = agent.StartupOpts{
	GitRemoteHelper: true,
}

type HelperLogger struct {
	xp rpc.Transporter
}

func newHelperLogger(xp rpc.Transporter) *HelperLogger {
	return &HelperLogger{xp: xp}
}

func (h *HelperLogger) GitLog(ctx context.Context, lines []lcl.LogLine) error {
	for _, l := range lines {
		var parts []string
		if l.CarriageReturn {
			parts = append(parts, "\r")
		}
		parts = append(parts, l.Msg)
		if l.Newline {
			parts = append(parts, "\n")
		}
		_, err := os.Stderr.WriteString(strings.Join(parts, ""))
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *HelperLogger) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (h *HelperLogger) Run(mctx libclient.MetaContext) {
	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	srv := rpc.NewServer(h.xp, wef)
	err := srv.RegisterV2(
		lcl.GitHelperLogProtocol(h),
	)
	if err != nil {
		mctx.Errorw("failed to register git helper log protocol", "err", err)
		return
	}
	<-srv.Run()
	err = srv.Err()
	if err != nil && err != io.EOF {
		mctx.Errorw("server error", "err", err)
	}
}

func runGit(
	mctx libclient.MetaContext,
	cmd *cobra.Command,
	args []string,
	cli lcl.GitHelperClient,
) error {

	xp, err := cli.Cli.Transport(mctx.Ctx())
	if err != nil {
		return err
	}
	go newHelperLogger(xp).Run(mctx)

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	err = cli.GitInit(mctx.Ctx(), lcl.GitInitArg{
		Argv:   args,
		Wd:     proto.LocalFSPath(wd),
		GitDir: proto.LocalFSPath(os.Getenv("GIT_DIR")),
	})

	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Text()
		res, err := cli.GitOp(mctx.Ctx(), line)
		if err != nil {
			return err
		}
		for _, l := range res.Lines {
			_, err = os.Stdout.WriteString(l + "\n")
			if err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return err
}

func rootCmdGitRemoteHelper(mctx libclient.MetaContext) *cobra.Command {
	return &cobra.Command{
		Use:   GitRemoteHelper + " branch remote",
		Short: "git remote helper",
		Long: libterm.MustRewrapSense(`Remote helper for git, following the Git-Remote-Helper protocol. 
Users should typically not call into this executable directly. Rather, it is called from git
when interacting with remote repositories prefixed by the foks:// protocol. It must be
in the current path for git to be able to find it. 

git doesn't supply any flags, so to change FOKS-specific behavior,
use either environment variables or configuration files.`, 0),
		Example:      GitRemoteHelper + " origin foks://ne43.pub/t:firingSquad/secrets",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return quickStartLambda(
				mctx,
				&gitOpts,
				func(cli lcl.GitHelperClient) error {
					return runGit(mctx, cmd, args, cli)
				})
		},
	}
}
