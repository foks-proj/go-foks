// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"os"
	"path/filepath"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libgit"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/spf13/cobra"
)

func quickGitCmd(
	m libclient.MetaContext,
	top *cobra.Command,
	use string,
	aliases []string,
	short string,
	long string,
	quickKVOpts quickKVOpts,
	setup func(cob *cobra.Command),
	quickGitFn func(arg []string, cfg lcl.KVConfig, kvcli lcl.GitClient) error,
) {
	quickKVCmd(m, top, use, aliases, short, long, quickKVOpts, setup,
		func(arg []string, cfg lcl.KVConfig, kvcli lcl.KVClient) error {
			gcli := kvcli.Cli
			cli := lcl.GitClient{
				Cli:            gcli,
				ErrorUnwrapper: lcl.GitErrorUnwrapper(kvcli.ErrorUnwrapper),
			}
			return quickGitFn(arg, cfg, cli)
		},
	)
}

func gitCreate(m libclient.MetaContext, top *cobra.Command) {
	quickGitCmd(m, top,
		"create reponame", nil,
		"Create a new git repository",
		"Create a new git repository",
		quickKVOpts{NoSupportMkdirP: true},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.GitClient) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the repo name")
			}
			name, err := libgit.NormalizedRepoName(arg[0])
			if err != nil {
				return err
			}
			url, err := cli.GitCreate(m.Ctx(), lcl.GitCreateArg{
				Nm:  name,
				Cfg: cfg,
			})
			if err != nil {
				return err
			}
			urlStr, err := url.StringErr()
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("Created: %s\n", urlStr)
			err = PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func gitShellConfig(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"shell-config",
		[]string{"env"},
		"print shell configuration for git",
		"print shell configuration for git; will output toward bash (i.e., with `export` statements)",
		func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return ArgsError("expected 0 arguments")
			}
			term := m.G().UIs().Terminal
			home, err := m.G().Cfg().HomeFinder().Home(true)
			if err != nil {
				return err
			}
			term.Printf("export HOME=%s\n", home)
			cfg, err := m.G().Cfg().ConfigFile()
			if err != nil {
				return err
			}
			term.Printf("export FOKS_CONFIG=%s\n", cfg)
			path := filepath.Dir(os.Args[0])
			if path != "" && path != "." && path != "./" {
				term.Printf("export PATH=%s:$PATH\n", path)
			}
			return nil
		},
	)
}

func gitSetDefaultBranch(m libclient.MetaContext, top *cobra.Command) {
	var force bool
	quickGitCmd(m, top,
		"set-default-branch", nil,
		"Set the default branch for a git repository",
		"Set the default branch for a git repository",
		quickKVOpts{
			NoSupportMkdirP: true,
		},
		func(cob *cobra.Command) {
			cob.Flags().BoolVar(&force, "force", false,
				"force setting the default branch even if the branch does not exist",
			)
		},
		func(arg []string, cfg lcl.KVConfig, kvcli lcl.GitClient) error {
			if len(arg) != 2 {
				return ArgsError("expected exactly two arguments -- the repo name and the branch name")
			}
			name, err := libgit.NormalizedRepoName(arg[0])
			if err != nil {
				return err
			}
			branch := arg[1]
			err = kvcli.GitSetDefaultBranch(m.Ctx(), lcl.GitSetDefaultBranchArg{
				Nm:    name,
				Rn:    lcl.GitReferenceName(branch),
				Cfg:   cfg,
				Force: force,
			})
			if dErr, dangler := err.(core.GitDanglingRefError); dangler && dErr.Forced {
				m.G().UIs().Terminal.Printf("Warning: dangling reference '%s' (forced)\n", branch)
			} else if err != nil {
				return err
			}
			err = PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func gitGetDefaultBranch(m libclient.MetaContext, top *cobra.Command) {
	quickGitCmd(m, top,
		"get-default-branch", nil,
		"Get the default branch for a git repository",
		"Get the default branch for a git repository",
		quickKVOpts{
			NoSupportMkdirP: true,
		}, nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.GitClient) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the repo name")
			}
			name, err := libgit.NormalizedRepoName(arg[0])
			if err != nil {
				return err
			}
			branch, err := cli.GitGetDefaultBranch(
				m.Ctx(),
				lcl.GitGetDefaultBranchArg{
					Nm:  name,
					Cfg: cfg,
				},
			)
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("%s\n", branch)
			err = PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func gitLs(m libclient.MetaContext, top *cobra.Command) {

	var doAll bool

	quickGitCmd(m, top,
		"ls", []string{"list"},
		"list remote git repositories",
		"list remote git repositories",
		quickKVOpts{},
		func(cob *cobra.Command) {
			cob.Flags().BoolVar(&doAll, "all-teams", false,
				"list remote git repositories for all teams current user is a member of",
			)
		},
		func(arg []string, cfg lcl.KVConfig, cli lcl.GitClient) error {
			if len(arg) != 0 {
				return ArgsError("expected 0 arguments")
			}
			urls, err := cli.GitLs(m.Ctx(),
				lcl.GitLsArg{
					Cfg:      cfg,
					AllTeams: doAll,
				},
			)

			// KVNoent errors on /app or /app/git is swallowed up
			// on the agent side, so we should never see it here.
			// Any error is a real error.
			if err != nil {
				return err
			}

			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, urls)
			}

			for _, url := range urls {
				s, err := url.StringErr()
				if err != nil {
					return err
				}
				m.G().UIs().Terminal.Printf("%s\t%s\n", url.Repo, s)
			}
			err = PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func gitCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "git",
		Short:        "manage remote git repositories",
		Long:         "manage remote git repositories",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}
	gitCreate(m, top)
	gitShellConfig(m, top)
	gitLs(m, top)
	gitGetDefaultBranch(m, top)
	gitSetDefaultBranch(m, top)
	return top
}

func init() {
	AddCmd(gitCmd)
}
