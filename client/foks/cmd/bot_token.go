// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"os"
	"strings"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

var botTokOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

func botTokenNewCmd(m libclient.MetaContext, top *cobra.Command) {
	var role string
	botTokNew := &cobra.Command{
		Use:     "new",
		Aliases: []string{"mk"},
		Short:   "create a new bot token key",
		Long: libterm.MustRewrapSense(`Create a new bot token key

Bot Token keys are awfully similar to backup keys, but have a diffferent
encoding system so they can be manipulated easier in the context of
automated deployments. Bot tokens look like: a428e.ABERee949038eEr;
i.e., there are no spaces or special characters, so they are easier to
use in scripts. 

They are intended largely for bots or automated deployments. Bot tokens
are loaded into an agent process when a container spins up; the key can then
remain in memory for the lifetime of the container, acting like any other
type of key.`, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			return quickStartLambda(m, &botTokOpts, func(cli lcl.BotTokenClient) error {
				if role == "" {
					role = "o"
				}
				rs := proto.RoleString(role)
				pr, err := rs.Parse()
				if err != nil {
					return err
				}
				res, err := cli.BotTokenNew(m.Ctx(), *pr)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				roleLong, err := pr.StringErr()
				if err != nil {
					return err
				}
				msg := "Bot Token Generated\n" +
					"-------------------\n\n" +
					"Bot Token was generated with control over this account, at role=" +
					roleLong + ".\n" +
					"\n" +
					"Please copy this bot token to a safe place, and never share it!\n" +
					"\n" +
					"   " + string(res) +
					"\n\n"

				m.G().UIs().Terminal.Printf(msg)
				return nil
			})
		},
	}
	botTokNew.Flags().StringVar(&role, "role", "o", "role to add the bot token as (defualts to 'owner')")
	top.AddCommand(botTokNew)
}

type botTokenLoadArgs struct {
	host proto.TCPAddr
	tok  lcl.BotTokenString
}

func botTokenUseCmd(m libclient.MetaContext, nm string, aliases []string, longExtra string) *cobra.Command {
	var tokStr string
	var hostStr string
	long := `Load a bot token into memory and set it as the active key; can
specify the bot token as a command line argument (via --token), via 
the environment variable FOKS_BOT_TOKEN, or via standard input. Standard input
is polled if no other method is specified. Either way, the target host must
be specified via --host.
`
	if len(longExtra) != 0 {
		long += ".\n" + longExtra
	}
	botTokLoad := &cobra.Command{
		Use:          nm,
		Aliases:      aliases,
		Short:        "load a bot token key into memory",
		Long:         long,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			var args botTokenLoadArgs
			if len(hostStr) == 0 {
				return ArgsError("expected --host to be set")
			}

			args.host = proto.TCPAddr(hostStr)
			err := core.ValidateTCPAddr(args.host)
			if err != nil {
				return err
			}

			// We can alternatively provide this token on standard input,
			// or via environment variable, if necessitated by security
			// concerns.

			tokStrEnv := os.Getenv("FOKS_BOT_TOKEN")
			if len(tokStr) != 0 && len(tokStrEnv) != 0 {
				return ArgsError("expected only one of --token or FOKS_BOT_TOKEN to be set")
			}
			if len(tokStrEnv) != 0 {
				tokStr = tokStrEnv
			}
			args.tok = lcl.BotTokenString(tokStr)

			if len(tokStr) != 0 {
				args.tok = lcl.BotTokenString(tokStr)
				var tmp core.BotToken
				err := tmp.Import(args.tok)
				if err != nil {
					return err
				}
			}
			return runBotTokenLoad(m, args)
		},
	}
	botTokLoad.Flags().StringVarP(&tokStr, "token", "", "", "bot token")
	botTokLoad.Flags().StringVarP(&hostStr, "host", "", "", "host to connect to")

	return botTokLoad
}

func runBotTokenLoad(m libclient.MetaContext, args botTokenLoadArgs) (err error) {
	err = agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer cleanFn()

	botTokCli := lcl.BotTokenClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	tok := args.tok

	if len(tok) == 0 {
		line, err := m.G().UIs().Terminal.ReadLine("")
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		err = core.ValidateBotTokenString(lcl.BotTokenString(line))
		if err != nil {
			return err
		}
		tok = lcl.BotTokenString(line)
	}

	return botTokCli.BotTokenLoad(m.Ctx(), lcl.BotTokenLoadArg{
		Host: args.host,
		Tok:  tok,
	})
}

func botTokenCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "bot",
		Aliases:      []string{"bot-token"},
		Short:        "manage bot tokens",
		Long:         "Manage bot tokens",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	botTokenNewCmd(m, top)
	load := botTokenUseCmd(m, "use", []string{"load", "ld"},
		`This command is a synonym for "foks key use-bot-token".`)
	top.AddCommand(load)
	return top
}

func init() {
	AddCmd(botTokenCmd)
}
