// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"strings"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

var bkpOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

func bkpNewCmd(m libclient.MetaContext, top *cobra.Command) {
	var role string
	bkpNew := &cobra.Command{
		Use:          "new",
		Aliases:      []string{"mk"},
		Short:        "create a new backup key",
		Long:         "Create a new backup key",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			return quickStartLambda(m, &bkpOpts, func(cli lcl.BackupClient) error {
				if role == "" {
					role = "o"
				}
				rs := proto.RoleString(role)
				pr, err := rs.Parse()
				if err != nil {
					return err
				}
				res, err := cli.BackupNew(m.Ctx(), *pr)
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
				msg := "Backup Key Generated\n" +
					"-------------------\n\n" +
					"Backup key was generated with control over this account, at role=" +
					roleLong + ".\n" +
					"\n" +
					"Please write this backup down in a safe place, and never share it!\n" +
					"\n" +
					"   " + strings.Join(res, " ") +
					"\n\n"

				m.G().UIs().Terminal.Printf(msg)
				return nil
			})
		},
	}
	bkpNew.Flags().StringVarP(&role, "role", "", "o", "role to add the backup key as (defualts to 'owner')")
	top.AddCommand(bkpNew)
}

type bkpLoadArgs struct {
	host proto.TCPAddr
	hesp lcl.BackupHESP
}

func bkpUseCmd(m libclient.MetaContext, nm string, aliases []string, longExtra string) *cobra.Command {
	var hespStr string
	var hostStr string
	long := "Load a backup key into memory and set it as the active key"
	if len(longExtra) != 0 {
		long += ".\n" + longExtra
	}
	bkpLoad := &cobra.Command{
		Use:          nm,
		Aliases:      aliases,
		Short:        "load a backup key into memory",
		Long:         long,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			var args bkpLoadArgs

			if len(hostStr) != 0 {
				args.host = proto.TCPAddr(hostStr)
				err := core.ValidateTCPAddr(args.host)
				if err != nil {
					return err
				}
			}

			if len(hespStr) != 0 {
				args.hesp = lcl.BackupHESPString(hespStr).Split()
				var tmp core.BackupKey
				err := tmp.Import(args.hesp)
				if err != nil {
					return err
				}
			}
			return runBackupLoad(m, args)
		},
	}
	bkpLoad.Flags().StringVarP(&hespStr, "seed", "", "", "backup key seed phrase")
	bkpLoad.Flags().StringVarP(&hostStr, "host", "", "", "host to connect to")

	return bkpLoad
}

func runBackupLoad(m libclient.MetaContext, args bkpLoadArgs) (err error) {
	err = agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer cleanFn()

	bkpCli := lcl.BackupClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	genCli := lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	id, err := genCli.NewSession(m.Ctx(), proto.UISessionType_LoadBackup)
	if err != nil {
		return err
	}
	defer func() {
		tmp := genCli.FinishSession(m.Ctx(), id)
		if tmp != nil && err == nil {
			err = tmp
		}
	}()

	var host *proto.TCPAddr

	if len(args.host) == 0 {
		defHost, err := genCli.GetDefaultServer(m.Ctx(), lcl.GetDefaultServerArg{SessionId: id})
		if err != nil {
			return err
		}
		var def proto.TCPAddr
		if !defHost.BigTop.Host.IsZero() {
			def = defHost.BigTop.Host
		}
		tmp, err := m.G().UIs().Backup.PickServer(m, def, 0)
		if err != nil {
			return err
		}
		host = tmp
	} else {
		host = &args.host
	}

	_, err = genCli.PutServer(m.Ctx(), lcl.PutServerArg{SessionId: id, Server: host})
	if err != nil {
		return err
	}

	var hesp lcl.BackupHESP

	if len(args.hesp) == 0 {
		hesp, err = m.G().UIs().Backup.GetBackupKeyHESP(m)
		if err != nil {
			return err
		}
	} else {
		hesp = args.hesp
	}

	err = bkpCli.BackupLoadPutHESP(m.Ctx(), lcl.BackupLoadPutHESPArg{
		SessionId: id,
		Hesp:      hesp,
	})
	if err != nil {
		return err
	}

	return nil
}

func bkpCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "backup",
		Aliases:      []string{"bkp"},
		Short:        "manage backup keys",
		Long:         "Manage backup keys",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	bkpNewCmd(m, top)
	load := bkpUseCmd(m, "use", []string{"load", "ld"},
		`This command is a synonym for "foks key use-backup".`)
	top.AddCommand(load)
	return top
}

func init() {
	AddCmd(bkpCmd)
}
