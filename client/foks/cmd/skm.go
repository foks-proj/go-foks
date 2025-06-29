// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"strings"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

func skmCmd(m libclient.MetaContext) *cobra.Command {

	top := &cobra.Command{
		Use:          "secret-key-material",
		Aliases:      []string{"skm"},
		Short:        "secret key material encryption settings",
		Long:         "device secret keys encrypted with a variety of strategies; this command queries and sets them",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}

	top.AddCommand(&cobra.Command{
		Use:          "info",
		Short:        "get info",
		Long:         "for active user, show which strategy is being used and with which parameters",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return skmInfo(m, cmd, arg)
		},
	})

	top.AddCommand(&cobra.Command{
		Use:          "set-mode",
		Short:        "set SKM encryption mode",
		Long:         "set SKM encryption mode; options include `macos`, `noise`, `passphrase` and `none`",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return skmSetMode(m, cmd, arg)
		},
	})

	return top
}

func skmSetMode(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	if len(arg) != 1 {
		return ArgsError("expected exactly one argument")
	}

	smode := strings.TrimSpace(strings.ToLower(arg[0]))
	var mode proto.SecretKeyStorageType
	switch smode {
	case "macos", "macos-keychain":
		mode = proto.SecretKeyStorageType_ENC_MACOS_KEYCHAIN
	case "noise", "noise-file":
		mode = proto.SecretKeyStorageType_ENC_NOISE_FILE
	case "passphrase":
		mode = proto.SecretKeyStorageType_ENC_PASSPHRASE
	case "none", "plaintext", "plain":
		mode = proto.SecretKeyStorageType_PLAINTEXT
	default:
		return ArgsError("unknown mode: " + smode)
	}

	return quickStartLambda(m, &agent.StartupOpts{NeedUser: true, NeedUnlockedUser: true},
		func(cli lcl.UserClient) error {
			return cli.SetSkmEncryption(m.Ctx(), mode)
		},
	)
}

func skmInfo(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	return quickStartLambda(m, &agent.StartupOpts{},
		func(cli lcl.UserClient) error {
			j, err := cli.SkmInfo(m.Ctx())
			if err != nil {
				return err
			}
			return JSONOutput(m, j)
		},
	)
}

func init() {
	AddCmd(skmCmd)
}
