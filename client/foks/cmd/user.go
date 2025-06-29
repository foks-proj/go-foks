// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/spf13/cobra"
)

func userLoadMeCmd(m libclient.MetaContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "load-me",
		Short:        "load active user (via user loader)",
		Long:         `Load active user (via user loader)`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunUserLoadMe(m, cmd, arg)
		},
	}
	return cmd
}

func RunUserLoadMe(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	return quickStartLambda(m, nil, func(cli lcl.UserClient) error {
		res, err := cli.LoadMe(m.Ctx())
		if err != nil {
			return err
		}
		return JSONOutput(m, res)
	})
}

func userCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "user",
		Short:        "manger local users",
		Long:         "Manage users active on this device",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	top.AddCommand(userLoadMeCmd(m))
	return top
}

func init() {
	AddCmd(userCmd)
}
