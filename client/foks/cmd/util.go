// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/spf13/cobra"
)

func triggerBgCLKR(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"trigger-bg-clkr", nil,
		"background clock refresh", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.UtilClient) error {
				return cli.TriggerBgClkr(m.Ctx())
			})
		},
	)
}

func triggerUserRefresh(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"trigger-bg-user-refresh", nil,
		"trigger user refresh", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.UtilClient) error {
				return cli.TriggerBgUserRefresh(m.Ctx())
			})
		},
	)
}

func utilCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "util",
		Short:        "utility commands",
		SilenceUsage: true,
	}
	triggerBgCLKR(m, top)
	triggerUserRefresh(m, top)
	return top
}

func init() {
	AddCmd(utilCmd)
}
