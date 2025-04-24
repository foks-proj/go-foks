// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/spf13/cobra"
)

func ping(m libclient.MetaContext, cmd *cobra.Command, args []string) error {
	return quickStartLambda(m, nil, func(cli lcl.UserClient) error {
		res, err := cli.Ping(m.Ctx())
		if err != nil {
			return err
		}
		return JSONOutput(m, res)
	})
}

func pingCmd(m libclient.MetaContext, parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "ping",
		Short: "ping the FOKS user server to validate login credentials",
		Long:  `ping the FOKS user server to validate login credentials`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ping(m, cmd, args)
		},
	}
	parent.AddCommand(cmd)
}
