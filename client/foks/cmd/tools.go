// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	cmdTools "github.com/foks-proj/go-foks/client/foks/cmd/tools"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/tools"
	"github.com/spf13/cobra"
)

func toolsCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "tools",
		Short:        "tools for use in debugging and development",
		Long:         `tools for use in debugging and development`,
		SilenceUsage: true,
	}
	top.AddCommand(tools.FilterLogCommand("filter-log"))
	probeCmd(m, top)
	cmdTools.B62Cmd(m, top)
	pingCmd(m, top)
	return top
}

func init() {
	AddCmd(toolsCmd)
}
