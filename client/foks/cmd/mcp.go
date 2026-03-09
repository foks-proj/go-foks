// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/spf13/cobra"
)

var mcpStartupOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

func runMCPServer(m libclient.MetaContext) (rpc.GenericClient, func(), error) {
	err := agent.Startup(m, mcpStartupOpts)
	if err != nil {
		return nil, nil, err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return nil, nil, err
	}
	return gcli, cleanFn, nil
}

func mcpCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "mcp",
		Short:        "MCP (Model Context Protocol) server commands",
		Long:         "Run MCP servers that expose FOKS functionality to LLM tools",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return subcommandHelp(cmd, args)
		},
	}
	mcpKVCmd(m, top)
	mcpTeamCmd(m, top)
	return top
}

func init() {
	AddCmd(mcpCmd)
}
