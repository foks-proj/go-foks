// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

var cmds []shared.CLIApp

func AddCmd(cmd shared.CLIApp) {
	cmds = append(cmds, cmd)
}

func newRootCmd() *shared.RootCommand {
	var ret shared.RootCommand
	ret.Cmd = &cobra.Command{
		Use:   "foks-tool",
		Short: "FOKS tool is a server-side CLI application for configuring and initializing a FOKS server",
		Long: `FOKS tool is a server-side command-line application for configuring and initializing a FOKS server.
It has various modalities like making new keysets for FOKS domains, writing initial Merkle Trees, hostchains, etc.
To be used largely when bootstrapping a new FOKS host.`,
	}
	ret.AddGlobalOptions()
	return &ret
}

func main() {
	core.DebugStop()
	shared.MainWrapperWithCLICmd(newRootCmd(), cmds)
}
