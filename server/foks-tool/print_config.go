// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type PrintConfig struct {
	CLIAppBase
}

func (p *PrintConfig) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "print-config",
		Short: "Print the current configuration in JSON",
	}
	return ret
}

func (p *PrintConfig) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	return nil
}

func (p *PrintConfig) Run(m shared.MetaContext) error {
	cfg := m.G().Config()
	raw, err := cfg.RawJSON()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", raw)
	return nil
}

func (p *PrintConfig) SetGlobalContext(gctx *shared.GlobalContext) {}

var _ shared.CLIApp = (*PrintConfig)(nil)

func init() {
	AddCmd(&PrintConfig{})
}
