// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/tools"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type FilterLog struct {
	CLIAppBase
	opts tools.FilterLogOpts
	cmd  *cobra.Command
}

func (f *FilterLog) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "filter-log",
		Short: "Filter log output",
		Long:  "Filter log output according to level (and maybe eventually tags); also convert time to human-readable",
	}
	ret.Flags().StringVarP(&f.opts.Level, "level", "l", "info", "Minimum log level to show")
	f.cmd = ret
	return ret
}

func (f *FilterLog) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	return nil
}

func (f *FilterLog) Run(m shared.MetaContext) error {
	return tools.RunFilterLog(f.cmd, nil, &f.opts)
}

func (f *FilterLog) SetGlobalContext(_ *shared.GlobalContext) {}

var _ shared.CLIApp = (*FilterLog)(nil)

func init() {
	AddCmd(&FilterLog{})
}
