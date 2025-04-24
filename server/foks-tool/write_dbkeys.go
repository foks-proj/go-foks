// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type WriteDbKeys struct {
	CLIAppBase
	DoCSRFPRotect bool // a late addition, can be done but itself
}

var _ shared.CLIApp = (*WriteDbKeys)(nil)

func (i *WriteDbKeys) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "write-db-keys",
		Short: "Generate and rite challenge MAC keys to the database",
	}
	ret.Flags().BoolVar(&i.DoCSRFPRotect, "csrf-protect", false, "do only CSRF protect")
	return ret
}

func (i *WriteDbKeys) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	return nil
}

func (i *WriteDbKeys) SetGlobalContext(g *shared.GlobalContext) {}

func (i *WriteDbKeys) Run(m shared.MetaContext) error {
	err := shared.InitHostID(m)
	if err != nil {
		return err
	}

	var lst []shared.HmacKeyType

	if i.DoCSRFPRotect {
		lst = append(lst, shared.HmacKeyCSRFProtect)
	}

	if len(lst) == 0 {
		return shared.GenerateNewChallengeHMACKeys(m)
	}

	return shared.GenerateSomeNewChallengeHMACKeys(m, lst)
}

var _ shared.CLIApp = (*WriteDbKeys)(nil)

func init() {
	AddCmd(&WriteDbKeys{})
}
