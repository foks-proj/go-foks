// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type WritePublicZone struct {
	CLIAppBase
	key string
}

func (i *WritePublicZone) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "write-public-zone",
		Short: "Write the public zone file",
	}
	ret.Flags().StringVarP(&i.key, "key", "", "", "where to read the metadata signing key from")
	return ret
}

func (i *WritePublicZone) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if i.key == "" {
		return errors.New("must specify file")
	}
	return nil
}

func (i *WritePublicZone) Run(m shared.MetaContext) error {
	hk, err := shared.ReadHostKeyFromFile(m.Ctx(), core.Path(i.key))
	if err != nil {
		return err
	}
	hkc := shared.NewHostChain()
	err = hkc.LoadKeyIntoState(hk)
	if err != nil {
		return err
	}
	err = hkc.LoadFromDB(m)
	if err != nil {
		return err
	}

	err = shared.StorePublicZone(m, *hk)
	if err != nil {
		return err
	}
	return nil
}

func (i *WritePublicZone) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*WritePublicZone)(nil)

func init() {
	AddCmd(&WritePublicZone{})
}
