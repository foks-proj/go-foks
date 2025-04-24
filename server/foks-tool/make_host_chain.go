// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type MakeHostChain struct {
	CLIAppBase
	keysDir  core.Path
	hostname string
}

func (m *MakeHostChain) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "make-host-chain",
		Short: "Initialize a new host chain",
	}
	ret.Flags().VarP(&m.keysDir, "keys-dir", "", "location to write keys")
	ret.Flags().StringVar(&m.hostname, "hostname", "", "hostname to use for the primary server")
	return ret
}

func (m *MakeHostChain) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if len(m.keysDir) == 0 {
		return errors.New("missing required --keys-dir parameter")
	}
	if len(m.hostname) == 0 {
		return errors.New("missing required --hostname parameter")
	}
	return nil
}

func (k *MakeHostChain) Run(m shared.MetaContext) error {
	hc := shared.NewHostChain().WithHostname(proto.Hostname(k.hostname))
	err := hc.Forge(m, k.keysDir)
	if err != nil {
		return err
	}
	return nil
}

func (k *MakeHostChain) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*MakeHostChain)(nil)

func init() {
	AddCmd(&MakeHostChain{})
}
