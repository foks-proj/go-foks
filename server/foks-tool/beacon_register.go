// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type BeaconRegister struct {
	CLIAppBase
}

func (k *BeaconRegister) CobraConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "beacon-register",
		Short: "Register this host with the global beacon service",
	}
}

func (k *BeaconRegister) Run(m shared.MetaContext) error {
	err := shared.InitHostID(m)
	if err != nil {
		return err
	}
	var zed proto.Hostname
	return shared.BeaconRegisterCli(m, zed, nil)
}

func (k *BeaconRegister) SetGlobalContext(g *shared.GlobalContext) {}
func (m *BeaconRegister) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	return nil
}

var _ shared.CLIApp = (*BeaconRegister)(nil)

func init() {
	AddCmd(&BeaconRegister{})
}
