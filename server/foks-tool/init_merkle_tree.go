// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type InitMerkleTree struct {
	CLIAppBase
}

func (i *InitMerkleTree) CobraConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "init-merkle-tree",
		Short: "Initialize the Merkle Tree for the given host",
	}
}

func (i *InitMerkleTree) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	return nil
}

func (i *InitMerkleTree) Run(m shared.MetaContext) error {
	s := shared.NewSQLStorage(m)
	err := merkle.InitTree(m, s)
	if err != nil {
		return err
	}
	return nil
}

func (i *InitMerkleTree) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*InitMerkleTree)(nil)

func init() {
	AddCmd(&InitMerkleTree{})
}
