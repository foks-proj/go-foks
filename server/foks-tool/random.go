// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type RandomCommand struct {
	CLIAppBase
	Base core.Base

	rb       int
	numBytes int
}

func (b *RandomCommand) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:     "random",
		Short:   "generate a random string of the given base",
		Aliases: []string{"rand"},
	}
	ret.Flags().IntVarP(&b.rb, "base", "b", 16, "base to use for encoding {10, 16, 36, 62, 64}")
	ret.Flags().IntVarP(&b.numBytes, "num-bytes", "n", 10, "number of bytes to generate")
	return ret
}

func (b *RandomCommand) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	switch b.rb {
	case 10, 16, 36, 62, 64:
		b.Base = core.Base(b.rb)
	default:
		return core.BadArgsError("invalid base")
	}
	return nil
}

func (b *RandomCommand) Run(m shared.MetaContext) error {
	bytes := make([]byte, b.numBytes)
	err := core.RandomFill(bytes[:])
	if err != nil {
		return err
	}
	s, err := b.Base.Encode(bytes)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", s)
	return nil
}

func (b *RandomCommand) TweakOpts(opts *shared.GlobalCLIConfigOpts) {
	opts.SkipNetwork = true
	opts.SkipConfig = true
}

func (b *RandomCommand) SetGlobalContext(g *shared.GlobalContext) {
}

func init() {
	AddCmd(&RandomCommand{})
}
