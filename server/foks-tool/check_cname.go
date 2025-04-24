// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type CheckCNAME struct {
	CLIAppBase
	from string
	to   string
	srvs []string
}

func (c *CheckCNAME) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "check-cname",
		Short: "Check that a CNAME record points to the correct target",
	}
	ret.Flags().StringVar(&c.from, "from", "", "the CNAME record to check")
	ret.Flags().StringVar(&c.to, "to", "", "the expected target of the CNAME record")
	ret.Flags().StringSliceVar(&c.srvs, "server", nil, "the DNS server(s) to use for the check")
	return ret
}

func (c *CheckCNAME) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if c.from == "" {
		return core.BadArgsError("no --from parameter specified")
	}
	if c.to == "" {
		return core.BadArgsError("no --to parameter specified")
	}
	if len(c.srvs) == 0 {
		c.srvs = []string{
			"1.1.1.1", // Cloudflare
			"8.8.8.8", // Google
		}
	}
	return nil
}

func (c *CheckCNAME) Run(m shared.MetaContext) error {
	srvs := core.Map(c.srvs, func(s string) proto.TCPAddr { return proto.TCPAddr(s) })
	return shared.CheckCNAME(
		m,
		proto.Hostname(c.from),
		proto.Hostname(c.to),
		srvs,
		time.Second*5,
		nil,
	)
}

func (c *CheckCNAME) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*CheckCNAME)(nil)

func init() {
	AddCmd(&CheckCNAME{})
}
