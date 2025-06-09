// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type ViewCmd struct {
	CLIAppBase
	SetTo string
	Set   *proto.ViewershipMode
	Hosts []int
}

func (o *ViewCmd) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:     "viewiership",
		Aliases: []string{"view"},
		Short:   "Check or change viewership settings for a FOKS host (or vhost)",
		Long: `Check or change viewership settings for a FOKS host (or vhost).
With --set, will try to set the value to the given bool. Withou --set, will print the current value.
If there is only one virtual host on this machine, no need to specify --host-id on --set,
but otherwise, you must.`,
	}
	ret.Flags().StringVar(&o.SetTo, "set", "", "Set the viewership setting to the given value; must be 'open' or 'closed'")
	ret.Flags().IntSliceVar(&o.Hosts, "host-id", nil, "Host IDs to apply changes to; required if there are multiple hosts on this machine")
	return ret
}

func (i *ViewCmd) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if i.SetTo != "" {
		var tmp proto.ViewershipMode
		err := tmp.ImportFromCLI(i.SetTo)
		if err != nil {
			return core.BadArgsError("invalid value for --set; must be 'open' or 'closed'")
		}
		i.Set = &tmp
	}
	return nil
}

func (o *ViewCmd) Run(m shared.MetaContext) error {
	hosts := core.Map(o.Hosts, func(i int) core.ShortHostID {
		return core.ShortHostID(i)
	})
	if o.Set == nil {
		_, err := shared.GetViewership(m, hosts)
		return err
	}
	return shared.SetViewership(m, *o.Set, hosts)
}

func (k *ViewCmd) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*ViewCmd)(nil)

func init() {
	AddCmd(&ViewCmd{})
}
