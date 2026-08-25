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

type WritePublicZone struct {
	CLIAppBase
	key   string
	vhost string
}

func (i *WritePublicZone) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "write-public-zone",
		Short: "Write the public zone file",
		Long: `Write the public zone file.

With --key, write the zone for the host the tool is scoped to (by default
the config's primary host), signing with the given metadata key file, and
addressing services at the config's external listen addresses.

With --vhost, refresh the named virtual host's zone instead: the vhost's
short host ID, hostname, and metadata signing key are all resolved
automatically, and services are addressed at the vhost's own hostname, as
they were when the vhost was first created.`,
	}
	ret.Flags().StringVarP(&i.key, "key", "", "", "where to read the metadata signing key from")
	ret.Flags().StringVarP(&i.vhost, "vhost", "", "", "hostname of the virtual host to write the zone for")
	return ret
}

func (i *WritePublicZone) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if (i.key == "") == (i.vhost == "") {
		return errors.New("must specify exactly one of --key or --vhost")
	}
	return nil
}

func (i *WritePublicZone) Run(m shared.MetaContext) error {
	if i.vhost != "" {
		return shared.WritePublicZoneForVHost(m, proto.Hostname(i.vhost))
	}
	return doWritePublicZone(m, core.Path(i.key))
}

func doWritePublicZone(m shared.MetaContext, key core.Path) error {
	hk, err := shared.ReadHostKeyFromFile(m.Ctx(), key)
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
