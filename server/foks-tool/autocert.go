// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type Autocert struct {
	CLIAppBase
	port int
	typ  proto.ServerType
}

func (a *Autocert) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "autocert",
		Short: "Get LetsEncrypt certificates for probe, beacon service (or both)",
		Long: `Get LetsEncrypt certificates for probe, beacon service (or both).
This command allows a port to be provided; the port can also be specified in configuration
via the 'autocert_port' field. However, this setting will only impact the port our 
HTTP server is listening on. Let's Encrypt insists on probing port 80 regardless
of what we'd want. Yet, this port feature might still be interesting if the port is 
remapped or proxied further upstream, so we leave it in.`,
	}
	ret.Flags().IntVarP(&a.port, "port", "", 0, "Port to listen for ACME request on")
	return ret
}

func (a *Autocert) CheckArgs(args []string) error {
	if len(args) != 1 {
		return core.BadArgsError("Must specify one argument, the server-type {beacon,probe})")
	}
	err := a.typ.ImportFromString(args[0])
	if err != nil {
		return core.BadArgsError("Invalid server type")
	}
	switch a.typ {
	case proto.ServerType_Beacon, proto.ServerType_Probe:
	default:
		return core.BadArgsError("need one of {beacon,probe}")
	}
	return nil
}

func (a *Autocert) Run(m shared.MetaContext) error {
	err := shared.InitHostID(m)
	if err != nil {
		return err
	}
	pkg, err := m.G().Config().AutocertPackage(m.Ctx(), a.typ, proto.Port(a.port))
	if err != nil {
		return err
	}
	hid := m.HostID().Id
	arg := infra.DoAutocertArg{
		WaitFor: proto.ExportDurationMilli(20 * time.Minute),
		Pkg: infra.AutocertPackage{
			Hostname: pkg.Hostname,
			Hostid:   hid,
			Styp:     a.typ,
		},
	}
	err = shared.OneshotAutocert(m, arg, proto.Port(a.port))
	if err != nil {
		return err
	}

	return nil
}

func (a *Autocert) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*Autocert)(nil)

func init() {
	AddCmd(&Autocert{})
}
