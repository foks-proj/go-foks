// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type ImportCert struct {
	CLIAppBase
	importer *shared.CKSCertImporter
	host     string
	cert     string
	key      string
	typRaw   string
}

func (i *ImportCert) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "import-cert",
		Short: "Import a TLS certificate/key pair for a host",
		Long: libterm.MustRewrapSense(`This command imports a TLS certificate and private key for a specified host.
Works for either the outward-facing Beacon or Probe server. Use this if you are bringing your own cert/keypair
and do not want to use the default Let's Encrypt machinery. If you do this, the impetus is on you to refresh
certs as needed, as there will be no automated mechanism (via the "autocert" process) to do this for you.

When supplying the cert, you should provide a chain of certificates, with the leaf certificate first.

Note that a hostname in the leaf cert must match the host you are working on behalf of. If none specified,
this will be the default host (specified foks.jsonnet). A host can be specified with the --host flag,
as either a host name (DNS name) or a host ID.
`, 0),
	}
	ret.Flags().StringVar(&i.host, "host", "", "host name or ID; if none specified, the default host is used")
	ret.Flags().StringVar(&i.cert, "cert", "", "Path to the TLS certificate file; chain of certs, leaf first")
	ret.Flags().StringVar(&i.key, "key", "", "Path to the TLS private key file")
	ret.Flags().StringVar(&i.typRaw, "type", "", "Cert type; one of: beacon, probe; if none specified, probe is assumed")
	return ret
}

func (i *ImportCert) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}

	for _, s := range []struct {
		key string
		val string
	}{
		{key: "cert", val: i.cert},
		{key: "key", val: i.key},
	} {
		if len(s.val) == 0 {
			return core.BadArgsError(fmt.Sprintf("missing required --%s parameter", s.key))
		}
	}

	var typ proto.CKSAssetType
	switch i.typRaw {
	case "", "probe":
		typ = proto.CKSAssetType_RootPKIFrontendX509Cert
	case "beacon":
		typ = proto.CKSAssetType_RootPKIBeaconX509Cert
	default:
		return core.BadArgsError(fmt.Sprintf("invalid cert type: %s", i.typRaw))
	}
	i.importer = shared.NewCKSCertImporter()

	err := i.importer.Configure(
		core.Path(i.key),
		core.Path(i.cert),
		typ,
		i.host,
	)
	if err != nil {
		return err
	}
	return nil
}

func (i *ImportCert) Run(m shared.MetaContext) error {
	err := shared.InitHostID(m)
	if err != nil {
		return err
	}
	err = i.importer.Run(m)
	if err != nil {
		return err
	}
	return nil
}

func (i *ImportCert) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*ImportCert)(nil)

func init() {
	AddCmd(&ImportCert{})
}
