// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CKSAssetType struct {
	v proto.CKSAssetType
}

func (c *CKSAssetType) IsZero() bool {
	return c.v == proto.CKSAssetType_None
}

var _ pflag.Value = (*CKSAssetType)(nil)

func (c *CKSAssetType) Set(s string) error {
	return c.v.ImportFromDB(s)
}

func (c *CKSAssetType) String() string {
	return c.v.String()
}

func (c *CKSAssetType) Type() string {
	return "CKS Asset Type"
}

type GenCA struct {
	CLIAppBase
	keyFile  string
	certFile string
	typ      CKSAssetType
}

func (g *GenCA) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "gen-ca",
		Short: "Generate a new CA pair",
	}
	ret.Flags().StringVarP(&g.keyFile, "key", "", "", "where to write the key file")
	ret.Flags().StringVarP(&g.certFile, "cert", "", "", "where to write the cert file")
	ret.Flags().Var(&g.typ, "type", "which type of CA (can't be used with --key or --cert)")
	return ret
}

func (g *GenCA) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}

	haveKey := g.keyFile != ""
	haveCert := g.certFile != ""
	haveType := !g.typ.IsZero()

	if haveType && (haveKey || haveCert) {
		return core.BadArgsError("--type can't be used with --key or --cert")
	}
	if haveKey != haveCert {
		return core.BadArgsError("both --key and --cert must be provided")
	}
	if !haveCert && !haveType {
		return core.BadArgsError("either --type or both --key and --cert must be provided")
	}
	return nil
}

func (g *GenCA) Run(m shared.MetaContext) error {
	switch {
	case g.keyFile != "" && g.certFile != "":
		return shared.GenCA(core.Path(g.keyFile), core.Path(g.certFile))
	case !g.typ.IsZero():
		switch g.typ.v {
		case proto.CKSAssetType_InternalClientCA,
			proto.CKSAssetType_ExternalClientCA,
			proto.CKSAssetType_BackendCA:
			return m.G().CertMgr().GenCA(m, g.typ.v)
		default:
			return core.BadArgsError("invalid CA type; need one of: internal-client-ca, external-client-ca, backend-ca")
		}
	default:
		return core.InternalError("unreachable")
	}
}

func (g *GenCA) SetGlobalContext(gctx *shared.GlobalContext) {}

var _ shared.CLIApp = (*GenCA)(nil)

func init() {
	AddCmd(&GenCA{})
}
