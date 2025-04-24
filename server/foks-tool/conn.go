// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"crypto/x509"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type Connect struct {
	CLIAppBase
	addr string
	typ  CKSAssetType
}

func (g *Connect) NeedConfig() bool {
	return true
}

func (g *Connect) TweakOpts(opts *shared.GlobalCLIConfigOpts) {
	if !g.NeedConfig() {
		opts.SkipNetwork = true
	}
}

func (g *Connect) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:     "connect",
		Aliases: []string{"conn"},
		Short:   "test connect to a FOKS server",
	}
	ret.Flags().StringVarP(&g.addr, "addr", "a", "", "address to connect to")
	ret.Flags().Var(&g.typ, "ca-type", "use the specified CAs to connect {backend-ca,hostchain-frontend-ca}")
	return ret
}

func (g *Connect) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if len(g.addr) == 0 {
		return core.BadArgsError("missing required --addr parameter")
	}

	switch g.typ.v {
	case proto.CKSAssetType_None,
		proto.CKSAssetType_BackendCA,
		proto.CKSAssetType_HostchainFrontendCA:
	default:
		return core.BadArgsError("invalid value for --ca-type")
	}
	return nil
}

func (g *Connect) Run(m shared.MetaContext) error {
	rm := shared.RpcClientMetaContext{
		MetaContext: shared.NewMetaContext(m.Ctx(), m.G()),
	}
	opts := core.NewRpcClientOpts()
	var pool *x509.CertPool
	var err error

	if g.typ.v == proto.CKSAssetType_None {
		pool, _, err = m.G().Config().ProbeRootCAs(m.Ctx())
	} else {
		pool, err = m.G().CertMgr().Pool(m, nil, g.typ.v, proto.Hostname(""))
	}
	if err != nil {
		return err
	}
	cli := core.NewRpcClient(
		rm,
		proto.TCPAddr(g.addr),
		pool,
		nil,
		opts,
	)
	_, err = cli.Connect(m.Ctx())
	if err != nil {
		return err
	}
	return nil
}

func (g *Connect) SetGlobalContext(gctx *shared.GlobalContext) {}

var _ shared.CLIApp = (*Connect)(nil)

func init() {
	AddCmd(&Connect{})
}
