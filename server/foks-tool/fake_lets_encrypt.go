// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type LetsEncrypt struct {
	BaseCertCommand
	caKey  core.Path
	caCert core.Path
}

func (l *LetsEncrypt) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "lets-encrypt",
		Short: "Fake issuing a certificate from Let's Encrypt (only for test)",
	}
	l.AddFlags(ret.Flags())
	ret.Flags().Var(&l.caKey, "ca-key", "CA key to sign with")
	ret.Flags().Var(&l.caCert, "ca-cert", "CA cert to sign with")
	return ret
}

func (l *LetsEncrypt) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if l.typ.IsZero() {
		return core.BadArgsError("missing required --type parameter")
	}
	switch l.typ.v {
	case proto.CKSAssetType_RootPKIBeaconX509Cert,
		proto.CKSAssetType_RootPKIFrontendX509Cert:
	default:
		return core.BadArgsError("unsupported --type parameter " +
			"(need root-pki-beacon-x509-cert or root-pki-frontend-x509-cert)")
	}
	if len(l.hosts) == 0 {
		return core.BadArgsError("missing --hosts parameter")
	}
	if len(l.caKey) == 0 {
		return core.BadArgsError("missing --key parameter")
	}
	if len(l.caCert) == 0 {
		return core.BadArgsError("missing --cert parameter")
	}
	return nil
}

func (l *LetsEncrypt) Run(m shared.MetaContext) error {
	cert, err := shared.ReadCertFromFile(l.caCert)
	if err != nil {
		return err
	}
	key, err := shared.ReadSecretKeyFromFile(m.Ctx(), l.caKey)
	if err != nil {
		return err
	}
	hosts, err := l.Hosts(m)
	if err != nil {
		return err
	}
	err = shared.EmulateLetsEncrypt(m, hosts, nil, cert, key, proto.CKSAssetType_RootPKIFrontendX509Cert, false)
	if err != nil {
		return err
	}
	return nil
}

func (l *LetsEncrypt) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*LetsEncrypt)(nil)

func init() {
	AddCmd(&LetsEncrypt{})
}
