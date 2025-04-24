// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"log"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BaseCertCommand struct {
	CLIAppBase
	typ   CKSAssetType
	hosts []string
}

type IssueCert struct {
	BaseCertCommand
}

func (b *BaseCertCommand) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&b.hosts, "hosts", nil, "Comma-separated hostnames and IPs to generate a certificate for")
	fs.Var(&b.typ, "type", "type of cert to issue")
}

func (i *IssueCert) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "issue-cert",
		Short: "Issue a certificates for a host",
	}
	i.AddFlags(ret.Flags())
	return ret
}

func (i *IssueCert) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if i.typ.IsZero() {
		return core.BadArgsError("missing required --type parameter")
	}
	if len(i.hosts) == 0 {
		return core.BadArgsError("missing --hosts parameter")
	}
	return nil
}

func (b *BaseCertCommand) Hosts(m shared.MetaContext) ([]proto.Hostname, error) {
	ret := core.Map(b.hosts, func(h string) proto.Hostname { return proto.Hostname(h) })
	return ret, nil
}

func (b *BaseCertCommand) Print(s string, args ...interface{}) {
	log.Printf(s+"\n", args...)
}

func (i *IssueCert) Run(m shared.MetaContext) error {

	caTyp := i.typ.v.CAType()
	if caTyp == proto.CKSAssetType_None {
		return core.BadArgsError("invalid cert type; need either 'hostchain-frontend-x509-cert' or 'backend-x509-cert'")
	}
	hosts, err := i.Hosts(m)
	if err != nil {
		return err
	}
	err = shared.InitHostID(m)
	if err != nil {
		return err
	}
	err = m.G().CertMgr().GenServerCert(m, hosts, nil, caTyp, i.typ.v)
	if err != nil {
		return err
	}
	return nil
}

func (k *IssueCert) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*IssueCert)(nil)

func init() {
	AddCmd(&IssueCert{})
}
