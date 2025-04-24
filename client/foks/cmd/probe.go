// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

// linked into foks CLI program via the `tools` command
type ProbeCmdConfig struct {
	addrRaw string
}

func probeCmd(m libclient.MetaContext, parent *cobra.Command) {
	var dcfg ProbeCmdConfig
	cmd := &cobra.Command{
		Use:          "probe",
		Short:        "probe FOKS servers",
		Long:         `Contact the hardcoded (or supplied) primary server and ask for other servers it knows about`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunProbe(m, cmd, &dcfg, arg)
		},
	}
	cmd.Flags().StringVarP(&dcfg.addrRaw, "addr", "a", "", "address to connect to")
	parent.AddCommand(cmd)
}

func RunProbe(m libclient.MetaContext, cmd *cobra.Command, scfg *ProbeCmdConfig, arg []string) error {
	err := agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer cleanFn()
	addr := proto.TCPAddr(scfg.addrRaw)
	cli := lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	res, err := cli.Probe(m.Ctx(), addr)
	if err != nil {
		return err
	}
	m.G().UIs().Terminal.Printf("%+v\n", res)
	if m.G().Cfg().JSONOutput() {
		return JSONOutput(m, res)
	}
	return nil
}
