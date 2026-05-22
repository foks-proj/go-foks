// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/engine"
	kvStore "github.com/foks-proj/go-foks/server/kv-store"
	"github.com/foks-proj/go-foks/server/realtime"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/app"
	"github.com/spf13/cobra"
)

func newRootCmd() *shared.RootCommand {
	var ret shared.RootCommand
	ret.Cmd = &cobra.Command{
		Use:   "foks-server",
		Short: "FOKS server is a monolithic server process that contains services required for a hosting a FOKS domain",
		Long: `FOKS server is a server-side daemon for running a FOKS server. It's a monolithic server, which
has code for running all necessary backend components for FOKS. Consult individual subcommands, which are logically
different services. They are bundled conveniently into a single binary for ease of deployment.`,
	}
	ret.AddGlobalOptions()
	return &ret
}

type serverCommand struct {
	shared.Server
	name string
	desc string
}

func (s *serverCommand) CobraConfig() *cobra.Command {
	return &cobra.Command{
		Use:   s.name,
		Short: s.desc,
		Long:  s.desc,
	}
}

var _ shared.ServerCommand = (*serverCommand)(nil)

func newServerList() []shared.ServerCommand {
	w := func(s shared.Server, name, desc string) shared.ServerCommand {
		return &serverCommand{
			Server: s,
			name:   name,
			desc:   desc,
		}
	}
	return []shared.ServerCommand{
		w(&engine.BeaconServer{}, "beacon", "FOKS beacon server, to allow hostID -> IP lookups"),
		w(&engine.InternalCAServer{}, "internal-ca", "FOKS internal CA server, used internally for FOKS servers to auth to each other"),
		w(engine.NewMerkleBatcherServer(), "merkle-batcher", "FOKS Merkle batcher server, to batch Merkle tree updates"),
		w(engine.NewMerkleBuilderServer(), "merkle-builder", "FOKS Merkle builder server, to build Merkle trees incrementally"),
		w(engine.NewMerkleSignerServer(), "merkle-signer", "FOKS Merkle signer server, to sign Merkle tree updates"),
		w(&engine.ProbeServer{}, "probe", "FOKS probe server, returns hostchains to allow service and CA discovery"),
		w(&engine.QueueServer{}, "queue", "FOKS queue server, a lightweight SQS-like service"),
		w(&engine.UserServer{}, "user", "FOKS user server, to allow user management"),
		w(&engine.RegServer{}, "reg", "FOKS reg server, to allow user registration"),
		w(&engine.MerkleQueryServer{}, "merkle-query", "FOKS Merkle query server, to allow querying Merkle trees"),
		w(&kvStore.Server{}, "kv-store", "FOKS Key-Value (KV) Store"),
		w(&engine.QuotaServer{}, "quota", "Quota Server"),
		w(&app.WebServer{}, "web", "Web Server (for admin panels, Stripe Callbacks and OAuth2 Callbacks)"),
		w(&engine.AutocertServer{}, "autocert", "autocert ACME server"),
		w(&realtime.Server{}, "realtime", "realtime/Chat server"),
	}
}

var (
	LinkerVersion = "unknown"
)

func main() {
	core.DebugStop()
	shared.MainWrapperWithServer(newRootCmd(), newServerList(),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version of the FOKS server",
			Run: func(cmd *cobra.Command, args []string) {
				var lv string
				if LinkerVersion != "unknown" {
					lv = " (linked as: " + LinkerVersion + ")"
				}
				cmd.Printf("%s%s\n", core.CurrentSoftwareVersion.String(), lv)
			},
		},
	)
}
