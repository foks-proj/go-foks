// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

type mcpTeam struct {
	m   libclient.MetaContext
	cli lcl.TeamClient
}

type mcpTeamListInput struct {
	Team string `json:"team" jsonschema:"team name or ID to list members of"`
}

func (t *mcpTeam) list(ctx context.Context, req *mcp.CallToolRequest, input mcpTeamListInput) (*mcp.CallToolResult, any, error) {
	fqt, err := core.ParseFQTeam(proto.FQTeamString(input.Team))
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	roster, err := t.cli.TeamList(ctx, *fqt)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	var sb strings.Builder
	for _, mem := range roster.Members {
		srcRole, err := mem.SrcRole.ShortStringErr()
		if err != nil {
			return mcpKVErrorResult(err), nil, nil
		}
		dstRole, err := mem.DstRole.ShortStringErr()
		if err != nil {
			return mcpKVErrorResult(err), nil, nil
		}
		name := string(mem.Mem.Name)
		if mem.Mem.Fqp.Party.IsTeam() {
			name += " (team)"
		}
		host := "-"
		if !roster.Fqp.Fqp.Host.Eq(mem.Mem.Fqp.Host) {
			host = string(mem.Mem.Host)
		}
		added := mem.Added.Time.Import().UTC().Format("2006-01-02T15:04:05Z")
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%s\n", name, host, srcRole, dstRole, added)
	}
	return mcpKVTextResult(sb.String()), nil, nil
}

type mcpTeamListMembershipsInput struct{}

func (t *mcpTeam) listMemberships(ctx context.Context, req *mcp.CallToolRequest, input mcpTeamListMembershipsInput) (*mcp.CallToolResult, any, error) {
	res, err := t.cli.TeamListMemberships(ctx)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	var sb strings.Builder
	for _, tm := range res.Teams {
		srcRole, err := tm.SrcRole.ShortStringErr()
		if err != nil {
			return mcpKVErrorResult(err), nil, nil
		}
		dstRole, err := tm.DstRole.ShortStringErr()
		if err != nil {
			return mcpKVErrorResult(err), nil, nil
		}
		teamName := string(tm.Team.Name)
		if !res.HomeHost.Eq(tm.Team.Fqp.Host) {
			teamName = fmt.Sprintf("%s@%s", teamName, tm.Team.Host)
		}
		via := "-"
		if tm.Via != nil {
			via = string(tm.Via.Name)
			if !res.HomeHost.Eq(tm.Via.Fqp.Host) {
				via = fmt.Sprintf("%s@%s", via, tm.Via.Host)
			}
		}
		rr := core.RationalRange{RationalRange: tm.Tir}
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%s\n", teamName, srcRole, dstRole, via, rr.String())
	}
	return mcpKVTextResult(sb.String()), nil, nil
}

func newMCPTeamServer(m libclient.MetaContext, gcli rpc.GenericClient) *mcp.Server {
	tm := &mcpTeam{
		m:   m,
		cli: libclient.NewRpcTypedClient[lcl.TeamClient](m, gcli),
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "foks-team",
		Version: core.CurrentSoftwareVersion.String(),
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list",
		Description: "List the members of a FOKS team",
	}, tm.list)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list-memberships",
		Description: "List all teams the current user is a member of",
	}, tm.listMemberships)

	return srv
}

func mcpTeamCmd(m libclient.MetaContext, top *cobra.Command) {
	cmd := &cobra.Command{
		Use:          "team",
		Short:        "Run MCP server for team operations",
		Long:         "Run an MCP (Model Context Protocol) server over stdio exposing FOKS team operations",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			gcli, cleanFn, err := runMCPServer(m)
			if err != nil {
				return err
			}
			defer cleanFn()
			srv := newMCPTeamServer(m, gcli)
			var transport mcp.Transport
			if mcpUI := m.G().UIs().MCP; mcpUI != nil {
				transport = mcpUI.Transport()
			} else {
				transport = &mcp.StdioTransport{}
			}
			return srv.Run(m.Ctx(), transport)
		},
	}
	top.AddCommand(cmd)
}
