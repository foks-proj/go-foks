// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// mcpTeamTest runs a test against the real `foks mcp team` command.
func mcpTeamTest(
	t *testing.T,
	a *testAgent,
	fn func(t *testing.T, session *mcp.ClientSession, ctx context.Context),
) {
	t.Helper()
	mock := newMockMCPUI()
	hook := func(m libclient.MetaContext) error {
		uis := m.G().UIs()
		uis.MCP = mock
		m.G().SetUIs(uis)
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- a.runCmdErr(hook, "mcp", "team")
	}()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "foks-mcp-team-test",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(ctx, mock.clientTransport, nil)
	require.NoError(t, err)
	defer session.Close()

	fn(t, session, ctx)
}

func TestMCPTeamListTools(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	merklePoke(t)

	mcpTeamTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		tools, err := session.ListTools(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, tools)

		names := make(map[string]bool)
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		for _, name := range []string{"list", "list-memberships"} {
			require.True(t, names[name], "expected tool %q in list", name)
		}
	})
}

func TestMCPTeamListMemberships(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	merklePoke(t)

	// Create a team so there's something to list
	bob.agent.runCmd(t, nil, "team", "create", "mcp-test-team")
	merklePoke(t)

	mcpTeamTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		text := mcpCallTool(t, session, ctx, "list-memberships", map[string]any{})
		require.Contains(t, text, "mcp-test-team")
	})
}

func TestMCPTeamList(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	merklePoke(t)

	bob.agent.runCmd(t, nil, "team", "create", "mcp-roster-team")
	merklePoke(t)

	mcpTeamTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		text := mcpCallTool(t, session, ctx, "list", map[string]any{
			"team": "mcp-roster-team",
		})
		// The creator should be listed as a member
		require.Contains(t, text, string(bob.username))
	})
}

func TestMCPTeamListNotFound(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)
	merklePoke(t)

	mcpTeamTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		_ = mcpCallToolExpectError(t, session, ctx, "list", map[string]any{
			"team": "nonexistent-team-xyz",
		})
	})
}
