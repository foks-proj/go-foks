// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type mockMCPUI struct {
	serverTransport mcp.Transport
	clientTransport mcp.Transport
}

func newMockMCPUI() *mockMCPUI {
	st, ct := mcp.NewInMemoryTransports()
	return &mockMCPUI{
		serverTransport: st,
		clientTransport: ct,
	}
}

func (m *mockMCPUI) Transport() mcp.Transport {
	return m.serverTransport
}

// mcpKVTest runs a test against the real `foks mcp kv` command.
// It injects a mock MCP UI with InMemoryTransport via the test hook,
// then connects an MCP client session over the in-memory transport.
func mcpKVTest(
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

	// Run the real `mcp kv` command in a goroutine (it blocks serving).
	done := make(chan error, 1)
	go func() {
		done <- a.runCmdErr(hook, "mcp", "kv")
	}()

	// Connect an MCP client over the in-memory transport.
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "foks-mcp-test",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(ctx, mock.clientTransport, nil)
	require.NoError(t, err)
	defer session.Close()

	fn(t, session, ctx)
}

func mcpCallTool(
	t *testing.T,
	session *mcp.ClientSession,
	ctx context.Context,
	name string,
	args map[string]any,
) string {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	require.NoError(t, err)
	if result.IsError {
		var errMsg string
		if len(result.Content) > 0 {
			if tc, ok := result.Content[0].(*mcp.TextContent); ok {
				errMsg = tc.Text
			}
		}
		t.Fatalf("tool %s returned error: %s", name, errMsg)
	}
	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])
	return tc.Text
}

func mcpCallToolExpectError(
	t *testing.T,
	session *mcp.ClientSession,
	ctx context.Context,
	name string,
	args map[string]any,
) string {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	require.NoError(t, err)
	require.True(t, result.IsError, "expected tool %s to return error", name)
	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])
	return tc.Text
}

func TestMCPKVListTools(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		tools, err := session.ListTools(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, tools)

		names := make(map[string]bool)
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		for _, name := range []string{"list", "get", "put", "mkdir", "rm", "mv", "stat", "usage"} {
			require.True(t, names[name], "expected tool %q in list", name)
		}
	})
}

func TestMCPKVPutGet(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Put a file
		text := mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/hello.txt",
			"content": "hello mcp world",
		})
		require.Equal(t, "ok", text)

		// Get it back
		text = mcpCallTool(t, session, ctx, "get", map[string]any{
			"path": "/hello.txt",
		})
		require.Equal(t, "hello mcp world", text)
	})
}

func TestMCPKVMkdirAndList(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Create nested directories
		text := mcpCallTool(t, session, ctx, "mkdir", map[string]any{
			"path":    "/a/b/c",
			"mkdir_p": true,
		})
		require.Contains(t, text, "DirID:")

		// Put files in the directory
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/a/b/c/file1.txt",
			"content": "data1",
		})
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/a/b/c/file2.txt",
			"content": "data2",
		})

		// List the directory
		text = mcpCallTool(t, session, ctx, "list", map[string]any{
			"path": "/a/b/c",
		})
		require.Contains(t, text, "file1.txt")
		require.Contains(t, text, "file2.txt")

		// List root
		text = mcpCallTool(t, session, ctx, "list", map[string]any{
			"path": "/",
		})
		require.Contains(t, text, "a")
		require.Contains(t, text, "dir")
	})
}

func TestMCPKVRm(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Create a file
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/to-delete.txt",
			"content": "ephemeral",
		})

		// Remove it
		text := mcpCallTool(t, session, ctx, "rm", map[string]any{
			"path": "/to-delete.txt",
		})
		require.Equal(t, "ok", text)

		// Verify it's gone
		errText := mcpCallToolExpectError(t, session, ctx, "get", map[string]any{
			"path": "/to-delete.txt",
		})
		require.NotEmpty(t, errText)
	})
}

func TestMCPKVRmRecursive(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Create dir with files
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/rmdir/child.txt",
			"content": "child",
			"mkdir_p": true,
		})

		// Non-recursive rm on directory should fail
		errText := mcpCallToolExpectError(t, session, ctx, "rm", map[string]any{
			"path": "/rmdir",
		})
		require.NotEmpty(t, errText)

		// Recursive rm should succeed
		text := mcpCallTool(t, session, ctx, "rm", map[string]any{
			"path":      "/rmdir",
			"recursive": true,
		})
		require.Equal(t, "ok", text)
	})
}

func TestMCPKVMv(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/original.txt",
			"content": "move me",
		})

		text := mcpCallTool(t, session, ctx, "mv", map[string]any{
			"src": "/original.txt",
			"dst": "/moved.txt",
		})
		require.Equal(t, "ok", text)

		// Read from new path
		text = mcpCallTool(t, session, ctx, "get", map[string]any{
			"path": "/moved.txt",
		})
		require.Equal(t, "move me", text)

		// Old path should be gone
		mcpCallToolExpectError(t, session, ctx, "get", map[string]any{
			"path": "/original.txt",
		})
	})
}

func TestMCPKVStat(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/stat-test.txt",
			"content": "stat me",
		})

		text := mcpCallTool(t, session, ctx, "stat", map[string]any{
			"path": "/stat-test.txt",
		})
		// Stat returns JSON; verify it has expected fields
		require.Contains(t, text, "\"De\"")
		require.Contains(t, text, "\"V\"")
	})
}

func TestMCPKVUsage(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Put some data
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/usage-test.txt",
			"content": "some data for usage",
		})

		text := mcpCallTool(t, session, ctx, "usage", map[string]any{})
		require.Contains(t, text, "Num Files:")
		require.Contains(t, text, "Total Size:")
	})
}

func TestMCPKVOverwrite(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/overwrite.txt",
			"content": "version1",
		})

		// Without overwrite flag, put to same path should fail
		mcpCallToolExpectError(t, session, ctx, "put", map[string]any{
			"path":    "/overwrite.txt",
			"content": "version2",
		})

		// With overwrite flag, should succeed
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":      "/overwrite.txt",
			"content":   "version2",
			"overwrite": true,
		})

		text := mcpCallTool(t, session, ctx, "get", map[string]any{
			"path": "/overwrite.txt",
		})
		require.Equal(t, "version2", text)
	})
}

func TestMCPKVMkdirPPut(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Put without mkdir_p to non-existent parent should fail
		mcpCallToolExpectError(t, session, ctx, "put", map[string]any{
			"path":    "/new/deep/path/file.txt",
			"content": "deep",
		})

		// Put with mkdir_p should succeed
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/new/deep/path/file.txt",
			"content": "deep",
			"mkdir_p": true,
		})

		text := mcpCallTool(t, session, ctx, "get", map[string]any{
			"path": "/new/deep/path/file.txt",
		})
		require.Equal(t, "deep", text)
	})
}

func TestMCPKVListPagination(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Create more files than the page size (3)
		dir := "/pagtest"
		mcpCallTool(t, session, ctx, "mkdir", map[string]any{
			"path": dir,
		})
		for i := range 8 {
			_ = i
			name := fsRandomString(t, 12)
			mcpCallTool(t, session, ctx, "put", map[string]any{
				"path":    dir + "/" + name,
				"content": "data",
			})
		}

		// List should return all files (pagination handled internally)
		text := mcpCallTool(t, session, ctx, "list", map[string]any{
			"path": dir,
		})
		lines := strings.Split(strings.TrimSpace(text), "\n")
		require.Len(t, lines, 8)
	})
}

func TestMCPKVBinaryPutGet(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	binData := []byte{0x00, 0xff, 0xfe, 0x80, 0x81, 0x82}
	encoded := base64.StdEncoding.EncodeToString(binData)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Put binary data via base64 flag
		text := mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "/binary.dat",
			"content": encoded,
			"base64":  true,
		})
		require.Equal(t, "ok", text)

		// Get returns base64-prefixed content for non-UTF-8 data
		text = mcpCallTool(t, session, ctx, "get", map[string]any{
			"path":   "/binary.dat",
			"base64": true,
		})
		decoded, err := base64.StdEncoding.DecodeString(text)
		require.NoError(t, err)
		require.Equal(t, binData, decoded)
	})
}

func TestMCPKVPathNormalization(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	merklePoke(t)

	mcpKVTest(t, bob.agent, func(t *testing.T, session *mcp.ClientSession, ctx context.Context) {
		// Path without leading slash should be normalized
		mcpCallTool(t, session, ctx, "put", map[string]any{
			"path":    "no-slash.txt",
			"content": "normalized",
		})

		text := mcpCallTool(t, session, ctx, "get", map[string]any{
			"path": "/no-slash.txt",
		})
		require.Equal(t, "normalized", text)
	})
}
