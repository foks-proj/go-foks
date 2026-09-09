// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsTransportError pins the classifier twelve call sites depend on to
// decide whether to serve a verified snapshot instead of an error. Getting it
// wrong in the permissive direction is the dangerous one: a definite refusal
// misread as transport would serve cached state where the server actually said
// no, and would do so silently. The default therefore has to stay semantic,
// and the table below is as much about what is NOT transport as what is.
func TestIsTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// Delivery outcome unknown: the request may never have landed.
		{"nil", nil, false},
		{"connect", NewConnectError("dial failed", io.EOF), true},
		{"agent connect", AgentConnectError{Path: Path("/tmp/sock")}, true},
		{"rpc eof", RPCEOFError{}, true},
		{"timeout", TimeoutError{}, true},
		{"net dns", &net.DNSError{Err: "no such host"}, true},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"context canceled", context.Canceled, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"ECONNREFUSED", syscall.ECONNREFUSED, true},
		{"EHOSTUNREACH", syscall.EHOSTUNREACH, true},

		// The server received the request and refused it. Retrying will not
		// help, and serving a snapshot in its place would be wrong.
		{"unknown error", errors.New("boom"), false},
		{"permission", PermissionError("nope"), false},
		{"row not found", RowNotFoundError{}, false},
		{"internal", InternalError("bad"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsTransportError(tc.err))
		})
	}
}

// TestIsTransportErrorUnwraps: the fallback sites see errors that have been
// annotated on the way up, so classification has to survive wrapping. A
// classifier that only matched bare values would degrade to "semantic" exactly
// when a caller had been most careful about context.
func TestIsTransportErrorUnwraps(t *testing.T) {
	wrapped := fmt.Errorf("loading team: %w",
		fmt.Errorf("probe: %w", NewConnectError("dial failed", io.EOF)))
	require.True(t, IsTransportError(wrapped))

	wrappedSemantic := fmt.Errorf("loading team: %w", PermissionError("nope"))
	require.False(t, IsTransportError(wrappedSemantic))
}
