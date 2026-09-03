// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

// IsTransportError classifies an RPC failure as transport-level (the request
// may never have reached the server, or the reply was lost) versus semantic
// (the server received and refused it). Callers that queue work for retry --
// notably the realtime outbox drain (docs/rt_offline.md, D7) -- retry only on
// transport errors.
//
// The default is deliberately semantic: an unrecognized error fails fast and
// surfaces to the caller rather than being retried forever. The table below is
// built from the error paths of the client transport stack (net dialing, TLS,
// the snowpack-RPC framing layer) rather than string matching.
//
// A note on wire-decoded statuses: TIMEOUT_ERROR, RPC_EOF, CONNECT_ERROR, and
// AGENT_CONNECT_ERROR reconstitute into types this table matches, so a server
// (or intermediary) that *answered* with one of those still classifies as
// transport. That is deliberate: every one of them describes a request whose
// delivery outcome is ambiguous, and retrying an ambiguous send is safe under
// rtSend's msg_id idempotency. Statuses describing a definite refusal decode
// into types this table does not match, and stay semantic.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}

	// Client-side connection establishment failed; the request never left.
	var connErr ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	var agentErr AgentConnectError
	if errors.As(err, &agentErr) {
		return true
	}

	// The RPC layer's own signals for a dropped or torn connection, an
	// unanswered call, or a stream that died mid-frame.
	var eofErr RPCEOFError
	if errors.As(err, &eofErr) {
		return true
	}
	var timeoutErr TimeoutError
	if errors.As(err, &timeoutErr) {
		return true
	}
	var packErr rpc.PacketizerError
	if errors.As(err, &packErr) {
		return true
	}
	var recvErr rpc.ReceiverError
	if errors.As(err, &recvErr) {
		return true
	}
	var decErr rpc.DecodeError
	if errors.As(err, &decErr) {
		return true
	}

	// Wire-level failures. net.Error also covers *net.OpError, *net.DNSError,
	// TLS handshake failures, and context.DeadlineExceeded.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}

	// A canceled context is the canonical ambiguous-delivery event: the
	// request may already be on the wire. Treating it as semantic would
	// delete or fail a durably-queued message on a mere interrupt; the
	// idempotent replay makes the retry safe instead.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED,
		syscall.EPIPE, syscall.EHOSTUNREACH, syscall.EHOSTDOWN,
		syscall.ENETDOWN, syscall.ENETUNREACH, syscall.ETIMEDOUT,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}

	// Everything else -- including every wire-decoded definite refusal -- is
	// semantic.
	return false
}
