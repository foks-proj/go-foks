// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsCertVerifyError: the point of this classifier is to name a failure,
// not to change how it is retried. The cases that matter most are the ones it
// must NOT claim -- a dial failure or a reset connection reported as "cannot
// verify server identity" would be a false alarm about an attack, which is
// worse than saying nothing.
func TestIsCertVerifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unknown authority", x509.UnknownAuthorityError{}, true},
		{"invalid certificate", x509.CertificateInvalidError{Reason: x509.Expired}, true},
		{"hostname mismatch", x509.HostnameError{Host: "example.com"}, true},
		{"tls verification", &tls.CertificateVerificationError{}, true},
		{"wrapped", fmt.Errorf("probe: %w", x509.UnknownAuthorityError{}), true},

		// Outages, not certificate problems.
		{"connect", NewConnectError("dial failed", io.EOF), false},
		{"refused", syscall.ECONNREFUSED, false},
		{"dns", &net.DNSError{Err: "no such host"}, false},
		{"io.EOF", io.EOF, false},
		{"unknown", errors.New("boom"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsCertVerifyError(tc.err))
		})
	}
}

// TestCertVerifyStillRetriesAsTransport: the retry contract is unchanged. A
// certificate failure means the request never arrived, so it is still
// transport-class and still safe to retry; only what we call it differs.
func TestCertVerifyStillRetriesAsTransport(t *testing.T) {
	err := NewConnectError("tls", x509.UnknownAuthorityError{})
	require.True(t, IsTransportError(err), "cert failures must stay retriable")
	require.True(t, IsCertVerifyError(err), "and must still be nameable as cert failures")
}
