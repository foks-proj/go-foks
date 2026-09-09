// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package chains

import (
	"crypto/x509"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/stretchr/testify/require"
)

// TestNoteCertOutcome pins the two-strike rule. One certificate failure is
// what a captive portal produces every time somebody opens a laptop in an
// airport; warning there teaches people to dismiss the warning, which costs
// exactly the attention it exists to buy. Two in a row against a host this
// device has already verified is the shape of an interception.
func TestNoteCertOutcome(t *testing.T) {
	certErr := core.NewConnectError("tls", x509.UnknownAuthorityError{})
	outage := core.NewConnectError("dial", core.TimeoutError{})

	t.Run("one failure stays quiet", func(t *testing.T) {
		p := &Probe{}
		require.False(t, p.noteCertOutcome(certErr))
	})

	t.Run("two in a row speak up", func(t *testing.T) {
		p := &Probe{}
		require.False(t, p.noteCertOutcome(certErr))
		require.True(t, p.noteCertOutcome(certErr))
	})

	t.Run("an outage is never a certificate problem", func(t *testing.T) {
		p := &Probe{}
		require.False(t, p.noteCertOutcome(outage))
		require.False(t, p.noteCertOutcome(outage))
		require.False(t, p.noteCertOutcome(outage))
	})

	t.Run("a success clears the count", func(t *testing.T) {
		p := &Probe{}
		require.False(t, p.noteCertOutcome(certErr))
		require.False(t, p.noteCertOutcome(nil))
		// Back to the first strike, not the second.
		require.False(t, p.noteCertOutcome(certErr))
	})

	t.Run("an intervening outage clears the count", func(t *testing.T) {
		p := &Probe{}
		require.False(t, p.noteCertOutcome(certErr))
		require.False(t, p.noteCertOutcome(outage))
		require.False(t, p.noteCertOutcome(certErr),
			"a run of failures broken by an outage is not a repeat")
	})
}
