// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// IsCertVerifyError reports that a connection failed because the peer's
// certificate could not be validated -- an unknown authority, an invalid or
// expired certificate, or a name that does not match.
//
// This deliberately does NOT change how such a failure is *retried*.
// IsTransportError still classifies it as transport, which is correct: the
// request never reached the server, and retrying is safe. The distinction this
// function draws is for what the failure is *called*. To a person holding the
// device, "cannot verify server identity" and "offline" mean very different
// things, and today they render identically -- which spends the one chance to
// notice an interception.
//
// It is a narrow test on purpose. A plain dial failure, a timeout, or a reset
// connection are not certificate problems and must not be reported as though
// they were.
func IsCertVerifyError(err error) bool {
	if err == nil {
		return false
	}
	// ConnectError carries the cause in a field and has no Unwrap method, so
	// errors.As cannot see through it -- and the dial path is exactly where a
	// certificate failure gets wrapped, which would make this check dead in
	// production. Look inside explicitly rather than giving ConnectError an
	// Unwrap, which would quietly change every other errors.Is/As in the tree.
	var connErr ConnectError
	if errors.As(err, &connErr) && connErr.Err != nil {
		if IsCertVerifyError(connErr.Err) {
			return true
		}
	}
	var certVerify *tls.CertificateVerificationError
	if errors.As(err, &certVerify) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	var hostname x509.HostnameError
	return errors.As(err, &hostname)
}
