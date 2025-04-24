// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func TestEmailValidator(t *testing.T) {
	vectors := []struct {
		email string
		err   error
	}{
		{"", ValidatorError("malformed email address")},
		{"a", ValidatorError("malformed email address")},
		{"a@", ValidatorError("malformed email address")},
		{"a@b", ValidatorError("domain doesn't have a TLD")},
		{"a@b.", ValidatorError("malformed email address")},
		{"a@b.com", nil},
		{"yo@localhost", ValidatorError("domain doesn't have a TLD")},
		{"bamba@10.2.2.3", ValidatorError("hostname cannot be an IP address")},
		{"Fancy Style <aa@bb.com>", ValidatorError("cannot allow Foo <bar@zam.com> style name")},
		{"bogie@bam.boozle", nil},
		{"yoyo+dyne@yaho.com", nil},
		{"bizzle.snizzle.badizzle@yaho.com", nil},
		{"a@b.cc", nil},
		{"joe.bam.49@gmail.com", nil},
	}
	for _, v := range vectors {
		err := ValidateEmail(proto.Email(v.email))
		require.Equal(t, v.err, err, "email: %s", v.email)
	}
}

func TestInviteCodeValidator(t *testing.T) {
	vectors := []struct {
		code rem.MultiUseInviteCode
		err  error
	}{
		{"", BadInviteCodeError{}},
		{"a", BadInviteCodeError{}},
		{"abc", BadInviteCodeError{}},
		{"AAAAA", nil},
		{"abcdef", nil},
		{"ab+def", nil},
		{"m7s+ws", nil},
		{"ab+def.a+4_r_", nil},
		{"a bcdefe", BadInviteCodeError{}},
	}
	for _, v := range vectors {
		err := ValidateInviteCode(
			rem.NewInviteCodeWithMultiuse(v.code),
		)
		require.Equal(t, v.err, err, "code: %s", v.code)
	}
}
