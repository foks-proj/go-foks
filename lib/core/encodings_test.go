// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	rem "github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func TestInviteCodeEncoding(t *testing.T) {
	b := make([]byte, InviteCodeBytes)
	err := RandomFill(b)
	require.NoError(t, err)
	txt := rem.MultiUseInviteCode(Base36Encoding.EncodeToString(b))
	code := rem.NewInviteCodeWithMultiuse(txt)
	s, err := ExportInviteCode(code)
	require.NoError(t, err)
	code2, err := ImportInviteCode(s)
	require.NoError(t, err)
	typ, err := code2.GetT()
	require.NoError(t, err)
	require.Equal(t, rem.InviteCodeType_MultiUse, typ)
	require.Equal(t, txt, code2.Multiuse())
}
