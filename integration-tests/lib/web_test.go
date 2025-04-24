// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

func TestCSRFToken(t *testing.T) {
	alice := core.RandomUID()
	bob := core.RandomUID()
	m := globalTestEnv.MetaContext()
	clock := clockwork.NewFakeClockAt(time.Now())

	origClock := m.Clock()
	m.SetClock(clock)
	defer m.SetClock(origClock)

	tok, err := lib.CreateCSRFToken(m, alice)
	require.NoError(t, err)
	err = lib.CheckCSRFToken(m, alice, tok)
	require.NoError(t, err)

	err = lib.CheckCSRFToken(m, bob, tok)
	require.Error(t, err)
	require.Equal(t, core.VerifyError("bad hmac"), err)

	raw, err := core.B62Decode(tok.String())
	require.NoError(t, err)
	raw[31] ^= 0x01
	corruptTok := lib.CSRFToken(core.B62Encode(raw))
	raw[31] ^= 0x01

	err = lib.CheckCSRFToken(m, alice, corruptTok)
	require.Error(t, err)
	require.Equal(t, core.VerifyError("bad hmac"), err)

	raw[10] ^= 0x01
	corruptTok = lib.CSRFToken(core.B62Encode(raw))
	raw[10] ^= 0x01
	err = lib.CheckCSRFToken(m, alice, corruptTok)
	require.Error(t, err)
	require.Equal(t, core.KeyNotFoundError{Which: "hmac"}, err)

	clock.Advance(time.Hour * 24 * 35)
	err = lib.CheckCSRFToken(m, alice, tok)
	require.Error(t, err)
	require.Equal(t, core.ExpiredError{}, err)

}
