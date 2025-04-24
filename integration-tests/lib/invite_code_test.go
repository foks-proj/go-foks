// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestMultiUserInviteCode(t *testing.T) {
	m := testMetaContext()
	cli, closeFn, err := newRegClient(m.Ctx())
	require.NoError(t, err)
	defer closeFn()

	code, err := common.InsertNewMutliuseInviteCode(m)
	require.NoError(t, err)
	err = cli.CheckInviteCode(m.Ctx(), *code)
	require.NoError(t, err)

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	_, err = db.Exec(m.Ctx(),
		`UPDATE multiuse_invite_codes SET valid=FALSE 
		 WHERE short_host_id=$1 AND code = $2`,
		int(m.G().ShortHostID()),
		code.Multiuse(),
	)
	require.NoError(t, err)
	err = cli.CheckInviteCode(m.Ctx(), *code)
	require.Error(t, err)
	require.Equal(t, core.BadInviteCodeError{}, err)
}

func TestStandardInviteCode(t *testing.T) {
	m := testMetaContext()
	cli, closeFn, err := newRegClient(m.Ctx())
	require.NoError(t, err)
	defer closeFn()

	tu := GenerateNewTestUser(t)
	uid := tu.uid

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	stdcode, err := shared.GenerateStandardInviteCode(m, uid)
	require.NoError(t, err)

	err = cli.CheckInviteCode(m.Ctx(), *stdcode)
	require.NoError(t, err)

	tu2 := NewTestUser(t)
	tu2.SignupWithInviteCode(m.Ctx(), t, cli, *stdcode)

	err = cli.CheckInviteCode(m.Ctx(), *stdcode)
	require.Error(t, err)
	require.Equal(t, core.BadInviteCodeError{}, err)

}
