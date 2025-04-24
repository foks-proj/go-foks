// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func readUsername(t *testing.T, m shared.MetaContext, u proto.UID) proto.NameUtf8 {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	var raw string
	err = db.QueryRow(m.Ctx(),
		`SELECT name_utf8
		 FROM names
		 JOIN users USING(short_host_id, name_ascii)
		 WHERE short_host_id=$1
		 AND uid=$2`,
		int(m.ShortHostID()),
		u.ExportToDB(),
	).Scan(&raw)
	require.NoError(t, err)
	return proto.NameUtf8(raw)
}

func readNumLinks(t *testing.T, m shared.MetaContext, u proto.UID) int {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	var c int
	err = db.QueryRow(m.Ctx(),
		`SELECT COUNT(*) FROM links WHERE short_host_id=$1 AND chain_type=$2 AND entity_id=$3`,
		int(m.ShortHostID()),
		proto.ChainType_User,
		u.ExportToDB(),
	).Scan(&c)
	require.NoError(t, err)
	return c
}

func readUsernameStatus(t *testing.T, m shared.MetaContext, un proto.Name) string {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	var raw string
	err = db.QueryRow(m.Ctx(),
		`SELECT state FROM names WHERE short_host_id=$1 AND name_ascii=$2`,
		int(m.ShortHostID()),
		string(un),
	).Scan(&raw)
	require.NoError(t, err)
	return raw
}

func TestChangeUsernameUTF8Only(t *testing.T) {
	tenv := globalTestEnv
	m := tenv.MetaContext()
	base, err := RandomUsername(9)
	require.NoError(t, err)
	un := proto.NameUtf8(base + "_é")
	u := GenerateNewTestUserWithUsername(t, tenv, un)
	un2 := proto.NameUtf8(base + "_è")
	crt := u.ClientCertRobust(m.Ctx(), t)
	ucli, userCloseFn, err := u.newUserClient(m.Ctx(), crt)
	require.NoError(t, err)
	defer userCloseFn()
	err = ucli.ChangeUsername(m.Ctx(), rem.ChangeUsernameArg{UsernameUtf8: un2})
	require.NoError(t, err)
	un3 := readUsername(t, m, u.uid)
	require.Equal(t, un2, un3)
}

func randomUsernameUtf8(t *testing.T) proto.NameUtf8 {
	un, err := RandomUsername(9)
	require.NoError(t, err)
	un += ".øół"
	return proto.NameUtf8(un)
}

func changeUsername(ctx context.Context, t *testing.T, u *TestUser) proto.NameUtf8 {
	crt := u.ClientCertRobust(ctx, t)
	ucli, userCloseFn, err := u.newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()
	un2 := randomUsernameUtf8(t)
	pun2, err := core.NormalizeName(un2)
	require.NoError(t, err)
	rur, err := ucli.ReserveUsernameForChange(ctx, pun2)
	require.NoError(t, err)
	unc := rem.NameCommitment{Name: pun2, Seq: proto.FirstNameSeqno}
	culr, err := core.MakeChangeUsernameLink(u.uid, u.host, u.eldest, unc, u.userSeqno, *u.prev, u.NextRoot())
	require.NoError(t, err)
	err = ucli.ChangeUsername(ctx, rem.ChangeUsernameArg{
		UsernameUtf8: un2,
		Full: &rem.ChangedUsernameFullUpdateArg{
			Link:                  *culr.Link,
			Rur:                   rur,
			UsernameCommitmentKey: *culr.UsernameCommitmentKey,
			NextTreeLocation:      *culr.NextTreeLocation,
		},
	})
	require.NoError(t, err)
	return un2
}

func TestChangeUsernameFull(t *testing.T) {
	tenv := globalTestEnv
	m := tenv.MetaContext()
	ctx := m.Ctx()
	un1 := randomUsernameUtf8(t)
	u := GenerateNewTestUserWithUsername(t, tenv, un1)
	un2 := changeUsername(ctx, t, u)
	un3 := readUsername(t, m, u.uid)
	require.Equal(t, proto.NameUtf8(un2), un3)
	nun1, err := core.NormalizeName(un1)
	require.NoError(t, err)
	uns := readUsernameStatus(t, m, nun1)
	require.Equal(t, "dead", uns)
	nLinks := readNumLinks(t, m, u.uid)
	require.Equal(t, 2, nLinks)
}
