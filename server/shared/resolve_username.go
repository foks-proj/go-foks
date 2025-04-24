// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func ResolveUsername(
	m MetaContext,
	loggedInUID *proto.UID,
	arg rem.ResolveUsernameArg,
) (
	proto.UID,
	error,
) {
	pde := core.PermissionError("resolve")
	var zed proto.UID
	hc, err := m.HostConfig()
	if err != nil {
		return zed, err
	}

	// For now, resolve only works on hosts with open user viewership.
	// Can change this later.
	if hc.Viewership.User != proto.ViewershipMode_OpenToAll {
		return zed, pde
	}
	typ, err := arg.Auth.GetT()
	if err != nil {
		return zed, err
	}
	if typ != rem.LoadUserChainAuthType_OpenVHost {
		return zed, err
	}
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return zed, err
	}
	defer db.Release()

	var uidRaw []byte
	err = db.QueryRow(
		m.Ctx(),
		`SELECT uid FROM users
		WHERE short_host_id=$1 AND name_ascii=$2`,
		m.ShortHostID().ExportToDB(),
		arg.N.Normalize().String(),
	).Scan(&uidRaw)

	if errors.Is(err, pgx.ErrNoRows) {
		return zed, pde
	}
	if err != nil {
		return zed, err
	}

	var uid proto.UID
	err = uid.ImportFromDB(uidRaw)
	if err != nil {
		return zed, err
	}
	return uid, nil
}
