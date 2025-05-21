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

	typ, err := arg.Auth.GetT()
	if err != nil {
		return zed, err
	}

	var authed bool

	switch typ {
	case rem.LoadUserChainAuthType_OpenVHost:
		if hc.Viewership.User != proto.ViewershipMode_OpenToAll {
			return zed, pde
		}
		authed = true
	case rem.LoadUserChainAuthType_AsLocalUser:
		// noop, need to check
	default:
		return zed, pde

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

	if !authed {

		q := `SELECT 1 FROM local_view_permissions 
			 WHERE short_host_id=$1
			 AND viewer_eid=$2
			 AND target_eid=$3
			 AND state='valid'`
		args := []any{
			m.ShortHostID().ExportToDB(),
			loggedInUID.ExportToDB(),
			uid.ExportToDB(),
		}
		var dummy int
		err = db.QueryRow(m.Ctx(), q, args...).Scan(&dummy)
		if err == pgx.ErrNoRows || dummy != 1 {
			return zed, pde
		}
		if err != nil {
			return zed, err
		}
	}

	return uid, nil
}
