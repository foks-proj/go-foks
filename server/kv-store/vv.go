// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

func getCurrentDirVersion(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	role *core.RoleKey,
	dir proto.DirID,
) (
	proto.KVVersion,
	error,
) {
	var v, rt, vl int
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT version, read_role_type, read_role_viz_level
		 FROM dir 
		 WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3
		 ORDER BY version DESC LIMIT 1`,
		int(m.ShortHostID()), pid.Shorten().ExportToDB(), dir.ExportToDB(),
	).Scan(&v, &rt, &vl)
	if err != nil && errors.Is(err, pgx.ErrNoRows) {
		return 0, core.NotFoundError("cached dir")
	}
	if err != nil {
		return 0, err
	}
	rkDb, err := core.ImportRoleKeyFromDB(rt, vl)
	if err != nil {
		return 0, err
	}
	if !rkDb.LessThanOrEqual(*role) {
		return 0, core.KVPermssionError{}
	}
	return proto.KVVersion(v), nil
}

func getCurrentDirentVersion(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	dir proto.DirID,
	dirent proto.DirentID,
) (
	proto.KVVersion,
	error,
) {
	var v int
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT version
		 FROM dirent 
		 WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3 AND dirent_id=$4
		 ORDER BY version DESC LIMIT 1
		 `,
		int(m.ShortHostID()), pid.Shorten().ExportToDB(), dir.ExportToDB(), dirent.ExportToDB(),
	).Scan(&v)
	if err != nil && errors.Is(err, pgx.ErrNoRows) {
		return 0, core.NotFoundError("cached dirent")
	}
	if err != nil {
		return 0, err
	}
	return proto.KVVersion(v), nil
}

func getCurrentRootVersion(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	role *core.RoleKey,
) (
	proto.KVVersion,
	error,
) {
	var v, rt, lv int
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT root_node_version, read_role_type, read_role_viz_level
		 FROM root 
		 WHERE short_host_id=$1 AND party_id=$2
		 ORDER BY root_node_version DESC LIMIT 1 `,
		int(m.ShortHostID()), pid.ExportToDB(),
	).Scan(&v, &rt, &lv)
	if err != nil && errors.Is(err, pgx.ErrNoRows) {
		return 0, core.NotFoundError("cached root")
	}
	if err != nil {
		return 0, err
	}
	rkDb, err := core.ImportRoleKeyFromDB(rt, lv)
	if err != nil {
		return 0, err
	}
	if !rkDb.LessThanOrEqual(*role) {
		return 0, core.KVPermssionError{}
	}
	return proto.KVVersion(v), nil
}

func checkVersionVector(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	rp proto.Role,
	vv *proto.PathVersionVector,
) error {
	if vv == nil {
		return nil
	}
	role, err := core.ImportRole(rp)
	if err != nil {
		return err
	}

	var ret proto.PathVersionVector

	for _, d := range vv.Path {

		v, err := getCurrentDirVersion(m, rq, pid, role, d.Id)
		if err != nil {
			return err
		}
		var dir proto.DirVersion

		var dv []proto.DirentVersion

		for _, de := range d.De {
			v, err := getCurrentDirentVersion(m, rq, pid, d.Id, de.Id)
			if err != nil {
				return err
			}
			if v < de.Vers {
				return core.BadArgsError("dirent version too big")
			}
			if v > de.Vers {
				dv = append(dv, proto.DirentVersion{Id: de.Id, Vers: v})
			}
		}

		if v > d.Vers || len(dv) > 0 {
			dir = proto.DirVersion{Id: d.Id, Vers: v}
			dir.De = dv
			ret.Path = append(ret.Path, dir)
		}
	}

	v, err := getCurrentRootVersion(m, rq, pid, role)
	if err != nil {
		return err
	}

	if v < vv.Root {
		return core.BadArgsError("root version too big")
	}

	// vv.Root = 0 implies we didn't hit the cache, since we'l only cache a version >= 1
	if (vv.Root == 0 || v == vv.Root) && len(ret.Path) == 0 {
		return nil
	}

	ret.Root = v
	return core.KVStaleCacheError{
		PathVersionVector: ret,
	}
}
