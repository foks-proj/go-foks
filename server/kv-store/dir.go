// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

func loadDir(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	dirid proto.DirID,
	vers proto.KVVersion, // if none specified (==0), will pick the latest
) (*proto.KVDir, error) {

	var dv, ptkgen, rrt, rvl, wrt, wvl int
	var seedBox []byte
	var status string
	q := `SELECT version, ptk_gen, read_role_type, read_role_viz_level, 
	          write_role_type, write_role_viz_level, seed_box, status
		  FROM dir
	      WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3`
	args := []any{int(m.ShortHostID()), pid.Shorten().ExportToDB(), dirid.ExportToDB()}
	if vers.IsZero() {
		q += ` ORDER BY version DESC LIMIT 1`
	} else {
		q += ` AND version=$4`
		args = append(args, vers)
	}

	err := rq.QueryRow(
		m.Ctx(),
		q, args...,
	).Scan(&dv, &ptkgen, &rrt, &rvl, &wrt, &wvl, &seedBox, &status)
	if err != nil && err == pgx.ErrNoRows {
		return nil, core.NotFoundError("dir")
	}
	if err != nil {
		return nil, err
	}
	var readRole, writeRole proto.Role
	err = readRole.ImportFromDB(rrt, rvl)
	if err != nil {
		return nil, err
	}
	err = writeRole.ImportFromDB(wrt, wvl)
	if err != nil {
		return nil, err
	}
	box := proto.SeedBoxExternalNonce{
		Rg: proto.RoleAndGen{
			Role: readRole,
			Gen:  proto.Generation(ptkgen),
		},
	}
	err = core.DecodeFromBytes(&box.Ctext, seedBox)
	if err != nil {
		return nil, err
	}
	ret := proto.KVDir{
		Id:        dirid,
		Version:   proto.KVVersion(dv),
		Box:       box,
		WriteRole: writeRole,
	}
	err = ret.Status.ImportFromDB(status)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func putDir(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	dir *proto.KVDir,
) error {
	err := assertAtOrAbove(role, dir.Box.Rg.Role, proto.KVOp_Write, proto.KVNodeType_Dir)
	if err != nil {
		return err
	}
	err = assertAtOrAbove(role, dir.WriteRole, proto.KVOp_Write, proto.KVNodeType_Dir)
	if err != nil {
		return err
	}
	rtyp, rlev, err := dir.Box.Rg.Role.ExportToDB()
	if err != nil {
		return err
	}
	wtyp, wlev, err := dir.WriteRole.ExportToDB()
	if err != nil {
		return err
	}
	box, err := core.EncodeToBytes(&dir.Box.Ctext)
	if err != nil {
		return err
	}
	if dir.Version != proto.KVVersion(1) {
		return core.BadArgsError("dir version must be 1 for mkdir")
	}
	spid := pid.Shorten()
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO dir(
			short_host_id, short_party_id, dir_id, version, ptk_gen,
			read_role_type, read_role_viz_level,
			write_role_type, write_role_viz_level,
			seed_box, status, ctime, mtime
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())`,
		int(m.HostID().Short),
		spid.ExportToDB(),
		dir.Id.ExportToDB(),
		int(dir.Version),
		dir.Box.Rg.Gen,
		rtyp, rlev,
		wtyp, wlev,
		box,
		string(proto.KVDirStatusStringActive),
	)
	if shared.IsDuplicateKeyError(err, "dir_pkey") {
		return core.DuplicateError("dir")
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("dir")
	}
	tag, err = tx.Exec(m.Ctx(),
		`INSERT INTO dir_refcount(
			short_host_id, short_party_id, dir_id, refcount, mtime)
		VALUES($1,$2,$3,0,NOW())`,
		int(m.HostID().Short),
		spid.ExportToDB(),
		dir.Id.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("dir_refcount")
	}
	return nil
}

func dirRef(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	dir proto.DirID,
	delta int,
) error {
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE dir_refcount SET refcount=refcount+$1, mtime=NOW()
		WHERE short_host_id=$2 AND short_party_id=$3 AND dir_id=$4`,
		delta, int(m.HostID().Short), pid.Shorten().ExportToDB(), dir.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("dir_refcount")
	}
	return nil
}

func dirIncref(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	dir proto.DirID,
) error {
	return dirRef(m, tx, pid, dir, 1)
}

func dirDecref(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	dir proto.DirID,
) error {
	return dirRef(m, tx, pid, dir, -1)
}

func getDir(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	role proto.Role,
	dir proto.DirID,
) (*proto.KVDirPair, error) {
	curr, err := loadDir(m, rq, pid, dir, proto.KVVersion(0))
	if err != nil {
		return nil, err
	}
	err = assertAtOrAbove(role, curr.Box.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Dir)
	if err != nil {
		return nil, err
	}

	switch curr.Status {
	case proto.KVDirStatus_Dead:
		return nil, core.NotFoundError("live dir")
	case proto.KVDirStatus_Active:
		return &proto.KVDirPair{
			Active: *curr,
		}, nil
	case proto.KVDirStatus_Encrypting:
		if curr.Version.IsFirst() {
			return nil, core.NotFoundError("live dir >= 0")
		}
		prev, err := loadDir(m, rq, pid, dir, curr.Version-1)
		if err != nil {
			return nil, err
		}
		if prev.Status != proto.KVDirStatus_Active {
			return nil, core.NotFoundError("live prev dir")
		}
		err = assertAtOrAbove(role, prev.Box.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Dir)
		if err != nil {
			return nil, err
		}
		return &proto.KVDirPair{
			Active:     *prev,
			Encrypting: curr,
		}, nil
	default:
		return nil, core.DbError("unknown dir status")
	}
}
