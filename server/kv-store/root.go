// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func getRoot(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
) (
	*proto.KVRoot,
	error,
) {
	var root, bm []byte
	var v, ptkg, rt, vl int
	err := db.QueryRow(m.Ctx(),
		`SELECT root_node_id, root_node_version, binding_mac,
		   ptk_gen, read_role_type, read_role_viz_level	
	    FROM root
		WHERE short_host_id=$1 AND party_id=$2`,
		int(m.HostID().Short),
		pid.ExportToDB(),
	).Scan(&root, &v, &bm, &ptkg, &rt, &vl)
	if err != nil && err == pgx.ErrNoRows {
		return nil, core.KVNoentError{}
	}
	if err != nil {
		return nil, err
	}
	ret := proto.KVRoot{
		Vers: proto.KVVersion(v),
		Rg: proto.RoleAndGen{
			Gen: proto.Generation(ptkg),
		},
	}
	err = ret.Root.ImportFromDB(root)
	if err != nil {
		return nil, err
	}
	err = ret.BindingMac.ImportFromDB(bm)
	if err != nil {
		return nil, err
	}
	err = ret.Rg.Role.ImportFromDB(rt, vl)
	if err != nil {
		return nil, err
	}
	err = assertAtOrAbove(role, ret.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Dir)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func putRoot(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvPutRootArg,
) error {
	err := assertAdmin(role)
	if err != nil {
		return err
	}
	if arg.Root.BindingMac.IsZero() {
		return core.BadArgsError("binding mac must not be zero")
	}
	var dir []byte
	var nv int
	err = tx.QueryRow(m.Ctx(),
		`SELECT root_node_id, root_node_version FROM root WHERE short_host_id=$1 AND party_id=$2 FOR UPDATE`,
		int(m.HostID().Short), pid.ExportToDB(),
	).Scan(&dir, &nv)
	var ins bool
	switch {
	case err != nil && err != pgx.ErrNoRows:
		return err
	case err != nil && err == pgx.ErrNoRows:
		if arg.Root.Vers != proto.KVVersion(1) {
			return core.BadArgsError("initial root version must be 1")
		}
		ins = true
	case err == nil:
		var dirId proto.DirID
		err = dirId.ImportFromDB(dir)
		if err != nil {
			return err
		}
		err = dirDecref(m, tx, pid, dirId)
		if err != nil {
			return err
		}
		if nv+1 != int(arg.Root.Vers) {
			return core.KVRaceError("root version")
		}
	}

	err = dirIncref(m, tx, pid, arg.Root.Root)
	if err != nil {
		return err
	}

	rk, err := core.ImportRole(arg.Root.Rg.Role)
	if err != nil {
		return err
	}

	if ins {
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO root(short_host_id, party_id, root_node_id,
				root_node_version, ptk_gen, read_role_type, read_role_viz_level, 
				binding_mac, ctime, mtime)
			VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
			int(m.HostID().Short),
			pid.ExportToDB(),
			arg.Root.Root.ExportToDB(),
			int(arg.Root.Vers),
			arg.Root.Rg.Gen,
			int(rk.Typ),
			int(rk.Lev),
			arg.Root.BindingMac.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("root")
		}
		return nil
	}

	tag, err := tx.Exec(m.Ctx(),
		`UPDATE root 
		 SET root_node_id=$1, mtime=NOW(), root_node_version=$2, binding_mac=$3,
		  ptk_gen=$4, read_role_type=$5, read_role_viz_level=$6
		 WHERE short_host_id=$7 AND party_id=$8`,
		arg.Root.Root.ExportToDB(),
		int(m.HostID().Short),
		arg.Root.BindingMac.ExportToDB(),
		int(arg.Root.Rg.Gen),
		int(rk.Typ),
		int(rk.Lev),
		int(arg.Root.Vers),
		pid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("ns")
	}
	return nil
}
