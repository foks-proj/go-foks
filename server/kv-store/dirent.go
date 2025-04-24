// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type direntUpdater struct {
	// passed-in params
	tx   pgx.Tx
	arg  rem.KvPutArg
	de   proto.KVDirent
	pid  proto.PartyID
	role proto.Role

	// internal state
	dir      *proto.KVDir
	existing *proto.KVDirent
}

func direntRef(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	val proto.KVNodeID,
	v int,
) error {
	typ, err := val.Type()
	if err != nil {
		return err
	}
	switch typ {
	case proto.KVNodeType_Dir:
		dirId, err := val.ToDirID()
		if err != nil {
			return err
		}
		return dirRef(m, tx, pid, *dirId, v)
	case proto.KVNodeType_File:
		fileID, err := val.ToFileID()
		if err != nil {
			return err
		}
		return fileRef(m, tx, pid, *fileID, v)
	case proto.KVNodeType_SmallFile, proto.KVNodeType_Symlink:
		return smallFileRef(m, tx, pid, val, v)
	case proto.KVNodeType_None:
		// noop
		return nil
	default:
		return core.InternalError("direntRef: invalid node id")
	}
}

func direntIncref(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	val proto.KVNodeID,
) error {
	return direntRef(m, tx, pid, val, 1)
}

func direntDecref(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	val proto.KVNodeID,
) error {
	return direntRef(m, tx, pid, val, -1)
}

func loadDirentByID(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	dirid proto.DirID,
	id proto.DirentID,
	vers proto.KVVersion,
	role proto.Role,
) (
	*proto.KVDirent,
	error,
) {
	f := func(q string, tab string, args []any) (string, []any) {
		i := len(args) + 1
		j := i + 1
		q = fmt.Sprintf("%s AND %s.dirent_id=$%d AND %s.version=$%d", q, tab, i, tab, j)
		args = append(args, id.ExportToDB(), int(vers))
		return q, args
	}
	return loadDirent(m, tx, pid, dirid, f, role)
}

func loadDirent(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	dirid proto.DirID,
	f func(q string, tab string, args []any) (string, []any),
	role proto.Role,
) (
	*proto.KVDirent,
	error,
) {
	var dv, wrt, wvl, ptkg, v, rrt, rvl int
	var val, nb, nmac, bmac, id []byte
	var status string

	args := []any{
		int(m.ShortHostID()),
		pid.Shorten().ExportToDB(),
		dirid.ExportToDB(),
	}

	q := `SELECT E.dir_version, E.name_box, E.value, E.write_role_type,
	        E.write_role_viz_level, E.name_mac, E.binding_mac, E.dirent_id, E.version, D.ptk_gen, D.status,
			D.read_role_type, D.read_role_viz_level
		FROM dirent AS E
	    JOIN dir AS D ON (
			E.short_host_id=D.short_host_id AND 
			E.short_party_id=D.short_party_id AND 
			E.dir_id=D.dir_id AND 
			E.dir_version=D.version
			)
		 WHERE E.short_host_id=$1 AND E.short_party_id=$2 AND E.dir_id=$3
	`
	q, args = f(q, "E", args)

	err := rq.QueryRow(m.Ctx(), q, args...).Scan(
		&dv, &nb, &val, &wrt, &wvl, &nmac, &bmac, &id, &v, &ptkg, &status, &rrt, &rvl,
	)

	if err != nil && err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var readRole proto.Role
	err = readRole.ImportFromDB(rrt, rvl)
	if err != nil {
		return nil, err
	}
	err = assertAtOrAbove(role, readRole, proto.KVOp_Read, proto.KVNodeType_Dir)
	if err != nil {
		return nil, err
	}
	var writeRole proto.Role
	err = writeRole.ImportFromDB(wrt, wvl)
	if err != nil {
		return nil, err
	}
	ret := proto.KVDirent{
		ParentDir:  dirid,
		Version:    proto.KVVersion(v),
		DirVersion: proto.KVVersion(dv),
		WriteRole:  writeRole,
	}
	err = ret.Value.ImportFromDB(val)
	if err != nil {
		return nil, err
	}
	err = ret.NameMac.ImportFromDB(nmac)
	if err != nil {
		return nil, err
	}
	err = ret.BindingMac.ImportFromDB(bmac)
	if err != nil {
		return nil, err
	}
	err = ret.Id.ImportFromDB(id)
	if err != nil {
		return nil, err
	}
	err = ret.DirStatus.ImportFromDB(status)
	if err != nil {
		return nil, err
	}
	err = core.DecodeFromBytes(&ret.NameBox, nb)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func putDirent(m shared.MetaContext, tx pgx.Tx, pid proto.PartyID, role proto.Role, arg rem.KvPutArg) error {
	for _, de := range arg.Dirents {
		kp := direntUpdater{tx: tx, arg: arg, role: role, pid: pid, de: de}
		err := kp.run(m)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *direntUpdater) loadParentDir(m shared.MetaContext) error {
	dir, err := loadDir(m, p.tx, p.pid, p.de.ParentDir, p.de.DirVersion)
	if err != nil {
		return err
	}
	p.dir = dir
	return nil
}

func (p *direntUpdater) loadExistingDirent(m shared.MetaContext, role proto.Role) error {
	if p.de.Version.IsFirst() {
		return nil
	}
	prev := p.de.Version - 1
	existing, err := loadDirentByID(
		m,
		p.tx,
		p.pid,
		p.de.ParentDir,
		p.de.Id, prev,
		role,
	)
	if err != nil {
		return err
	}
	if existing != nil && p.de.DirVersion != existing.DirVersion && p.de.DirVersion != existing.DirVersion+1 {
		return core.KVRaceError("dir version wasn't current or prev")
	}
	p.existing = existing
	return nil
}

func (p *direntUpdater) checkArg(m shared.MetaContext) error {
	if p.de.Version < 1 {
		return core.BadArgsError("dirent version must be >= 1")
	}
	return nil
}

func (p *direntUpdater) checkPermissions(m shared.MetaContext) error {
	if p.existing != nil {
		err := assertAtOrAbove(p.role, p.existing.WriteRole, proto.KVOp_Write, proto.KVNodeType_Dir)
		if err != nil {
			return err
		}
	}
	err := assertAtOrAbove(p.role, p.dir.WriteRole, proto.KVOp_Write, proto.KVNodeType_Dir)
	if err != nil {
		return err
	}
	err = assertAtOrAbove(p.role, p.dir.Box.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Dir)
	if err != nil {
		return err
	}
	return nil
}

func (p *direntUpdater) insertNewDirent(m shared.MetaContext) error {
	wrt, wlev, err := p.de.WriteRole.ExportToDB()
	if err != nil {
		return err
	}
	de := p.de
	nb, err := core.EncodeToBytes(&de.NameBox)
	if err != nil {
		return err
	}

	tag, err := p.tx.Exec(
		m.Ctx(),
		`INSERT INTO dirent (short_host_id, short_party_id, dir_id, 
			dirent_id, version, dir_version, name_box,
			value, write_role_type, write_role_viz_level, 
			name_mac, binding_mac, ctime, active
		)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),TRUE)`,
		int(m.ShortHostID()),
		p.pid.Shorten().ExportToDB(),
		de.ParentDir.ExportToDB(),
		de.Id.ExportToDB(),
		de.Version,
		int(de.DirVersion),
		nb,
		de.Value.ExportToDB(),
		wrt, wlev,
		de.NameMac.ExportToDB(),
		de.BindingMac.ExportToDB(),
	)
	if err != nil && shared.IsDuplicateKeyError(err, "dirent_pkey") {
		return core.DuplicateError("dirent")
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("dirent")
	}

	_, err = p.tx.Exec(
		m.Ctx(),
		`UPDATE dirent SET active=false
		 WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3
		   AND dirent_id=$4 AND version < $5`,
		int(m.ShortHostID()),
		p.pid.Shorten().ExportToDB(),
		de.ParentDir.ExportToDB(),
		de.Id.ExportToDB(),
		de.Version,
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *direntUpdater) updateRefcounts(m shared.MetaContext) error {
	// Only the case of a new put do we need to incref the new value
	if !p.de.Value.IsTombstone() {
		err := direntIncref(m, p.tx, p.pid, p.de.Value)
		if err != nil {
			return err
		}
	}
	if p.existing != nil {
		err := direntDecref(m, p.tx, p.pid, p.existing.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *direntUpdater) store(m shared.MetaContext) error {
	return p.insertNewDirent(m)
}

func (p *direntUpdater) run(m shared.MetaContext) error {
	err := p.checkArg(m)
	if err != nil {
		return err
	}
	err = p.loadParentDir(m)
	if err != nil {
		return err
	}
	err = p.loadExistingDirent(m, p.role)
	if err != nil {
		return err
	}
	err = p.checkPermissions(m)
	if err != nil {
		return err
	}
	err = p.updateRefcounts(m)
	if err != nil {
		return err
	}
	err = p.store(m)
	if err != nil {
		return err
	}
	return nil
}

func loadDirentAtName(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvGetArg,
	name rem.KVNameMACAtDirVersion,
) (
	*proto.KVDirent,
	error,
) {
	f := func(q string, tab string, args []any) (string, []any) {
		i := len(args) + 1
		j := i + 1
		q = fmt.Sprintf(
			"%s AND %s.name_mac=$%d AND %s.dir_version=$%d ORDER BY %s.version DESC LIMIT 1",
			q, tab, i, tab, j, tab,
		)
		args = append(args, name.Mac.ExportToDB(), int(name.DirVers))
		return q, args
	}
	return loadDirent(m, db, pid, arg.Path.ParentDir, f, role)
}

func getDirent(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvGetArg,
) (
	*rem.KVGetRes,
	error,
) {
	var de *proto.KVDirent
	for _, n := range arg.Path.Names {
		var err error
		de, err = loadDirentAtName(m, db, pid, role, arg, n)
		if err != nil {
			return nil, err
		}
		if de != nil {
			break
		}
	}
	if de == nil {
		return nil, core.KVNoentError{}
	}

	ret := rem.KVGetRes{
		De: *de,
	}

	typ, err := de.Value.Type()
	if err != nil {
		return nil, err
	}
	var follow bool
	switch {
	case typ == proto.KVNodeType_None:
		follow = false
	case arg.Follow == rem.FollowBehavior_Any:
		follow = true
	case arg.Follow == rem.FollowBehavior_DirOnly && typ == proto.KVNodeType_Dir:
		follow = true
	}

	if !follow {
		return &ret, nil
	}

	dat, err := loadNode(m, db, pid, de.Value, role)
	if err != nil {
		return nil, err
	}
	ret.Data = dat

	return &ret, nil
}

func listDir(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvListArg,
) (
	*rem.KVListRes,
	error,
) {
	dir, err := loadDir(m, db, pid, arg.Dir, 0)
	if err != nil {
		return nil, err
	}
	err = assertAtOrAbove(role, dir.Box.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Dir)
	if err != nil {
		return nil, err
	}

	startTyp, err := arg.Opts.Start.GetT()
	if err != nil {
		return nil, err
	}

	lim := int(arg.Opts.Num)
	if lim == 0 || lim > 4096 {
		lim = 4096
	}
	q := `SELECT dirent_id, version, name_box, value, write_role_type, 
		    write_role_viz_level, name_mac, binding_mac, dir_version,
			ctime
		FROM dirent
		WHERE short_host_id=$1 AND short_party_id=$2
		AND dir_id=$3 AND active=true `

	args := []any{
		int(m.ShortHostID()),
		pid.Shorten().ExportToDB(),
		arg.Dir.ExportToDB(),
	}

	switch startTyp {
	case proto.KVListPaginationType_None:
		q += `ORDER BY name_mac ASC LIMIT $4`
		args = append(args, lim)
	case proto.KVListPaginationType_MAC:
		bottom := arg.Opts.Start.Mac()
		q += `AND name_mac > $4
		ORDER BY name_mac ASC
		LIMIT $5`
		args = append(args, bottom.ExportToDB(), lim)
	case proto.KVListPaginationType_Time:
		startTime := arg.Opts.Start.Time().Import()
		// note that there is a very small chance that 2 files have the same ctime.
		// So we need to use '>=' here and then dedupe on the caller side.
		q += `AND ctime >= $4
		ORDER BY ctime ASC
		LIMIT $5`
		args = append(args, startTime, lim)
	}

	rows, err := db.Query(
		m.Ctx(),
		q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var des []proto.KVDirent

	var smallFilePos []int
	var smallFileIDs []proto.KVNodeID

	var i int
	for rows.Next() {
		var de proto.KVDirent
		var wrt, wvl, dv int
		var direntIdRaw, nameBoxRaw, nameMacRaw, bindingMacRaw, valueRaw []byte
		var ctime time.Time
		err = rows.Scan(
			&direntIdRaw, &de.Version, &nameBoxRaw, &valueRaw,
			&wrt, &wvl, &nameMacRaw, &bindingMacRaw, &dv,
			&ctime,
		)
		if err != nil {
			return nil, err
		}
		err = de.Id.ImportFromDB(direntIdRaw)
		if err != nil {
			return nil, err
		}
		err = core.DecodeFromBytes(&de.NameBox, nameBoxRaw)
		if err != nil {
			return nil, err
		}
		err = de.Value.ImportFromDB(valueRaw)
		if err != nil {
			return nil, err
		}
		err = de.NameMac.ImportFromDB(nameMacRaw)
		if err != nil {
			return nil, err
		}
		err = de.BindingMac.ImportFromDB(bindingMacRaw)
		if err != nil {
			return nil, err
		}
		tmp, err := proto.ImportRoleFromDB(wrt, wvl)
		if err != nil {
			return nil, err
		}
		de.WriteRole = *tmp
		de.DirVersion = proto.KVVersion(dv)
		de.Ctime = proto.ExportTimeMicro(ctime)
		des = append(des, de)

		if arg.Opts.LoadSmallFiles {
			typ, err := de.Value.Type()
			if err != nil {
				return nil, err
			}
			if typ == proto.KVNodeType_SmallFile {
				smallFilePos = append(smallFilePos, i)
				smallFileIDs = append(smallFileIDs, de.Value)
			}
		}
		i++
	}
	ret := &rem.KVListRes{Ents: des, Final: len(des) < lim}

	if arg.Opts.LoadSmallFiles {
		ext := make([]proto.KVExtendedDirent, 0, len(smallFilePos))
		files, err := mLoadSmallFilesOrSymlinks(m, db, pid, smallFileIDs, role, false)
		if err != nil {
			return nil, err
		}
		for i, f := range files {
			if f != nil {
				ext = append(ext, proto.KVExtendedDirent{
					Pos: uint64(smallFilePos[i]),
					Sfb: *f,
				})
			}
		}
		ret.ExtEnts = ext
	}
	return ret, nil

}
