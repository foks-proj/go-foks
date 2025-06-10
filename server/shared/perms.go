// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func InsertLocalViewPermission(
	m MetaContext,
	db DbExecer,
	viewer proto.PartyID,
	viewerRole proto.Role,
	viewee proto.PartyID,
) (
	*proto.PermissionToken,
	error,
) {

	ret, err := core.NewPermissionToken()
	if err != nil {
		return nil, err
	}
	rk, vl, err := viewerRole.ExportToDB()
	if err != nil {
		return nil, err
	}
	tag, err := db.Exec(
		m.Ctx(),
		`INSERT INTO local_view_permissions(short_host_id, target_eid, viewer_eid, state, ctime, mtime, token,
		   viewer_role_type, viewer_viz_level)
		 VALUES($1, $2, $3, 'valid', NOW(), NOW(), $4, $5, $6)
		 ON CONFLICT(short_host_id, target_eid, viewer_eid)
		 DO UPDATE SET state='valid', mtime=NOW(),
		    viewer_role_type=$5, viewer_viz_level=$6`,
		m.ShortHostID().ExportToDB(),
		viewee.ExportToDB(),
		viewer.ExportToDB(),
		ret.ExportToDB(),
		rk,
		vl,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, core.InsertError("failed to insert new view permission")
	}
	return &ret, nil
}

func GrantLocalViewPermission(
	ctx context.Context,
	c ClientConn,
	arg rem.GrantLocalViewPermissionPayload,
	sig *rem.SharedKeySig,
	typ proto.PartyType,
) (
	proto.PermissionToken,
	error,
) {
	m := NewMetaContextConn(ctx, c)
	db, err := m.Db(DbTypeUsers)
	var zed proto.PermissionToken
	if err != nil {
		return zed, err
	}
	defer db.Release()
	err = CheckActsFor(m, typ, &arg, sig)
	if err != nil {
		return zed, err
	}

	role := arg.ViewerRole.WithDefaultMemberLoadFloor()

	ret, err := InsertLocalViewPermission(m, db, arg.Viewer, role, arg.Viewee)
	if err != nil {
		return zed, err
	}
	return *ret, nil
}

func GrantRemoteViewPermission(
	ctx context.Context,
	c ClientConn,
	arg rem.GrantRemoteViewPermissionPayload,
	sig *rem.SharedKeySig,
	typ proto.PartyType,
) (
	proto.PermissionToken,
	error,
) {
	var ret proto.PermissionToken
	m := NewMetaContextConn(ctx, c)
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()
	var tokRaw []byte

	err = CheckActsFor(m, typ, &arg, sig)
	if err != nil {
		return ret, err
	}

	err = db.QueryRow(ctx,
		`SELECT token FROM remote_view_permissions
		 WHERE short_host_id=$1
		 AND target_eid=$2
		 AND viewer_eid=$3
		 AND viewer_host_id=$4
		 AND state='valid'`,
		m.ShortHostID().ExportToDB(),
		arg.Viewee.ExportToDB(),
		arg.Viewer.Party.ExportToDB(),
		arg.Viewer.Host.ExportToDB(),
	).Scan(&tokRaw)

	if err == nil {
		err = ret.ImportFromDB(tokRaw)
		if err != nil {
			return ret, err
		}
		return ret, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ret, err
	}
	ret, err = core.NewPermissionToken()
	if err != nil {
		return ret, err
	}

	tag, err := db.Exec(
		ctx,
		`INSERT INTO remote_view_permissions(short_host_id, target_eid, viewer_eid, viewer_host_id, token,
			   state, ctime)
		 VALUES($1, $2, $3, $4, $5, 'valid', NOW())`,
		m.ShortHostID().ExportToDB(),
		arg.Viewee.ExportToDB(),
		arg.Viewer.Party.ExportToDB(),
		arg.Viewer.Host.ExportToDB(),
		ret.ExportToDB(),
	)
	if err != nil {
		return ret, err
	}
	if tag.RowsAffected() != 1 {
		return ret, core.InsertError("failed to insert new view token")
	}
	return ret, nil
}

// BulkInsertLocalViewPermissions inserts a list of view permissions for a viewer.
// It assumes that the host is in open viewership mode. If not, it will return an error.
// If you pass it teamIDs in the viewees list, it
// will return an error. Finally, it also assumes the insert is in the context of a
// team edit. It therefore checks that all the viewees are in the list of entities being
// added (or more precisely, not being removed) from the team. It's a noop if the list
// of viewees is empty.
//
// Why do we do this? In case we later turn a host to be closed viewership, working teams
// will not break; they'll be more or less frozen at the time of the change.
func BulkInsertLocalViewPermissions(
	m MetaContext,
	db DbExecer,
	viewer proto.PartyID,
	viewerRole proto.Role,
	viewees []proto.PartyID,
	edits []proto.MemberRole,
) error {
	if len(viewees) == 0 {
		return nil
	}
	cfg, err := m.G().HostIDMap().Config(m, m.ShortHostID())
	if err != nil {
		return err
	}
	if cfg.Viewership.User != proto.ViewershipMode_Open {
		return core.PermissionError("no open viewership mode")
	}

	adds := make(map[proto.FixedEntityID]struct{})
	for _, edit := range edits {
		role, err := edit.DstRole.GetT()
		if err != nil {
			return err
		}
		if role == proto.RoleType_NONE {
			continue
		}
		if edit.Member.Id.Host != nil {
			continue
		}
		eid := edit.Member.Id.Entity
		fx, err := eid.Fixed()
		if err != nil {
			return err
		}
		adds[fx] = struct{}{}
	}

	for _, viewee := range viewees {
		fx, err := viewee.EntityID().Fixed()
		if err != nil {
			return err
		}
		if _, ok := adds[fx]; !ok {
			return core.BadArgsError("viewee not in edit list")
		}
		_, err = InsertLocalViewPermission(m, db, viewer, viewerRole, viewee)
		if err != nil {
			return err
		}
	}

	return nil
}
