// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func GenerateStandardInviteCode(m MetaContext, creator proto.UID) (*rem.InviteCode, error) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	b := make([]byte, core.InviteCodeBytes)
	err = core.RandomFill(b)
	if err != nil {
		return nil, err
	}
	tags, err := db.Exec(m.Ctx(),
		`INSERT INTO invite_codes(short_host_id, code, creator)
		VALUES($1, $2, $3)`,
		m.ShortHostID().ExportToDB(),
		b, creator.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	if tags.RowsAffected() != 1 {
		return nil, core.InsertError("invite_codes")
	}
	ret := rem.NewInviteCodeWithStandard(b)
	return &ret, nil
}

type MultiUseInviteCode struct {
	Code  rem.MultiUseInviteCode
	Valid bool
	Uses  int
}

func DisableMultiUseInviteCode(m MetaContext, code rem.MultiUseInviteCode) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	tags, err := db.Exec(m.Ctx(),
		`UPDATE multiuse_invite_codes
		SET valid=FALSE
		WHERE short_host_id=$1 AND code=$2`,
		m.ShortHostID().ExportToDB(),
		code.String(),
	)
	if err != nil {
		return err
	}
	if tags.RowsAffected() != 1 {
		return core.UpdateError("multiuse_invite_codes")
	}
	return nil
}

func LoadAllMultiuseInviteCodes(m MetaContext) ([]MultiUseInviteCode, error) {

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT code, valid, num_uses
		 FROM multiuse_invite_codes
		 WHERE short_host_id=$1`,
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []MultiUseInviteCode
	for rows.Next() {
		var codeRaw string
		var valid bool
		var uses int
		err = rows.Scan(&codeRaw, &valid, &uses)
		if err != nil {
			return nil, err
		}
		ret = append(ret, MultiUseInviteCode{
			Code:  rem.MultiUseInviteCode(codeRaw),
			Valid: valid,
			Uses:  uses,
		})
	}
	slices.SortFunc(ret, func(a, b MultiUseInviteCode) int {
		// Sort the valid codes first
		if a.Valid != b.Valid {
			if a.Valid {
				return -1
			}
			return 1
		}
		// then sort by code, ascending
		return a.Code.Cmp(a.Code)
	})
	return ret, nil
}

func InsertMultiuseInviteCode(
	m MetaContext,
	code rem.MultiUseInviteCode,
) error {
	return insertMultiuseInviteCode(m, code, false)
}

func InsertMultiuseInviteCodeAllowRepeat(
	m MetaContext,
	code rem.MultiUseInviteCode,
) error {
	return insertMultiuseInviteCode(m, code, true)
}

func insertMultiuseInviteCode(
	m MetaContext,
	code rem.MultiUseInviteCode,
	allowRepeat bool,
) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	q := `INSERT INTO multiuse_invite_codes(short_host_id, code, num_uses, valid)
		VALUES($1, $2, 0, TRUE)`
	if allowRepeat {
		q += ` ON CONFLICT(short_host_id, code) DO NOTHING`
	}

	tags, err := db.Exec(m.Ctx(), q,
		m.ShortHostID().ExportToDB(),
		code.String(),
	)
	if err != nil {
		return err
	}
	n := tags.RowsAffected()
	if !(n == 1 || (n == 0 && allowRepeat)) {
		return core.InsertError("multiuse_invite_codes")
	}
	return nil
}

func CheckInviteCode(m MetaContext, ic rem.InviteCode) error {

	err := core.ValidateInviteCode(ic)
	if err != nil {
		m.Warnw("bad invite code", "err", err)
		return err
	}

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	var query string
	var arg any
	typ, err := ic.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case rem.InviteCodeType_Standard:
		query = `SELECT 1 
		         FROM invite_codes 
				 WHERE short_host_id=$1 AND code=$2
				 AND used_by IS NULL`
		b := ic.Standard()
		arg = b
	case rem.InviteCodeType_MultiUse:
		query = `SELECT 1 
		         FROM multiuse_invite_codes
				 WHERE short_host_id=$1
				 AND code=$2 AND valid=TRUE`
		txt := ic.Multiuse()
		arg = txt
	default:
		m.Warnw("bad invite code type", "type", typ)
		return core.BadInviteCodeError{}
	}
	var tmp int
	err = db.QueryRow(
		m.Ctx(),
		query,
		m.ShortHostID().ExportToDB(),
		arg,
	).Scan(&tmp)
	found := (err == nil && tmp == 1)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if !found {
		return core.BadInviteCodeError{}
	}
	return nil
}
