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

type TeamVerifiable interface {
	core.Verifiable
	Signer() proto.PartyID
	Time() proto.Time
}

func loadTeamVerifyKey(
	m MetaContext,
	t proto.TeamID,
	g proto.Generation,
	r proto.Role,
) (
	core.EntityPublic,
	error,
) {

	rk, err := core.ImportRole(r)
	if err != nil {
		return nil, err
	}
	if !rk.Typ.IsAdminOrAbove() {
		return nil, core.PermissionError("role must be admin or above")
	}

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	var vk []byte
	var gLatest int

	err = db.QueryRow(
		m.Ctx(),
		`SELECT verify_key, gen FROM shared_keys
		WHERE short_host_id=$1 AND entity_id=$2
		AND role_type=$3 AND viz_level=$4
		ORDER BY gen DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		t.ExportToDB(),
		int(rk.Typ),
		int(rk.Lev),
	).Scan(&vk, &gLatest)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("no such team")
	}
	if err != nil {
		return nil, err
	}
	if proto.Generation(gLatest) != g {
		return nil, core.TeamRaceError("team key generation was wrong")
	}

	eid, err := proto.ImportEntityIDFromBytes(vk)
	if err != nil {
		return nil, err
	}
	ep, err := core.ImportEntityPublic(eid)
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func CheckActsFor(
	m MetaContext,
	typ proto.PartyType,
	v TeamVerifiable,
	sig *rem.SharedKeySig,
) error {
	uid, teamid, err := v.Signer().Select()
	switch {
	case err != nil:
		return err
	case uid != nil:
		if typ != proto.PartyType_User {
			return core.ValidationError("CheckActsFor expected a user")
		}
		if sig != nil {
			return core.ValidationError("signature not allowed")
		}
		if !m.UID().Eq(*uid) {
			return core.PermissionError("wrong UID")
		}
		return nil
	case teamid != nil:
		if typ != proto.PartyType_Team {
			return core.ValidationError("CheckActsFor expected a team")
		}
		return checkActsForTeam(m, v, sig, *teamid)
	default:
		return core.InternalError("invalid principal")
	}
}

func checkActsForTeam(
	m MetaContext,
	v TeamVerifiable,
	sig *rem.SharedKeySig,
	teamid proto.TeamID,
) error {
	if sig == nil {
		return core.ValidationError("signature required")
	}
	if !v.Time().IsNowish() {
		return core.ValidationError("signature too old")
	}
	ep, err := loadTeamVerifyKey(m, teamid, sig.Gen, sig.Role)
	if err != nil {
		return err
	}

	err = ep.Verify(sig.Sig, v)
	if err != nil {
		return err
	}
	return nil
}
