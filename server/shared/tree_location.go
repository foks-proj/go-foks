// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

func InsertTreeLocationMachinery(
	m MetaContext,
	tx pgx.Tx,
	typ proto.ChainType,
	uid proto.EntityID,
	seqno proto.Seqno,
	vrfid *proto.LocationVRFID,
	loc proto.TreeLocation,
	com proto.TreeLocationCommitment,
) error {

	// insert into the location VRF if we need that
	if vrfid != nil {
		err := InsertLocationVRFID(m, tx, uid, seqno, *vrfid)
		if err != nil {
			return err
		}
	}

	if !seqno.IsValid() {
		return core.InternalError("refusing to insert seqno=0 tree location, which should not exist")
	}

	err := core.VerifyTreeLocationCommitment(loc, com)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO tree_locations(short_host_id, chain_type, 
			   entity_id, seqno, loc, ctime) VALUES($1,$2,$3,$4,$5,NOW())`,
		int(m.ShortHostID()),
		int(typ),
		uid.ExportToDB(), seqno+1, loc.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert next tree location")
	}

	return nil
}

func InsertLocationVRFID(
	m MetaContext,
	tx pgx.Tx,
	eid proto.EntityID,
	seqno proto.Seqno,
	id proto.LocationVRFID,
) error {

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO location_vrf_public_keys(short_host_id, entity_id, seqno, public_key, ctime)
			 VALUES($1, $2, $3, $4, NOW())`,
		int(m.ShortHostID()),
		eid.ExportToDB(),
		uint(seqno),
		id.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("cannot insert new VRF key ID")
	}
	return nil
}
