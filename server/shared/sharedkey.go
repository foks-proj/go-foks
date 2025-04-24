// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

func InsertHEPK(
	m MetaContext,
	tx pgx.Tx,
	fp proto.HEPKFingerprint,
	hepks *core.HEPKSet,
) error {
	hepk, ok := hepks.Lookup(&fp)
	if !ok {
		return core.KeyNotFoundError{Which: "hepk"}
	}
	return InsertHEPKDirect(m, tx, fp, hepk.Obj())
}

func InsertHEPKDirect(
	m MetaContext,
	tx pgx.Tx,
	fp proto.HEPKFingerprint,
	hepk *proto.HEPK,
) error {
	hepkRaw, err := core.EncodeToBytes(hepk)
	if err != nil {
		return err
	}

	_, err = tx.Exec(m.Ctx(),
		`INSERT INTO hepks(short_host_id, hepk_fp, hepk) VALUES($1, $2, $3) ON CONFLICT DO NOTHING`,
		m.ShortHostID().ExportToDB(),
		fp.ExportToDB(),
		hepkRaw,
	)
	if err != nil {
		return err
	}
	// we don't check the number of rows inserted, since it's OK to noop on a dup
	return nil
}

func InsertSharedKey(
	m MetaContext,
	tx pgx.Tx,
	vtyp proto.EntityType,
	eid proto.EntityID,
	creator proto.EntityID,
	sk proto.SharedKey,
	hepks *core.HEPKSet,
) error {

	rk, err := core.ImportRole(sk.Role)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO shared_keys(short_host_id, entity_id, 
			gen, role_type, viz_level, ctime, creator_uid, verify_key, hepk_fp, key_state)
             VALUES($1, $2, $3, $4, $5, NOW(), $6, $7, $8, 'valid')`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(), // can be a user or a team
		sk.Gen,
		rk.Typ,
		rk.Lev,
		creator.ExportToDB(), // if on a team, the member who did it
		sk.VerifyKey.ExportToDB(),
		sk.HepkFp.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("shared key")
	}

	err = InsertHEPK(m, tx, sk.HepkFp, hepks)
	if err != nil {
		return err
	}

	return nil
}

func InsertRotateSharedKeys(
	m MetaContext,
	tx pgx.Tx,
	ceiling core.RoleKey,
	signingDevice proto.EntityID,
	sharedKeyGens map[core.RoleKey]proto.Generation,
	currentMembers map[proto.FQEntityFixed]core.RoleKey,
	sbs proto.SharedKeyBoxSet,
	sharedKeys []core.SharedPublicSuite,
	seedChainBoxes []proto.SeedChainBox,
	hepksVec proto.HEPKSet,
) error {

	// No new keys (self-revoke?) so no need for new boxes or shared keys
	if len(sharedKeys) == 0 {
		return nil
	}

	hepks, err := core.ImportHEPKSet(&hepksVec)
	if err != nil {
		return err
	}

	// Figure out the new mapping of <Role,Level> -> Generation; should be +1 the previous
	newGens := make(map[core.RoleKey]proto.Generation)
	for _, box := range sbs.Boxes {
		rk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		if gen, found := newGens[*rk]; found && gen != box.Gen {
			return core.BoxError(fmt.Sprintf("conflicting generations for role %+v: %d vs %d", *rk, gen, box.Gen))
		}
		newGens[*rk] = box.Gen
		if gen, found := sharedKeyGens[*rk]; !found || gen+1 != box.Gen {
			return core.BoxError(
				fmt.Sprintf("got wronte generation for role %+v; expected %d but got %d",
					*rk, gen+1, box.Gen,
				))
		}
	}

	// Now insert the new shared key box generations into the DB, stomping the old
	for k, v := range newGens {
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE shared_key_generations
			SET gen=$1
			WHERE short_host_id=$2 
			AND entity_id=$3 
			AND role_type=$4
			AND viz_level=$5`,
			v,
			m.ShortHostID().ExportToDB(),
			m.UID().ExportToDB(),
			k.Typ,
			k.Lev,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert into shared_key_generations")
		}
	}

	// next insert the new public keys into the DB
	for _, sk := range sharedKeys {
		uid := m.UID().EntityID()
		err := InsertSharedKey(m, tx, proto.EntityType_PUKVerify, uid, uid, sk.SharedKey, hepks)
		if err != nil {
			return err
		}
	}

	// Also add seed chain boxes, since we have a new geneartion of keys that references the old one
	foundSeedChainBoxes := make(map[core.RoleKey]bool)
	for _, box := range seedChainBoxes {
		rk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		if foundSeedChainBoxes[*rk] {
			return core.BoxError(fmt.Sprintf("found multiple seed chain boxes for role: %v", *rk))
		}
		foundSeedChainBoxes[*rk] = true
		if gen, found := newGens[*rk]; !found {
			return core.BoxError(fmt.Sprintf("spurious seed chain box found: %v", *rk))
		} else if gen != box.Gen+1 {
			return core.BoxError(fmt.Sprintf("wrong gen for %v seedChainBox: %d vs %d", *rk, gen, box.Gen+1))
		}
		b, err := core.EncodeToBytes(&box.Box)
		if err != nil {
			return err
		}
		tags, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_seed_chain(short_host_id, entity_id, gen, role_type, viz_level, ctime, secret_box)
	         VALUES($1, $2, $3, $4, $5, NOW(), $6)`,
			m.ShortHostID().ExportToDB(),
			m.UID().ExportToDB(),
			box.Gen,
			rk.Typ,
			rk.Lev,
			b,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.InsertError("failed to insert into shared_key_seed_chain")
		}
	}

	// finally all the corresponding boxes
	gameplan, err := core.ComputeRotateNewBoxGameplan(currentMembers, sharedKeyGens, ceiling)
	if err != nil {
		return err
	}

	dh, err := ExportTmpDHKeySignedToDB(sbs.TempDHKeySigned)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO shared_key_box_metadata (short_host_id, box_set_id, signer_id, ephemeral_dh_key)
         VALUES($1,$2,$3,$4)`,
		m.ShortHostID().ExportToDB(),
		sbs.Id.ExportToDB(),
		signingDevice.ExportToDB(),
		dh,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert shared key box metadata")
	}

	found := make(map[core.DeviceAtRole]bool)
	hostID := m.HostID().Id
	for _, box := range sbs.Boxes {
		rk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		fid, err := box.Targ.Eid.Fixed()
		if err != nil {
			return err
		}
		dar := core.DeviceAtRole{Role: *rk, Id: fid, Host: hostID}
		if found[dar] {
			return core.BoxError(fmt.Sprintf("repeated box for %+v", dar))
		}
		found[dar] = true
		gen, found := gameplan[dar]
		if !found {
			return core.BoxError(fmt.Sprintf("unnecessary box: %+v", dar))
		}
		b, err := core.EncodeToBytes(&box.Box)
		if err != nil {
			return err
		}
		if box.Gen != gen {
			return core.BoxError(fmt.Sprintf("bad generation for %+v, wanted %d", dar, gen))
		}
		trk, err := core.ImportRole(box.Targ.Role)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_boxes(
				short_host_id, entity_id, 
				target_entity_id, target_host_id, gen, role_type, viz_level, 
				box_set_id, box, ctime,
				target_gen, target_role_type, target_viz_level)
		     VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12)`,
			m.ShortHostID().ExportToDB(),
			m.UID().ExportToDB(),
			box.Targ.Eid.ExportToDB(),
			box.Targ.Host.ExportToDBIfNotCurrentHost(&hostID),
			box.Gen,
			rk.Typ,
			rk.Lev,
			sbs.Id.ExportToDB(),
			b,
			box.Targ.Gen,
			trk.Typ,
			trk.Lev,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert shared_key_boxes")
		}
	}
	if len(sbs.Boxes) != len(gameplan) {
		return core.BoxError(fmt.Sprintf("not enough boxes (got %d but needed %d)", len(sbs.Boxes), len(gameplan)))
	}

	return nil
}

// - Case 1: adding at an existing level --> one box
// - Case 2: adding at a new level --> boxes for all devices at or above the level
func InsertProvisionSharedKeys(
	m MetaContext,
	tx pgx.Tx,
	uot proto.EntityID, // the user or team we are working on
	actor proto.EntityID, // the user who is working, will be the same as target for user operations
	newMember core.PublicSuiter,
	sharedKeyGens map[core.RoleKey]proto.Generation,
	currentMembers map[proto.FQEntityFixed]core.RoleKey,
	sbs proto.SharedKeyBoxSet,
	sharedKey *core.SharedPublicSuite,
	signer core.EntityPublic,
	hepksVec proto.HEPKSet,
) error {
	newDeviceRK, err := core.ImportRole(newMember.GetRole())
	if err != nil {
		return err
	}
	hepks, err := core.ImportHEPKSet(&hepksVec)
	if err != nil {
		return err
	}

	if sharedKeyGens == nil {
		sharedKeyGens = make(map[core.RoleKey]proto.Generation)
	}
	if currentMembers == nil {
		currentMembers = make(map[proto.FQEntityFixed]core.RoleKey)
	}

	lookup := make(map[proto.FQEntityFixed]bool)
	hostID := m.HostID().Id
	for _, box := range sbs.Boxes {
		fid, err := box.Targ.Fixed(hostID)
		if err != nil {
			return err
		}
		if lookup[*fid] {
			return core.BoxError(fmt.Sprintf("repeated box for target %s", box.Targ.Eid.EncodeHex()))
		}
		lookup[*fid] = true
	}
	ndfid, err := newMember.GetEntityID().Fixed()
	if err != nil {
		return err
	}
	if !lookup[proto.FQEntityFixed{Entity: ndfid, Host: hostID}] {
		return core.BoxError("no box for new device")
	}

	if sharedKey != nil && !sharedKey.Gen.IsValid() {
		return core.LinkError("invalid shared key generation")
	}

	// Case 1
	if _, found := sharedKeyGens[*newDeviceRK]; found {
		if len(sbs.Boxes) != 1 {
			return core.BoxError("expected exactly one box for existing key")
		}
		if sharedKey != nil {
			return core.LinkError("no new shared key expected")
		}
	} else {

		// Case 2
		if sharedKey == nil {
			return core.LinkError("new shared key expected")
		}
		if !sharedKey.Gen.IsFirst() {
			return core.LinkError("need generation=1 for new shared key")
		}

		isEq, err := newMember.GetRole().Eq(sharedKey.Role)
		if err != nil {
			return err
		}
		if !isEq {
			return core.LinkError("role for shared key does not match new device")
		}

		numDevices := 0
		for fqe, devRk := range currentMembers {
			if devRk.LessThan(*newDeviceRK) {
				continue
			}
			if !lookup[fqe] {
				s, _ := fqe.Entity.Unfix().StringErr()
				return core.BoxError(fmt.Sprintf("box missing for device %s", s))
			}
			numDevices++
		}
		// add 1 extra for the new device
		if numDevices+1 != len(sbs.Boxes) {
			return core.BoxError("number of boxes doesn't match number of devices")
		}

		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_generations(short_host_id, entity_id, role_type, viz_level, gen)
		     VALUES($1, $2, $3, $4, $5)`,
			m.ShortHostID().ExportToDB(),
			uot.ExportToDB(),
			newDeviceRK.Typ,
			newDeviceRK.Lev,
			int(sharedKey.Gen),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("shared_key_generations")
		}
		sharedKeyGens[*newDeviceRK] = proto.FirstGeneration

		tag, err = tx.Exec(m.Ctx(),
			`INSERT INTO shared_keys(short_host_id, entity_id, gen, role_type, 
				  viz_level, ctime, creator_uid, verify_key, hepk_fp, key_state)
             VALUES($1, $2, $3, $4, $5, NOW(), $6, $7, $8, 'valid')`,
			m.ShortHostID().ExportToDB(),
			uot.ExportToDB(),
			sharedKey.Gen,
			newDeviceRK.Typ,
			newDeviceRK.Lev,
			actor.ExportToDB(),
			sharedKey.VerifyKey.ExportToDB(),
			sharedKey.HepkFp.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("shared key")
		}
		err = InsertHEPK(m, tx, sharedKey.HepkFp, hepks)
		if err != nil {
			return err
		}
	}

	signerId := signer.GetEntityID()
	dh, err := ExportTmpDHKeySignedToDB(sbs.TempDHKeySigned)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO shared_key_box_metadata(short_host_id, box_set_id, signer_id, ephemeral_dh_key)
         VALUES($1,$2,$3,$4)`,
		m.ShortHostID().ExportToDB(),
		sbs.Id.ExportToDB(),
		signerId.ExportToDB(),
		dh,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert shared key box metadata")
	}

	found := make(map[core.DeviceAtRole]bool)
	for _, box := range sbs.Boxes {

		tmpRk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		fid, err := box.Targ.Eid.Fixed()
		if err != nil {
			return err
		}
		dar := core.DeviceAtRole{Role: *tmpRk, Id: fid, Host: hostID}
		if found[dar] {
			return core.BoxError(fmt.Sprintf("repeated box for %+v", dar))
		}
		found[dar] = true
		gen, found := sharedKeyGens[*tmpRk]
		if !found {
			return core.BoxError("no generation found for role in box")
		}
		if gen != box.Gen {
			return core.BoxError("wrong generation found for box")
		}

		b, err := core.EncodeToBytes(&box.Box)
		if err != nil {
			return err
		}
		targRk, err := core.ImportRole(box.Targ.Role)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_boxes(
				short_host_id, entity_id, 
				target_entity_id, target_host_id, 
				gen, role_type, viz_level, box_set_id, box, ctime,
				target_gen, target_role_type, target_viz_level)
		     VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12)`,
			m.ShortHostID().ExportToDB(),
			uot.ExportToDB(),
			box.Targ.Eid.ExportToDB(),
			box.Targ.Host.ExportToDBIfNotCurrentHost(&hostID),
			box.Gen,
			tmpRk.Typ,
			tmpRk.Lev,
			sbs.Id.ExportToDB(),
			b,
			box.Targ.Gen,
			targRk.Typ,
			targRk.Lev,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InternalError("failed to insert shared_key_box")
		}
	}

	return nil
}
