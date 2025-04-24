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

func InsertDevice(
	m MetaContext,
	tx pgx.Tx,
	hepks *core.HEPKSet,
	hostID core.ShortHostID,
	uid proto.UID,
	role proto.Role,
	keyID proto.EntityID,
	newDev core.PublicSuiter,
	devNameCommitment *proto.Commitment,
	dlnck rem.DeviceLabelNameAndCommitmentKey,
	tok proto.PermissionToken,
	seqno proto.Seqno,
	pqhint *proto.YubiSlotAndPQKeyID,
) error {

	err := core.CheckDeviceLabelAndName(dlnck.Dln)
	if err != nil {
		return err
	}

	rk, err := core.ImportRole(role)
	if err != nil {
		return err
	}

	if !dlnck.Dln.Label.Serial.IsValid() {
		return core.ValidationError("invalid serial number")
	}

	if tok.IsZero() {
		return core.ValidationError("need a non-zero permission token")
	}

	hepk, err := newDev.ExportHEPK()
	if err != nil {
		return err
	}
	fp, err := core.HEPK(hepk).Fingerprint()
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO device_keys(
			 short_host_id, verify_key, uid, role_type, viz_level, key_state, hepk_fp,
			 device_name_commitment, 
			 device_name, 
			 device_name_normalized, 
			 device_name_normalization_version, 
			 device_serial, device_type, 
			 ctime, mtime, 
			 seqno)
		 VALUES($1, $2, $3, $4, $5, 'valid', $6, $7, $8, $9, $10, $11, $12, NOW(), NOW(), $13)`,
		int(hostID),
		keyID.ExportToDB(),
		uid.ExportToDB(),
		rk.Typ, rk.Lev,
		fp.ExportToDB(),
		devNameCommitment.ExportToDB(),
		dlnck.Dln.Name.ExportToDB(),
		dlnck.Dln.Label.Name.ExportToDB(),
		dlnck.Dln.Nv.ExportToDB(),
		dlnck.Dln.Label.Serial,
		dlnck.Dln.Label.DeviceType.ExportToDB(),
		int(seqno),
	)
	if err != nil && IsDuplicateKeyError(err, "device_keys_pkey") {
		return core.KeyInUseError{}
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("device_keys")
	}

	err = InsertHEPKDirect(m, tx, *fp, hepk)
	if err != nil {
		return err
	}

	tag, err = tx.Exec(m.Ctx(),
		`INSERT INTO self_view_tokens(short_host_id, uid, view_token, verify_key, ctime)
		 VALUES($1, $2, $3, $4, NOW())`,
		int(hostID),
		uid.ExportToDB(),
		tok.ExportToDB(),
		keyID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("self_view_tokens")
	}

	aux := proto.DeviceNameNormalizationPreimage{
		Nv:   proto.NormalizationVersion_V0,
		Name: dlnck.Dln.Name,
	}

	err = OpenAndStoreCommitment(
		m.Ctx(),
		tx,
		&dlnck.Dln.Label,
		&dlnck.CommitmentKey,
		devNameCommitment,
		hostID,
		&aux,
	)
	if err != nil {
		return err
	}

	err = InsertYubiPQHint(m, tx, uid, keyID, pqhint)
	if err != nil {
		return err
	}
	var pkid *proto.YubiPQKeyID
	if pqhint != nil {
		pkid = &pqhint.Id
	}

	err = StoreYubiPQKeyID(m, tx, uid, keyID, pkid)
	if err != nil {
		return err
	}

	err = FillDeviceNag(m, tx, uid)
	if err != nil {
		return err
	}

	return nil
}

func insPQKeyID(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	keyID proto.YubiPQKeyID,
	knownPreimage bool,
) (int, error) {
	var uniq string
	if knownPreimage {
		uniq = "ON CONFLICT DO NOTHING"
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO yubi_pq_key_ids(short_host_id, uid, pqkeyid, known_preimage) VALUES($1,$2,$3,$4) `+uniq,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		keyID.ExportToDB(),
		knownPreimage,
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func StoreYubiPQKeyID(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	keyID proto.EntityID,
	pkid *proto.YubiPQKeyID,
) error {

	// Only need to operate on yubikeys
	if keyID.Type() != proto.EntityType_Yubi {
		return nil
	}

	// If we're actually inserting a yubi slot used a PQ key, then we don't know the
	// preimage, and it's important that our insert succeeds.
	if pkid != nil {
		n, err := insPQKeyID(m, tx, uid, *pkid, false)
		if err != nil {
			return err
		}
		if n != 1 {
			return core.InsertError("yubi_pq_key_ids")
		}
	}

	yid, err := keyID.ToYubiID()
	if err != nil {
		return err
	}
	pqidDerived, err := core.YubiIDtoYubiPQKeyID(yid)
	if err != nil {
		return err
	}
	n, err := insPQKeyID(m, tx, uid, *pqidDerived, true)
	if err != nil {
		return err
	}
	if n == 0 {
		var npi bool
		err = tx.QueryRow(
			m.Ctx(),
			`SELECT known_preimage 
			 FROM yubi_pq_key_ids 
			 WHERE short_host_id = $1 AND uid = $2 AND pqkeyid = $3`,
			m.ShortHostID().ExportToDB(),
			uid.ExportToDB(),
			pqidDerived.ExportToDB(),
		).Scan(&npi)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.BadServerDataError("no pq_key_id after failed insert!")
		}
		if err != nil {
			return err
		}
		if !npi {
			return core.KeyInUseError{}
		}
	}
	return nil
}

func InsertYubiPQHint(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	parent proto.EntityID,
	hint *proto.YubiSlotAndPQKeyID,
) error {

	typ := parent.Type()
	isYubi := (typ == proto.EntityType_Yubi)

	if isYubi && hint == nil {
		return core.BadArgsError("need PQ key hint with a yubikey")
	}

	if hint != nil && !isYubi {
		return core.BadArgsError("can't provide yubi PQ hints for non-yubi key")
	}
	if hint == nil {
		return nil
	}
	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO yubi_pq_hints(short_host_id, uid, parent, slot, pqkeyid, ctime)
		 VALUES($1, $2, $3, $4, $5, NOW())`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		parent.ExportToDB(),
		int(hint.Slot),
		hint.Id.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("yubi PQ hints")
	}
	return nil
}

func RemoveDevice(
	m MetaContext,
	tx pgx.Tx,
	id proto.EntityID,
	epno proto.MerkleEpno,
) error {
	shid := m.ShortHostID().ExportToDB()

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO revoked_device_keys(short_host_id, verify_key, revoke_header_epno, uid, role_type, viz_level, key_state,
		   hepk_fp, device_name_commitment, device_name, device_name_normalized, device_name_normalization_version,
		   device_serial, device_type, ctime, mtime, provision_epno)
  	     SELECT short_host_id, verify_key, $1, uid, role_type, viz_level, $2,
	       hepk_fp, device_name_commitment, device_name, device_name_normalized, device_name_normalization_version,
		    device_serial, device_type, ctime, NOW(), provision_epno
	     FROM device_keys
	     WHERE short_host_id=$3 AND verify_key=$4 AND uid=$5`,
		int(epno),
		"revoked",
		shid,
		id.ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("revoked_device_keys")
	}

	tag, err = tx.Exec(
		m.Ctx(),
		`DELETE FROM device_keys WHERE short_host_id=$1 AND verify_key=$2 AND uid=$3`,
		shid,
		id.ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("failed to delete row from device_keys")
	}

	err = FillDeviceNag(m, tx, m.UID())
	if err != nil {
		return err
	}
	return nil
}

func FillDeviceNag(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
) error {
	if uid.IsZero() {
		return core.NoActiveUserError{}
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO data_loss_nag(short_host_id, uid, ctime, mtime, cleared, num_active_devices)
		 VALUES(
		 	$1, $2, NOW(), NOW(), false, 
		 	(SELECT COUNT(*) FROM device_keys WHERE short_host_id=$1 AND uid=$2 AND key_state='valid'))
		 ON CONFLICT (short_host_id, uid) 
		 DO UPDATE SET
		 	mtime = NOW(),
			num_active_devices=EXCLUDED.num_active_devices`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("data_loss_nags")
	}
	return nil
}

func GetDeviceNagData(
	m MetaContext,
) (proto.DeviceNagInfo, error) {
	var ret proto.DeviceNagInfo

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	find := func() error {
		var n int
		err := db.QueryRow(
			m.Ctx(),
			`SELECT cleared, num_active_devices
			 FROM data_loss_nag
			 WHERE short_host_id=$1 AND uid=$2`,
			m.ShortHostID().ExportToDB(),
			m.UID().ExportToDB(),
		).Scan(&ret.Cleared, &n)
		if err == nil {
			ret.NumDevices = uint64(n)
		}
		return err
	}

	err = find()
	if err == nil {
		return ret, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ret, err
	}
	err = RetryTx(m, db, "GetDeviceNagData", func(m MetaContext, tx pgx.Tx) error {
		return FillDeviceNag(m, tx, m.UID())
	})
	if err != nil {
		return ret, err
	}
	err = find()
	if err != nil {
		return ret, err
	}
	return ret, nil
}
