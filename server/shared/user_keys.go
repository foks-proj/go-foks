// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

func InsertSubkey(
	m MetaContext,
	tx pgx.Tx,
	parent proto.EntityID,
	key core.EntityPublic,
	box *proto.Box,
) error {

	if (key == nil) != (box == nil) {
		return core.ValidationError("subkey can be supplied iff secret key box is supplied")
	}
	if key == nil {
		return nil
	}

	if parent.Type() != proto.EntityType_Yubi {
		return core.ValidationError("subkeys are currently only allowed for parent yubikeys")
	}

	bbytes, err := core.EncodeToBytes(box)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO subkeys(short_host_id, parent, verify_key, key_state, box, ctime, mtime)
         VALUES($1, $2, $3, 'valid', $4, NOW(), NOW())`,
		int(m.ShortHostID()),
		parent.ExportToDB(),
		key.GetEntityID().ExportToDB(),
		bbytes,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("subkeys")
	}
	return nil
}

func InsertSubkeyCheckSanity(
	m MetaContext,
	tx pgx.Tx,
	parent proto.EntityID,
	subkey core.EntityPublic,
	box *proto.Box,
) error {
	switch parent.Type() {
	case proto.EntityType_Device, proto.EntityType_BackupKey, proto.EntityType_BotTokenKey:
		if subkey != nil || box != nil {
			return core.ValidationError("cannot post subkey for regular or backup device")
		}
		return nil
	case proto.EntityType_Yubi:
		if subkey == nil || box == nil {
			return core.VerifyError("subkeys must provide subkey in link and also a subkey box")
		}
		return InsertSubkey(m, tx, parent, subkey, box)
	default:
		return core.ValidationError("unknown new device signer type")
	}
}
