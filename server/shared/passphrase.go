// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func UpdatePassphrase(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	shortHostID core.ShortHostID,
	key proto.EntityID,
	skwkBox proto.SecretBox,
	passphraseBox proto.PpePassphraseBox,
	pukBox *proto.PpePUKBox,
	stretchVersion proto.StretchVersion,
	salt *proto.PassphraseSalt,
	ppgen proto.PassphraseGeneration,
	link *rem.PostGenericLinkArg,
) error {
	ctx := m.Ctx()

	sbox, err := core.EncodeToBytes(&skwkBox)
	if err != nil {
		return err
	}
	var pukBoxRaw []byte
	var pukGen proto.Generation
	if pukBox != nil {
		typ, err := pukBox.PukRole.GetT()
		if err != nil {
			return err
		}
		if typ != proto.RoleType_OWNER {
			return core.RoleError("backup box must be for owner")
		}
		tmp, err := core.EncodeToBytes(&pukBox.Box)
		if err != nil {
			return err
		}
		pukBoxRaw = tmp
		pukGen = pukBox.PukGen
		if !pukGen.IsValid() {
			return core.PassphraseError("invalid PUK generation")
		}
	}

	if !ppgen.IsValid() {
		return core.PassphraseError("invalid passphrase generation")
	}

	if ppgen.IsFirst() && salt == nil {
		return core.InsertError("for first passphrase generation, need a salt")
	}
	if !ppgen.IsFirst() && salt != nil {
		return core.InsertError("can only set a salt on first generation")
	}

	typ, err := passphraseBox.Box.GetT()
	if err != nil {
		return err
	}
	if typ != proto.BoxType_HYBRID {
		return core.PassphraseError("can only handle hybrid-encrypted passphrase boxes")
	}
	box := passphraseBox.Box.Hybrid()
	hv, err := box.GetV()
	if err != nil {
		return err
	}
	if hv != proto.BoxHybridVersion_V1 {
		return core.VersionNotSupportedError("can only handle Hybrid encryption V1")
	}
	v1 := box.V1()
	if len(v1.KemCtext) < 10 {
		return core.PassphraseError("kem ciphertext too short")
	}
	btyp, err := v1.Sbox.GetT()
	if err != nil {
		return err
	}
	if btyp != proto.BoxType_NACL {
		return core.PassphraseError("can only handle nacl secret boxes")
	}
	if v1.DhType != proto.DHType_Curve25519 {
		return core.PassphraseError("can only handle curve25519 DH types")
	}

	if key == nil {
		return core.PassphraseError("key not supplied")
	}
	if key.Type() != proto.EntityType_PassphraseKey {
		return core.PassphraseError("key not a passphrase key")
	}

	passphraseBoxRaw, err := core.EncodeToBytes(&passphraseBox.Box)
	if err != nil {
		return err
	}

	var cnt int
	err = tx.QueryRow(
		ctx,
		"SELECT COUNT(ppgen) FROM passphrase_boxes WHERE short_host_id=$1 AND uid=$2",
		int(shortHostID),
		uid.ExportToDB(),
	).Scan(&cnt)
	if err != nil {
		return err
	}

	if ppgen.IsFirst() {
		if cnt != 0 {
			return core.InsertError("passphrase already set, cannot establish a new one")
		}
	} else {
		var max int
		err = tx.QueryRow(
			ctx,
			"SELECT MAX(ppgen) FROM passphrase_boxes WHERE short_host_id=$1 AND uid=$2",
			int(shortHostID),
			uid.ExportToDB(),
		).Scan(&max)
		if err != nil {
			return err
		}
		if cnt != max {
			return core.InsertError("expected sequence passphrase generations but got a skip")
		}
		if ppgen != proto.PassphraseGeneration(max)+1 {
			return core.InsertError(fmt.Sprintf("expected passphrase generation %d but got %d", max+1, ppgen))
		}
	}

	tag, err := tx.Exec(ctx,
		`INSERT INTO passphrase_boxes(short_host_id, uid, ppgen, verify_key, 
			skwk_box, passphrase_box, puk_box, puk_gen, ctime, stretch_version)
		 VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)`,
		int(shortHostID),
		uid.ExportToDB(), ppgen, key.ExportToDB(),
		sbox, passphraseBoxRaw, pukBoxRaw, int(pukGen), stretchVersion,
	)
	if err != nil {
		return err
	}

	if tag.RowsAffected() != 1 {
		return core.InsertError("passphrase boxes")
	}

	if salt != nil {

		if salt.IsZero() {
			return core.InsertError("cannot specify a 0 salt")
		}

		tag, err = tx.Exec(ctx,
			`INSERT INTO user_salts(short_host_id, uid, salt, ctime) VALUES($1, $2, $3, NOW())`,
			int(shortHostID),
			uid.ExportToDB(),
			salt.EncodeToDB(),
		)
		if err != nil {
			return err
		}

		if tag.RowsAffected() != 1 {
			return core.InsertError("user_salts")
		}
	}

	if link != nil {
		err = PostGenericLinkTryTx(m, tx, *link, uid.ToPartyID(), nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func StretchVersion(m MetaContext) (proto.StretchVersion, error) {
	settings, err := m.G().Config().Settings(m.Ctx())
	ret := proto.StretchVersion_V1
	if err != nil {
		return ret, err
	}
	if settings.Testing {
		ret = proto.StretchVersion_TEST
	}
	return ret, nil
}
