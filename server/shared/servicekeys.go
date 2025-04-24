// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// "Service Keys" are used to make client certificates for when various backend FOKS services
// talk to each other. Private and public half are stored in the DB. It's basically saying that
// if you have DB access, you're OK to make backend connects to different FOKS infrastructure
// services.

func FetchServiceKey(m MetaContext, t proto.ServerType) (*proto.Ed25519SecretKey, error) {
	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	return fetchServiceKey(m, db, t)
}

func fetchServiceKey(m MetaContext, db *pgxpool.Conn, t proto.ServerType) (*proto.Ed25519SecretKey, error) {
	var keyRaw []byte

	err := db.QueryRow(m.Ctx(),
		`SELECT secret_key FROM service_keys WHERE service_id=$1 AND key_state='valid' ORDER BY ctime DESC LIMIT 1`,
		t.ServiceID().ExportToDB(),
	).Scan(&keyRaw)
	if err != nil {
		return nil, err
	}
	var ret proto.Ed25519SecretKey
	if len(keyRaw) != len(ret) {
		return nil, core.KeyImportError("wrong size")
	}
	copy(ret[:], keyRaw)

	return &ret, nil
}

func FetchOrGenerateServiceKey(m MetaContext, t proto.ServerType) (*proto.Ed25519SecretKey, error) {
	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	ret, err := fetchServiceKey(m, db, t)
	if ret != nil {
		return ret, nil
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}

	priv, err := core.NewEntityPrivateEd25519(proto.EntityType_Device)
	if err != nil {
		return nil, err
	}
	seed := priv.PrivateSeed()
	pub, err := priv.EntityPublic()
	if err != nil {
		return nil, err
	}
	devid := pub.GetEntityID()

	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO service_keys(key_id, service_id, secret_key, key_state, ctime, mtime)
		VALUES($1, $2, $3, 'valid', NOW(), NOW())`,
		devid.ExportToDB(),
		t.ServiceID().ExportToDB(),
		seed.ExportToDB(),
	)

	if err != nil {
		return nil, err
	}

	if tag.RowsAffected() != 1 {
		return nil, core.InsertError("failed to insert service key")
	}

	return &seed, nil
}
