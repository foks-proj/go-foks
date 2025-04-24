// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

type HmacKeyType string

const (
	HmacKeyTypeLogin             HmacKeyType = "login"
	HmacKeyTypeLookup            HmacKeyType = "user_lookup"
	HmacKeyTypeSubkeyBox         HmacKeyType = "subkey_box"
	HmacKeyTypeTeamVOBearerToken HmacKeyType = "team_vo_bearer_token"
	HmacKeyCSRFProtect           HmacKeyType = "csrf_protect"
)

func GenerateNewChallengeHMACKeys(m MetaContext) error {
	allTypes := []HmacKeyType{
		HmacKeyTypeLogin,
		HmacKeyTypeLookup,
		HmacKeyTypeSubkeyBox,
		HmacKeyTypeTeamVOBearerToken,
		HmacKeyCSRFProtect,
	}
	return GenerateSomeNewChallengeHMACKeys(m, allTypes)
}

func GenerateSomeNewChallengeHMACKeys(m MetaContext, which []HmacKeyType) error {
	for _, i := range which {
		err := generateNewChallengeHMACKey(m, i)
		if err != nil {
			return err
		}
	}
	return nil

}

func generateNewChallengeHMACKey(m MetaContext, typ HmacKeyType) error {
	db, err := m.G().Db(m.Ctx(), DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	var keyID proto.HMACKeyID
	var key proto.HMACKey
	err = core.RandomFill(key[:])
	if err != nil {
		return err
	}
	err = core.RandomFill(keyID[:])
	if err != nil {
		return err
	}
	hostID := m.ShortHostID()
	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO challenge_keys(short_host_id, key_id, key_secret, typ, ctime)
		 VALUES($1,$2,$3,$4,NOW())`,
		int(hostID), keyID[:], key[:], typ,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("login challenge")
	}
	return nil
}

func LookupLatestChallengeKey(
	m MetaContext,
	typ HmacKeyType,
) (
	*proto.HMACKeyID,
	*proto.HMACKey,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, nil, err
	}
	defer db.Release()
	var rawId, rawKey []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT key_id, key_secret
		 FROM challenge_keys
		 WHERE short_host_id=$1 AND typ=$2
		 ORDER BY ctime DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		string(typ),
	).Scan(&rawId, &rawKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, core.BadServerDataError("can't find HMAC key")
	}
	if err != nil {
		return nil, nil, err
	}

	var id proto.HMACKeyID
	err = id.ImportFromDB(rawId)
	if err != nil {
		return nil, nil, err
	}
	var key proto.HMACKey
	err = key.ImportFromDB(rawKey)
	if err != nil {
		return nil, nil, err
	}
	return &id, &key, nil
}

func LookupHMACKeyByID(
	m MetaContext,
	rq Querier,
	id proto.HMACKeyID,
	typ HmacKeyType,
) (
	*proto.HMACKey,
	error,
) {
	var rawKey []byte
	err := rq.QueryRow(m.Ctx(),
		`SELECT key_secret 
		 FROM challenge_keys 
		 WHERE short_host_id=$1 AND key_id=$2 AND typ=$3`,
		m.ShortHostID().ExportToDB(),
		id.ExportToDB(),
		string(typ),
	).Scan(&rawKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.KeyNotFoundError{Which: "hmac"}
	}
	if err != nil {
		return nil, err
	}
	var key proto.HMACKey
	err = key.ImportFromDB(rawKey)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func MarkChallengeUsed(
	m MetaContext,
	db DbExecer,
	b []byte,
) error {
	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO used_random_challenges(short_host_id, challenge) VALUES($1,$2)`,
		m.ShortHostID().ExportToDB(),
		b,
	)
	if err != nil {
		return core.ReplayError{}
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("replay")
	}
	return nil

}
