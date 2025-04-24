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

func LoadSSOConfig(
	m MetaContext,
	cfgId *proto.SSOConfigID,
) (
	*proto.SSOConfig,
	error,
) {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var ret proto.SSOConfig
	var a string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT active
		 FROM sso_config
		 WHERE short_host_id=$1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var active proto.SSOProtocolType
	err = active.ImportFromDB(a)
	if err != nil {
		return nil, err
	}
	ret.Active = active
	switch active {
	case proto.SSOProtocolType_Oauth2:
		o2, err := loadOAuth2Config(m, db, cfgId)
		if err != nil {
			return nil, err
		}
		ret.Oauth2 = o2
	case proto.SSOProtocolType_None:
		return nil, nil
	default:
		return nil, core.VersionNotSupportedError("SSO protocol")
	}
	return &ret, nil
}

func SetVHostSSOConfig(
	m MetaContext,
	sso *proto.SSOConfig,
) error {
	return RetryTxServerConfigDB(m, "SetVHostSSOConfig", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO sso_config 
		   (short_host_id, active, ctime, mtime)
		 VALUES ($1, $2, NOW(), NOW())
		 ON CONFLICT (short_host_id) DO UPDATE
		 SET active=$2, mtime=NOW()`,
			m.ShortHostID().ExportToDB(),
			sso.Active.String(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("sso_config")
		}
		if sso.Oauth2 != nil {
			err = setOAuth2Config(m, tx, *sso.Oauth2)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func SignupHandleSSO(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	key proto.EntityID,
	arg rem.RegSSOArgs,
	un proto.NameUtf8,
	em proto.Email,
) error {
	return signupHandleOAuth2(m, tx, uid, key, arg, un, em)
}

func AuthSSO(
	m MetaContext,
	typ proto.SSOProtocolType,
	uhc UserHostContext,
) error {
	switch typ {
	case proto.SSOProtocolType_Oauth2:
		return authOAuth2(m, uhc)
	case proto.SSOProtocolType_None:
		return nil
	default:
		return core.VersionNotSupportedError("SSO protocol")
	}
}

func LoginSSO(
	m MetaContext,
	uid proto.UID,
	arg rem.RegSSOArgs,
) error {
	typ, err := arg.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case proto.SSOProtocolType_Oauth2:
		return oauth2Login(m, uid, arg)
	default:
		return core.VersionNotSupportedError("SSO protocol")
	}
}
