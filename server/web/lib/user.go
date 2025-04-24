// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"errors"
	"net/http"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

type User struct {
	Uid         proto.UID
	Name        proto.NameUtf8
	Host        *Host
	CSRFToken   CSRFToken
	AdminOfHost *core.HostID
}

func (u *User) ToUHC() shared.UserHostContext {
	return shared.UserHostContext{
		HostID: &u.Host.HostID,
		Uid:    u.Uid,
	}
}

func LoadUserBySession(
	m shared.MetaContext,
	sess rem.WebSession,
) (
	*User,
	error,
) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var uidRaw []byte
	var nameRaw string
	var shidRaw int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT short_host_id, uid, name_utf8
     	 FROM user_web_sessions 
	     JOIN users USING(short_host_id, uid)
	     JOIN names USING(short_host_id, name_ascii)
	     WHERE session_id = $1 AND etime > NOW() AND active=true AND state='in_use'`,
		sess.ExportToDB(),
	).Scan(&shidRaw, &uidRaw, &nameRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.WebSessionNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	var uid proto.UID
	err = uid.ImportFromDB(uidRaw)
	if err != nil {
		return nil, err
	}
	shid := core.ShortHostID(shidRaw)
	host, err := LoadHostByShortID(m, shid)
	if err != nil {
		return nil, err
	}
	ret := &User{
		Uid:  uid,
		Name: proto.NameUtf8(nameRaw),
		Host: host,
	}
	return ret, nil
}

func LoadUserFromCookie(
	m shared.MetaContext,
	r *http.Request,
) (
	*User,
	error,
) {
	ws, err := GetSessionCookie(m, r)
	if err != nil {
		return nil, err
	}
	user, err := LoadUserBySession(m, *ws)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *User) Email(m shared.MetaContext) (proto.Email, error) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return "", err
	}
	defer db.Release()
	var email string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT email
		 FROM emails
		 WHERE short_host_id=$1 AND uid=$2`,
		u.Host.Short.ExportToDB(),
		u.Uid.ExportToDB(),
	).Scan(&email)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.NotFoundError("email")
	}
	if err != nil {
		return "", err
	}
	return proto.Email(email), nil
}

func (u *User) StripeCustomerID(m shared.MetaContext) (infra.StripeCustomerID, error) {
	return shared.LoadCustomerID(m, u.Uid)
}

func (u *User) LoadOrCreateCustomerID(m shared.MetaContext) (infra.StripeCustomerID, error) {
	id, err := u.StripeCustomerID(m)
	if err == nil {
		return id, nil
	}
	if _, ok := err.(core.UserNotFoundError); !ok {
		return "", err
	}
	em, err := u.Email(m)
	if err != nil {
		return "", err
	}
	cid, err := m.Stripe().CreateCustomer(m, u.Uid, em)
	if err != nil {
		return "", err
	}

	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return "", err
	}
	defer db.Release()
	tag, err := db.Exec(
		m.Ctx(),
		`INSERT INTO stripe_users
 		 (short_host_id, uid, cancel_id, customer_id, ctime)
		 VALUES ($1, $2, $3, $4, NOW())`,
		m.ShortHostID().ExportToDB(),
		u.Uid.ExportToDB(),
		proto.NilCancelID(),
		cid.String(),
	)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", core.InsertError("stripe user")
	}
	return cid, nil
}

func (u *User) CheckIsAdminOf(m shared.MetaContext, hid proto.HostID) (*core.HostID, error) {
	chid, err := m.G().HostIDMap().LookupByHostID(m, hid)
	if err != nil {
		return nil, err
	}
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var one int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT 1 FROM vhost_admins WHERE short_host_id=$1 AND uid=$2 AND vhost_id=$3`,
		m.ShortHostID().ExportToDB(),
		u.Uid.ExportToDB(),
		chid.VId.ExportToDB(),
	).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.PermissionError("not admin")
	}
	if err != nil {
		return nil, err
	}
	return chid, nil
}
