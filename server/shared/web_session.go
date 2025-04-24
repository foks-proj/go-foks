// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func NewWebSession(
	m MetaContext,
) (
	*rem.WebSession,
	error,
) {
	var ret rem.WebSession
	err := core.RandomFill(ret[:])
	if err != nil {
		return nil, err
	}

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	wsd := wcfg.SessionDuration()

	_, err = db.Exec(
		m.Ctx(),
		`INSERT INTO user_web_sessions
		   (short_host_id, uid, session_id, ctime, etime, active)
		   VALUES($1, $2, $3, NOW(), NOW() + $4, true)`,
		int(m.ShortHostID()),
		m.UID().ExportToDB(),
		ret.ExportToDB(),
		wsd,
	)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func CheckWebSession(
	m MetaContext,
	sess rem.WebSession,
) (*proto.UID, error) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var uidRaw []byte
	err = db.QueryRow(
		m.Ctx(),
		`SELECT uid FROM user_web_sessions
		 WHERE short_host_id = $1 AND session_id = $2
		 AND etime > NOW() AND active = true`,
		int(m.ShortHostID()),
		sess.ExportToDB(),
	).Scan(&uidRaw)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.WebSessionNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	var ret proto.UID
	err = ret.ImportFromDB(uidRaw)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func EncodedWebSessionV1(
	s rem.WebSession,
) string {
	ret := core.B62Encode(s[:])
	return ret
}

func adminBaseURL(m MetaContext, wcfg WebConfigger) (proto.URLString, error) {
	isTls := wcfg.UseTLS()

	// This external port might differ from the port that the web server is listening
	// on, in the presence of a load balancer or reverse proxy. But we need to include the
	// external port in URLs that we ship to the clients.
	port := wcfg.GetExternalPort()

	// In the case of running integration or client tests, we ignore the port in the WebConfigger
	// and use the port that the test server is listening on.
	testPort := m.G().GetTestPort(proto.ServerType_Web)

	var finalPort int
	switch {
	case testPort > 0:
		finalPort = testPort
	case port > 0 && isTls && port != 443:
		finalPort = int(port)
	case port > 0 && !isTls && port != 80:
		finalPort = int(port)
	}

	hn, err := m.G().HostIDMap().Hostname(m, m.ShortHostID())
	if err != nil {
		return "", err
	}
	ret := fmt.Sprintf("%s://%s", core.Sel(isTls, "https", "http"), hn)
	if finalPort != 0 {
		ret = fmt.Sprintf("%s:%d", ret, finalPort)
	}
	return proto.URLString(ret), nil
}

func AdminBaseURL(m MetaContext) (proto.URLString, error) {
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return "", err
	}
	return adminBaseURL(m, wcfg)
}

func OAuth2CallbackURL(m MetaContext) (proto.URLString, error) {
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return "", err
	}
	base, err := adminBaseURL(m, wcfg)
	if err != nil {
		return "", err
	}
	path := wcfg.OAuth2().Callback()
	ret := base.PathJoin(path)
	return ret, nil
}

func WebAdminPanelURL(
	m MetaContext,
	uid proto.UID,
	sess rem.WebSession,
) (
	*proto.URLString,
	error,
) {
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return nil, err
	}

	baseURL, err := adminBaseURL(m, wcfg)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add(wcfg.SessionParam(), EncodedWebSessionV1(sess))
	finalURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	ret := proto.URLString(finalURL)
	return &ret, nil
}

func NewWebAdminPanelURL(
	m MetaContext,
) (
	*proto.URLString,
	error,
) {
	uid := m.UID()
	sess, err := NewWebSession(m)
	if err != nil {
		return nil, err
	}
	return WebAdminPanelURL(m, uid, *sess)
}

func CheckURL(
	m MetaContext,
	inp proto.URLString,
) error {
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return err
	}
	u, err := url.Parse(string(inp))
	if err != nil {
		return err
	}
	val := u.Query().Get(wcfg.SessionParam())
	if val == "" {
		return core.NotFoundError("session parameter not found")
	}
	raw, err := core.B62Decode(val)
	if err != nil {
		return err
	}
	var sess rem.WebSession
	err = sess.ImportFromBytes(raw)
	if err != nil {
		return err
	}
	uid, err := CheckWebSession(m, sess)
	if err != nil {
		return err
	}
	if !m.UID().Eq(*uid) {
		return core.WrongUserError{}
	}
	return nil
}
