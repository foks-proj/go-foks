// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"errors"
	"net/http"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
)

var sessionCookieName = "sess"

func SetSessionCookie(
	m shared.MetaContext,
	w http.ResponseWriter,
	ws rem.WebSession,
) error {
	cook := http.Cookie{
		Name:     sessionCookieName,
		Value:    string(ws.EncodeToString()),
		Expires:  time.Now().Add(time.Duration(7*24) * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return err
	}
	if wcfg.UseTLS() {
		cook.Secure = true
	}
	http.SetCookie(w, &cook)
	return nil
}

func GetSessionCookie(
	m shared.MetaContext,
	r *http.Request,
) (
	*rem.WebSession,
	error,
) {
	cook, err := r.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, core.NoActiveUserError{}
	}
	if err != nil {
		return nil, err
	}
	val := rem.WebSessionString(cook.Value)

	ret, err := val.Parse()
	if err != nil {
		return nil, err
	}
	return ret, nil
}
