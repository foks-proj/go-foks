// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package app

import (
	"net/http"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/app/admin"
	"github.com/foks-proj/go-foks/server/web/app/oauth2"
	"github.com/go-chi/chi/v5"
)

type WebServer struct {
	shared.BaseWebServer
	testVanityHelper bool
}

var _ shared.WebServer = (*WebServer)(nil)

func (a *WebServer) ToWebServer() shared.WebServer { return a }
func (a *WebServer) ServerType() proto.ServerType  { return proto.ServerType_Web }

func (a *WebServer) InitRouter(m shared.MetaContext, mux *chi.Mux) error {

	fs := http.FileServerFS(GetStaticFS())
	mux.Handle("/static/*", setStaticContentType(http.StripPrefix("/static/", fs)))
	scfg, err := m.G().Config().StripeConfig(m.Ctx())
	if err != nil {
		return err
	}
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return err
	}
	ocfg := wcfg.OAuth2()

	mux.Group(func(mux chi.Router) {
		StandardMiddleware(mux)
		mux.Get("/", admin.NewIndexHandler(m.G()).ServeHTTP)
		mux.Get(ocfg.Tiny().String()+"/{id}", oauth2.TinyHandler(m.G()))
		mux.Get(ocfg.Callback().String(), oauth2.CallbackHandler(m.G()))
		admin.InitRouter(m.G(), "/admin", scfg, mux)
	})
	return nil
}

func NewWebServer() *WebServer {
	return &WebServer{}
}

func (a *WebServer) WithTest() *WebServer {
	a.testVanityHelper = true
	return a
}

func (a *WebServer) configVanityHelper(m shared.MetaContext) error {
	if a.testVanityHelper {
		return nil
	}
	vh, err := shared.ConfigNewRealVanityHelper(m)
	if err != nil {
		return err
	}
	m.G().SetVanityHelper(vh)
	return nil
}

func (a *WebServer) Setup(m shared.MetaContext) error {
	err := a.configVanityHelper(m)
	if err != nil {
		return err
	}
	return nil
}
