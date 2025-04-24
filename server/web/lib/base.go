// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"net/http"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
)

type ErrHandler func(w http.ResponseWriter, r *http.Request, err error)

type BaseHandler struct {
	g    *shared.GlobalContext
	errH ErrHandler
}

type RedirectError struct {
	Msg  string
	Code int
	Url  string
}

func (r RedirectError) Error() string {
	return "redirected (" + r.Msg + ")"
}

func (b *BaseHandler) Serve(
	w http.ResponseWriter,
	r *http.Request,
	h func(m shared.MetaContext) error,
) {
	m := shared.NewMetaContext(r.Context(), b.g)
	err := h(m)
	switch terr := err.(type) {
	case RedirectError:
		code := terr.Code
		if code == 0 {
			code = http.StatusFound
		}
		http.Redirect(w, r, terr.Url, code)
	case nil:
	default:
		b.errH(w, r, err)
	}
}

func (b *BaseHandler) ServeWithVHost(
	w http.ResponseWriter,
	r *http.Request,
	h func(m shared.MetaContext) error,
) {
	b.Serve(w, r, func(m shared.MetaContext) error {
		// r.Host can sometimes come with a port, so strip that off
		// before looking up the host ID.
		addr := proto.TCPAddr(r.Host)
		hn := addr.Hostname().Normalize()
		hid, err := m.G().HostIDMap().LookupByHostname(m, hn)
		if err != nil {
			return err
		}
		m = m.WithHostID(hid)
		return h(m)
	})
}

func NewBaseHandler(g *shared.GlobalContext) *BaseHandler {
	return NewBaseHandlerWithErr(g, HandleErr)
}

func NewBaseHandlerWithErr(g *shared.GlobalContext, eh ErrHandler) *BaseHandler {
	return &BaseHandler{g: g, errH: eh}
}

func HandleErr(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	var desc string
	code := http.StatusUnprocessableEntity
	switch te := err.(type) {
	case core.OverQuotaError:
		desc = "over quota"
	case core.NotFoundError:
		code = 404
		desc = te.Error()
	case core.HttpError:
		if te.Code == 401 {
			code = int(te.Code)
			desc = "Unauthorized: " + te.Desc
		} else if te.Desc == "" {
			desc = te.Err.Error()
		} else {
			desc = te.Desc + ": " + te.Err.Error()
		}
	default:
		desc = "Internal error: " + err.Error()
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)

	_, _ = w.Write([]byte(desc))
}
