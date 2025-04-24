// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package admin

import (
	"net/http"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/foks-proj/go-foks/server/web/templates"
)

func handleVHostCheckError(
	w http.ResponseWriter,
	r *http.Request,
	ve lib.VHostCheckError,
) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Add("HX-Retarget", "#vhost-check-error")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = templates.VHostCheckError(ve).Render(r.Context(), w)

}

func handleVHostSetupError(
	w http.ResponseWriter,
	r *http.Request,
	ve lib.VHostSetupError,
) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Add("HX-Retarget", "#vhost-setup-error")
	w.Header().Add("HX-Reswap", "outerHTML")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = templates.VHostSetupError(ve).Render(r.Context(), w)
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
	case core.HttpError:
		if te.Code == 401 {
			code = int(te.Code)
			desc = "Unauthorized: " + te.Desc
		} else if te.Desc == "" {
			desc = te.Err.Error()
		} else {
			desc = te.Desc + ": " + te.Err.Error()
		}
	case lib.VHostCheckError:
		handleVHostCheckError(w, r, te)
		return
	case lib.VHostSetupError:
		handleVHostSetupError(w, r, te)
		return
	default:
		desc = "Internal error: " + err.Error()
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Add("HX-Reswap", "none")
	w.WriteHeader(code)

	_ = templates.ErrorToast(desc).Render(r.Context(), w)
}
