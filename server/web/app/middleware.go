// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package app

import (
	"fmt"
	"net/http"

	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/go-chi/chi/v5"
)

func TextHTMLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

func CSPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		np, err := lib.NewNoncePackage()
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("default-src 'self'; "+
				"connect-src 'self' https://checkout.stripe.com https://api.stripe.com; "+
				"style-src-elem 'nonce-%s'; script-src 'nonce-%s';",
				np.StyleSrcElem,
				np.ScriptSrc,
			))
		ctx := np.AddToCtx(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func StandardMiddleware(mux chi.Router) {
	mux.Use(
		TextHTMLMiddleware,
		CSPMiddleware,
	)
}
