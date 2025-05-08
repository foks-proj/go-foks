// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package admin

import (
	"io"
	"net/http"

	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/stripe/stripe-go/v82/webhook"
)

func StripeSuccessHandler(
	g *shared.GlobalContext,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeLoggedIn(w, r, ServeOpts{},
			func(m shared.MetaContext, u *lib.User) error {
				sid, err := lib.NewArgs(r).StripeSessionID(lib.ParamSourceQuery, "session_id")
				if err != nil {
					return err
				}
				err = shared.RecordStripeSubscribeSuccess(m, u.Uid, sid)
				if err != nil {
					return err
				}

				// Redirect to clear out the GET url with the session id;
				// might cause an annoying flicker, but I think it's
				// still 10 fewer redirects than SSO.
				return AdminHandler{}.RedirectTo()
			},
		)
	}
}

func StripeCancelHandler(
	g *shared.GlobalContext,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeLoggedIn(w, r, ServeOpts{},
			func(m shared.MetaContext, u *lib.User) error {
				id, err := lib.NewArgs(r).StripeSessionID(lib.ParamSourceQuery, "session_id")
				if err != nil {
					return err
				}
				err = shared.CancelStripeSession(m, u.Uid, id)
				if err != nil {
					return err
				}

				// As above, we want to clear out the GET url with the session id,
				// so we redirect to the plans page.
				return lib.RedirectError{Url: "/plans"}
			},
		)
	}
}

func StripeWebhookHandler(
	g *shared.GlobalContext,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).Serve(w, r,
			func(m shared.MetaContext) error {
				strpcfg, err := m.G().Config().StripeConfig(m.Ctx())
				if err != nil {
					return err
				}
				whsec := strpcfg.WebhookSecret()
				b, err := io.ReadAll(r.Body)
				if err != nil {
					return err
				}
				event, err := webhook.ConstructEvent(b, r.Header.Get("Stripe-Signature"), string(whsec))
				if err != nil {
					m.Warnw("StripeWebhookHandler", "stage", "constructEvent", "err", err)
					return err
				}
				err = shared.StripeHandleWebhookEvent(m, event)
				if err != nil {
					return err
				}
				return nil
			},
		)
	}
}

func StripeDeleteSessionHandler(
	g *shared.GlobalContext,
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeLoggedIn(w, r, ServeOpts{},
			func(m shared.MetaContext, u *lib.User) error {
				id, err := lib.NewArgs(r).StripeSessionID(lib.ParamSourceURL, "sessionId")
				if err != nil {
					return err
				}
				err = shared.CancelStripeSession(m, u.Uid, id)
				if err != nil {
					return err
				}
				d, err := lib.LoadAdminPageData(m, u, lib.DataLoadOpts{Usage: true, Plans: true, Sess: true})
				if err != nil {
					return err
				}
				return servePlans(m, w, r, d)
			},
		)
	}
}
