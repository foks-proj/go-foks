// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package admin

import (
	"net/http"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/foks-proj/go-foks/server/web/templates"
)

func PlansTopHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{CSRFSend: true},
			lib.DataLoadOpts{
				Usage:    true,
				Headers:  true,
				Plans:    true,
				Sess:     true,
				UserPlan: true,
				VHosts:   true,
				Which: lib.PageSelector{
					PageType: lib.PageTypePlans,
				},
			},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				return renderTop(m, pd, w)
			},
		)
	}
}

type PlanOp int

const (
	PlanOpManage    PlanOp = 1
	PlanOpSubscribe PlanOp = 2
	PlanOpUpgrade   PlanOp = 3
	PlanOpDowngrade PlanOp = 4
)

func servePlans(
	m shared.MetaContext,
	w http.ResponseWriter,
	r *http.Request,
	d *lib.AdminPageData,
) error {
	return templates.Plans(d).Render(m.Ctx(), w)
}

func PlansMainPanelHandler(
	g *shared.GlobalContext,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{},
			lib.DataLoadOpts{Usage: true, Plans: true, Sess: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				return servePlans(m, w, r, pd)
			},
		)
	}
}

func PlanManageHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{},
			lib.DataLoadOpts{Usage: true, Plans: true, DefInvoices: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				return templates.ManagePlan(pd).Render(m.Ctx(), w)
			},
		)
	}
}

func PlanChangeHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{CSRFCheck: true},
			lib.DataLoadOpts{Usage: true, Plans: true, DefInvoices: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				args := lib.NewArgs(r)
				action, err := args.ActionType(lib.ParamSourceForm, "action")
				if err != nil {
					return err
				}

				// Early out if we clicked cancel.
				if action != lib.ActionTypeApprove {
					return templates.ManagePlanSwapUsagePill(pd).Render(m.Ctx(), w)
				}

				subId, err := args.StripeSubscriptionID(lib.ParamSourceForm, "subscription_id")
				if err != nil {
					return err
				}
				priceId, err := args.PriceID(lib.ParamSourceForm, "price_id")
				if err != nil {
					return err
				}
				planId, err := args.PlanID(lib.ParamSourceForm, "plan_id")
				if err != nil {
					return err
				}
				time, err := args.Time(lib.ParamSourceForm, "time")
				if err != nil {
					return err
				}
				newPlanPrice, err := shared.LookupPlanPriceInfo(m, *planId, *priceId)
				if err != nil {
					return err
				}
				up := pd.UserPlan
				if up == nil {
					return core.NewHttp422Error(nil, "user plan not found")
				}
				currPlanPrice, err := shared.LookupPlanPriceInfo(m, up.Plan.Id, up.Price)
				if err != nil {
					return err
				}
				arg := shared.PreviewProrationArg{
					Time:     *time,
					SubID:    subId,
					NewPlan:  newPlanPrice.ToSubscription(),
					CurrPlan: currPlanPrice.ToSubscription(),
				}
				cbpa := shared.ChangeBillingPlanArg{
					PreviewProrationArg: arg,
					NewPlanID:           *planId,
					NewPriceID:          *priceId,
				}

				doDebugDelay(m)

				err = shared.ChangeBillingPlan(m, cbpa)
				if err != nil {
					return err
				}

				// Need to reload this to reflect the upgrade/downgrade.
				err = pd.LoadUsageData(m)
				if err != nil {
					return err
				}

				return templates.ManagePlanSwapUsagePill(pd).Render(m.Ctx(), w)
			},
		)
	}
}

func PlanEditHandler(g *shared.GlobalContext, op shared.PlanEditOp) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{CSRFCheck: true},
			lib.DataLoadOpts{Usage: true, Plans: true, DefInvoices: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				args := lib.NewArgs(r)
				subId, err := args.StripeSubscriptionID(lib.ParamSourceForm, "subscription_id")
				if err != nil {
					return err
				}
				planId, err := args.PlanID(lib.ParamSourceForm, "plan_id")
				if err != nil {
					return err
				}

				doDebugDelay(m)

				err = shared.EditStripeSubscription(m, pd.User.Uid, *planId, subId, op)
				if err != nil {
					return err
				}

				// We need to reload most of the page anyway in this case, so
				// easiest just to redirect to the main page.
				if op == shared.PlanEditOpRageQuit {
					w.Header().Set("HX-Redirect", (AdminHandler{}).URL())
					w.WriteHeader(http.StatusOK)
					return nil
				}

				// Need to reload this to reflect the cancelation.
				err = pd.LoadUsageData(m)
				if err != nil {
					return err
				}
				return templates.ManagePlan(pd).Render(m.Ctx(), w)
			},
		)
	}
}

func InvoicesHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{},
			lib.DataLoadOpts{Usage: true, Plans: true, DefInvoices: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				return templates.Invoices(pd).Render(m.Ctx(), w)
			},
		)
	}
}

func PlanSubscribeHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeLoggedIn(w, r,
			ServeOpts{CSRFCheck: true},
			func(m shared.MetaContext, u *lib.User) error {
				args := lib.NewArgs(r)
				planId, err := args.PlanID(lib.ParamSourceURL, "planId")
				if err != nil {
					return err
				}
				priceId, err := args.PriceID(lib.ParamSourceForm, "price")
				if err != nil {
					return err
				}
				base, err := shared.AdminBaseURL(m)
				if err != nil {
					return err
				}
				cfg, err := m.G().Config().StripeConfig(m.Ctx())
				if err != nil {
					return err
				}
				ppi, err := shared.LookupPlanPriceInfo(m, *planId, *priceId)
				if err != nil {
					return core.NewHttp422Error(err, "stripe object ids")
				}
				sffx := proto.URLString("?session_id={CHECKOUT_SESSION_ID}")
				succ := base.PathJoin(cfg.Callbacks().Success()) + sffx
				canc := base.PathJoin(cfg.Callbacks().Cancel()) + sffx

				cid, err := u.LoadOrCreateCustomerID(m)
				if err != nil {
					return err
				}
				dur := cfg.SessionDuration()
				expire := time.Now().Add(dur)

				m.Infow("PlanSubscribeHandler", "succ", succ, "canc", canc, "dur", dur, "expire", expire)

				sessId, url, err := m.Stripe().CheckoutSession(m, shared.CheckoutArg{
					CustomerID: cid,
					PriceID:    ppi.StripeIDs.Price,
					Expire:     expire,
					SuccessURL: succ,
					CancelURL:  canc,
				})
				if err != nil {
					return err
				}

				err = shared.InsertStripeSession(m, u.Uid, sessId, *planId, *priceId, dur)
				if _, ok := err.(core.StripeSessionExistsError); ok {
					return core.NewHttp422Error(err, "subscribe")
				}
				if err != nil {
					return err
				}

				w.Header().Set("HX-Redirect", url.String())
				w.Header().Set("X-Stripe-Checkout-Session", string(sessId))
				w.WriteHeader(http.StatusOK)
				return nil
			},
		)
	}
}

func PlanPreviewProrateHandler(g *shared.GlobalContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithDataLoad(w, r,
			ServeOpts{CSRFCheck: true},
			lib.DataLoadOpts{Usage: true, Plans: true, UserPlan: true},
			func(m shared.MetaContext, pd *lib.AdminPageData) error {
				u := pd.User
				args := lib.NewArgs(r)
				planId, err := args.PlanID(lib.ParamSourceURL, "planId")
				if err != nil {
					return err
				}
				priceId, err := args.PriceID(lib.ParamSourceForm, "price")
				if err != nil {
					return err
				}
				cid, err := u.LoadOrCreateCustomerID(m)
				if err != nil {
					return err
				}
				up := pd.UserPlan
				if up == nil {
					return core.NewHttp422Error(nil, "user plan not found")
				}
				currPPI, err := shared.LookupPlanPriceInfo(m, up.Plan.Id, up.Price)
				if err != nil {
					return err
				}
				newPPI, err := shared.LookupPlanPriceInfo(m, *planId, *priceId)
				if err != nil {
					return err
				}
				arg := shared.ChangeBillingPlanArg{
					PreviewProrationArg: shared.PreviewProrationArg{
						CustomerID: cid,
						SubID:      up.SubscriptionId,
						CurrPlan:   currPPI.ToSubscription(),
						NewPlan:    newPPI.ToSubscription(),
					},
					NewPlanID:  *planId,
					NewPriceID: *priceId,
				}
				prorationData, err := m.Stripe().PreviewProration(m, arg.PreviewProrationArg)
				if err != nil {
					return err
				}
				ppd := shared.ProrationPreviewData{
					Arg:  arg,
					Data: *prorationData,
				}
				return templates.PreviewProration(pd, &ppd).Render(m.Ctx(), w)
			},
		)
	}
}
