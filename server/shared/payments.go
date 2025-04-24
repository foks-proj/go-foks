// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/stripe/stripe-go/v81"
)

func LookupUserByStripeCustomerID(
	m MetaContext,
	rq Querier,
	cid infra.StripeCustomerID,
) (
	core.ShortHostID,
	*proto.UID,
	error,
) {
	var uid proto.UID
	var uidRaw []byte
	var shid int
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT short_host_id, uid
		 FROM stripe_users
		 WHERE customer_id=$1 AND cancel_id=$2`,
		cid.String(),
		proto.NilCancelID(),
	).Scan(&shid, &uidRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, core.UserNotFoundError{}
	}
	if err != nil {
		return 0, nil, err
	}
	err = uid.ImportFromDB(uidRaw)
	if err != nil {
		return 0, nil, err
	}
	return core.ShortHostID(shid), &uid, nil
}

func InsertStripeSession(
	m MetaContext,
	uid proto.UID,
	sessId infra.StripeSessionID,
	planID proto.PlanID,
	priceID proto.PriceID,
	duration time.Duration,
) error {
	return RetryTxUserDB(m, "InsertStripeSession", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO stripe_sessions
			 (short_host_id, uid, cancel_id, session_id, plan_id, price_id, ctime, etime)
			 VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + $7::interval)`,
			m.ShortHostID().ExportToDB(),
			uid.ExportToDB(),
			proto.NilCancelID(),
			string(sessId),
			planID.ExportToDB(),
			priceID.ExportToDB(),
			duration,
		)
		if IsDuplicateKeyError(err, "stripe_sessions_pkey") {
			return core.StripeSessionExistsError{}
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("stripe session")
		}
		return nil
	})
}

type StripeIDs struct {
	Prod  infra.StripeProdID
	Price infra.StripePriceID
}

func LookupStripeIDs(
	m MetaContext,
	planID proto.PlanID,
	priceID proto.PriceID,
) (
	*StripeIDs,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	var prod, price string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT stripe_prod_id, stripe_price_id
		 FROM quota_plan_prices
		 JOIN quota_plans USING(plan_id)
		 WHERE plan_id = $1 AND price_id = $2`,
		planID.ExportToDB(),
		priceID.ExportToDB(),
	).Scan(&prod, &price)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("stripe ids")
	}
	if err != nil {
		return nil, err
	}
	return &StripeIDs{
		Prod:  infra.StripeProdID(prod),
		Price: infra.StripePriceID(price),
	}, nil
}

func FakeStripe(prfx string) (string, error) {
	var sffx [10]byte
	err := core.RandomFill(sffx[:])
	if err != nil {
		return "", err
	}
	s := core.B62Encode(sffx[:])
	return prfx + "_FAKE" + s, nil
}

// CheckForOutstandingSessions checks if there are any outstanding sessions for the given user.
// Will return a core.StripeSessionExistsError if there are any outstanding sessions, and other
// errors if there are any issues with the database.
func CheckForOutstandingSessions(
	m MetaContext,
	uid proto.UID,
) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	var cancelID proto.CancelID
	err = core.RandomFill(cancelID[:])
	if err != nil {
		return err
	}

	tag, err := db.Exec(
		m.Ctx(),
		`UPDATE stripe_sessions
		 SET cancel_id = $1
		 WHERE short_host_id=$2 AND uid=$3 AND cancel_id=$4 AND etime < NOW()`,
		cancelID.ExportToDB(),
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		m.Infow("CheckForOutstandingSessions", "uid", uid, "cancel_id", cancelID)
	}

	var id string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT session_id
		 FROM stripe_sessions
		 WHERE short_host_id=$1 AND uid=$2 AND cancel_id=$3`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
	).Scan(&id)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err == nil {
		return core.StripeSessionExistsError{
			Id: infra.StripeSessionID(id),
		}
	}
	return err
}

func LoadPlanAndPriceByStripeIDs(
	m MetaContext,
	qr Querier,
	prodID infra.StripeProdID,
	priceID infra.StripePriceID,
) (
	*proto.PlanID,
	*proto.PriceID,
	error,
) {
	var planRaw, priceRaw []byte
	err := qr.QueryRow(
		m.Ctx(),
		`SELECT plan_id, price_id
		 FROM quota_plan_prices
		 JOIN quota_plans USING(plan_id)
		 WHERE stripe_prod_id = $1 AND stripe_price_id = $2`,
		prodID.String(),
		priceID.String(),
	).Scan(&planRaw, &priceRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, core.NotFoundError("quota plan")
	}
	if err != nil {
		return nil, nil, err
	}
	var retPlan proto.PlanID
	err = retPlan.ImportFromDB(planRaw)
	if err != nil {
		return nil, nil, err
	}
	var retPrice proto.PriceID
	err = retPrice.ImportFromDB(priceRaw)
	if err != nil {
		return nil, nil, err
	}
	return &retPlan, &retPrice, nil
}

func CancelStripeSession(
	m MetaContext,
	uid proto.UID,
	sessId infra.StripeSessionID,
) error {

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	var one int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT 1
		 FROM stripe_sessions
		 WHERE short_host_id=$1 AND uid=$2 AND session_id=$3 AND cancel_id=$4`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		sessId.String(),
		proto.NilCancelID(),
	).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) || one != 1 {
		return core.NotFoundError("stripe session")
	}
	if err != nil {
		return err
	}

	err = m.Stripe().ExpireSession(m, sessId)
	if err != nil {
		m.Warnw("CancelStripeSession", "err", err, "sessId", sessId, "action", "ignore")
	}

	err = markSessionCancelled(m, db, uid, sessId, nil)
	if err != nil {
		return err
	}

	return nil
}

func markSessionCancelled(
	m MetaContext,
	db DbExecer,
	uid proto.UID,
	sessId infra.StripeSessionID,
	subId *infra.StripeSubscriptionID,
) error {
	cancId, err := proto.NewCancelID()
	if err != nil {
		return err
	}
	query := `UPDATE stripe_sessions SET cancel_id = $1`
	args := []any{cancId.ExportToDB()}
	nxt := 2
	if subId != nil && !subId.IsZero() {
		query += `, sub_id = $2`
		args = append(args, subId.String())
		nxt = 3
	}
	query += fmt.Sprintf(" WHERE short_host_id=$%d AND uid=$%d AND session_id=$%d",
		nxt, nxt+1, nxt+2)
	args = append(args,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		sessId.String(),
	)

	tag, err := db.Exec(m.Ctx(), query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.NotFoundError("stripe session")
	}
	return nil
}

func LoadCustomerID(
	m MetaContext,
	uid proto.UID,
) (
	infra.StripeCustomerID,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return "", err
	}
	defer db.Release()
	return loadCustomerID(m, db, uid)
}

func loadCustomerID(
	m MetaContext,
	db Querier,
	uid proto.UID,
) (
	infra.StripeCustomerID,
	error,
) {
	var id string
	err := db.QueryRow(
		m.Ctx(),
		`SELECT customer_id
		 FROM stripe_users
		 WHERE short_host_id=$1 AND uid=$2 AND cancel_id=$3`,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
	).Scan(&id)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.UserNotFoundError{}
	}
	if err != nil {
		return "", err
	}
	return infra.StripeCustomerID(id), nil
}

type stripeSubscribeSuccessRecorder struct {
	uid             proto.UID
	stripeSessionId infra.StripeSessionID
	tx              pgx.Tx
	ps              *PaymentSuccess
	hostID          *core.HostID
}

func (s *stripeSubscribeSuccessRecorder) recordPayment(m MetaContext) (err error) {

	defer func() {
		err = eatStripeErr(m, "stripeSubscriptionSuccessRecorder.recordPayment", err)
	}()

	if s.ps.ChargeID.IsZero() || s.ps.InvID.IsZero() || s.ps.PriceID.IsZero() ||
		s.ps.ProdID.IsZero() || s.ps.SubID.IsZero() {
		return stripeErr(core.NotFoundError("stripe ids"))
	}

	// We'll wind up recording this payment twice on initial subscription --
	// once in the Web flow, and once via the Webhook. Just ignore the
	// duplicate.
	_, err = s.tx.Exec(
		m.Ctx(),
		`INSERT INTO stripe_payments
		 (short_host_id, uid, charge_id, invoice_id, price_id, prod_id, subscription_id, ctime)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		 ON CONFLICT DO NOTHING`,
		m.ShortHostID().ExportToDB(),
		s.uid.ExportToDB(),
		s.ps.ChargeID.String(),
		s.ps.InvID.String(),
		s.ps.PriceID.String(),
		s.ps.ProdID.String(),
		s.ps.ProdID.String(),
	)
	if err != nil {
		return err
	}
	return nil
}

func stripeErr(e error) error {
	return core.StripeWrapperError{
		Err: e,
	}
}

func eatStripeErr(m MetaContext, caller string, err error) error {
	if err == nil {
		return nil
	}
	if strerr, ok := err.(core.StripeWrapperError); ok {
		m.Warnw(caller, "err", strerr.Err, "action", "charge-ahead")
		return nil
	}
	return err
}

func (s *stripeSubscribeSuccessRecorder) extractIDs(m MetaContext) (err error) {
	defer func() {
		err = eatStripeErr(m, "stripeSubscriptionSuccessRecorder.extractIDs", err)
	}()

	ps, err := m.Stripe().LoadPaymentSuccess(m, s.stripeSessionId)
	if err != nil {
		return err
	}
	s.ps = ps

	return nil
}

func (s *stripeSubscribeSuccessRecorder) recordPlan(m MetaContext) (err error) {

	defer func() {
		err = eatStripeErr(m, "stripeSubscribeSuccessRecoder.recordPlan", err)
	}()

	if s.ps.PriceID.IsZero() || s.ps.ProdID.IsZero() || s.ps.SubID.IsZero() {
		return stripeErr(core.NotFoundError("stripe ids"))
	}

	return LoadAndUpdatePlanForUser(m, s.tx, s.uid, s.ps.ProdID, s.ps.PriceID,
		s.ps.SubID, s.ps.CurrentPeriodEnd)
}

func (s *stripeSubscribeSuccessRecorder) dbLock(m MetaContext, id string) error {
	tag, err := s.tx.Exec(
		m.Ctx(),
		`INSERT INTO stripe_locks(stripe_id, ctime) VALUES ($1, NOW())`,
		id,
	)
	if IsDuplicateKeyError(err, "stripe_locks_pkey") {
		return core.StripeSessionExistsError{}
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("stripe session lock")
	}
	return nil
}

func (s *stripeSubscribeSuccessRecorder) runTx(m MetaContext) error {

	err := s.dbLock(m, s.stripeSessionId.String())
	if err != nil {
		return err
	}
	err = s.recordPlan(m)
	if err != nil {
		return err
	}
	err = s.recordPayment(m)
	if err != nil {
		return err
	}
	err = s.insQuotaPoke(m)
	if err != nil {
		return err
	}
	err = markSessionCancelled(m, s.tx, s.uid, s.stripeSessionId, &s.ps.SubID)
	if err != nil {
		return err
	}
	return nil
}

func (s *stripeSubscribeSuccessRecorder) run(m MetaContext) error {
	err := s.extractIDs(m)
	if err != nil {
		return err
	}

	return RetryTxUserDB(m, "stripeSubscribeSuccessRecorder", func(m MetaContext, tx pgx.Tx) error {
		s.tx = tx
		return s.runTx(m)
	})
}

func RecordStripeSubscribeSuccess(
	m MetaContext,
	uid proto.UID,
	sess infra.StripeSessionID,
) error {
	return (&stripeSubscribeSuccessRecorder{uid: uid, stripeSessionId: sess}).run(m)
}

type StripeInvoices struct {
	Cus  infra.StripeCustomerID
	Data []infra.StripeInvoice
}

type StripePaginate struct {
	Limit         int
	StartingAfter *string
	EndingBefore  *string
}

func LoadStripeInvoices(
	m MetaContext,
	uid proto.UID,
	obj StripePaginate,
) (
	*StripeInvoices,
	error,
) {

	cid, err := LoadCustomerID(m, uid)
	switch {
	case errors.Is(err, core.UserNotFoundError{}):
		return nil, nil
	case err != nil:
		return nil, err
	}
	inv, err := m.Stripe().LoadInvoices(m, cid, obj)
	if err != nil {
		return nil, err
	}
	ret := StripeInvoices{
		Cus:  cid,
		Data: inv,
	}
	return &ret, nil

}

type PlanEditOp int

const (
	PlanEditOpCancel   PlanEditOp = 1
	PlanEditOpResume   PlanEditOp = 2
	PlanEditOpRageQuit PlanEditOp = 3
)

func editStripeSubscriptionTx(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	plan proto.PlanID,
	sub infra.StripeSubscriptionID,
	op PlanEditOp,
) error {

	q := "UPDATE user_plans"
	args := []any{}
	switch op {
	case PlanEditOpCancel, PlanEditOpResume:
		q += " SET pending_cancel = $1, pending_cancel_time = $2"
	case PlanEditOpRageQuit:
		q += " SET cancel_id = $1, cancel_time = $2"
	default:
		return core.InternalError("unknown plan edit op")
	}

	switch op {
	case PlanEditOpCancel:
		args = append(args, true, time.Now())
	case PlanEditOpResume:
		args = append(args, false, nil)
	case PlanEditOpRageQuit:
		cid, err := proto.NewCancelID()
		if err != nil {
			return err
		}
		args = append(args, cid.ExportToDB(), time.Now())
	default:
		return core.InternalError("unknown plan edit op")

	}
	q += " WHERE short_host_id=$3 AND uid=$4 AND plan_id=$5 AND stripe_sub_id=$6"
	args = append(args,
		m.ShortHostID().ExportToDB(),
		uid.ExportToDB(),
		plan.ExportToDB(),
		sub.String(),
	)
	tag, err := tx.Exec(
		m.Ctx(),
		q,
		args...,
	)
	if err != nil {
		return err
	}

	if tag.RowsAffected() != 1 {
		return core.NotFoundError("stripe subscription")
	}
	err = InsQuotaPoke(m, tx, []proto.PartyID{uid.ToPartyID()})
	if err != nil {
		return err
	}
	return nil
}

func EditStripeSubscription(
	m MetaContext,
	uid proto.UID,
	plan proto.PlanID,
	sub infra.StripeSubscriptionID,
	op PlanEditOp,
) error {

	switch op {
	case PlanEditOpCancel, PlanEditOpResume:
		cape := (op == PlanEditOpCancel)
		err := m.Stripe().UpdateCancelAtPeriodEnd(m, sub, cape)
		if err != nil {
			return err
		}
	case PlanEditOpRageQuit:
		err := m.Stripe().CancelSubscription(m, sub)
		if err != nil {
			return err
		}
	default:
		return core.InternalError("unknown plan edit op")
	}

	return RetryTxUserDB(m, "CancelStripeSubscription", func(m MetaContext, tx pgx.Tx) error {
		return editStripeSubscriptionTx(m, tx, uid, plan, sub, op)
	})

}

func handleInvoicePaymentSucceeded(
	m MetaContext,
	event stripe.Event,
) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return err
	}
	sss := stripeSubscribeSuccessRecorder{}
	err := sss.runInvoice(m, infra.StripeEventID(event.ID), &invoice)
	if err != nil {
		return err
	}
	return nil
}

func (r *stripeSubscribeSuccessRecorder) extractFromInvoice(
	m MetaContext,
	eventID infra.StripeEventID,
	inv *stripe.Invoice,
) error {
	var ret PaymentSuccess
	if len(inv.Customer.ID) == 0 {
		return stripeErr(core.NotFoundError("stripe invoice customer"))
	}
	ret.CustomerID = infra.StripeCustomerID(inv.Customer.ID)
	if inv.Lines == nil || len(inv.Lines.Data) == 0 || inv.Lines.Data[0] == nil {
		return stripeErr(core.NotFoundError("stripe invoice lines"))
	}
	item := inv.Lines.Data[0]
	if item.Price == nil || len(item.Price.ID) == 0 {
		return stripeErr(core.NotFoundError("stripe invoice lines price"))
	}
	if item.Plan == nil || item.Plan.Product == nil || len(item.Plan.Product.ID) == 0 {
		return stripeErr(core.NotFoundError("stripe invoice lines plan"))
	}
	if inv.Charge == nil || len(inv.Charge.ID) == 0 {
		return stripeErr(core.NotFoundError("stripe invoice charge"))
	}
	if item.Type != stripe.InvoiceLineItemTypeSubscription {
		return stripeErr(core.NotFoundError("stripe invoice subscription"))
	}
	if item.Period == nil {
		return stripeErr(core.NotFoundError("stripe invoice period"))
	}
	ret.ChargeID = infra.StripeChargeID(inv.Charge.ID)
	ret.ProdID = infra.StripeProdID(item.Plan.Product.ID)
	ret.PriceID = infra.StripePriceID(item.Price.ID)
	if item.Subscription == nil || len(item.Subscription.ID) == 0 {
		return stripeErr(core.NotFoundError("stripe invoice subscription"))
	}
	ret.SubID = infra.StripeSubscriptionID(item.Subscription.ID)
	if len(eventID) == 0 {
		return stripeErr(core.NotFoundError("stripe event id"))
	}
	ret.EventID = infra.StripeEventID(eventID)
	ret.CurrentPeriodEnd = time.Unix(int64(item.Period.End), 0)
	ret.InvID = infra.StripeInvoiceID(inv.ID)
	r.ps = &ret
	return nil
}

func (r *stripeSubscribeSuccessRecorder) runInvoice(
	m MetaContext,
	eventID infra.StripeEventID,
	inv *stripe.Invoice,
) error {
	err := r.extractFromInvoice(m, eventID, inv)
	if err != nil {
		return err
	}
	return RetryTxUserDB(m, "stripeSubscribeSuccessRecorder", func(m MetaContext, tx pgx.Tx) error {
		r.tx = tx
		return r.runInvoiceTx(m)
	})
}

func (r *stripeSubscribeSuccessRecorder) lookupUser(m MetaContext) error {
	shid, uid, err := LookupUserByStripeCustomerID(m, r.tx, r.ps.CustomerID)
	if err != nil {
		return err
	}
	r.uid = *uid
	chid, err := m.G().HostIDMap().LookupByShortID(m, shid)
	if err != nil {
		return err
	}
	r.hostID = chid
	return nil
}

func (r *stripeSubscribeSuccessRecorder) insQuotaPoke(m MetaContext) error {
	return InsQuotaPoke(m, r.tx, []proto.PartyID{r.uid.ToPartyID()})
}

func (r *stripeSubscribeSuccessRecorder) runInvoiceTx(
	m MetaContext,
) error {

	err := r.dbLock(m, r.ps.EventID.String())
	if err != nil {
		return err
	}
	err = r.lookupUser(m)
	if err != nil {
		return err
	}
	if r.hostID == nil {
		return core.InternalError("no host id set, but needed one")
	}

	// After we've done the user lookup, we know the right virtual host to work on.
	m = m.WithHostID(r.hostID)

	err = r.recordPayment(m)
	if err != nil {
		return err
	}
	err = r.recordPlan(m)
	if err != nil {
		return err
	}
	err = r.insQuotaPoke(m)
	if err != nil {
		return err
	}
	return nil
}

func ResurrectPlan(
	m MetaContext,
	db Querier,
	uid proto.UID,
	subID infra.StripeSubscriptionID,
) (bool, error) {
	striper := m.Stripe()
	sub, err := striper.LoadSubscription(m, subID)
	if err != nil {
		return false, err
	}
	now := m.Now()
	if !sub.CurrentPeriodEnd.After(now) {
		m.Infow("ResurrectPlan", "uid", uid, "sub_id", subID, "outcome", "noop-expired",
			"cpe", sub.CurrentPeriodEnd, "now", now)
		return false, nil
	}
	err = RetryTxUserDB(m, "ResurrectPlan", func(m MetaContext, tx pgx.Tx) error {
		return LoadAndUpdatePlanForUser(m, tx, uid, sub.ProdID, sub.PriceID, subID, sub.CurrentPeriodEnd)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func LoadAndUpdatePlanForUser(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	plan infra.StripeProdID,
	price infra.StripePriceID,
	sub infra.StripeSubscriptionID,
	currentPeriodEnd time.Time,
) error {
	planId, priceId, err := LoadPlanAndPriceByStripeIDs(m, tx, plan, price)

	switch err.(type) {
	case core.NotFoundError:
		return stripeErr(err)
	case nil:
	default:
		return err
	}

	curr, err := LoadPlanForUser(m, tx, m.ShortHostID(), uid)
	var canc bool

	switch err.(type) {
	case core.NoActivePlanError:
	case nil:
		if !curr.SubscriptionId.Eq(sub) {
			canc = true
			curr = nil
		}
	default:
		return err
	}

	cpe := currentPeriodEnd

	// Might have failed if stripe gave us a bad reply, but err on the side of
	// giving the user a plan.
	if cpe.IsZero() {
		cpe = time.Now().Add(time.Duration(24*30) * time.Hour)
		m.Warnw("recordPlan", "uid", uid, "action", "default-cpe", "cpe", cpe)
	}

	if canc {
		id, err := CancelPlanForUser(m, tx, m.ShortHostID(), uid, curr.Plan.Id)
		if err != nil {
			return err
		}
		idStr, err := id.ToID16().ID16StringErr()
		if err != nil {
			return err
		}
		m.Warnw("recordPlan", "uid", uid, "action", "cancel", "plan",
			curr.Plan.Id, "cancel_id", idStr, "status", curr.Status)
	}

	// If we don't currently have a plan, or if we just canceled
	// the active plan, then just insert
	if curr == nil {
		err = SetPlanForUser(m, tx, m.ShortHostID(), uid, *planId, *priceId, cpe, sub)
	} else {
		err = UpdatePlanForUser(m, tx,
			m.ShortHostID(), uid,
			core.Sel(planId.Eq(curr.Plan.Id), nil, planId),
			core.Sel(priceId.Eq(curr.Price), nil, priceId),
			core.Sel(cpe.After(curr.PaidThrough.Import()), &cpe, nil),
			sub,
		)
	}
	if err != nil {
		return err
	}
	return nil
}

type ChangeBillingPlanArg struct {
	PreviewProrationArg
	NewPlanID  proto.PlanID
	NewPriceID proto.PriceID
}

type ProrationPreviewData struct {
	Arg  ChangeBillingPlanArg
	Data ProrationData
}

func ChangeBillingPlan(m MetaContext, arg ChangeBillingPlanArg) error {

	err := m.Stripe().ApplyProration(m, arg.PreviewProrationArg)
	if err != nil {
		return err
	}

	err = RetryTxUserDB(m, "ChangeBillingPlan", func(m MetaContext, tx pgx.Tx) error {
		return UpdatePlanForUser(m, tx, m.ShortHostID(), m.UID(), &arg.NewPlanID, &arg.NewPriceID, nil, arg.SubID)
	})

	if err != nil {
		return err
	}
	return nil
}
