// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"time"

	infra "github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/proto/lib"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type PaymentSuccess struct {
	EventID            infra.StripeEventID
	CustomerID         infra.StripeCustomerID
	SessionID          infra.StripeSessionID
	ProdID             infra.StripeProdID
	PriceID            infra.StripePriceID
	SubID              infra.StripeSubscriptionID
	InvID              infra.StripeInvoiceID
	ChargeID           infra.StripeChargeID
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
	Amount             infra.Cents
}

type CheckoutArg struct {
	CustomerID infra.StripeCustomerID
	PriceID    infra.StripePriceID
	SuccessURL proto.URLString
	CancelURL  proto.URLString
	Expire     time.Time
}

type Subscription struct {
	CurrentPeriodEnd time.Time
	ProdID           infra.StripeProdID
	PriceID          infra.StripePriceID
	PI               infra.PaymentInterval
}

type ProrationAdjustment struct {
	Amount infra.SignedCents
	Desc   string
}

type Billing struct {
	Time           lib.Time
	Subtotal       infra.SignedCents
	Tax            infra.SignedCents
	AppliedBalance infra.SignedCents
	Total          infra.SignedCents
	AmountDue      infra.SignedCents
}

type PreviewProrationArg struct {
	Time       lib.Time
	CustomerID infra.StripeCustomerID
	SubID      infra.StripeSubscriptionID
	NewPlan    Subscription
	CurrPlan   Subscription
}

type ProrationData struct {
	Time        time.Time
	SubID       infra.StripeSubscriptionID
	Adj         []ProrationAdjustment
	CatchUpBill *Billing
	NextBill    Billing
}

type Striper interface {
	CreateCustomer(MetaContext, proto.UID, proto.Email) (infra.StripeCustomerID, error)
	LoadPaymentSuccess(MetaContext, infra.StripeSessionID) (*PaymentSuccess, error)
	ExpireSession(MetaContext, infra.StripeSessionID) error
	LoadSubscription(MetaContext, infra.StripeSubscriptionID) (*Subscription, error)
	LoadInvoices(MetaContext, infra.StripeCustomerID, StripePaginate) ([]infra.StripeInvoice, error)
	UpdateCancelAtPeriodEnd(MetaContext, infra.StripeSubscriptionID, bool) error
	CancelSubscription(MetaContext, infra.StripeSubscriptionID) error
	CheckoutSession(m MetaContext, arg CheckoutArg) (infra.StripeSessionID, proto.URLString, error)
	CreatePrice(MetaContext, infra.StripeProdID, infra.Cents, infra.PaymentInterval) (infra.StripePriceID, error)
	CreatePlan(m MetaContext, name string, details []string) (infra.StripeProdID, error)
	PreviewProration(m MetaContext, arg PreviewProrationArg) (*ProrationData, error)
	ApplyProration(m MetaContext, arg PreviewProrationArg) error
}
