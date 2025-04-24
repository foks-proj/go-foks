// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/infra/quota.snowp

package infra

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type QuotaConfig struct {
	Slacks         Slacks
	Delay          lib.DurationMilli
	NoPlanMaxTeams int64
	NoResurrection bool
}

type QuotaConfigInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Slacks         *SlacksInternal__
	Delay          *lib.DurationMilliInternal__
	NoPlanMaxTeams *int64
	NoResurrection *bool
}

func (q QuotaConfigInternal__) Import() QuotaConfig {
	return QuotaConfig{
		Slacks: (func(x *SlacksInternal__) (ret Slacks) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(q.Slacks),
		Delay: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(q.Delay),
		NoPlanMaxTeams: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(q.NoPlanMaxTeams),
		NoResurrection: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(q.NoResurrection),
	}
}

func (q QuotaConfig) Export() *QuotaConfigInternal__ {
	return &QuotaConfigInternal__{
		Slacks:         q.Slacks.Export(),
		Delay:          q.Delay.Export(),
		NoPlanMaxTeams: &q.NoPlanMaxTeams,
		NoResurrection: &q.NoResurrection,
	}
}

func (q *QuotaConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(q.Export())
}

func (q *QuotaConfig) Decode(dec rpc.Decoder) error {
	var tmp QuotaConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*q = tmp.Import()
	return nil
}

func (q *QuotaConfig) Bytes() []byte { return nil }

type Cents uint64
type CentsInternal__ uint64

func (c Cents) Export() *CentsInternal__ {
	tmp := ((uint64)(c))
	return ((*CentsInternal__)(&tmp))
}

func (c CentsInternal__) Import() Cents {
	tmp := (uint64)(c)
	return Cents((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *Cents) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Cents) Decode(dec rpc.Decoder) error {
	var tmp CentsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c Cents) Bytes() []byte {
	return nil
}

type SignedCents int64
type SignedCentsInternal__ int64

func (s SignedCents) Export() *SignedCentsInternal__ {
	tmp := ((int64)(s))
	return ((*SignedCentsInternal__)(&tmp))
}

func (s SignedCentsInternal__) Import() SignedCents {
	tmp := (int64)(s)
	return SignedCents((func(x *int64) (ret int64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SignedCents) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignedCents) Decode(dec rpc.Decoder) error {
	var tmp SignedCentsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SignedCents) Bytes() []byte {
	return nil
}

type StripeProdID string
type StripeProdIDInternal__ string

func (s StripeProdID) Export() *StripeProdIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeProdIDInternal__)(&tmp))
}

func (s StripeProdIDInternal__) Import() StripeProdID {
	tmp := (string)(s)
	return StripeProdID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeProdID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeProdID) Decode(dec rpc.Decoder) error {
	var tmp StripeProdIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeProdID) Bytes() []byte {
	return nil
}

type StripePriceID string
type StripePriceIDInternal__ string

func (s StripePriceID) Export() *StripePriceIDInternal__ {
	tmp := ((string)(s))
	return ((*StripePriceIDInternal__)(&tmp))
}

func (s StripePriceIDInternal__) Import() StripePriceID {
	tmp := (string)(s)
	return StripePriceID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripePriceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripePriceID) Decode(dec rpc.Decoder) error {
	var tmp StripePriceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripePriceID) Bytes() []byte {
	return nil
}

type StripeSessionID string
type StripeSessionIDInternal__ string

func (s StripeSessionID) Export() *StripeSessionIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeSessionIDInternal__)(&tmp))
}

func (s StripeSessionIDInternal__) Import() StripeSessionID {
	tmp := (string)(s)
	return StripeSessionID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeSessionID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeSessionID) Decode(dec rpc.Decoder) error {
	var tmp StripeSessionIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeSessionID) Bytes() []byte {
	return nil
}

type StripeCustomerID string
type StripeCustomerIDInternal__ string

func (s StripeCustomerID) Export() *StripeCustomerIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeCustomerIDInternal__)(&tmp))
}

func (s StripeCustomerIDInternal__) Import() StripeCustomerID {
	tmp := (string)(s)
	return StripeCustomerID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeCustomerID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeCustomerID) Decode(dec rpc.Decoder) error {
	var tmp StripeCustomerIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeCustomerID) Bytes() []byte {
	return nil
}

type StripeSubscriptionID string
type StripeSubscriptionIDInternal__ string

func (s StripeSubscriptionID) Export() *StripeSubscriptionIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeSubscriptionIDInternal__)(&tmp))
}

func (s StripeSubscriptionIDInternal__) Import() StripeSubscriptionID {
	tmp := (string)(s)
	return StripeSubscriptionID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeSubscriptionID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeSubscriptionID) Decode(dec rpc.Decoder) error {
	var tmp StripeSubscriptionIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeSubscriptionID) Bytes() []byte {
	return nil
}

type StripeInvoiceID string
type StripeInvoiceIDInternal__ string

func (s StripeInvoiceID) Export() *StripeInvoiceIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeInvoiceIDInternal__)(&tmp))
}

func (s StripeInvoiceIDInternal__) Import() StripeInvoiceID {
	tmp := (string)(s)
	return StripeInvoiceID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeInvoiceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeInvoiceID) Decode(dec rpc.Decoder) error {
	var tmp StripeInvoiceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeInvoiceID) Bytes() []byte {
	return nil
}

type StripeChargeID string
type StripeChargeIDInternal__ string

func (s StripeChargeID) Export() *StripeChargeIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeChargeIDInternal__)(&tmp))
}

func (s StripeChargeIDInternal__) Import() StripeChargeID {
	tmp := (string)(s)
	return StripeChargeID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeChargeID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeChargeID) Decode(dec rpc.Decoder) error {
	var tmp StripeChargeIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeChargeID) Bytes() []byte {
	return nil
}

type StripeEventID string
type StripeEventIDInternal__ string

func (s StripeEventID) Export() *StripeEventIDInternal__ {
	tmp := ((string)(s))
	return ((*StripeEventIDInternal__)(&tmp))
}

func (s StripeEventIDInternal__) Import() StripeEventID {
	tmp := (string)(s)
	return StripeEventID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StripeEventID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeEventID) Decode(dec rpc.Decoder) error {
	var tmp StripeEventIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StripeEventID) Bytes() []byte {
	return nil
}

type QuotaScope int

const (
	QuotaScope_None  QuotaScope = 0
	QuotaScope_Teams QuotaScope = 1
	QuotaScope_VHost QuotaScope = 2
)

var QuotaScopeMap = map[string]QuotaScope{
	"None":  0,
	"Teams": 1,
	"VHost": 2,
}

var QuotaScopeRevMap = map[QuotaScope]string{
	0: "None",
	1: "Teams",
	2: "VHost",
}

type QuotaScopeInternal__ QuotaScope

func (q QuotaScopeInternal__) Import() QuotaScope {
	return QuotaScope(q)
}

func (q QuotaScope) Export() *QuotaScopeInternal__ {
	return ((*QuotaScopeInternal__)(&q))
}

type Plan struct {
	Id           lib.PlanID
	Name         string
	MaxSeats     uint64
	Quota        lib.Size
	DisplayName  string
	StripeProdId StripeProdID
	Points       []string
	Prices       []PlanPrice
	Promoted     bool
	Scope        QuotaScope
	MaxVhosts    uint64
	Sso          bool
}

type PlanInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id           *lib.PlanIDInternal__
	Name         *string
	MaxSeats     *uint64
	Quota        *lib.SizeInternal__
	DisplayName  *string
	StripeProdId *StripeProdIDInternal__
	Points       *[](string)
	Prices       *[](*PlanPriceInternal__)
	Promoted     *bool
	Scope        *QuotaScopeInternal__
	MaxVhosts    *uint64
	Sso          *bool
}

func (p PlanInternal__) Import() Plan {
	return Plan{
		Id: (func(x *lib.PlanIDInternal__) (ret lib.PlanID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Id),
		Name: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Name),
		MaxSeats: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(p.MaxSeats),
		Quota: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Quota),
		DisplayName: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(p.DisplayName),
		StripeProdId: (func(x *StripeProdIDInternal__) (ret StripeProdID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.StripeProdId),
		Points: (func(x *[](string)) (ret []string) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]string, len(*x))
			for k, v := range *x {
				ret[k] = (func(x *string) (ret string) {
					if x == nil {
						return ret
					}
					return *x
				})(&v)
			}
			return ret
		})(p.Points),
		Prices: (func(x *[](*PlanPriceInternal__)) (ret []PlanPrice) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]PlanPrice, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *PlanPriceInternal__) (ret PlanPrice) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(p.Prices),
		Promoted: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Promoted),
		Scope: (func(x *QuotaScopeInternal__) (ret QuotaScope) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Scope),
		MaxVhosts: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(p.MaxVhosts),
		Sso: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Sso),
	}
}

func (p Plan) Export() *PlanInternal__ {
	return &PlanInternal__{
		Id:           p.Id.Export(),
		Name:         &p.Name,
		MaxSeats:     &p.MaxSeats,
		Quota:        p.Quota.Export(),
		DisplayName:  &p.DisplayName,
		StripeProdId: p.StripeProdId.Export(),
		Points: (func(x []string) *[](string) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](string), len(x))
			copy(ret, x)
			return &ret
		})(p.Points),
		Prices: (func(x []PlanPrice) *[](*PlanPriceInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*PlanPriceInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(p.Prices),
		Promoted:  &p.Promoted,
		Scope:     p.Scope.Export(),
		MaxVhosts: &p.MaxVhosts,
		Sso:       &p.Sso,
	}
}

func (p *Plan) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *Plan) Decode(dec rpc.Decoder) error {
	var tmp PlanInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *Plan) Bytes() []byte { return nil }

type PaymentInterval struct {
	Interval Interval
	Count    uint64
}

type PaymentIntervalInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Interval *IntervalInternal__
	Count    *uint64
}

func (p PaymentIntervalInternal__) Import() PaymentInterval {
	return PaymentInterval{
		Interval: (func(x *IntervalInternal__) (ret Interval) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Interval),
		Count: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Count),
	}
}

func (p PaymentInterval) Export() *PaymentIntervalInternal__ {
	return &PaymentIntervalInternal__{
		Interval: p.Interval.Export(),
		Count:    &p.Count,
	}
}

func (p *PaymentInterval) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PaymentInterval) Decode(dec rpc.Decoder) error {
	var tmp PaymentIntervalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PaymentInterval) Bytes() []byte { return nil }

type PlanPrice struct {
	Id            lib.PriceID
	StripePriceId StripePriceID
	Cents         Cents
	Pi            PaymentInterval
	Promoted      bool
	Pri           int64
}

type PlanPriceInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id            *lib.PriceIDInternal__
	StripePriceId *StripePriceIDInternal__
	Cents         *CentsInternal__
	Pi            *PaymentIntervalInternal__
	Promoted      *bool
	Pri           *int64
}

func (p PlanPriceInternal__) Import() PlanPrice {
	return PlanPrice{
		Id: (func(x *lib.PriceIDInternal__) (ret lib.PriceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Id),
		StripePriceId: (func(x *StripePriceIDInternal__) (ret StripePriceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.StripePriceId),
		Cents: (func(x *CentsInternal__) (ret Cents) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Cents),
		Pi: (func(x *PaymentIntervalInternal__) (ret PaymentInterval) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Pi),
		Promoted: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Promoted),
		Pri: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(p.Pri),
	}
}

func (p PlanPrice) Export() *PlanPriceInternal__ {
	return &PlanPriceInternal__{
		Id:            p.Id.Export(),
		StripePriceId: p.StripePriceId.Export(),
		Cents:         p.Cents.Export(),
		Pi:            p.Pi.Export(),
		Promoted:      &p.Promoted,
		Pri:           &p.Pri,
	}
}

func (p *PlanPrice) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PlanPrice) Decode(dec rpc.Decoder) error {
	var tmp PlanPriceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PlanPrice) Bytes() []byte { return nil }

type PlanStatus int

const (
	PlanStatus_Active   PlanStatus = 0
	PlanStatus_Overtime PlanStatus = 1
	PlanStatus_Expired  PlanStatus = 2
)

var PlanStatusMap = map[string]PlanStatus{
	"Active":   0,
	"Overtime": 1,
	"Expired":  2,
}

var PlanStatusRevMap = map[PlanStatus]string{
	0: "Active",
	1: "Overtime",
	2: "Expired",
}

type PlanStatusInternal__ PlanStatus

func (p PlanStatusInternal__) Import() PlanStatus {
	return PlanStatus(p)
}

func (p PlanStatus) Export() *PlanStatusInternal__ {
	return ((*PlanStatusInternal__)(&p))
}

type UserPlan struct {
	Plan           Plan
	TimeLeft       lib.DurationSecs
	Status         PlanStatus
	PendingCancel  bool
	Price          lib.PriceID
	PaidThrough    lib.Time
	SubscriptionId StripeSubscriptionID
}

type UserPlanInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Plan           *PlanInternal__
	TimeLeft       *lib.DurationSecsInternal__
	Status         *PlanStatusInternal__
	PendingCancel  *bool
	Price          *lib.PriceIDInternal__
	PaidThrough    *lib.TimeInternal__
	SubscriptionId *StripeSubscriptionIDInternal__
}

func (u UserPlanInternal__) Import() UserPlan {
	return UserPlan{
		Plan: (func(x *PlanInternal__) (ret Plan) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Plan),
		TimeLeft: (func(x *lib.DurationSecsInternal__) (ret lib.DurationSecs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.TimeLeft),
		Status: (func(x *PlanStatusInternal__) (ret PlanStatus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Status),
		PendingCancel: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(u.PendingCancel),
		Price: (func(x *lib.PriceIDInternal__) (ret lib.PriceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Price),
		PaidThrough: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.PaidThrough),
		SubscriptionId: (func(x *StripeSubscriptionIDInternal__) (ret StripeSubscriptionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.SubscriptionId),
	}
}

func (u UserPlan) Export() *UserPlanInternal__ {
	return &UserPlanInternal__{
		Plan:           u.Plan.Export(),
		TimeLeft:       u.TimeLeft.Export(),
		Status:         u.Status.Export(),
		PendingCancel:  &u.PendingCancel,
		Price:          u.Price.Export(),
		PaidThrough:    u.PaidThrough.Export(),
		SubscriptionId: u.SubscriptionId.Export(),
	}
}

func (u *UserPlan) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserPlan) Decode(dec rpc.Decoder) error {
	var tmp UserPlanInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserPlan) Bytes() []byte { return nil }

type StripeInvoice struct {
	Id   StripeInvoiceID
	Amt  Cents
	Time lib.Time
	Url  lib.URLString
	Desc string
}

type StripeInvoiceInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *StripeInvoiceIDInternal__
	Amt     *CentsInternal__
	Time    *lib.TimeInternal__
	Url     *lib.URLStringInternal__
	Desc    *string
}

func (s StripeInvoiceInternal__) Import() StripeInvoice {
	return StripeInvoice{
		Id: (func(x *StripeInvoiceIDInternal__) (ret StripeInvoiceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Amt: (func(x *CentsInternal__) (ret Cents) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Amt),
		Time: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Time),
		Url: (func(x *lib.URLStringInternal__) (ret lib.URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Url),
		Desc: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Desc),
	}
}

func (s StripeInvoice) Export() *StripeInvoiceInternal__ {
	return &StripeInvoiceInternal__{
		Id:   s.Id.Export(),
		Amt:  s.Amt.Export(),
		Time: s.Time.Export(),
		Url:  s.Url.Export(),
		Desc: &s.Desc,
	}
}

func (s *StripeInvoice) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StripeInvoice) Decode(dec rpc.Decoder) error {
	var tmp StripeInvoiceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *StripeInvoice) Bytes() []byte { return nil }

type CannedVHostStage int

const (
	CannedVHostStage_None     CannedVHostStage = 0
	CannedVHostStage_Complete CannedVHostStage = 1
	CannedVHostStage_Aborted  CannedVHostStage = 2
	CannedVHostStage_Stage1   CannedVHostStage = 3
)

var CannedVHostStageMap = map[string]CannedVHostStage{
	"None":     0,
	"Complete": 1,
	"Aborted":  2,
	"Stage1":   3,
}

var CannedVHostStageRevMap = map[CannedVHostStage]string{
	0: "None",
	1: "Complete",
	2: "Aborted",
	3: "Stage1",
}

type CannedVHostStageInternal__ CannedVHostStage

func (c CannedVHostStageInternal__) Import() CannedVHostStage {
	return CannedVHostStage(c)
}

func (c CannedVHostStage) Export() *CannedVHostStageInternal__ {
	return ((*CannedVHostStageInternal__)(&c))
}

type AutocertStatus int

const (
	AutocertStatus_None    AutocertStatus = 0
	AutocertStatus_Staged  AutocertStatus = 1
	AutocertStatus_Granted AutocertStatus = 2
	AutocertStatus_Aborted AutocertStatus = 3
)

var AutocertStatusMap = map[string]AutocertStatus{
	"None":    0,
	"Staged":  1,
	"Granted": 2,
	"Aborted": 3,
}

var AutocertStatusRevMap = map[AutocertStatus]string{
	0: "None",
	1: "Staged",
	2: "Granted",
	3: "Aborted",
}

type AutocertStatusInternal__ AutocertStatus

func (a AutocertStatusInternal__) Import() AutocertStatus {
	return AutocertStatus(a)
}

func (a AutocertStatus) Export() *AutocertStatusInternal__ {
	return ((*AutocertStatusInternal__)(&a))
}

type Interval int

const (
	Interval_Day   Interval = 0
	Interval_Month Interval = 1
	Interval_Year  Interval = 2
)

var IntervalMap = map[string]Interval{
	"Day":   0,
	"Month": 1,
	"Year":  2,
}

var IntervalRevMap = map[Interval]string{
	0: "Day",
	1: "Month",
	2: "Year",
}

type IntervalInternal__ Interval

func (i IntervalInternal__) Import() Interval {
	return Interval(i)
}

func (i Interval) Export() *IntervalInternal__ {
	return ((*IntervalInternal__)(&i))
}

type MakePlanOpts struct {
}

type MakePlanOptsInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (m MakePlanOptsInternal__) Import() MakePlanOpts {
	return MakePlanOpts{}
}

func (m MakePlanOpts) Export() *MakePlanOptsInternal__ {
	return &MakePlanOptsInternal__{}
}

func (m *MakePlanOpts) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MakePlanOpts) Decode(dec rpc.Decoder) error {
	var tmp MakePlanOptsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MakePlanOpts) Bytes() []byte { return nil }

type Slacks struct {
	FloatingTeam lib.Size
	NoPlanUser   lib.Size
	PlanUser     lib.Size
	PaidThrough  lib.DurationSecs
}

type SlacksInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	FloatingTeam *lib.SizeInternal__
	NoPlanUser   *lib.SizeInternal__
	PlanUser     *lib.SizeInternal__
	PaidThrough  *lib.DurationSecsInternal__
}

func (s SlacksInternal__) Import() Slacks {
	return Slacks{
		FloatingTeam: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.FloatingTeam),
		NoPlanUser: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.NoPlanUser),
		PlanUser: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.PlanUser),
		PaidThrough: (func(x *lib.DurationSecsInternal__) (ret lib.DurationSecs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.PaidThrough),
	}
}

func (s Slacks) Export() *SlacksInternal__ {
	return &SlacksInternal__{
		FloatingTeam: s.FloatingTeam.Export(),
		NoPlanUser:   s.NoPlanUser.Export(),
		PlanUser:     s.PlanUser.Export(),
		PaidThrough:  s.PaidThrough.Export(),
	}
}

func (s *Slacks) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *Slacks) Decode(dec rpc.Decoder) error {
	var tmp SlacksInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *Slacks) Bytes() []byte { return nil }

var QuotaProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xfa82ee9c)

type QuotaPokeArg struct {
}

type QuotaPokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (q QuotaPokeArgInternal__) Import() QuotaPokeArg {
	return QuotaPokeArg{}
}

func (q QuotaPokeArg) Export() *QuotaPokeArgInternal__ {
	return &QuotaPokeArgInternal__{}
}

func (q *QuotaPokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(q.Export())
}

func (q *QuotaPokeArg) Decode(dec rpc.Decoder) error {
	var tmp QuotaPokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*q = tmp.Import()
	return nil
}

func (q *QuotaPokeArg) Bytes() []byte { return nil }

type TestSetConfigArg struct {
	Config QuotaConfig
}

type TestSetConfigArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Config  *QuotaConfigInternal__
}

func (t TestSetConfigArgInternal__) Import() TestSetConfigArg {
	return TestSetConfigArg{
		Config: (func(x *QuotaConfigInternal__) (ret QuotaConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Config),
	}
}

func (t TestSetConfigArg) Export() *TestSetConfigArgInternal__ {
	return &TestSetConfigArgInternal__{
		Config: t.Config.Export(),
	}
}

func (t *TestSetConfigArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestSetConfigArg) Decode(dec rpc.Decoder) error {
	var tmp TestSetConfigArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TestSetConfigArg) Bytes() []byte { return nil }

type TestUnsetConfigArg struct {
}

type TestUnsetConfigArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (t TestUnsetConfigArgInternal__) Import() TestUnsetConfigArg {
	return TestUnsetConfigArg{}
}

func (t TestUnsetConfigArg) Export() *TestUnsetConfigArgInternal__ {
	return &TestUnsetConfigArgInternal__{}
}

func (t *TestUnsetConfigArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestUnsetConfigArg) Decode(dec rpc.Decoder) error {
	var tmp TestUnsetConfigArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TestUnsetConfigArg) Bytes() []byte { return nil }

type TestBumpUsageArg struct {
	Hid lib.HostID
	Pid lib.PartyID
	Amt lib.Size
}

type TestBumpUsageArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hid     *lib.HostIDInternal__
	Pid     *lib.PartyIDInternal__
	Amt     *lib.SizeInternal__
}

func (t TestBumpUsageArgInternal__) Import() TestBumpUsageArg {
	return TestBumpUsageArg{
		Hid: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hid),
		Pid: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Pid),
		Amt: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Amt),
	}
}

func (t TestBumpUsageArg) Export() *TestBumpUsageArgInternal__ {
	return &TestBumpUsageArgInternal__{
		Hid: t.Hid.Export(),
		Pid: t.Pid.Export(),
		Amt: t.Amt.Export(),
	}
}

func (t *TestBumpUsageArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestBumpUsageArg) Decode(dec rpc.Decoder) error {
	var tmp TestBumpUsageArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TestBumpUsageArg) Bytes() []byte { return nil }

type MakePlanArg struct {
	Plan Plan
	Opts MakePlanOpts
}

type MakePlanArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Plan    *PlanInternal__
	Opts    *MakePlanOptsInternal__
}

func (m MakePlanArgInternal__) Import() MakePlanArg {
	return MakePlanArg{
		Plan: (func(x *PlanInternal__) (ret Plan) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Plan),
		Opts: (func(x *MakePlanOptsInternal__) (ret MakePlanOpts) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Opts),
	}
}

func (m MakePlanArg) Export() *MakePlanArgInternal__ {
	return &MakePlanArgInternal__{
		Plan: m.Plan.Export(),
		Opts: m.Opts.Export(),
	}
}

func (m *MakePlanArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MakePlanArg) Decode(dec rpc.Decoder) error {
	var tmp MakePlanArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MakePlanArg) Bytes() []byte { return nil }

type SetPlanArg struct {
	Fqu         lib.FQUser
	Plan        lib.PlanID
	Price       lib.PriceID
	Replace     bool
	ValidFor    lib.DurationSecs
	StripeSubId StripeSubscriptionID
}

type SetPlanArgInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu         *lib.FQUserInternal__
	Plan        *lib.PlanIDInternal__
	Price       *lib.PriceIDInternal__
	Replace     *bool
	ValidFor    *lib.DurationSecsInternal__
	StripeSubId *StripeSubscriptionIDInternal__
}

func (s SetPlanArgInternal__) Import() SetPlanArg {
	return SetPlanArg{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqu),
		Plan: (func(x *lib.PlanIDInternal__) (ret lib.PlanID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Plan),
		Price: (func(x *lib.PriceIDInternal__) (ret lib.PriceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Price),
		Replace: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Replace),
		ValidFor: (func(x *lib.DurationSecsInternal__) (ret lib.DurationSecs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.ValidFor),
		StripeSubId: (func(x *StripeSubscriptionIDInternal__) (ret StripeSubscriptionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.StripeSubId),
	}
}

func (s SetPlanArg) Export() *SetPlanArgInternal__ {
	return &SetPlanArgInternal__{
		Fqu:         s.Fqu.Export(),
		Plan:        s.Plan.Export(),
		Price:       s.Price.Export(),
		Replace:     &s.Replace,
		ValidFor:    s.ValidFor.Export(),
		StripeSubId: s.StripeSubId.Export(),
	}
}

func (s *SetPlanArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetPlanArg) Decode(dec rpc.Decoder) error {
	var tmp SetPlanArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetPlanArg) Bytes() []byte { return nil }

type CancelPlanArg struct {
	Fqu lib.FQUser
}

type CancelPlanArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *lib.FQUserInternal__
}

func (c CancelPlanArgInternal__) Import() CancelPlanArg {
	return CancelPlanArg{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Fqu),
	}
}

func (c CancelPlanArg) Export() *CancelPlanArgInternal__ {
	return &CancelPlanArgInternal__{
		Fqu: c.Fqu.Export(),
	}
}

func (c *CancelPlanArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CancelPlanArg) Decode(dec rpc.Decoder) error {
	var tmp CancelPlanArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CancelPlanArg) Bytes() []byte { return nil }

type AssignQuotaMasterArg struct {
	Fqu  lib.FQUser
	Team lib.TeamID
}

type AssignQuotaMasterArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *lib.FQUserInternal__
	Team    *lib.TeamIDInternal__
}

func (a AssignQuotaMasterArgInternal__) Import() AssignQuotaMasterArg {
	return AssignQuotaMasterArg{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Fqu),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Team),
	}
}

func (a AssignQuotaMasterArg) Export() *AssignQuotaMasterArgInternal__ {
	return &AssignQuotaMasterArgInternal__{
		Fqu:  a.Fqu.Export(),
		Team: a.Team.Export(),
	}
}

func (a *AssignQuotaMasterArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssignQuotaMasterArg) Decode(dec rpc.Decoder) error {
	var tmp AssignQuotaMasterArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssignQuotaMasterArg) Bytes() []byte { return nil }

type UnassignQuotaMasterArg struct {
	Fqu  lib.FQUser
	Team lib.TeamID
}

type UnassignQuotaMasterArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *lib.FQUserInternal__
	Team    *lib.TeamIDInternal__
}

func (u UnassignQuotaMasterArgInternal__) Import() UnassignQuotaMasterArg {
	return UnassignQuotaMasterArg{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Fqu),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Team),
	}
}

func (u UnassignQuotaMasterArg) Export() *UnassignQuotaMasterArgInternal__ {
	return &UnassignQuotaMasterArgInternal__{
		Fqu:  u.Fqu.Export(),
		Team: u.Team.Export(),
	}
}

func (u *UnassignQuotaMasterArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UnassignQuotaMasterArg) Decode(dec rpc.Decoder) error {
	var tmp UnassignQuotaMasterArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UnassignQuotaMasterArg) Bytes() []byte { return nil }

type QuotaInterface interface {
	Poke(context.Context) error
	TestSetConfig(context.Context, QuotaConfig) error
	TestUnsetConfig(context.Context) error
	TestBumpUsage(context.Context, TestBumpUsageArg) error
	MakePlan(context.Context, MakePlanArg) (Plan, error)
	SetPlan(context.Context, SetPlanArg) (lib.CancelID, error)
	CancelPlan(context.Context, lib.FQUser) (lib.CancelID, error)
	AssignQuotaMaster(context.Context, AssignQuotaMasterArg) error
	UnassignQuotaMaster(context.Context, UnassignQuotaMasterArg) error
	ErrorWrapper() func(error) lib.Status
}

func QuotaMakeGenericErrorWrapper(f QuotaErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type QuotaErrorUnwrapper func(lib.Status) error
type QuotaErrorWrapper func(error) lib.Status

type quotaErrorUnwrapperAdapter struct {
	h QuotaErrorUnwrapper
}

func (q quotaErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (q quotaErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return q.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = quotaErrorUnwrapperAdapter{}

type QuotaClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper QuotaErrorUnwrapper
}

func (c QuotaClient) Poke(ctx context.Context) (err error) {
	var arg QuotaPokeArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 0, "Quota.poke"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c QuotaClient) TestSetConfig(ctx context.Context, config QuotaConfig) (err error) {
	arg := TestSetConfigArg{
		Config: config,
	}
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 1, "Quota.testSetConfig"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c QuotaClient) TestUnsetConfig(ctx context.Context) (err error) {
	var arg TestUnsetConfigArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 2, "Quota.testUnsetConfig"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c QuotaClient) TestBumpUsage(ctx context.Context, arg TestBumpUsageArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 3, "Quota.testBumpUsage"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c QuotaClient) MakePlan(ctx context.Context, arg MakePlanArg) (res Plan, err error) {
	warg := arg.Export()
	var tmp PlanInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 4, "Quota.makePlan"), warg, &tmp, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c QuotaClient) SetPlan(ctx context.Context, arg SetPlanArg) (res lib.CancelID, err error) {
	warg := arg.Export()
	var tmp lib.CancelIDInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 5, "Quota.setPlan"), warg, &tmp, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c QuotaClient) CancelPlan(ctx context.Context, fqu lib.FQUser) (res lib.CancelID, err error) {
	arg := CancelPlanArg{
		Fqu: fqu,
	}
	warg := arg.Export()
	var tmp lib.CancelIDInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 6, "Quota.cancelPlan"), warg, &tmp, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c QuotaClient) AssignQuotaMaster(ctx context.Context, arg AssignQuotaMasterArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 7, "Quota.assignQuotaMaster"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c QuotaClient) UnassignQuotaMaster(ctx context.Context, arg UnassignQuotaMasterArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QuotaProtocolID, 8, "Quota.unassignQuotaMaster"), warg, nil, 0*time.Millisecond, quotaErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func QuotaProtocol(i QuotaInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Quota",
		ID:   QuotaProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret QuotaPokeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*QuotaPokeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*QuotaPokeArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Poke(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "poke",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret TestSetConfigArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*TestSetConfigArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*TestSetConfigArgInternal__)(nil), args)
							return nil, err
						}
						err := i.TestSetConfig(ctx, (typedArg.Import()).Config)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "testSetConfig",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret TestUnsetConfigArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*TestUnsetConfigArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*TestUnsetConfigArgInternal__)(nil), args)
							return nil, err
						}
						err := i.TestUnsetConfig(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "testUnsetConfig",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret TestBumpUsageArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*TestBumpUsageArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*TestBumpUsageArgInternal__)(nil), args)
							return nil, err
						}
						err := i.TestBumpUsage(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "testBumpUsage",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret MakePlanArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*MakePlanArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*MakePlanArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.MakePlan(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "makePlan",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret SetPlanArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*SetPlanArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*SetPlanArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.SetPlan(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "setPlan",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret CancelPlanArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*CancelPlanArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*CancelPlanArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.CancelPlan(ctx, (typedArg.Import()).Fqu)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "cancelPlan",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret AssignQuotaMasterArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*AssignQuotaMasterArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*AssignQuotaMasterArgInternal__)(nil), args)
							return nil, err
						}
						err := i.AssignQuotaMaster(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "assignQuotaMaster",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret UnassignQuotaMasterArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*UnassignQuotaMasterArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*UnassignQuotaMasterArgInternal__)(nil), args)
							return nil, err
						}
						err := i.UnassignQuotaMaster(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "unassignQuotaMaster",
			},
		},
		WrapError: QuotaMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(QuotaProtocolID)
}
