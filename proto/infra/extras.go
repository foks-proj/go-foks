// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package infra

import (
	"fmt"
	"strconv"
	"time"

	lib "github.com/foks-proj/go-foks/proto/lib"
)

func (p *Plan) MaxTeamsString() string {
	if p == nil {
		return "0"
	}
	return strconv.Itoa(int(p.MaxSeats))
}

func (p *Plan) QuotaString() string {
	var val lib.Size
	if p != nil {
		val = p.Quota
	}
	return val.HumanReadable()
}

func (u *UserPlan) QuotaString() string {
	var val lib.Size
	if u != nil && u.IsLive() {
		val = u.Plan.Quota
	}
	return val.HumanReadable()
}

func (p *Plan) RandomID() error {
	id, err := lib.ID16Type_Plan.RandomID()
	if err != nil {
		return err
	}
	pid, err := id.ToPlanID()
	if err != nil {
		return err
	}
	p.Id = *pid
	return nil
}

func (p *PlanPrice) RandomID() error {
	id, err := lib.ID16Type_Price.RandomID()
	if err != nil {
		return err
	}
	prid, err := id.ToPriceID()
	if err != nil {
		return err
	}
	p.Id = *prid
	return nil
}

func (p Plan) Validate() error {
	if len(p.Points) == 0 {
		return lib.DataError("need plan bullet points (at least 1)")
	}
	for _, x := range p.Points {
		if len(x) == 0 {
			return lib.DataError("cannot pass an empty plan bullet point")
		}
	}
	if len(p.Name) == 0 {
		return lib.DataError("need a plan name (for display, doesn't need to be unique)")
	}
	if len(p.Prices) == 0 {
		return lib.DataError("all pricing data is empty")
	}
	return nil
}

func (u UserPlan) IsLive() bool {
	return u.Status == PlanStatus_Active || u.Status == PlanStatus_Overtime
}

func (i Interval) String() string {
	switch i {
	case Interval_Day:
		return "day"
	case Interval_Month:
		return "month"
	case Interval_Year:
		return "year"
	default:
		return ""
	}
}

func (i Interval) Duration() time.Duration {
	switch i {
	case Interval_Day:
		return 24 * time.Hour
	case Interval_Month:
		return 30 * 24 * time.Hour
	case Interval_Year:
		return 365 * 24 * time.Hour
	default:
		return 0
	}
}

func (i *Interval) ImportFromDB(s string) error {
	switch s {
	case "day":
		*i = Interval_Day
	case "month":
		*i = Interval_Month
	case "year":
		*i = Interval_Year
	default:
		return lib.DataError("bad interval")
	}
	return nil
}

func (p PaymentInterval) Eq(p2 PaymentInterval) bool {
	return p.Interval == p2.Interval && p.Count == p2.Count
}

func (c Cents) String() string {
	pennies := c % 100
	dollars := c / 100
	return fmt.Sprintf("$%d.%02d", dollars, pennies)
}

func (s SignedCents) String() string {
	pennies := s % 100
	dollars := s / 100
	if s < 0 {
		return fmt.Sprintf("-$%d.%02d", -dollars, -pennies)
	}
	return fmt.Sprintf("$%d.%02d", dollars, pennies)
}

func (i StripeProdID) String() string {
	return string(i)
}

func (i StripePriceID) String() string {
	return string(i)
}

func (p *Plan) MonthlyPrice() *PlanPrice {
	for _, x := range p.Prices {
		if x.Pi.Interval == Interval_Month && x.Pi.Count == 1 {
			return &x
		}
	}
	return nil
}

func (p *Plan) MonthlyCents() Cents {
	pr := p.MonthlyPrice()
	if pr == nil {
		return 0
	}
	return pr.Cents
}

func (p PaymentInterval) String() string {
	switch {
	case p.Interval == Interval_Month && p.Count == 1:
		return "month"
	case p.Interval == Interval_Year && p.Count == 1:
		return "year"
	case p.Interval == Interval_Month && p.Count == 6:
		return "6mo"
	default:
		return fmt.Sprintf("%d %ss", p.Count, p.Interval.String())
	}
}

func (p *PlanPrice) String() string {
	if p == nil {
		return "(can't load pricing plan)"
	}
	return fmt.Sprintf("%s / %s", p.Cents.String(), p.Pi.String())
}

func (s StripeSessionID) String() string {
	return string(s)
}

func (c StripeCustomerID) String() string {
	return string(c)
}

func (a StripeCustomerID) Eq(b StripeCustomerID) bool {
	return a == b
}

func (s StripeSubscriptionID) String() string {
	return string(s)
}

func (s StripeSessionID) IsZero() bool      { return s == "" }
func (c StripeCustomerID) IsZero() bool     { return c == "" }
func (s StripeProdID) IsZero() bool         { return s == "" }
func (s StripePriceID) IsZero() bool        { return s == "" }
func (s StripeSubscriptionID) IsZero() bool { return s == "" }
func (s StripeInvoiceID) IsZero() bool      { return s == "" }
func (s StripeChargeID) IsZero() bool       { return s == "" }

func (u *UserPlan) ActivePrice() *PlanPrice {
	for _, x := range u.Plan.Prices {
		if x.Id.Eq(u.Price) {
			return &x
		}
	}
	return nil
}

func (c StripeCustomerID) StringP() *string {
	ret := string(c)
	return &ret
}

func (p StripePriceID) StringP() *string {
	ret := string(p)
	return &ret
}

func (c Cents) Int64P() *int64 {
	ret := int64(c)
	return &ret
}

func (p StripeProdID) StringP() *string {
	ret := p.String()
	return &ret
}

func (i Interval) StringP() *string {
	ret := i.String()
	return &ret
}

func (c StripeChargeID) String() string  { return string(c) }
func (i StripeInvoiceID) String() string { return string(i) }

func (e StripeEventID) String() string {
	return string(e)
}

func (c Cents) Int() int {
	return int(c)
}

func (p PlanStatus) CanCancel() bool {
	return p == PlanStatus_Active || p == PlanStatus_Overtime
}

func (s StripeSubscriptionID) Eq(t StripeSubscriptionID) bool {
	return s == t
}

func (p PaymentInterval) Duration() time.Duration {
	return time.Duration(p.Count) * p.Interval.Duration()
}

func (s QuotaScope) String() string {
	switch s {
	case QuotaScope_Teams:
		return "teams"
	case QuotaScope_VHost:
		return "vhost"
	default:
		return "none"
	}
}

func (q *QuotaScope) ImportFromDB(s string) error {
	switch s {
	case "teams":
		*q = QuotaScope_Teams
	case "vhost":
		*q = QuotaScope_VHost
	default:
		return lib.DataError("bad quota scope")
	}
	return nil
}

func QuotaScopeFromHostType(t lib.HostType) QuotaScope {
	switch t {
	case lib.HostType_VHostManagement:
		return QuotaScope_VHost
	case lib.HostType_BigTop:
		return QuotaScope_Teams
	default:
		return QuotaScope_None
	}
}

func (u *UserPlan) MaxVHosts() int {
	if u == nil {
		return 0
	}
	return int(u.Plan.MaxVhosts)
}

func (u *UserPlan) MaxSeats() int {
	if u == nil {
		return 0
	}
	return int(u.Plan.MaxSeats)
}

func (c CannedVHostStage) String() string {
	switch c {
	case CannedVHostStage_None:
		return "none"
	case CannedVHostStage_Stage1:
		return "stage1"
	case CannedVHostStage_Complete:
		return "complete"
	case CannedVHostStage_Aborted:
		return "aborted"
	default:
		return "none"
	}
}

func (c *CannedVHostStage) ImportFromString(s string) error {
	switch s {
	case "none":
		*c = CannedVHostStage_None
	case "stage1":
		*c = CannedVHostStage_Stage1
	case "complete":
		*c = CannedVHostStage_Complete
	case "aborted":
		*c = CannedVHostStage_Aborted
	default:
		return lib.DataError("bad canned vhost stage")
	}
	return nil
}

func (s AutocertStatus) String() string {
	switch s {
	case AutocertStatus_None:
		return "none"
	case AutocertStatus_Staged:
		return "staged"
	case AutocertStatus_Granted:
		return "granted"
	case AutocertStatus_Aborted:
		return "aborted"
	default:
		return "none"
	}
}

func (t *AutocertStatus) ImportFromDB(s string) error {
	switch s {
	case "none":
		*t = AutocertStatus_None
	case "staged":
		*t = AutocertStatus_Staged
	case "granted":
		*t = AutocertStatus_Granted
	case "aborted":
		*t = AutocertStatus_Aborted
	default:
		return lib.DataError("bad autocert status")
	}
	return nil
}
