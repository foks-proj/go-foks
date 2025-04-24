// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/webhook"
)

func TestWebAdmin(t *testing.T) {
	bob := makeBobAndHisAgent(t)

	defer bob.stop(t)
	x := bob.agent

	var urlBob string
	x.runCmdToJSON(t, &urlBob, "admin", "web")
	require.NotEqual(t, "", urlBob)

	x.runCmd(t, nil, "admin", "check-link", urlBob)

	// Now mangle the query by one bit, and check that the check fails
	urlParsed, err := url.Parse(urlBob)
	require.NoError(t, err)
	sess := urlParsed.Query().Get("s")
	require.NotEqual(t, "", sess)
	dat, err := core.B62Decode(sess)
	require.NoError(t, err)
	dat[5] ^= 0x01
	sess = core.B62Encode(dat)
	params := url.Values{"s": {sess}}
	urlParsed.RawQuery = params.Encode()

	urlBad := urlParsed.String()
	err = x.runCmdErr(nil, "admin", "check-link", urlBad)
	require.Error(t, err)
	require.Equal(t, core.WebSessionNotFoundError{}, err)

	charlie := makeBobAndHisAgent(t)
	defer charlie.stop(t)

	var urlCharlie string
	charlie.agent.runCmdToJSON(t, &urlCharlie, "admin", "web")

	err = x.runCmdErr(nil, "admin", "check-link", urlCharlie)
	require.Error(t, err)
	require.Equal(t, core.WrongUserError{}, err)
}

func (a *adminWebClient) makePlan(t *testing.T, dn string) {

	plan := common.MakeRandomPlan(
		t,
		a.env.MetaContext(),
		dn,
		infra.Plan{
			MaxSeats: 3,
			Quota:    1024 * 1024 * 512,
			Scope:    infra.QuotaScope_Teams,
		},
	)
	a.plan = plan
}

type adminWebClient struct {
	jar           *cookiejar.Jar
	status        *lcl.AgentStatus
	cli           *http.Client
	uab           *userAgentBundle
	redirs        []string
	home          *goquery.Document
	base          proto.URLString
	sess          infra.StripeSessionID
	plan          *infra.Plan
	managePlanUrl proto.URLString
	last          *goquery.Document
	csrfTok       string
	env           *common.TestEnv
	subId         infra.StripeSubscriptionID
	testBadCSRF   bool
	firstPlan     string
}

func newAdminWebClient(t *testing.T, uab *userAgentBundle, env *common.TestEnv) *adminWebClient {
	if env == nil {
		env = globalTestEnv
	}
	ret := &adminWebClient{
		uab: uab,
		env: env,
	}
	ret.init(t)
	return ret
}

func (a *adminWebClient) getStatus(t *testing.T) *lcl.AgentStatus {
	if a.status != nil {
		return a.status
	}
	var status lcl.AgentStatus
	a.uab.agent.runCmdToJSON(t, &status, "status")
	a.status = &status
	return &status
}

func (a *adminWebClient) getUID(t *testing.T) proto.UID {
	status := a.getStatus(t)
	uid := status.Users[0].Info.Fqu.Uid
	require.False(t, uid.IsZero())
	return uid
}

func (a *adminWebClient) getFQU(t *testing.T) proto.FQUser {
	status := a.getStatus(t)
	return status.Users[0].Info.Fqu
}

func (a *adminWebClient) assertPendingCancelInDB(t *testing.T, val bool) {
	uid := a.getUID(t)
	m := a.env.MetaContext()
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	var ret bool
	err = db.QueryRow(
		m.Ctx(),
		`SELECT pending_cancel FROM user_plans
		 WHERE short_host_id=$1 
		 AND uid=$2 AND cancel_id=$3 AND stripe_sub_id=$4`,
		m.ShortHostID(),
		uid.ExportToDB(),
		proto.NilCancelID(),
		a.subId.String(),
	).Scan(&ret)
	require.NoError(t, err)
	require.Equal(t, val, ret)
}

func (a *adminWebClient) resetRedirs() {
	a.redirs = nil
}

func (a *adminWebClient) init(t *testing.T) {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	a.jar = jar
	a.redirs = nil
	a.cli = &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			a.redirs = append(a.redirs, req.URL.String())
			return nil
		},
	}
}

func (a *adminWebClient) rewriteURL(t *testing.T, u proto.URLString) proto.URLString {
	urlp, err := url.Parse(u.String())
	require.NoError(t, err)
	host := a.env.G.CnameResolver().Resolve(proto.Hostname(urlp.Hostname()))
	urlp.Host = string(host) + ":" + urlp.Port()
	return proto.URLString(urlp.String())
}

func (a *adminWebClient) get(t *testing.T, u proto.URLString) *http.Response {
	u = a.rewriteURL(t, u)
	resp, err := a.cli.Get(u.String())
	require.NoError(t, err)
	return resp
}

func (a *adminWebClient) login(t *testing.T) {
	var urlBob string
	a.uab.agent.runCmdToJSON(t, &urlBob, "admin", "web")
	require.NotEqual(t, "", urlBob)

	a.resetRedirs()
	resp := a.get(t, proto.URLString(urlBob))
	defer resp.Body.Close()

	require.Equal(t, 1, len(a.redirs))
	require.True(t, strings.Contains(a.redirs[0], "/admin"))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	a.redirs = nil

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	title := doc.Find("title").Text()
	require.Equal(t, "FOKS Admin Control Panel", title)
	username := doc.Find("span#username").Text()
	require.Equal(t, a.uab.username, proto.NameUtf8(username))
	a.home = doc
	a.last = doc

	csrf, ok := doc.Find("meta[name=csrf-token]").First().Attr("content")
	require.True(t, ok)
	a.csrfTok = csrf

	// Stow away the base URL so that we can make further requests.
	baseUrl, err := url.Parse(urlBob)
	require.NoError(t, err)
	baseUrl.Path = ""
	baseUrl.Fragment = ""
	baseUrl.RawQuery = ""
	a.base = proto.URLString(baseUrl.String())
}

func (a *adminWebClient) absUrl(rel string) proto.URLString {
	return proto.URLString(string(a.base) + rel)
}

func (a *adminWebClient) addCSRFTok(t *testing.T, req *http.Request) {
	tok := a.csrfTok
	if a.testBadCSRF {
		raw, err := core.B62Decode(tok)
		require.NoError(t, err)
		raw[24] ^= 0x01
		tok = core.B62Encode(raw)
	}
	req.Header.Set("X-CSRF-Token", tok)
}

func (a *adminWebClient) clickOnFirstPlanAndPrice(t *testing.T) {
	purl, found := a.home.Find("a#menu-plans").First().Attr("hx-get")
	require.True(t, found)
	plans := a.absUrl(purl)
	resp := a.get(t, plans)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	box := doc.Find("div.plan-box").First()
	a.firstPlan = box.Find("h4.plan-name").First().Text()
	plan := box.Find("form.plan-manage").First()
	targ, ok := plan.Attr("hx-post")
	require.True(t, ok)
	sel := plan.Find("select").First()
	name, ok := sel.Attr("name")
	require.True(t, ok)
	price, ok := sel.Find("option").First().Attr("value")
	require.True(t, ok)

	data := url.Values{}
	data.Add(name, price)
	resp2 := a.httpOp(t, "POST", proto.URLString(targ), data, nil)

	if a.testBadCSRF {
		require.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
		return
	}
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	defer resp2.Body.Close()
	redir := resp2.Header[http.CanonicalHeaderKey("HX-Redirect")]
	require.Equal(t, 1, len(redir))
	require.Equal(t, redir[0], "https://fake.stripe.com/checkout/v1")
	sess := resp2.Header[http.CanonicalHeaderKey("X-Stripe-Checkout-Session")]
	require.Equal(t, 1, len(sess))
	require.NotEqual(t, "", sess[0])
	a.sess = infra.StripeSessionID(sess[0])
}

func (a *adminWebClient) injectFirstPaymentEvent(t *testing.T) {
	m := a.env.MetaContext()
	psd, err := m.Stripe().LoadPaymentSuccess(a.env.MetaContext(), a.sess)
	psd.EventID = infra.StripeEventID(common.MakeFakeStripeID(t, "evt"))
	require.NoError(t, err)
	pse := &paymentSuccessEvent{
		PaymentSuccess: *psd,
		Email:          "bbbb@rocketmail.com",
	}
	a.injectPSE(t, pse)
}

func (a *adminWebClient) checkVirtualHostMgmt(t *testing.T) {
	require.Equal(t,
		"Virtual Hosts",
		a.home.Find("div#vhost-usage-pill a#virtual-hosts").First().Text(),
	)
	require.Equal(t,
		"Virtual Host Management",
		a.home.Find("div#page-title span#page-subtitle").First().Text(),
	)
}

func (a *adminWebClient) doCheckout(t *testing.T) {
	url, err := a.env.G.Stripe().(*common.FakeStripe).SessionSuccess(a.sess)
	require.NoError(t, err)
	resp := a.get(t, url)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	managePlan := doc.Find("a.active-plan").First()
	planName := managePlan.Text()
	require.Equal(t, a.firstPlan, planName)
	targ, ok := managePlan.Attr("hx-get")
	require.True(t, ok)
	a.managePlanUrl = a.absUrl(targ)
	a.last = doc
}

func (a *adminWebClient) loadManagePlan(t *testing.T) {
	resp := a.get(t, a.managePlanUrl)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	a.last = doc

	dn := doc.Find("div.plan-name").First().Text()
	require.Equal(t, a.firstPlan, dn)
}

func (a *adminWebClient) httpOp(
	t *testing.T,
	method string,
	url proto.URLString,
	data url.Values,
	hook func(*http.Request),
) *http.Response {
	if !strings.HasPrefix(url.String(), "http") {
		url = a.absUrl(url.String())
	}
	url = a.rewriteURL(t, url)
	req, err := http.NewRequest(method, url.String(), strings.NewReader(data.Encode()))
	require.NoError(t, err)
	if hook != nil {
		hook(req)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	a.addCSRFTok(t, req)
	client := &http.Client{Jar: a.jar}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func (a *adminWebClient) stopBilling(t *testing.T) {
	form := a.last.Find("form#plans-active-cancel").First()
	purl, ok := form.Attr("hx-put")
	require.True(t, ok)
	sub, ok := form.Find("input[name=subscription_id]").First().Attr("value")
	require.True(t, ok)
	a.subId = infra.StripeSubscriptionID(sub)
	a.assertPendingCancelInDB(t, false)
	plan, ok := form.Find("input[name=plan_id]").First().Attr("value")
	require.True(t, ok)

	data := url.Values{}
	data.Add("subscription_id", sub)
	data.Add("plan_id", plan)

	resp := a.httpOp(t, "PUT", proto.URLString(purl), data, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	a.last = doc
	txt := doc.Find("form#plans-active-resume").First().Find("button span.resume-plan").First().Text()
	require.Equal(t, "Resume plan", txt)
	a.assertPendingCancelInDB(t, true)
}

func (a *adminWebClient) resumeBilling(t *testing.T) {
	form := a.last.Find("form#plans-active-resume").First()
	purl, ok := form.Attr("hx-put")
	require.True(t, ok)
	sub, ok := form.Find("input[name=subscription_id]").First().Attr("value")
	require.True(t, ok)
	plan, ok := form.Find("input[name=plan_id]").First().Attr("value")
	require.True(t, ok)

	data := url.Values{}
	data.Add("subscription_id", sub)
	data.Add("plan_id", plan)
	resp := a.httpOp(t, "PUT", proto.URLString(purl), data, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	a.last = doc
	txt := doc.Find("form#plans-active-cancel").First().Find("button span.cancel-plan").First().Text()
	require.Equal(t, "Cancel", txt)
	a.assertPendingCancelInDB(t, false)
}

func (a *adminWebClient) loadQuotaPage(t *testing.T) {
	targ := "/admin/main"
	resp := a.get(t, a.absUrl(targ))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	a.last = doc
}

func (a *adminWebClient) quotaPageCountTheirs(t *testing.T, count int) {
	forms := a.last.Find("form.usage-row.theirs")
	require.Equal(t, count, forms.Length())
}

func (a *adminWebClient) quotaPageCountMine(t *testing.T, count int) {
	forms := a.last.Find("form.usage-row.mine")
	require.Equal(t, count, forms.Length())
}

func (a *adminWebClient) claimFirst(t *testing.T) {
	purl, ok := a.last.Find("form.usage-row.theirs").First().Find("button").Attr("hx-put")
	require.True(t, ok)
	data := url.Values{}
	resp := a.httpOp(t, "PUT", proto.URLString(purl), data, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func (a *adminWebClient) unclaimFirst(t *testing.T) {
	second := a.last.Find("form.usage-row.mine").EachWithBreak(func(i int, s *goquery.Selection) bool {
		return (i == 1)
	})
	butt := second.Find("button")
	_, disabled := butt.Attr("disabled")
	require.False(t, disabled)
	purl, ok := butt.Attr("hx-delete")
	require.True(t, ok)

	data := url.Values{}
	resp := a.httpOp(t, "DELETE", proto.URLString(purl), data, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func (a *adminWebClient) testClaimsAllSpent(t *testing.T) {
	butt := a.last.Find("form.usage-row.theirs").First().Find("button")
	_, ok := butt.Attr("disabled")
	require.True(t, ok)
	purl, ok := butt.Attr("hx-put")
	require.True(t, ok)
	data := url.Values{}
	resp := a.httpOp(t, "PUT", proto.URLString(purl), data, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	txt := doc.Find("span.error-text").First().Text()
	require.Equal(t, "over quota", txt)
}

type paymentSuccessEvent struct {
	shared.PaymentSuccess
	TimeCreated        time.Time
	Email              string
	SubscriptionItemID string
	IlID               string
	IdempotencyKey     string
}

func (p *paymentSuccessEvent) makeRandomIDs(t *testing.T) {
	if p.InvID == "" {
		p.InvID = infra.StripeInvoiceID(common.MakeFakeStripeID(t, "inv"))
	}
	if p.ChargeID == "" {
		p.ChargeID = infra.StripeChargeID(common.MakeFakeStripeID(t, "ch"))
	}
	p.SubscriptionItemID = common.MakeFakeStripeID(t, "si")
	p.IlID = common.MakeFakeStripeID(t, "il")
	p.EventID = infra.StripeEventID(common.MakeFakeStripeID(t, "evt"))
	p.IdempotencyKey = common.MakeFakeStripeID(t, "idem")
}

func (p *paymentSuccessEvent) export() map[string]interface{} {
	return map[string]interface{}{
		"InvoiceID":          p.InvID.String(),
		"ChargeID":           p.ChargeID.String(),
		"TimeCreated":        p.TimeCreated.Unix(),
		"CustomerID":         p.CustomerID.String(),
		"Email":              p.Email,
		"Amount":             p.Amount.Int(),
		"PeriodStart":        p.CurrentPeriodStart.Unix(),
		"PeriodEnd":          p.CurrentPeriodEnd.Unix(),
		"PlanID":             p.ProdID.String(),
		"PriceID":            p.PriceID.String(),
		"SubscriptionID":     p.SubID.String(),
		"SubscriptionItemID": p.SubscriptionItemID,
		"IlID":               p.IlID,
		"EventID":            p.EventID,
		"IdempotencyKey":     p.IdempotencyKey,
		"AmountDecimal":      fmt.Sprintf("%.2f", float64(p.Amount)/100.0),
	}
}

func (a *adminWebClient) loadPaymentSuccessData(t *testing.T) *paymentSuccessEvent {
	m := a.env.MetaContext()
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	fqu := a.getFQU(t)
	uid := fqu.Uid
	hostID, err := m.G().HostIDMap().LookupByHostID(m, fqu.HostID)
	require.NoError(t, err)

	var stripeSubId, stripeProdId, stripePriceId, intervalRaw, stripeCustomerId string
	var paidThrough time.Time
	var priceCents, intervalCount int

	err = db.QueryRow(
		m.Ctx(),
		`SELECT A.stripe_sub_id, A.paid_through, 
			B.stripe_prod_id,
		    C.stripe_price_id, C.price_cents, C.interval, C.interval_count,
			D.customer_id
		 FROM user_plans AS A
		 JOIN quota_plans AS B ON A.plan_id=B.plan_id
		 JOIN quota_plan_prices AS C ON (A.price_id=C.price_id AND A.plan_id=C.plan_id)
		 JOIN stripe_users AS D ON (A.uid=D.uid AND A.short_host_id=D.short_host_id)
		 WHERE A.short_host_id=$1 AND A.uid=$2 AND A.cancel_id=$3 AND D.cancel_id=$3`,
		hostID.Short.ExportToDB(),
		uid.ExportToDB(),
		proto.NilCancelID(),
	).Scan(&stripeSubId, &paidThrough, &stripeProdId, &stripePriceId, &priceCents,
		&intervalRaw, &intervalCount, &stripeCustomerId)
	require.NoError(t, err)

	var i infra.Interval
	err = i.ImportFromDB(intervalRaw)
	require.NoError(t, err)
	period := time.Duration(intervalCount) * i.Duration()
	now := m.Now()
	start := now
	end := now.Add(period)

	pse := &paymentSuccessEvent{
		PaymentSuccess: shared.PaymentSuccess{
			CustomerID:         infra.StripeCustomerID(stripeCustomerId),
			ProdID:             infra.StripeProdID(stripeProdId),
			PriceID:            infra.StripePriceID(stripePriceId),
			SubID:              infra.StripeSubscriptionID(stripeSubId),
			CurrentPeriodStart: start,
			Amount:             infra.Cents(priceCents),
			CurrentPeriodEnd:   end,
		},
		TimeCreated: now,
		Email:       "dobyns@hotmail.com",
	}
	pse.makeRandomIDs(t)
	return pse
}

func (a *adminWebClient) injectSubscriptionReupEvent(t *testing.T) {
	pse := a.loadPaymentSuccessData(t)
	a.injectPSE(t, pse)
}

func (a *adminWebClient) injectPSE(t *testing.T, pse *paymentSuccessEvent) {
	data := pse.export()
	tmpl := paymentSuccessWebhookJson
	tmplParsed, err := template.New("invoice").Parse(tmpl)
	require.NoError(t, err)
	var buf strings.Builder
	err = tmplParsed.Execute(&buf, data)
	require.NoError(t, err)
	payload := buf.String()

	var ev stripe.Event
	err = json.Unmarshal([]byte(payload), &ev)
	require.NoError(t, err)

	m := a.env.MetaContext()

	cfg, err := m.G().Config().StripeConfig(m.Ctx())
	require.NoError(t, err)
	whsec := cfg.WebhookSecret()
	up := webhook.UnsignedPayload{
		Payload:   []byte(payload),
		Secret:    string(whsec),
		Timestamp: time.Now(),
	}
	sp := webhook.GenerateTestSignedPayload(&up)
	webhookUrl := a.rewriteURL(t, a.absUrl("/stripe/webhook")).String()
	req, err := http.NewRequest("POST", webhookUrl, strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", sp.Header)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestWebLogin(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	defer bob.stop(t)
	awc := newAdminWebClient(t, bob, nil)
	awc.login(t)
}

func TestWebPaymentFlow(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	defer bob.stop(t)
	awc := newAdminWebClient(t, bob, nil)
	awc.login(t)
	awc.makePlan(t, "Basic 11 Alpha")
	awc.clickOnFirstPlanAndPrice(t)
	awc.doCheckout(t)
	awc.loadManagePlan(t)
	awc.stopBilling(t)
	awc.resumeBilling(t)
}

func TestWebPaymentWithWebhookRace(t *testing.T) {
	doit := func(checkoutThenWebhook bool) {
		bob := makeBobAndHisAgent(t)
		defer bob.stop(t)
		awc := newAdminWebClient(t, bob, nil)
		awc.login(t)
		awc.makePlan(t, "Basic 19 Nu")
		awc.clickOnFirstPlanAndPrice(t)
		if checkoutThenWebhook {
			awc.doCheckout(t)
		}
		awc.injectFirstPaymentEvent(t)
		if !checkoutThenWebhook {
			awc.doCheckout(t)
		}
		awc.loadManagePlan(t)
		awc.stopBilling(t)
		awc.resumeBilling(t)
	}
	doit(true)
	doit(false)
}

func TestBadCSRF(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	defer bob.stop(t)
	awc := newAdminWebClient(t, bob, nil)
	awc.login(t)
	awc.makePlan(t, "Basic 3 Alpha")
	awc.testBadCSRF = true
	awc.clickOnFirstPlanAndPrice(t)
}

func randomTeamName(t *testing.T) string {
	var buf [8]byte
	err := core.RandomFill(buf[:])
	require.NoError(t, err)
	return "team-" + hex.EncodeToString(buf[:])
}

func TestClaim(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	defer bob.stop(t)
	x := bob.agent
	merklePoke(t)
	for i := 0; i < 4; i++ {
		merklePoke(t)
		x.runCmd(t, nil, "team", "create", randomTeamName(t))
	}
	awc := newAdminWebClient(t, bob, nil)
	awc.login(t)
	awc.makePlan(t, "Basic 2 Iota")
	awc.clickOnFirstPlanAndPrice(t)
	awc.doCheckout(t)

	theirs := 4
	mine := 1

	grab := func() {
		theirs--
		mine++
	}

	giveUp := func() {
		theirs++
		mine--
	}

	loadAndCount := func() {
		awc.loadQuotaPage(t)
		awc.quotaPageCountTheirs(t, theirs)
		awc.quotaPageCountMine(t, mine)
	}

	loadAndCount()
	for i := 0; i < 3; i++ {
		awc.claimFirst(t)
		grab()
		loadAndCount()
	}

	awc.testClaimsAllSpent(t)

	awc.unclaimFirst(t)
	giveUp()
	loadAndCount()
	awc.claimFirst(t)
	grab()
	loadAndCount()
}
