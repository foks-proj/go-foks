// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

type vanityHostTester struct {
	mgmt            *core.HostIDAndName
	mgmtProbe       proto.TCPAddr
	base            *common.TestEnv
	ctx             context.Context
	plan            *infra.Plan
	hosting         proto.Hostname
	hostingWildcard proto.Hostname
	cleeanupHooks   []func()
	mvh             *common.MockVanityHelper
}

var mut sync.Mutex
var _vht *vanityHostTester

func newVanityDomain(t *testing.T, prefix string) proto.Hostname {
	rd, err := core.RandomDomain()
	require.NoError(t, err)
	vd := prefix + "." + rd
	return proto.Hostname(vd)
}

func newVanityHostTester(t *testing.T) *vanityHostTester {
	mut.Lock()
	defer mut.Unlock()
	if _vht != nil {
		return _vht
	}

	domain := common.RandomDomain(t)

	mgmtHn := proto.Hostname("mgmt." + domain)
	hosting := proto.Hostname("hosting." + domain)
	hostingWildcard := proto.Hostname("*." + hosting.String())

	base := globalTestEnv.Fork(t, common.SetupOpts{
		Hostnames: &common.Hostnames{
			Probe: []proto.Hostname{
				mgmtHn, "localhost", "127.0.0.1", "::1",
			},
			User: []proto.Hostname{
				"localhost", "127.0.0.1", "::1",
				hostingWildcard,
			},
		},
		UseCertDirs:         true,
		MerklePollWait:      time.Hour,
		UseMockAutocertDoer: true,
	})

	cfg, ok := base.G.Config().(*shared.ConfigJSonnet)
	require.True(t, ok)
	require.NotNil(t, cfg)
	cfg.Data.VHosts.Vanity.HostingDomain_ = shared.DNSZoneJSON{
		Domain_: hosting,
		ZoneID_: proto.ZoneID("FAKEZONEID42"),
	}
	gs := base.Beacon(t)
	cfg.Data.GlobalServices.Beacon.Addr = gs.Addr

	chid := base.VHostMakeWithOpts(t, mgmtHn, shared.VHostInitOpts{
		Config: proto.HostConfig{
			Metering: proto.Metering{VHosts: true},
			Typ:      proto.HostType_VHostManagement,
		},
	})

	helper := common.NewMockVanityHelper(base.X509Material().ProbeCA)
	vh := base.G.VanityHelper()
	base.G.SetVanityHelper(helper)

	_vht = &vanityHostTester{
		mgmt:            chid,
		base:            base,
		ctx:             context.Background(),
		mvh:             helper,
		hosting:         hosting,
		hostingWildcard: hostingWildcard,
		cleeanupHooks: []func(){func() {
			base.G.SetVanityHelper(vh)
			_ = base.Shutdown()
		},
		},
	}

	// prepop the base host with some plans, so that way we can jump to the next step
	// in the various tests.
	_vht.poke(t)
	_vht.makePlan(t, "Basic 4 Iota")

	return _vht
}

func (v *vanityHostTester) MetaContext() shared.MetaContext {
	return shared.NewMetaContext(v.ctx, v.base.G)
}

func (v *vanityHostTester) setCNAMEMapping(t *testing.T, vn proto.Hostname, hn proto.Hostname) {
	err := v.mvh.SetCNAME(v.MetaContext(), vn, hn)
	require.NoError(t, err)
}

func (v *vanityHostTester) poke(t *testing.T) {
	v.base.DirectMerklePokeInTest(t)
}

func (v *vanityHostTester) serverMetaContext() shared.MetaContext {
	return v.base.MetaContext().WithContext(v.ctx)
}

func (v *vanityHostTester) makePlan(t *testing.T, dn string) {
	mc := v.serverMetaContext()
	plan := common.MakeRandomPlan(
		t,
		mc,
		dn,
		infra.Plan{
			MaxSeats:  3,
			MaxVhosts: 2,
			Quota:     1024 * 1024 * 512,
			Scope:     infra.QuotaScope_VHost,
			Sso:       true,
		},
	)
	v.plan = plan
}

func (v *vanityHostTester) newAgent(t *testing.T, vn proto.Hostname) *testAgent {
	agentOpts := agentOpts{
		dnsAliases: []proto.Hostname{v.mgmt.Hostname, vn, v.hostingWildcard},
		env:        v.base,
	}
	agent := newTestAgentWithOpts(t, agentOpts)
	return agent
}

func (v *vanityHostTester) makeUser(t *testing.T, vn proto.Hostname) (*testAgent, proto.UserContext) {
	agent := v.newAgent(t, vn)
	agent.runAgent(t)

	v.cleeanupHooks = append(v.cleeanupHooks, func() {
		agent.stop(t)
	})

	addr, ok := v.base.ProbeSrv().ListenerAddr().(*net.TCPAddr)
	require.True(t, ok)
	port := proto.Port(addr.Port)
	probe := proto.NewTCPAddr(v.mgmt.Hostname, port)
	v.mgmtProbe = probe

	uis := libclient.UIs{
		Signup: newMockSignupUI().
			withServer(probe).
			withEnv(v.base),
	}
	agent.runCmdWithUIs(t, uis, "--simple-ui", "signup")
	var st lcl.AgentStatus
	agent.runCmdToJSON(t, &st, "status")
	require.Equal(t, len(st.Users), 1)
	return agent, st.Users[0]
}

func (v *vanityHostTester) makeUserOnPrimaryHost(t *testing.T, vn proto.Hostname) *userAgentBundle {
	agent, user := v.makeUser(t, vn)
	return &userAgentBundle{
		agent:    agent,
		username: user.Info.Username.NameUtf8,
	}
}

func (v *vanityHostTester) newUserAtVHostWithAgent(
	t *testing.T,
	codeRaw string,
	agent *testAgent,
	nUsersExpected int,
	vn proto.Hostname,
	cb func(proto.URLString),
) *proto.UserContext {
	muic := rem.MultiUseInviteCode(codeRaw)
	code := rem.NewInviteCodeWithMultiuse(muic)

	addr, ok := v.base.ProbeSrv().ListenerAddr().(*net.TCPAddr)
	require.True(t, ok)
	probe := proto.NewTCPAddr(vn, proto.Port(addr.Port))

	sigui := newMockSignupUI().
		withServer(probe).
		withInviteCode(&code).
		withEnv(v.base).
		withSSOUrlCb(cb).
		withDeviceKey()
	uis := libclient.UIs{
		Signup: sigui,
	}
	agent.runCmdWithUIs(t, uis, "--simple-ui", "signup")
	var st lcl.AgentStatus
	agent.runCmdToJSON(t, &st, "status")
	require.Equal(t, len(st.Users), nUsersExpected)

	for _, u := range st.Users {
		if u.Info.Active {
			return &u
		}
	}
	require.Fail(t, "no active user found")
	return nil
}

func (v *vanityHostTester) newUserAtVHost(
	t *testing.T,
	codeRaw string,
	agent *testAgent,
	vn proto.Hostname,
) *proto.UserContext {
	return v.newUserAtVHostWithAgent(t, codeRaw, agent, 2, vn, nil)
}

func selOne(
	t *testing.T,
	doc interface {
		Find(sel string) *goquery.Selection
	},
	sel string,
) *goquery.Selection {
	s := doc.Find(sel)
	require.Equal(t, 1, s.Length())
	return s.First()
}

func (a *adminWebClient) addVanityHost(t *testing.T, nm proto.Hostname) proto.Hostname {

	form := selOne(t, a.last, "form#vhost-add")
	targ, found := form.Attr("hx-post")
	require.True(t, found, "hx-post")
	inp := selOne(t, form, "input#full-vanity-hostname")
	inpName, found := inp.Attr("name")
	require.True(t, found, "name")

	data := url.Values{}
	data.Add(inpName, nm.String())
	data.Add("toggle-byod", "checked")
	resp := a.httpOp(t, "POST", proto.URLString(targ), data, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()

	// the next page to load up is the "edit" vanity host mapper page
	button := selOne(t, doc, "div.vhost-row button.edit-vhost-button")
	getTarg, found := button.Attr("hx-get")
	require.True(t, found, "hx-get")

	data = url.Values{}
	resp2 := a.httpOp(t, "GET", proto.URLString(getTarg), data, nil)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	doc, err = goquery.NewDocumentFromReader(resp2.Body)
	require.NoError(t, err)
	defer resp2.Body.Close()
	hcn := selOne(t, doc, "span#hosting-cname").Text()
	a.last = doc
	return proto.Hostname(hcn)
}

func (a *adminWebClient) checkCNAME(t *testing.T) {
	but := selOne(t, a.last, "button#button-check-vhost")
	targ, found := but.Attr("hx-get")
	require.True(t, found, "hx-get")

	resp := a.httpOp(t, "GET", proto.URLString(targ), url.Values{}, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	a.last = doc
}

func (a *adminWebClient) newVhostInvite(t *testing.T) string {
	but := selOne(t, a.last, "button#new-invite-code")
	targ, found := but.Attr("hx-post")
	require.True(t, found, "hx-post")

	resp := a.httpOp(t, "POST", proto.URLString(targ), url.Values{}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	code := selOne(t, doc, "span.invite-code").Text()
	require.NotEmpty(t, code)
	return code
}

func (a *adminWebClient) openUserViewership(t *testing.T) {
	form := selOne(t, a.last, "form#user-viewership")
	sel := selOne(t, form, "select")
	opts := sel.Find("option")
	require.Equal(t, 2, opts.Length())
	var vals []string
	opts.Each(func(i int, s *goquery.Selection) {
		val, found := s.Attr("value")
		require.True(t, found, "value")
		vals = append(vals, val)
	},
	)
	slices.Sort(vals)
	require.Equal(t, []string{
		proto.ViewershipMode_Closed.String(),
		proto.ViewershipMode_Open.String(),
	}, vals)
	targ, found := form.Attr("hx-patch")
	require.True(t, found, "hx-patch")
	varName, found := sel.Attr("name")
	require.True(t, found, "name")
	data := url.Values{}
	data.Add(varName, proto.ViewershipMode_Open.String())
	resp := a.httpOp(t, "PATCH", proto.URLString(targ), data, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewVanityDomainViaWeb(t *testing.T) {
	defer common.DebugEntryAndExit()()

	mh := newVanityHostTester(t)
	vn := newVanityDomain(t, "nike")

	// need to pass the vanity name (vn) so we can write it into the agent's
	// DNS alias mappings
	mgmtUab := mh.makeUserOnPrimaryHost(t, vn)
	awc := newAdminWebClient(t, mgmtUab, mh.base)
	awc.login(t)
	awc.checkVirtualHostMgmt(t)
	awc.clickOnFirstPlanAndPrice(t)

	awc.doCheckout(t)
	awc.injectFirstPaymentEvent(t)
	hostingHost := awc.addVanityHost(t, vn)

	mh.setCNAMEMapping(t, vn, hostingHost)
	awc.checkCNAME(t)
	code := awc.newVhostInvite(t)

	// Part 2: Set the new vhost to have open user viewing.
	// Then create a team and add a user to the team with a simple
	// 1-way round trip (not with a 3-way handshake).
	awc.openUserViewership(t)

	// This is the default user used below to make a team
	mh.newUserAtVHost(t, code, mgmtUab.agent, vn)

	// bob is our second user, who will be added to the team by name
	bobAgent := mh.newAgent(t, vn)
	bobAgent.runAgent(t)
	defer bobAgent.stop(t)
	bob := mh.newUserAtVHostWithAgent(t, code, bobAgent, 1, vn, nil)

	// do the addition
	mh.poke(t)
	mh.poke(t)
	teamname := "toronto-maple-leafs"
	awc.uab.agent.runCmd(t, nil, "team", "create", teamname)
	mh.poke(t)
	awc.uab.agent.runCmd(t, nil, "team", "add", teamname, bob.Info.Username.NameUtf8.String())

}
