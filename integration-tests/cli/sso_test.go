// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func (a *adminWebClient) enableSSO(t *testing.T, app *common.FakeIdPApp) proto.URLString {
	cb := proto.URLString(selOne(t, a.last, "span#sso-callback-url").Text())
	form := selOne(t, a.last, "form#vhost-sso")
	targ, exists := form.Attr("hx-put")
	require.True(t, exists)
	data := url.Values{}
	data.Add("sso-oauth2-config-url", app.ConfigURL().String())
	data.Add("sso-oauth2-client-id", app.ClientID().String())
	resp := a.httpOp(t, "PUT", proto.URLString(targ), data, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return cb
}

func rollbackAccessTokenExpirationTime(
	t *testing.T,
	mh *vanityHostTester,
	fqu proto.FQUser,
) {
	var etime time.Time
	m := mh.MetaContext()
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	shid, err := m.G().HostIDMap().LookupByHostID(m, fqu.HostID)
	require.NoError(t, err)
	defer db.Release()
	err = db.QueryRow(
		m.Ctx(),
		`SELECT etime FROM oauth2_access WHERE short_host_id=$1 and uid=$2`,
		shid.Short.ExportToDB(),
		fqu.Uid.ExportToDB(),
	).Scan(&etime)
	require.NoError(t, err)
	etime = etime.Add(-time.Duration(2) * common.MockIdPAccessTokenExpiration)
	tag, err := db.Exec(
		m.Ctx(),
		`UPDATE oauth2_access SET etime=$1 WHERE short_host_id=$2 and uid=$3`,
		etime,
		shid.Short.ExportToDB(),
		fqu.Uid.ExportToDB(),
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
}

type mockSSOLoginUI struct {
	url   proto.URLString
	res   proto.SSOLoginRes
	err   error
	urlCh chan proto.URLString
}

func (u *mockSSOLoginUI) ShowSSOLoginResult(
	m libclient.MetaContext,
	res proto.SSOLoginRes,
	err error,
) error {
	u.res = res
	u.err = err
	return nil
}

func (u *mockSSOLoginUI) ShowSSOLoginURL(
	m libclient.MetaContext,
	url proto.URLString,
) error {
	u.url = url
	if u.urlCh != nil {
		u.urlCh <- url
	}
	return nil
}

var _ libclient.SSOLoginUIer = &mockSSOLoginUI{}

func TestSSOHappyPath(t *testing.T) {
	defer common.DebugEntryAndExit()()

	mh := newVanityHostTester(t)
	vn := newVanityDomain(t, "adidas")

	mgmtUab := mh.makeUserOnPrimaryHost(t, vn)
	agent := mgmtUab.agent
	awc := newAdminWebClient(t, mgmtUab, mh.base)
	awc.login(t)
	awc.checkVirtualHostMgmt(t)
	awc.clickOnFirstPlanAndPrice(t)

	awc.doCheckout(t)
	awc.injectFirstPaymentEvent(t)
	hostingHost := awc.addVanityHost(t, vn)

	ctx := context.Background()
	idp := common.NewFakeIDP()
	app, err := idp.NewApp(common.AppName("adidas"))
	require.NoError(t, err)
	err = idp.Launch()
	require.NoError(t, err)
	defer func() {
		err := idp.Shutdown(ctx)
		require.NoError(t, err)
	}()

	mh.setCNAMEMapping(t, vn, hostingHost)
	awc.checkCNAME(t)
	callback := awc.enableSSO(t, app)
	app.AddCallback(callback)
	idpu, err := common.NewIdPUser("zed", "zodo", "adidas.ru")
	require.NoError(t, err)
	app.SetCurrentUser(idpu)
	zed := mh.newUserAtVHostWithAgent(t, "", agent, 2, vn, func(u proto.URLString) {
		cli := mh.base.HttpClient(time.Minute * time.Duration(15))
		resp, err := cli.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	status := agent.status(t)
	active := activeUserContext(t, status)
	require.Equal(t, zed.Info.Username.NameUtf8, active.Info.Username.NameUtf8)
	require.Equal(t, zed.Info.Fqu, active.Info.Fqu)

	// merkle poke is required to trigger proper user load and device list display
	mh.poke(t)

	ping := func() {
		var res proto.FQUser
		agent.runCmdToJSON(t, &res, "tools", "ping")
	}

	ping()

	rtPre := idpu.Refresh
	require.False(t, rtPre.IsZero())

	doRollback := func() {
		rollbackAccessTokenExpirationTime(t, mh, zed.Info.Fqu)
	}
	doRollback()

	// Check that the refresh token system is working
	ping()

	// Ensure that the refresh token got used and rotated
	rtPost := idpu.Refresh
	require.False(t, rtPost.IsZero())
	require.NotEqual(t, rtPre, rtPost)

	doRollback()
	idpu.LoggedOut = true
	err = agent.runCmdErr(nil, "tools", "ping")
	require.Error(t, err)
	require.Equal(t, core.OAuth2AuthError{Err: core.AuthError{}}, err)

	idpu.LoggedOut = false

	doSSoLoginViaCLI := func() {

		urlCh := make(chan proto.URLString)
		ui := mockSSOLoginUI{
			urlCh: urlCh,
		}
		uis := libclient.UIs{
			SSOLogin: &ui,
		}
		doneCh := make(chan error)
		go func() {
			err := agent.runCmdErrWithUIs(uis, "sso", "login")
			doneCh <- err
		}()

		var didSsoGet bool

		for i := 0; i < 2; i++ {
			select {
			case url := <-urlCh:
				require.NotEmpty(t, url)
				cli := mh.base.HttpClient(time.Minute)
				resp, err := cli.Get(url.String())
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				didSsoGet = true

			case err := <-doneCh:
				require.NoError(t, err)
				require.True(t, didSsoGet)
				require.NoError(t, ui.err)
				require.Equal(t, idpu.Email, ui.res.Email)
			}
		}

		ping()
	}

	doSSoLoginViaCLI()

	// now simulate what happens when the agent is restarted, the server-side access token
	// expires, and the refresh token is no longer good. The status command (`foks user list`)
	// should show the user account as "locked via SSO". But an `sso login` should clear
	// the lock.
	idpu.LoggedOut = true
	doRollback()
	agent.stop(t)
	agent.runAgent(t)
	st := agent.status(t)
	require.Len(t, st.Users, 1)
	require.Equal(t, zed.Info.Fqu, st.Users[0].Info.Fqu)
	typ, err := st.Users[0].LockStatus.GetSc()
	require.NoError(t, err)
	require.Equal(t, proto.StatusCode_SSO_IDP_LOCKED_ERROR, typ)
	idpu.LoggedOut = false

	doSSoLoginViaCLI()
}
