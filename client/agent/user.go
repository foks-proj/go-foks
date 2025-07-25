// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/sso"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func (c *AgentConn) Clear(ctx context.Context) error {
	m := c.MetaContext(ctx)
	err := libclient.ClearActiveUsers(m)
	return err
}

func (c *AgentConn) AgentStatus(ctx context.Context) (lcl.AgentStatus, error) {
	var ret lcl.AgentStatus
	tmp, err := c.g.AgentStatus(ctx)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ActiveUser(ctx context.Context) (proto.UserContext, error) {
	var ret proto.UserContext
	tmp, err := c.g.ActiveUserExport()
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) Ping(ctx context.Context) (proto.FQUser, error) {
	m := c.MetaContext(ctx)
	var ret proto.FQUser
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{AssertUnlocked: true})
	if err != nil {
		return ret, err
	}
	tmp, err := pingWithActiveUser(m, au)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func pingWithActiveUser(m libclient.MetaContext, au *libclient.UserContext) (*proto.FQUser, error) {
	gcli, err := au.UserGCli(m)
	if err != nil {
		return nil, err
	}
	gcli.Reset()
	cli, err := au.UserClient(m)
	if err != nil {
		return nil, err
	}
	uid, err := cli.Ping(m.Ctx())
	if err != nil {
		return nil, err
	}
	ret := proto.FQUser{
		Uid:    uid,
		HostID: au.HostID(),
	}
	return &ret, nil

}

func (c *AgentConn) ActiveUserCheckLocked(ctx context.Context) (lcl.ActiveUserCheckLockedRes, error) {
	m := c.MetaContext(ctx)
	var ret lcl.ActiveUserCheckLockedRes
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return ret, err
	}
	aux, err := au.Export()
	if err != nil {
		return ret, err
	}
	err = au.AssertUnlocked(ctx)
	status := core.ErrorToStatus(err)
	return lcl.ActiveUserCheckLockedRes{
		LockStatus: status,
		User:       *aux,
	}, nil
}

func getDefaultHostID(c *AgentConn) func(m libclient.MetaContext) (proto.HostID, error) {
	return func(m libclient.MetaContext) (proto.HostID, error) {
		var zed proto.HostID
		var def proto.TCPAddr
		pr, err := c.probe(m, def, 0)
		if err != nil {
			return zed, err
		}
		return pr.Chain().HostID(), nil
	}
}

func (c *AgentConn) SwitchUser(ctx context.Context, u lcl.LocalUserIndexParsed) error {
	m := c.MetaContext(ctx)
	return libclient.LookupAndSwitchUserWithFallback(m, u, getDefaultHostID(c))
}

func (c *AgentConn) SwitchUserByInfo(ctx context.Context, i proto.UserInfo) error {
	m := c.MetaContext(ctx)
	return libclient.SwitchActiveUserFallbackToLoad(m, i)
}

func (c *AgentConn) GetExistingUsers(ctx context.Context) ([]proto.UserInfo, error) {
	m := c.MetaContext(ctx)
	alu := libclient.NewAllUserLoader()
	err := alu.Run(m)
	if err != nil {
		return nil, err
	}
	return alu.Users(), nil
}

func (c *AgentConn) SkmInfo(ctx context.Context) (lcl.StoredSecretKeyBundle, error) {
	m := c.MetaContext(ctx)
	var zed lcl.StoredSecretKeyBundle
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return zed, err
	}
	skm, err := au.LoadSkkm(m)
	if err != nil {
		return zed, err
	}
	bun := skm.Bundle()
	if bun == nil {
		return zed, core.NotFoundError("skm bundle")
	}
	ret, err := bun.StripSecrets()
	if err != nil {
		return zed, err
	}
	return ret, err
}

type pmeWrapper struct {
	pme *libclient.PMELoggedIn
}

func (p *pmeWrapper) PME() libclient.PassphraseManagerEngine { return p.pme }
func (p *pmeWrapper) RawPassphrase() proto.Passphrase        { return "" }
func (p *pmeWrapper) PUK() core.SharedPrivateSuiter          { return nil }
func (p *pmeWrapper) Arg() *rem.SetPassphraseArg             { return nil }

func (c *AgentConn) SetSkmEncryption(ctx context.Context, mode proto.SecretKeyStorageType) error {
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return err
	}
	puks := au.PUKs()

	skm, err := au.LoadSkkm(m)
	if err != nil {
		return err
	}

	pme, err := libclient.NewPMELoggedIn(m, au)
	if err != nil {
		return err
	}

	typ, err := skm.UnlockSeed(m.Ctx(), pme, puks)
	if err != nil {
		return err
	}

	if typ == mode {
		return core.NoChangeError("encryption mode was already set")
	}

	row := skm.Row()

	skm, err = libclient.UpdateSecretWithMode(
		m,
		row,
		*skm.Seed(),
		&pmeWrapper{pme: pme},
		puks,
		mode,
	)
	if err != nil {
		return err
	}
	au.SetSkmm(skm)
	return nil
}

func (c *AgentConn) LoadMe(ctx context.Context) (lcl.UserMetadataAndSigchainState, error) {
	var ret lcl.UserMetadataAndSigchainState
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return ret, err
	}
	uw, err := libclient.LoadMe(m, au)
	if err != nil {
		return ret, err
	}
	return *uw.ProtoWithMetadata(), nil
}

func (c *AgentConn) UserLock(ctx context.Context) error {
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{AssertUnlocked: true})
	if err != nil {
		return err
	}
	err = au.ClearSecrets()
	if err != nil {
		return err
	}
	return nil
}

type SwitchSession struct {
	SessionBase
	id proto.UISessionID
}

func (s *SwitchSession) Init(id proto.UISessionID) {
	s.SessionBase.Init()
	s.id = id
}

func (c *AgentConn) LoginStartSsoLoginFlow(
	ctx context.Context,
	id proto.UISessionID,
) (
	lcl.SsoLoginFlow,
	error,
) {
	var ret lcl.SsoLoginFlow
	m := c.MetaContext(ctx)
	sess, err := c.agent.sessions.SSOLogin(id)
	if err != nil {
		return ret, err
	}
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{AssertUnlocked: true, SSOLogin: true})
	if err != nil {
		return ret, err
	}
	hs := au.HomeServer()
	if hs == nil {
		return ret, core.InternalError("no home server")
	}
	reg, err := hs.RegCli(m)
	if err != nil {
		return ret, err
	}
	cfg, err := reg.GetServerConfig(m.Ctx())
	if err != nil {
		return ret, err
	}
	if cfg.Sso == nil {
		return ret, core.OAuth2Error("no sso config for server")
	}
	if cfg.Sso.Oauth2 == nil {
		return ret, core.VersionNotSupportedError("SSO protocol")
	}
	ma, err := hs.MerkleAgent(m)
	if err != nil {
		return ret, err
	}
	defer ma.Shutdown()
	root, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return ret, err
	}
	flow, err := sso.PrepOAuth2Session(au.FQU(), root)
	if err != nil {
		return ret, err
	}
	uid := au.FQU().Uid
	authURI, err := reg.InitOAuth2Session(
		m.Ctx(),
		rem.InitOAuth2SessionArg{
			Id:           flow.Id,
			PkceVerifier: flow.Verifier,
			Nonce:        flow.Nonce,
			Uid:          &uid,
		},
	)
	if err != nil {
		return ret, err
	}
	ret.Url = authURI
	sess.oauth2 = flow
	sess.ssoCfg = cfg.Sso
	return ret, nil
}

func (c *AgentConn) LoginWaitForSsoLogin(
	ctx context.Context,
	id proto.UISessionID,
) (
	proto.SSOLoginRes,
	error,
) {
	var ret proto.SSOLoginRes
	m := c.MetaContext(ctx)
	sess, err := c.agent.sessions.SSOLogin(id)
	if err != nil {
		return ret, err
	}
	if sess.ssoCfg == nil || sess.ssoCfg.Oauth2 == nil {
		return ret, core.InternalError("no sso config")
	}
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{AssertUnlocked: true, SSOLogin: true})
	if err != nil {
		return ret, err
	}
	hs := au.HomeServer()
	if hs == nil {
		return ret, core.InternalError("no home server")
	}
	reg, err := hs.RegCli(m)
	if err != nil {
		return ret, err
	}
	toks, err := reg.PollOAuth2SessionCompletion(m.Ctx(),
		rem.PollOAuth2SessionCompletionArg{
			Id:       sess.oauth2.Id,
			Wait:     proto.ExportDurationMilli(time.Duration(10) * time.Minute),
			ForLogin: true,
		},
	)
	if err != nil {
		return ret, err
	}
	if sess.oauth2 == nil {
		return ret, core.InternalError("no oauth2 flow")
	}
	g, err := m.G().OAuth2GlobalContext()
	if err != nil {
		return ret, err
	}
	idpCfg, err := m.G().OAuth2IdPConfigSet().Get(m.Ctx(), g, sess.ssoCfg.Oauth2.ConfigURI)
	if err != nil {
		return ret, err
	}
	idtok, err := sso.OAuth2CheckTokens(m.Ctx(), g, idpCfg, toks.Toks, sess.ssoCfg.Oauth2.ClientID, sess.oauth2.Nonce)
	if err != nil {
		return ret, err
	}
	sess.oauth2.Idtok = idtok
	ssoArg, err := c.signSSOArgs(m, sess.oauth2, au.PrivKeys.GetDevkey(), au.HostID())
	if err != nil {
		return ret, err
	}

	err = reg.SsoLogin(m.Ctx(), rem.SsoLoginArg{
		Uid:  au.UID(),
		Args: ssoArg,
	})
	if err != nil {
		return ret, err
	}

	err = au.MarkSSOUnlocked()
	if err != nil {
		return ret, err
	}

	// Check that our userclient is up and running now that we've made an SSO login
	_, err = pingWithActiveUser(m, au)
	if err != nil {
		return ret, err
	}

	ret.Email = idtok.Email
	ret.Username = idtok.Username
	ret.Issuer = idtok.Issuer

	return ret, nil
}

func (c *AgentConn) RemoveKey(ctx context.Context, u lcl.LocalUserIndexParsed) error {
	m := c.MetaContext(ctx)
	return libclient.RemoveKey(m, u, getDefaultHostID(c))
}

func (c *AgentConn) RemoveKeyByInfo(ctx context.Context, info proto.UserInfo) error {
	m := c.MetaContext(ctx)
	return libclient.RemoveKeyByInfo(m, info)
}

var _ lcl.UserInterface = (*AgentConn)(nil)
