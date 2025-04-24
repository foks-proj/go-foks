// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/sso"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type oauth2Session struct {
	tinyURI      proto.URLString
	cfg          *proto.OAuth2Config
	cfgId        proto.SSOConfigID
	idpCfg       *sso.OAuth2IdPConfig
	authURI      proto.URLString
	tokenURI     proto.URLString
	nonce        proto.OAuth2Nonce
	pkceVerifier proto.OAuth2PKCEVerifier
	idToken      proto.OAuth2IDToken
	accessToken  proto.OAuth2AccessToken
	refreshToken proto.OAuth2RefreshToken
	etime        time.Time
	issuer       proto.URLString
	username     proto.NameUtf8
	displayName  proto.NameUtf8
	email        proto.Email
	subject      proto.OAuth2Subject
	uid          *proto.UID
	accessValid  bool
}

func (o *oauth2Session) loadReferencedConfig(m MetaContext) error {
	if o.cfgId.IsZero() {
		return core.InternalError("oauth2 config not set")
	}
	cfg, err := LoadSSOConfig(m, &o.cfgId)
	if err != nil {
		return err
	}
	err = sso.AssertOAuth2(cfg)
	if err != nil {
		return err
	}
	o.cfg = cfg.Oauth2
	return nil
}

func (o *oauth2Session) loadLatestConfig(m MetaContext) error {
	cfg, err := LoadSSOConfig(m, nil)
	if err != nil {
		return err
	}
	err = sso.AssertOAuth2(cfg)
	if err != nil {
		return err
	}
	o.cfg = cfg.Oauth2
	return nil
}

func (o *oauth2Session) getIdPConfig(m MetaContext) error {
	og, err := m.G().OAuth2GlobalContext(m.Ctx())
	if err != nil {
		return err
	}
	u, err := m.G().oauth2ConfigSet.Get(m.Ctx(), og, o.cfg.ConfigURI)
	if err != nil {
		return err
	}
	o.idpCfg = u
	return nil
}

func (o *oauth2Session) lookupAuthURI(m MetaContext) error {
	err := o.getIdPConfig(m)
	if err != nil {
		return err
	}
	o.authURI = o.idpCfg.AuthURI
	return nil
}

func (o *oauth2Session) lookupTokenURI(m MetaContext) error {
	err := o.getIdPConfig(m)
	if err != nil {
		return err
	}
	o.tokenURI = o.idpCfg.TokenURI
	return nil
}

func (o *oauth2Session) loadFromDB(m MetaContext, id proto.OAuth2SessionID) error {
	var nonce string
	var pkceVerifier string
	var cfgId []byte
	var err error
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	err = db.QueryRow(
		m.Ctx(),
		`SELECT nonce, pkce_verifier, config_id
		FROM oauth2_sessions
		WHERE short_host_id=$1 AND oauth2_session_id=$2`,
		m.ShortHostID().ExportToDB(),
		id.ExportToDB(),
	).Scan(&nonce, &pkceVerifier, &cfgId)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NotFoundError("oauth2 session")
	}
	if err != nil {
		return err
	}

	err = o.cfgId.ImportFromDB(cfgId)
	if err != nil {
		return err
	}

	o.pkceVerifier = proto.OAuth2PKCEVerifier(pkceVerifier)
	o.nonce = proto.OAuth2Nonce(nonce)
	return nil
}

func (o *oauth2Session) writeDB(m MetaContext, arg rem.InitOAuth2SessionArg) error {
	return RetryTxUserDB(m, "oauth2_session", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO oauth2_sessions
			   (short_host_id, config_id, oauth2_session_id, nonce, pkce_verifier, ctime, uid)
			 VALUES($1, $2, $3, $4, $5, $6, $7)`,
			m.ShortHostID().ExportToDB(),
			o.cfg.Id.ExportToDB(),
			arg.Id.ExportToDB(),
			arg.Nonce.String(),
			arg.PkceVerifier.String(),
			m.Now(),
			arg.Uid.ExportToDBMaybeNil(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert oauth2 session")
		}
		return nil
	})
}

func (o *oauth2Session) makeURI(m MetaContext, arg rem.InitOAuth2SessionArg) error {
	state, err := arg.Id.StringErr()
	if err != nil {
		return err
	}
	base, err := AdminBaseURL(m)
	if err != nil {
		return err
	}
	wcfg, err := m.G().Config().WebConfig(m.Ctx())
	if err != nil {
		return err
	}
	o.tinyURI = base.PathJoin(
		wcfg.OAuth2().Tiny().PathJoin(
			proto.URLString(state),
		),
	)
	return nil
}

func (o *oauth2Session) init(m MetaContext, arg rem.InitOAuth2SessionArg) error {
	err := o.loadLatestConfig(m)
	if err != nil {
		return err
	}
	err = o.makeURI(m, arg)
	if err != nil {
		return err
	}
	err = o.writeDB(m, arg)
	if err != nil {
		return err
	}
	return nil
}

func (o *oauth2Session) pkceChallengeCode() (proto.OAuth2PKCEChallengeCode, error) {
	if o.pkceVerifier == "" {
		return "", core.InternalError("pkce verifier not set")
	}
	return sso.HashPKCE(o.pkceVerifier)
}

func (o *oauth2Session) makeAuthURI(m MetaContext, id proto.OAuth2SessionID) error {

	u, err := url.Parse(o.authURI.String())
	if err != nil {
		return err
	}
	// Include "offline_access" to get a refresh token.
	scopes := []string{"openid", "email", "profile", "offline_access"}
	ids, err := id.StringErr()
	if err != nil {
		return err
	}
	chal, err := o.pkceChallengeCode()
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("client_id", o.cfg.ClientID.String())
	q.Set("redirect_uri", o.cfg.RedirectURI.String())
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", ids)
	q.Set("nonce", o.nonce.String())
	if o.cfg.ClientSecret.IsZero() {
		q.Set("code_challenge", chal.String())
		q.Set("code_challenge_method", "S256")
	} else {
		q.Set("client_secret", o.cfg.ClientSecret.String())
	}
	u.RawQuery = q.Encode()

	o.authURI = proto.URLString(u.String())
	return nil
}

func (o *oauth2Session) authRedirect(m MetaContext, id proto.OAuth2SessionID) error {
	err := o.loadFromDB(m, id)
	if err != nil {
		return err
	}
	err = o.loadReferencedConfig(m)
	if err != nil {
		return err
	}
	err = o.lookupAuthURI(m)
	if err != nil {
		return err
	}
	err = o.makeAuthURI(m, id)
	if err != nil {
		return err
	}
	return nil
}

func (o *oauth2Session) writeTokensToDB(
	m MetaContext,
	id proto.OAuth2SessionID,
) error {
	return RetryTxUserDB(m, "oauth2_session", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE oauth2_sessions
			 SET id_token=$1, access_token=$2, refresh_token=$3, etime=$4, issuer=$5, 
			   preferred_username=$6, email=$7, name=$8, sub=$9
			 WHERE short_host_id=$10 AND oauth2_session_id=$11`,
			o.idToken.String(),
			o.accessToken.String(),
			o.refreshToken.String(),
			o.etime.UTC(),
			o.issuer.String(),
			o.username.String(),
			o.email.String(),
			o.displayName.String(),
			o.subject.String(),
			m.ShortHostID().ExportToDB(),
			id.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update oauth2 session")
		}
		return nil
	})
}

func (o *oauth2Session) checkTokens(m MetaContext) error {

	g, err := m.G().OAuth2GlobalContext(m.Ctx())
	if err != nil {
		return err
	}
	toks := proto.OAuth2TokenSet{
		IdToken:     o.idToken,
		AccessToken: o.accessToken,
	}
	tmp, err := sso.OAuth2CheckTokens(m.Ctx(), g, o.idpCfg, toks, o.cfg.ClientID, o.nonce)
	if err != nil {
		return err
	}
	o.issuer = tmp.Issuer
	o.username = tmp.Username
	o.email = tmp.Email
	o.displayName = tmp.DisplayName
	o.subject = tmp.Subject
	return nil
}

func (o *oauth2Session) pokeQueue(m MetaContext, id proto.OAuth2SessionID) error {
	qs := m.G().QueueServer(m.Ctx())
	if o.accessToken.IsZero() || o.idToken.IsZero() {
		return core.InternalError("missing access or id token")
	}
	return OAuth2Poke(m.Ctx(), qs, id, proto.OAuth2TokenSet{
		IdToken:     o.idToken,
		AccessToken: o.accessToken,
		Expires:     proto.ExportTime(o.etime),
		Username:    o.username,
	})
}

func (o *oauth2Session) exchange(m MetaContext, arg *ExchangeArg) error {
	err := o.loadFromDB(m, arg.Oid)
	if err != nil {
		return err
	}
	err = o.loadReferencedConfig(m)
	if err != nil {
		return err
	}
	err = o.lookupTokenURI(m)
	if err != nil {
		return err
	}
	err = o.postExchange(m, &arg.Code)
	if err != nil {
		return err
	}
	err = o.checkTokens(m)
	if err != nil {
		return err
	}
	err = o.writeTokensToDB(m, arg.Oid)
	if err != nil {
		return err
	}
	err = o.pokeQueue(m, arg.Oid)
	if err != nil {
		return err
	}
	return nil
}

// TokenResponse is the shape of typical OAuth2 token JSON
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (o *oauth2Session) postExchange(m MetaContext, arg *proto.OAuth2Code) error {
	if o.tokenURI.IsZero() {
		return core.InternalError("token URI not set")
	}
	endpoint := o.tokenURI.String()

	data := url.Values{}

	if arg != nil {
		data.Set("grant_type", "authorization_code")
		data.Set("code", arg.String())
	} else {
		if o.refreshToken.IsZero() {
			return errors.New("no valid refresh token")
		}
		data.Set("grant_type", "refresh_token")
		data.Set("refresh_token", o.refreshToken.String())
	}
	data.Set("redirect_uri", o.cfg.RedirectURI.String())
	data.Set("client_id", o.cfg.ClientID.String())
	if o.cfg.ClientSecret.IsZero() {
		data.Set("client_secret", o.cfg.ClientSecret.String())
	}
	if o.pkceVerifier != "" {
		data.Set("code_verifier", o.pkceVerifier.String())
	}

	req, err := http.NewRequestWithContext(m.Ctx(), http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusBadRequest:
		var er ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
			return err
		}
		if er.Error == "invalid_grant" {
			return core.AuthError{}
		}
		return core.NewOAuth2IdPError(er.Error, er.ErrorDescription)
	case http.StatusOK:
	default:
		bodyBytes, _ := io.ReadAll(resp.Body)
		return core.HttpError{Code: uint(resp.StatusCode), Desc: string(bodyBytes)}
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return err
	}
	o.idToken = proto.OAuth2IDToken(tr.IDToken)
	o.accessToken = proto.OAuth2AccessToken(tr.AccessToken)
	o.refreshToken = proto.OAuth2RefreshToken(tr.RefreshToken)
	now := m.Now()
	expireDur := time.Duration(tr.ExpiresIn) * time.Second
	etime := now.Add(expireDur)
	o.etime = etime

	return nil
}

func InitOAuth2Session(
	m MetaContext,
	arg rem.InitOAuth2SessionArg,
) (
	proto.URLString,
	error,
) {
	var sess oauth2Session
	err := sess.init(m, arg)
	return sess.tinyURI, err
}

func OAuth2AuthRedirect(
	m MetaContext,
	id proto.OAuth2SessionID,
) (
	proto.URLString,
	error,
) {
	var sess oauth2Session
	err := sess.authRedirect(m, id)
	return sess.authURI, err
}

type OAuth2GlobalContext struct {
	g              *GlobalContext
	refreshInteral time.Duration
	requestTimeout time.Duration
}

func (o *OAuth2GlobalContext) Now() time.Time                     { return o.g.Now() }
func (o *OAuth2GlobalContext) ConfigSet() *sso.OAuth2IdPConfigSet { return o.g.oauth2ConfigSet }
func (o *OAuth2GlobalContext) RefreshInterval() time.Duration     { return o.refreshInteral }
func (o *OAuth2GlobalContext) RequestTimeout() time.Duration      { return o.requestTimeout }

var _ sso.OAuth2GlobalContext = (*OAuth2GlobalContext)(nil)

func (g *GlobalContext) OAuth2GlobalContext(ctx context.Context) (*OAuth2GlobalContext, error) {
	wcfg, err := g.Config().WebConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &OAuth2GlobalContext{
		g:              g,
		refreshInteral: wcfg.OAuth2().RefreshInterval(),
		requestTimeout: wcfg.OAuth2().RequestTimeout(),
	}, nil
}

type ExchangeArg struct {
	Oid  proto.OAuth2SessionID
	Code proto.OAuth2Code
}

func OAuth2ExchangeCodeForToken(
	m MetaContext,
	arg *ExchangeArg,
) error {
	var sess oauth2Session
	return sess.exchange(m, arg)
}

func loadOAuth2Config(
	m MetaContext,
	db *pgxpool.Conn,
	cfgId *proto.SSOConfigID,
) (
	*proto.OAuth2Config,
	error,
) {
	var cfgu, cliId, cliSec string
	var configID []byte
	args := []any{m.ShortHostID().ExportToDB()}
	q := `SELECT config_url, client_id, client_secret, config_id
		 FROM sso_oauth2_config
		 WHERE short_host_id=$1`
	if cfgId != nil {
		q += " AND config_id=$2"
		args = append(args, cfgId.ExportToDB())
	} else {
		q += " AND cancel_id=$2"
		args = append(args, proto.NilCancelID())
	}
	err := db.QueryRow(m.Ctx(), q, args...).Scan(&cfgu, &cliId, &cliSec, &configID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ret := proto.OAuth2Config{
		ConfigURI:    proto.URLString(cfgu).Normalize(),
		ClientID:     proto.OAuth2ClientID(cliId),
		ClientSecret: proto.OAuth2ClientSecret(cliSec),
	}
	cburl, err := OAuth2CallbackURL(m)
	if err != nil {
		return nil, err
	}
	err = ret.Id.ImportFromDB(configID)
	if err != nil {
		return nil, err
	}
	ret.RedirectURI = cburl
	return &ret, nil
}

func setOAuth2Config(
	m MetaContext,
	db DbExecer,
	cfg proto.OAuth2Config,
) error {

	canc, err := proto.RandomID16er[proto.CancelID]()
	if err != nil {
		return err
	}
	tag, err := db.Exec(
		m.Ctx(),
		`UPDATE sso_oauth2_config SET cancel_id=$1, mtime=NOW() WHERE short_host_id=$2`,
		canc.ExportToDB(),
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 && tag.RowsAffected() != 0 {
		return core.UpdateError("failed to cancel current oauth2 config")
	}

	cfgid, err := proto.RandomID16er[proto.SSOConfigID]()
	if err != nil {
		return err
	}

	tag, err = db.Exec(
		m.Ctx(),
		`INSERT INTO sso_oauth2_config
		 (short_host_id, config_id, cancel_id, config_url, client_id, client_secret, ctime, mtime)
		 VALUES($1, $2, $3, $4, $5, $6, $7, $7)`,
		m.ShortHostID().ExportToDB(),
		cfgid.ExportToDB(),
		proto.NilCancelID(),
		cfg.ConfigURI.String(),
		cfg.ClientID.String(),
		cfg.ClientSecret.String(),
		m.Now(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert oauth2 config")
	}
	return nil
}

func PollOAuth2SessionCompletion(
	m MetaContext,
	id proto.OAuth2SessionID,
	wait time.Duration,
) (
	*proto.OAuth2TokenSet,
	error,
) {
	end := m.Now().Add(wait)
	pollInterval := time.Second * 5 // wait 5 minutes on each poll and retry

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	pollDBOnce := func() (*proto.OAuth2TokenSet, error) {
		var accessToken, idToken, username *string
		var etime *time.Time

		err := db.QueryRow(
			m.Ctx(),
			`SELECT access_token, id_token, etime, preferred_username  
			 FROM oauth2_sessions
			 WHERE short_host_id=$1 AND oauth2_session_id=$2`,
			m.ShortHostID().ExportToDB(),
			id.ExportToDB(),
		).Scan(&accessToken, &idToken, &etime, &username)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if accessToken == nil || idToken == nil || etime == nil {
			return nil, nil
		}
		var un proto.NameUtf8
		if username != nil {
			un = proto.NameUtf8(*username)
		}
		return &proto.OAuth2TokenSet{
			IdToken:     proto.OAuth2IDToken(*idToken),
			AccessToken: proto.OAuth2AccessToken(*accessToken),
			Expires:     proto.ExportTime(*etime),
			Username:    un,
		}, nil
	}

	pollQueueOnce := func() (*proto.OAuth2TokenSet, error) {
		qs := m.G().QueueServer(m.Ctx())
		return OAuth2Wait(m.Ctx(), qs, id, pollInterval)
	}

	for m.Now().Before(end) {
		for _, hook := range []func() (*proto.OAuth2TokenSet, error){
			pollDBOnce,
			pollQueueOnce,
		} {
			ret, err := hook()
			if err != nil || ret != nil {
				return ret, err
			}
		}
	}
	return nil, core.TimeoutError{}
}

// access the Oauth2 credentials established earlier, either for a signup or login
type oauth2AccessSession struct {
	cfg         *proto.OAuth2Config
	arg         rem.RegSSOArgs
	argOauth2   *rem.RegSSOArgsOAuth2
	tx          pgx.Tx
	uid         proto.UID
	username    proto.NameUtf8
	displayName proto.NameUtf8
	subject     proto.OAuth2Subject
	em          proto.Email
	nonce       proto.OAuth2Nonce
	key         proto.EntityID
	idtok       proto.OAuth2IDToken
	accessTok   proto.OAuth2AccessToken
	refreshTok  proto.OAuth2RefreshToken
	root        proto.TreeRoot
	cfgId       proto.SSOConfigID
	etime       time.Time
	isSignup    bool
}

func (s *oauth2AccessSession) loadReferencedConfig(m MetaContext) error {
	if s.cfgId.IsZero() {
		return core.InternalError("oauth2 config not set")
	}
	if s.cfg != nil && s.cfg.Id.Eq(s.cfgId) {
		return nil
	}
	cfg, err := LoadSSOConfig(m, &s.cfgId)
	if err != nil {
		return err
	}
	err = sso.AssertOAuth2(cfg)
	if err != nil {
		return err
	}
	s.cfg = cfg.Oauth2
	return nil
}

func (s *oauth2AccessSession) loadLatestConfig(m MetaContext) error {
	cfg, err := LoadSSOConfig(m, nil)
	if err != nil {
		return err
	}
	typ, err := s.arg.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case proto.SSOProtocolType_Oauth2:
		tmp := s.arg.Oauth2()
		s.argOauth2 = &tmp
	case proto.SSOProtocolType_None:
	default:
		return core.VersionNotSupportedError("SSO protocol")
	}
	if s.argOauth2 == nil && cfg == nil {
		return nil
	}
	if s.argOauth2 == nil && cfg != nil {
		return core.OAuth2Error("oauth2 signup not found, but required for this host")
	}
	if s.argOauth2 != nil && cfg == nil {
		return core.OAuth2Error("oauth2 signup found, but not available for this host")
	}
	err = sso.AssertOAuth2(cfg)
	if err != nil {
		return err
	}
	s.cfg = cfg.Oauth2
	return nil
}

func (s *oauth2AccessSession) loadFromDB(m MetaContext) error {
	var em, un, tok, atok, nonce, dn, sub, rtok string
	var tokEtime time.Time
	var cfgId []byte
	var uidp *[]byte
	err := s.tx.QueryRow(
		m.Ctx(),
		`SELECT email, preferred_username, id_token, access_token,
		 etime, nonce, config_id, name, sub, refresh_token, uid
		FROM oauth2_sessions
		WHERE short_host_id=$1 AND oauth2_session_id=$2`,
		m.ShortHostID().ExportToDB(),
		s.argOauth2.Id.ExportToDB(),
	).Scan(&em, &un, &tok, &atok, &tokEtime, &nonce, &cfgId, &dn, &sub, &rtok, &uidp)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NotFoundError("oauth2 session")
	}
	if err != nil {
		return err
	}
	if s.isSignup && s.em != proto.Email(em) {
		return core.OAuth2Error("email mismatch")
	}
	if s.isSignup && s.username != proto.NameUtf8(un) {
		return core.OAuth2Error("username mismatch")
	}
	now := m.Now()
	if now.After(tokEtime) {
		return core.ExpiredError{}
	}
	err = s.cfgId.ImportFromDB(cfgId)
	if err != nil {
		return err
	}
	s.nonce = proto.OAuth2Nonce(nonce)
	s.idtok = proto.OAuth2IDToken(tok)
	s.accessTok = proto.OAuth2AccessToken(atok)
	s.displayName = proto.NameUtf8(dn)
	s.etime = tokEtime
	s.subject = proto.OAuth2Subject(sub)
	s.refreshTok = proto.OAuth2RefreshToken(rtok)
	if uidp != nil {
		if s.isSignup {
			return core.BadServerDataError("uid present in oauth2 signup session")
		}
		var tmp proto.UID
		err = tmp.ImportFromDB(*uidp)
		if err != nil {
			return err
		}
		if !tmp.Eq(s.uid) {
			return core.WrongUserError{}
		}
	}
	return nil
}

func (s *oauth2AccessSession) checkExistingAccess(m MetaContext) error {
	if s.isSignup {
		return nil
	}
	var sub string
	err := s.tx.QueryRow(
		m.Ctx(),
		`SELECT sub FROM oauth2_access WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		s.uid.ExportToDB(),
	).Scan(&sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.UserNotFoundError{}
	}
	if err != nil {
		return err
	}
	if proto.OAuth2Subject(sub) != s.subject {
		return core.WrongUserError{}
	}
	return nil
}

func (s *oauth2AccessSession) checkKey(m MetaContext) error {

	// On the signup path, it only could be one key
	if s.isSignup {
		if !s.key.Eq(s.argOauth2.Sig.Key) {
			return core.KeyMismatchError{}
		}
		return nil
	}

	eid := s.argOauth2.Sig.Key
	hid := m.HostID()
	uhc := UserHostContext{
		Uid:    s.uid,
		HostID: &hid,
	}

	_, err := checkClientKeyValidExternal(m, nil, uhc, eid)
	if err != nil {
		return err
	}

	return nil
}

func (s *oauth2AccessSession) openSig(m MetaContext) error {
	sig := s.argOauth2.Sig
	ep, err := core.ImportEntityPublic(sig.Key)
	if err != nil {
		return err
	}
	payload, err := core.Verify2(ep, sig.Sig, &sig.Inner)
	if err != nil {
		return err
	}
	if payload.IdToken == "" {
		return core.OAuth2Error("id token missing from binding")
	}
	if payload.IdToken != s.idtok {
		return core.OAuth2Error("id token mismatch")
	}
	if !payload.Binding.Fqu.HostID.Eq(m.HostID().Id) {
		return core.HostMismatchError{}
	}
	if !payload.Binding.Fqu.Uid.Eq(s.uid) {
		return core.OAuth2Error("uid mismatch")
	}
	nnc, err := sso.HashOAuth2Binding(&payload.Binding)
	if err != nil {
		return err
	}
	if nnc != s.nonce {
		return core.OAuth2Error("nonce mismatch")
	}
	s.root = payload.Binding.Root
	return nil
}

func (s *oauth2AccessSession) checkTreeRoot(m MetaContext) error {
	cli, err := m.G().MerkleCli(m.Ctx())
	if err != nil {
		return err
	}
	err = cli.ConfirmRoot(m.Ctx(), rem.ConfirmRootArg{
		HostID: m.HostID().Id,
		Root:   s.root,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *oauth2AccessSession) putIdTokenToDB(m MetaContext) error {
	rawSig, err := core.EncodeToBytes(&s.argOauth2.Sig.Sig)
	if err != nil {
		return err
	}
	tag, err := s.tx.Exec(
		m.Ctx(),
		`INSERT INTO oauth2_identity
		   (short_host_id, uid, config_id, email, preferred_username, name, ctime, etime,
		    id_token, sig, device_key_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (short_host_id, uid) 
		 DO UPDATE SET config_id=$3, email=$4, preferred_username=$5, 
		  name=$6, etime=$8, id_token=$9, sig=$10, device_key_id=$11`,
		m.ShortHostID().ExportToDB(),
		s.uid.ExportToDB(),
		s.cfgId.ExportToDB(),
		s.em.String(),
		s.username.String(),
		s.displayName.String(),
		m.Now().UTC(),
		s.etime.UTC(),
		s.argOauth2.Sig.Inner.Bytes(),
		rawSig,
		s.argOauth2.Sig.Key.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("oauth2_identity")
	}
	return nil
}

func (s *oauth2AccessSession) putAccessTokenToDB(m MetaContext) error {
	tag, err := s.tx.Exec(
		m.Ctx(),
		`INSERT INTO oauth2_access
 		 (short_host_id, uid, config_id, access_token, refresh_token, 
		   sub, ctime, etime, valid)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
		 ON CONFLICT (short_host_id, uid)
 		 DO UPDATE SET config_id=$3, access_token=$4, refresh_token=$5, etime=$8, valid=true`,
		m.ShortHostID().ExportToDB(),
		s.uid.ExportToDB(),
		s.cfgId.ExportToDB(),
		s.accessTok.String(),
		s.refreshTok.String(),
		s.subject.String(),
		m.Now().UTC(),
		s.etime.UTC(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("oauth2_access_token")
	}
	return nil
}

func (s *oauth2AccessSession) run(m MetaContext) error {
	err := s.loadLatestConfig(m)
	if err != nil {
		return err
	}
	// if no arg given and none required, it's ok to short-circuit out
	if s.isSignup && s.argOauth2 == nil {
		return nil
	}
	err = s.loadFromDB(m)
	if err != nil {
		return err
	}
	err = s.checkExistingAccess(m)
	if err != nil {
		return err
	}
	// Reload the config in case it changed; and we need the exact referenced config
	err = s.loadReferencedConfig(m)
	if err != nil {
		return err
	}
	err = s.openSig(m)
	if err != nil {
		return err
	}
	err = s.checkKey(m)
	if err != nil {
		return err
	}
	err = s.checkTreeRoot(m)
	if err != nil {
		return err
	}
	err = s.putIdTokenToDB(m)
	if err != nil {
		return err
	}
	err = s.putAccessTokenToDB(m)
	if err != nil {
		return err
	}
	return nil
}

func signupHandleOAuth2(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	key proto.EntityID,
	arg rem.RegSSOArgs,
	un proto.NameUtf8,
	em proto.Email,
) error {
	sess := &oauth2AccessSession{
		arg:      arg,
		tx:       tx,
		key:      key,
		uid:      uid,
		em:       em,
		username: un,
		isSignup: true,
	}
	return sess.run(m)
}

func oauth2Login(
	m MetaContext,
	uid proto.UID,
	arg rem.RegSSOArgs,
) error {
	return RetryTxUserDB(m, "oauth2Login", func(m MetaContext, tx pgx.Tx) error {
		sess := &oauth2AccessSession{
			arg: arg,
			tx:  tx,
			uid: uid,
		}
		return sess.run(m)
	})
}

func (s *oauth2Session) loadAccessFromDB(m MetaContext) error {
	var cfgIdRaw []byte
	var at, rt, sub string
	var etime time.Time
	var valid bool

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	err = db.QueryRow(
		m.Ctx(),
		`SELECT config_id, access_token, refresh_token, sub, etime, valid
		 FROM oauth2_access
		 WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		s.uid.ExportToDB(),
	).Scan(&cfgIdRaw, &at, &rt, &sub, &etime, &valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.UserNotFoundError{}
	}
	if err != nil {
		return err
	}
	err = s.cfgId.ImportFromDB(cfgIdRaw)
	if err != nil {
		return err
	}
	s.accessToken = proto.OAuth2AccessToken(at)
	s.refreshToken = proto.OAuth2RefreshToken(rt)
	s.subject = proto.OAuth2Subject(sub)
	s.etime = etime
	s.accessValid = valid

	return nil
}

func (s *oauth2Session) checkFresh(m MetaContext) error {
	now := m.Now()
	// With about 1 minute left, try for a refresh
	diff := s.etime.Sub(now)
	if diff < time.Minute {
		return core.ExpiredError{}
	}
	return nil
}

func (s *oauth2Session) writeRefreshToDB(m MetaContext) error {
	return RetryTxUserDB(m, "oauth2_access ", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE oauth2_access
			 SET access_token=$1, refresh_token=$2, etime=$3, valid=true
			 WHERE short_host_id=$4 AND uid=$5`,
			s.accessToken.String(),
			s.refreshToken.String(),
			s.etime.UTC(),
			m.ShortHostID().ExportToDB(),
			s.uid.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update oauth2 access")
		}
		return nil
	})
}

func (s *oauth2Session) checkAccessToken(m MetaContext) error {
	g, err := m.G().OAuth2GlobalContext(m.Ctx())
	if err != nil {
		return err
	}
	tok, err := sso.OAuth2CheckToken(m.Ctx(), g, s.idpCfg, s.accessToken.String(), "access", s.cfg.ClientID, "")
	if err != nil {
		return err
	}
	if tok.Subject != s.subject {
		return core.WrongUserError{}
	}
	return nil
}

func (s *oauth2Session) writeInvalidToDB(m MetaContext) error {
	return RetryTxUserDB(m, "oauth2_access", func(m MetaContext, tx pgx.Tx) error {
		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE oauth2_access
			 SET valid=false
			 WHERE short_host_id=$1 AND uid=$2`,
			m.ShortHostID().ExportToDB(),
			s.uid.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update oauth2 access")
		}
		return nil
	})
}

func (s *oauth2Session) doAuth(m MetaContext) error {

	err := s.loadAccessFromDB(m)
	if err != nil {
		return err
	}
	if !s.accessValid {
		return core.AuthError{}
	}
	if s.subject == "" {
		return errors.New("missing subject")
	}
	err = s.checkFresh(m)
	if err == nil {
		return nil
	}
	if !errors.Is(err, core.ExpiredError{}) {
		return err
	}
	err = s.loadReferencedConfig(m)
	if err != nil {
		return err
	}
	err = s.lookupTokenURI(m)
	if err != nil {
		return err
	}
	err = s.postExchange(m, nil)

	if err != nil && errors.Is(err, core.AuthError{}) {
		err := s.writeInvalidToDB(m)
		if err != nil {
			return err
		}
		return core.AuthError{}
	}

	if err != nil {
		return err
	}

	err = s.checkAccessToken(m)
	if err != nil {
		return err
	}
	err = s.writeRefreshToDB(m)
	if err != nil {
		return err
	}
	return nil
}

func authOAuth2(
	m MetaContext,
	uhc UserHostContext,
) error {
	m = m.WithHostID(uhc.HostID)
	sess := &oauth2Session{
		uid: &uhc.Uid,
	}
	err := sess.doAuth(m)
	if err != nil {
		return core.OAuth2AuthError{Err: err}
	}
	return nil
}
