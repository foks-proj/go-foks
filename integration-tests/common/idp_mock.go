// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/keybase/clockwork"
)

type AppName string
type RSAKid string

func (r RSAKid) String() string {
	return string(r)
}

type IdPUser struct {
	Username    proto.NameUtf8
	Email       proto.Email
	DisplayName proto.NameUtf8
	Sub         proto.OAuth2Subject
	Refresh     proto.OAuth2RefreshToken
	LoggedOut   bool
}

const MockIdPAccessTokenExpiration = 1 * time.Hour

func (i *IdPUser) refreshRefreshToken() error {
	rt, err := core.RandomBase36String(20)
	if err != nil {
		return err
	}
	i.Refresh = proto.OAuth2RefreshToken(rt)
	return nil
}

func NewIdPUser(first, last, domain string) (*IdPUser, error) {
	middle, err := core.RandomBase36String(10)
	if err != nil {
		return nil, err
	}
	un := strings.Join([]string{first, middle, last}, ".")
	dn := strings.Join([]string{first, middle, last}, " ")
	ret := &IdPUser{
		Username:    proto.NameUtf8(un),
		Email:       proto.Email(un + "@" + domain),
		DisplayName: proto.NameUtf8(dn),
		Sub:         proto.OAuth2Subject(middle),
	}
	return ret, nil
}

type IdPSession struct {
	User  *IdPUser
	Nonce proto.OAuth2Nonce
	Id    proto.OAuth2SessionID
}

type FakeIdPApp struct {
	parent           *FakeIdP
	name             AppName
	clientID         proto.OAuth2ClientID
	allowedCallbacks map[proto.URLString]bool
	sessions         map[proto.OAuth2Code]*IdPSession
	refreshTokens    map[proto.OAuth2RefreshToken]*IdPUser
	key              *rsa.PrivateKey
	kid              RSAKid
	current          *IdPUser
}

type openidConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JkwsURI               string `json:"jwks_uri"`
	UserInfo              string `json:"userinfo_endpoint"`
}

func (p *FakeIdPApp) AddCallback(cb proto.URLString) {
	p.allowedCallbacks[cb] = true
}

func (p *FakeIdPApp) PathPrefix() proto.URLString {
	return proto.URLString("/application/o/" + p.name + "/")
}

func (p *FakeIdPApp) ConfigPath() proto.URLString {
	return p.PathPrefix().PathJoin(".well-known/openid-configuration")
}

func (p *FakeIdPApp) ConfigURL() proto.URLString {
	return p.parent.BaseURL().PathJoin(p.ConfigPath())
}

func (p *FakeIdPApp) JwksPath() proto.URLString {
	return p.PathPrefix().PathJoin("jwks")
}

func (p *FakeIdPApp) ClientID() proto.OAuth2ClientID {
	return p.clientID
}

func (p *FakeIdPApp) serveConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(p.makeConfig())
		if err != nil {
			panic(err)
		}
	}
}

func (p *FakeIdPApp) SetCurrentUser(u *IdPUser) {
	p.current = u
}

// JWK structure to advertise in .well-known/jwks.json
// This is simplified; many fields omitted
type JWK struct {
	Kty string `json:"kty"` // Key type, e.g. "RSA"
	N   string `json:"n"`   // Modulus, base64url
	E   string `json:"e"`   // Exponent, base64url
	Alg string `json:"alg"` // Algorithm, e.g. "RS256"
	Use string `json:"use"` // Intended use, e.g. "sig"
	Kid string `json:"kid"` // Key ID
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func intToBytes(val int) []byte {
	// We’ll assume val fits in 64 bits (typical for int on modern systems).
	// Convert val to a uint64, then serialize in big-endian order.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(val))

	// Trim leading zeros so that the resulting slice has no unnecessary padding.
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

func (p *FakeIdPApp) serveAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		clientID := query.Get("client_id")
		redirectURI := query.Get("redirect_uri")
		if !p.allowedCallbacks[proto.URLString(redirectURI)] {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		stateRaw := proto.OAuth2SessionIDString(query.Get("state"))
		sid, err := stateRaw.Parse()
		if err != nil {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		if proto.OAuth2ClientID(clientID) != p.clientID {
			http.Error(w, "invalid client_id", http.StatusBadRequest)
			return
		}
		nonce := proto.OAuth2Nonce(query.Get("nonce"))
		sess := &IdPSession{
			Nonce: nonce,
			Id:    *sid,
			User:  p.current,
		}
		code, err := core.RandomBase36String(20)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		p.sessions[proto.OAuth2Code(code)] = sess
		vals := url.Values{}
		vals.Set("code", code)
		vals.Set("state", string(stateRaw))

		redirectURIWithParmss := redirectURI + "?" + vals.Encode()
		http.Redirect(w, r, redirectURIWithParmss, http.StatusFound)
	}
}

func (p *FakeIdPApp) makeIDToken(user *IdPUser, nonce proto.OAuth2Nonce) (proto.OAuth2IDToken, error) {
	if user == nil {
		return "", core.InternalError("no user active in session")
	}
	now := p.parent.clock.Now()
	claims := jwt.MapClaims{
		"iss":                p.parent.BaseURL().String(),
		"email":              user.Email.String(),
		"iat":                now.UTC().Unix(),
		"exp":                now.Add(1 * time.Hour).UTC().Unix(),
		"name":               user.DisplayName.String(),
		"preferred_username": user.Username.String(),
		"sub":                user.Sub.String(),
		"aud":                p.clientID.String(),
	}
	if !nonce.IsZero() {
		claims["nonce"] = nonce.String()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid.String()
	ret, err := token.SignedString(p.key)
	if err != nil {
		return "", err
	}
	return proto.OAuth2IDToken(ret), nil
}

func (p *FakeIdPApp) makeAccessToken(user *IdPUser, nonce proto.OAuth2Nonce) (proto.OAuth2AccessToken, error) {
	idtok, err := p.makeIDToken(user, nonce)
	if err != nil {
		return "", err
	}
	return proto.OAuth2AccessToken(idtok.String()), nil
}

func (p *FakeIdPApp) serveToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := proto.OAuth2ClientID(r.Form.Get("client_id"))
		if clientID != p.clientID {
			http.Error(w, "invalid client_id", http.StatusBadRequest)
			return
		}
		grantType := r.Form.Get("grant_type")
		var tok *TokenReply
		switch grantType {
		case "authorization_code":
			tok = p.serveTokenAuthCode(w, r)
		case "refresh_token":
			tok = p.serveTokenRefresh(w, r)
		default:
			http.Error(w, "unsupported grant type", http.StatusBadRequest)
			return
		}
		if tok == nil {
			return
		}
		tok.ExpiresIn = int(MockIdPAccessTokenExpiration.Seconds())
		tok.TokenType = "Bearer"
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(tok)
		if err != nil {
			http.Error(w, "internal error in JSON output of token", http.StatusInternalServerError)
			return
		}
	}
}

type TokenReply struct {
	AccessToken  proto.OAuth2AccessToken  `json:"access_token"`
	IDToken      proto.OAuth2IDToken      `json:"id_token"`
	TokenType    string                   `json:"token_type"`
	ExpiresIn    int                      `json:"expires_in"`
	RefreshToken proto.OAuth2RefreshToken `json:"refresh_token"`
}

func (p *FakeIdPApp) serveTokenRefresh(w http.ResponseWriter, r *http.Request) *TokenReply {
	rt := proto.OAuth2RefreshToken(r.Form.Get("refresh_token"))
	user, ok := p.refreshTokens[rt]
	if !ok {
		http.Error(w, "invalid refresh token; user not found", http.StatusNotFound)
		return nil
	}
	delete(p.refreshTokens, rt)
	if user.LoggedOut {
		er := shared.ErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "token is invalid or is no longer valid",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(er)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return nil
	}
	rt, err := p.makeRefreshToken(user)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}
	at, err := p.makeAccessToken(user, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}
	ret := &TokenReply{
		AccessToken:  at,
		RefreshToken: rt,
	}
	return ret
}

func (p *FakeIdPApp) makeRefreshToken(u *IdPUser) (proto.OAuth2RefreshToken, error) {
	err := u.refreshRefreshToken()
	if err != nil {
		return "", err
	}
	p.refreshTokens[u.Refresh] = u
	return u.Refresh, nil
}

func (p *FakeIdPApp) serveTokenAuthCode(w http.ResponseWriter, r *http.Request) *TokenReply {
	code := proto.OAuth2Code(r.Form.Get("code"))
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return nil
	}
	sess, ok := p.sessions[code]
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return nil
	}
	// once a token is issued, the session is no longer valid
	delete(p.sessions, code)

	rt, err := p.makeRefreshToken(sess.User)
	if err != nil {
		return nil
	}

	idToken, err := p.makeIDToken(sess.User, sess.Nonce)
	if err != nil {
		http.Error(w, "internal error (idtoken)", http.StatusInternalServerError)
		return nil
	}
	accessToken, err := p.makeAccessToken(sess.User, sess.Nonce)
	if err != nil {
		http.Error(w, "internal error (accesstoken)", http.StatusInternalServerError)
		return nil
	}
	ret := &TokenReply{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: rt,
	}
	return ret
}

func rsaPubToKid(pub *rsa.PublicKey) RSAKid {
	x := proto.RSAPub{
		N: pub.N.Bytes(),
		E: uint64(pub.E),
	}
	var tmp [32]byte
	err := core.PrefixedHashInto(&x, tmp[:])
	if err != nil {
		panic(err)
	}
	return RSAKid(core.B36Encode(tmp[:]))
}

func (p *FakeIdPApp) serveJwks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub := p.key.PublicKey

		// Convert the modulus and exponent to base64 (URL-encoded)
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

		// The public exponent is typically small (e.g. 65537).
		// Convert it to bytes, then base64url-encode.
		eBytes := intToBytes(pub.E)

		e := base64.RawURLEncoding.EncodeToString(eBytes)

		jwk := JWK{
			Kty: "RSA",
			N:   n,
			E:   e,
			Alg: "RS256",
			Use: "sig",
			// In a real IDP, you'd compute or set a stable key ID (kid) for rotation
			Kid: p.kid.String(),
		}

		jwks := JWKS{Keys: []JWK{jwk}}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(jwks)
		if err != nil {
			panic(err)
		}
	}
}

func (p *FakeIdPApp) makeConfig() *openidConfiguration {
	return &openidConfiguration{
		AuthorizationEndpoint: p.parent.AuthURL().String(),
		TokenEndpoint:         p.parent.TokenURL().String(),
		JkwsURI:               p.parent.BaseURL().PathJoin(p.JwksPath()).String(),
		UserInfo:              p.parent.UserinfoURL().String(),
	}
}

func (p *FakeIdPApp) initRoutes(mux *chi.Mux) {
	mux.Group(func(mux chi.Router) {
		mux.Get(p.ConfigPath().String(), p.serveConfig())
		mux.Get(p.JwksPath().String(), p.serveJwks())
	})
}

// FakeIdP is an IdP mock that simulates some of the flows that we use to enable IdP for a vhost
// and to signup using IdP (just yet). Eventually we'll add login hooks too. Seems like the easiest
// way to mock it is via a local web server, so we'll do just that.
type FakeIdP struct {
	addr  *net.TCPAddr
	apps  map[proto.OAuth2ClientID]*FakeIdPApp
	srv   *http.Server
	clock clockwork.Clock
}

func NewFakeIDP() *FakeIdP {
	return &FakeIdP{
		apps:  make(map[proto.OAuth2ClientID]*FakeIdPApp),
		clock: clockwork.NewRealClock(),
	}
}

func (f *FakeIdP) WithClock(c clockwork.Clock) *FakeIdP {
	f.clock = c
	return f
}

func newFakeIdPApp(f *FakeIdP, n AppName) (*FakeIdPApp, error) {
	ret := &FakeIdPApp{
		parent:           f,
		name:             n,
		allowedCallbacks: make(map[proto.URLString]bool),
		sessions:         make(map[proto.OAuth2Code]*IdPSession),
		refreshTokens:    make(map[proto.OAuth2RefreshToken]*IdPUser),
	}
	code, err := core.RandomBase36String(10)
	if err != nil {
		return nil, err
	}
	ret.clientID = proto.OAuth2ClientID(code)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ret.key = key
	ret.kid = rsaPubToKid(&key.PublicKey)
	return ret, nil
}

func (f *FakeIdP) NewApp(n AppName) (*FakeIdPApp, error) {
	app, err := newFakeIdPApp(f, n)
	if err != nil {
		return nil, err
	}
	f.apps[app.clientID] = app
	return app, nil
}

func (f *FakeIdP) ConfigPath() proto.URLString {
	return proto.URLString("/")
}

func (f *FakeIdP) BaseURL() proto.URLString {
	return proto.URLString(
		fmt.Sprintf("http://localhost:%d/",
			f.addr.Port,
		),
	)
}

func (p *FakeIdP) AuthPath() proto.URLString     { return proto.URLString("/application/o/authorize") }
func (p *FakeIdP) TokenPath() proto.URLString    { return proto.URLString("/application/o/token") }
func (p *FakeIdP) UserinfoPath() proto.URLString { return proto.URLString("/application/o/userinfo") }
func (p *FakeIdP) AuthURL() proto.URLString      { return p.BaseURL().PathJoin(p.AuthPath()) }
func (p *FakeIdP) TokenURL() proto.URLString     { return p.BaseURL().PathJoin(p.TokenPath()) }
func (p *FakeIdP) UserinfoURL() proto.URLString  { return p.BaseURL().PathJoin(p.UserinfoPath()) }
func (p *FakeIdP) serveAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		clientID := proto.OAuth2ClientID(query.Get("client_id"))
		app, ok := p.apps[clientID]
		if !ok {
			http.Error(w, "invalid client_id", http.StatusNotFound)
			return
		}
		app.serveAuth()(w, r)
	}
}

func (p *FakeIdP) serveToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		clientID := proto.OAuth2ClientID(r.Form.Get("client_id"))
		app, ok := p.apps[clientID]
		if !ok {
			http.Error(w, "invalid client_id", http.StatusNotFound)
			return
		}
		app.serveToken()(w, r)
	}
}

func (f *FakeIdP) Launch() error {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return core.InternalError("failed to cast web listener addr to TCPAddr")
	}
	mux := chi.NewRouter()
	for _, app := range f.apps {
		app.initRoutes(mux)
	}
	mux.Group(func(mux chi.Router) {
		mux.Get(f.AuthPath().String(), f.serveAuth())
		mux.Post(f.TokenPath().String(), f.serveToken())
	})

	f.addr = addr
	server := &http.Server{
		Addr:    addr.String(),
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)

	}()
	f.srv = server

	return nil
}

func (f *FakeIdP) Shutdown(ctx context.Context) error {
	return f.srv.Shutdown(ctx)
}
