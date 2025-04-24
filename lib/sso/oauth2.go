// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package sso

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/golang-jwt/jwt"
)

func Base64URLEncode(data []byte) string {
	// base64 url-encoding, no padding
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(data), "=")
}

func HashOAuth2Binding(
	binding *proto.OAuth2Binding,
) (
	proto.OAuth2Nonce,
	error,
) {
	var hsh proto.StdHash
	err := core.PrefixedHashInto(binding, hsh[:])
	if err != nil {
		return "", err
	}
	ret := proto.OAuth2Nonce(Base64URLEncode(hsh[:]))
	return ret, nil
}

func HashPKCE(
	verifier proto.OAuth2PKCEVerifier,
) (
	proto.OAuth2PKCEChallengeCode,
	error,
) {
	sum := sha256.Sum256([]byte(verifier))
	ret := proto.OAuth2PKCEChallengeCode(Base64URLEncode(sum[:]))
	return ret, nil
}

func GenPKCE(
	s *proto.OAuth2Session,
) error {
	var buf [20]byte
	err := core.RandomFill(buf[:])
	if err != nil {
		return err
	}
	s.Verifier = proto.OAuth2PKCEVerifier(Base64URLEncode(buf[:]))
	s.ChallengeCode, err = HashPKCE(s.Verifier)
	if err != nil {
		return err
	}
	return nil
}

func PrepOAuth2Session(
	fqu proto.FQUser,
	root proto.TreeRoot,
) (
	*proto.OAuth2Session,
	error,
) {
	var ret proto.OAuth2Session

	ret.Binding.Fqu = fqu
	ret.Binding.Root = root
	err := core.RandomFill(ret.Binding.Rand[:])
	if err != nil {
		return nil, err
	}
	ret.Nonce, err = HashOAuth2Binding(&ret.Binding)
	if err != nil {
		return nil, err
	}

	err = GenPKCE(&ret)
	if err != nil {
		return nil, err
	}

	tmp, err := proto.RandomID16er[proto.OAuth2SessionID]()
	if err != nil {
		return nil, err
	}
	ret.Id = *tmp

	return &ret, nil
}

func AssertOAuth2(
	ssoCfg *proto.SSOConfig,
) error {
	if !ssoCfg.HasOAuth2() {
		return core.OAuth2Error("OAuth2 SSO is not enabled for host")
	}
	return nil
}

func MakeOAuth2Session(
	ctx context.Context,
	g OAuth2GlobalContext,
	ssoCfg proto.SSOConfig,
	fqu proto.FQUser,
	root proto.TreeRoot,
) (
	*proto.OAuth2Session,
	error,
) {
	err := AssertOAuth2(&ssoCfg)
	if err != nil {
		return nil, err
	}

	ret, err := PrepOAuth2Session(fqu, root)
	if err != nil {
		return nil, err
	}
	ocfg := ssoCfg.Oauth2

	instanceCfg, err := g.ConfigSet().Get(ctx, g, ocfg.ConfigURI)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(instanceCfg.AuthURI.String())
	if err != nil {
		return nil, err
	}
	scopes := []string{"openid", "email", "profile", "offline_access"}

	q := u.Query()
	q.Set("client_id", ocfg.ClientID.String())
	q.Set("redirect_uri", ocfg.RedirectURI.String())
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", Base64URLEncode(ret.Binding.Rand[:]))
	q.Set("nonce", ret.Nonce.String())

	if ocfg.ClientSecret.IsZero() {
		q.Set("code_challenge", ret.Verifier.String())
		q.Set("code_challenge_method", "S256")
	} else {
		q.Set("client_secret", ocfg.ClientSecret.String())
	}

	u.RawQuery = q.Encode()
	ret.AuthURI = proto.URLString(u.String())

	return ret, nil
}

type OAuth2KeyID string

type OAuth2IdPConfig struct {
	sync.Mutex

	isInit bool

	ConfigURI   proto.URLString
	AuthURI     proto.URLString
	TokenURI    proto.URLString
	JwksURI     proto.URLString
	UserinfoURI proto.URLString

	jkws map[OAuth2KeyID]*rsa.PublicKey

	RefreshedAt time.Time // Should refresh every ~15 minutes or so (see Oauth2Configger.RefreshInterval
}

func newOAuth2Config(u proto.URLString) *OAuth2IdPConfig {
	return &OAuth2IdPConfig{
		ConfigURI: u,
		jkws:      make(map[OAuth2KeyID]*rsa.PublicKey),
	}
}

type OAuth2IdPConfigSet struct {
	sync.Mutex
	configs map[proto.URLString]*OAuth2IdPConfig
}

type OAuth2GlobalContext interface {
	Now() time.Time
	RefreshInterval() time.Duration
	RequestTimeout() time.Duration
	ConfigSet() *OAuth2IdPConfigSet
}

func NewOAuth2ConfigSet() *OAuth2IdPConfigSet {
	return &OAuth2IdPConfigSet{
		configs: make(map[proto.URLString]*OAuth2IdPConfig),
	}
}

func (c *OAuth2IdPConfigSet) Get(ctx context.Context, g OAuth2GlobalContext, s proto.URLString) (*OAuth2IdPConfig, error) {
	s = s.Normalize()

	c.Lock()
	ret, found := c.configs[s]
	if !found {
		ret = newOAuth2Config(s)
		c.configs[s] = ret
	}
	c.Unlock()

	return ret.populate(ctx, g)
}

func (c *OAuth2IdPConfig) populate(ctx context.Context, g OAuth2GlobalContext) (*OAuth2IdPConfig, error) {
	c.Lock()
	defer c.Unlock()
	if c.isInit && g.Now().Sub(c.RefreshedAt) < g.RefreshInterval() {
		return c, nil
	}
	ctx, canc := context.WithTimeout(ctx, g.RequestTimeout())
	defer canc()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ConfigURI.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	type config struct {
		AuthURI     string `json:"authorization_endpoint"`
		TokenURI    string `json:"token_endpoint"`
		JwksURI     string `json:"jwks_uri"`
		UserinfoURI string `json:"userinfo_endpoint"`
	}

	var cfg config
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	if cfg.AuthURI == "" || cfg.TokenURI == "" || cfg.JwksURI == "" || cfg.UserinfoURI == "" {
		return nil, core.OAuth2Error("missing required fields")
	}

	c.AuthURI = proto.URLString(cfg.AuthURI)
	c.TokenURI = proto.URLString(cfg.TokenURI)
	c.JwksURI = proto.URLString(cfg.JwksURI)
	c.UserinfoURI = proto.URLString(cfg.UserinfoURI)
	c.RefreshedAt = g.Now()
	c.isInit = true

	return c, nil
}

func (c *OAuth2IdPConfig) GetJwks(ctx context.Context, g OAuth2GlobalContext, kid OAuth2KeyID) (*rsa.PublicKey, error) {
	c.Lock()
	defer c.Unlock()
	if key, found := c.jkws[kid]; found {
		return key, nil
	}
	err := c.refreshJKWS(ctx, g)
	if err != nil {
		return nil, err
	}
	if key, found := c.jkws[kid]; found {
		return key, nil
	}
	return nil, core.KeyNotFoundError{Which: "JWKS"}
}

func (c *OAuth2IdPConfig) refreshJKWS(ctx context.Context, g OAuth2GlobalContext) error {
	ctx, canc := context.WithTimeout(ctx, g.RequestTimeout())
	defer canc()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.JwksURI.String(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			E   string `json:"e"`
			N   string `json:"n"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return err
	}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Alg != "RS256" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return err
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return err
		}
		c.jkws[OAuth2KeyID(key.Kid)] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	}
	return nil
}

func OAuth2CheckToken(
	ctx context.Context,
	g OAuth2GlobalContext,
	cfg *OAuth2IdPConfig,
	tok string,
	which string,
	audExpected proto.OAuth2ClientID,
	nonceExpected proto.OAuth2Nonce,
) (
	*proto.OAuth2ParsedIDToken,
	error,
) {
	if tok == "" {
		return nil, core.OAuth2TokenError{Which: which, Err: errors.New("missing token")}
	}
	ptok, err := jwt.Parse(
		tok,
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != "RS256" {
				return nil, core.OAuth2TokenError{Which: which, Err: core.VersionNotSupportedError(t.Method.Alg())}
			}
			kid, ok := t.Header["kid"].(string)
			if !ok {
				return nil, core.OAuth2TokenError{Which: which, Err: core.KeyNotFoundError{Which: "kid"}}
			}
			return cfg.GetJwks(ctx, g, OAuth2KeyID(kid))
		},
	)
	if err != nil {
		return nil, err
	}
	if !ptok.Valid {
		return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("invalid token")}
	}
	claims, ok := ptok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("invalid token claims")}
	}
	aud, ok := claims["aud"].(string)
	if !ok {
		return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("missing aud claim")}
	}
	if proto.OAuth2ClientID(aud) != audExpected {
		return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("invalid aud")}
	}
	if !nonceExpected.IsZero() {
		nonce, ok := claims["nonce"].(string)
		if !ok {
			return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("missing nonce claim")}
		}
		if proto.OAuth2Nonce(nonce) != nonceExpected {
			return nil, core.OAuth2TokenError{Which: which, Err: core.BadArgsError("invalid nonce")}
		}
	}
	iss, ok := claims["iss"].(string)
	if !ok {
		return nil, core.OAuth2TokenError{Which: which, Err: core.MissingHostError{}}
	}
	ret := proto.OAuth2ParsedIDToken{
		Issuer: proto.URLString(iss),
	}
	name, ok := claims["preferred_username"].(string)
	if ok {
		ret.Username = proto.NameUtf8(name)
	}
	dn, ok := claims["name"].(string)
	if ok {
		ret.DisplayName = proto.NameUtf8(dn)
	}
	email, ok := claims["email"].(string)
	if ok {
		ret.Email = proto.Email(email)
	}
	issued, ok := claims["iat"].(float64)
	if ok {
		ret.Issued = proto.ExportTime(time.Unix(int64(issued), 0))
	}
	exp, ok := claims["exp"].(float64)
	if ok {
		ret.Expires = proto.ExportTime(time.Unix(int64(exp), 0))
	}
	sub, ok := claims["sub"].(string)
	if ok {
		ret.Subject = proto.OAuth2Subject(sub)
	}
	return &ret, nil
}

// OAuth2CheckTokens takes the ID and access token returned from an OIDC flow and
// checks them against the issuer's public key. It also sanity checks that the tokens
// match the expected audience/clientID and that the nonce matches the one we generated.
func OAuth2CheckTokens(
	ctx context.Context,
	g OAuth2GlobalContext,
	cfg *OAuth2IdPConfig,
	toks proto.OAuth2TokenSet,
	audExpected proto.OAuth2ClientID,
	nonceExpected proto.OAuth2Nonce,
) (
	*proto.OAuth2ParsedIDToken,
	error,
) {

	checkOne := func(tok string, which string) (*proto.OAuth2ParsedIDToken, error) {
		return OAuth2CheckToken(ctx, g, cfg, tok, which, audExpected, nonceExpected)
	}

	idtok, err := checkOne(toks.IdToken.String(), "ID")
	if err != nil {
		return nil, err
	}
	accesTok, err := checkOne(toks.AccessToken.String(), "access")
	if err != nil {
		return nil, err
	}
	if idtok.Issuer != accesTok.Issuer {
		return nil, core.OAuth2TokenError{Which: "access", Err: core.HostMismatchError{}}
	}
	if idtok.Subject != accesTok.Subject {
		return nil, core.OAuth2TokenError{Which: "access", Err: core.WrongUserError{}}
	}
	idtok.Raw = toks.IdToken
	return idtok, nil
}
