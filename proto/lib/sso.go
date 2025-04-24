// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/sso.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type SSOClientID string
type SSOClientIDInternal__ string

func (s SSOClientID) Export() *SSOClientIDInternal__ {
	tmp := ((string)(s))
	return ((*SSOClientIDInternal__)(&tmp))
}

func (s SSOClientIDInternal__) Import() SSOClientID {
	tmp := (string)(s)
	return SSOClientID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SSOClientID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SSOClientID) Decode(dec rpc.Decoder) error {
	var tmp SSOClientIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SSOClientID) Bytes() []byte {
	return nil
}

type SSOLoginRes struct {
	Username NameUtf8
	Email    Email
	Issuer   URLString
}

type SSOLoginResInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Username *NameUtf8Internal__
	Email    *EmailInternal__
	Issuer   *URLStringInternal__
}

func (s SSOLoginResInternal__) Import() SSOLoginRes {
	return SSOLoginRes{
		Username: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Username),
		Email: (func(x *EmailInternal__) (ret Email) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Email),
		Issuer: (func(x *URLStringInternal__) (ret URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Issuer),
	}
}

func (s SSOLoginRes) Export() *SSOLoginResInternal__ {
	return &SSOLoginResInternal__{
		Username: s.Username.Export(),
		Email:    s.Email.Export(),
		Issuer:   s.Issuer.Export(),
	}
}

func (s *SSOLoginRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SSOLoginRes) Decode(dec rpc.Decoder) error {
	var tmp SSOLoginResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SSOLoginRes) Bytes() []byte { return nil }

type OAuth2Config struct {
	Id           SSOConfigID
	ConfigURI    URLString
	ClientID     OAuth2ClientID
	ClientSecret OAuth2ClientSecret
	RedirectURI  URLString
}

type OAuth2ConfigInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id           *SSOConfigIDInternal__
	ConfigURI    *URLStringInternal__
	ClientID     *OAuth2ClientIDInternal__
	ClientSecret *OAuth2ClientSecretInternal__
	RedirectURI  *URLStringInternal__
}

func (o OAuth2ConfigInternal__) Import() OAuth2Config {
	return OAuth2Config{
		Id: (func(x *SSOConfigIDInternal__) (ret SSOConfigID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Id),
		ConfigURI: (func(x *URLStringInternal__) (ret URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.ConfigURI),
		ClientID: (func(x *OAuth2ClientIDInternal__) (ret OAuth2ClientID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.ClientID),
		ClientSecret: (func(x *OAuth2ClientSecretInternal__) (ret OAuth2ClientSecret) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.ClientSecret),
		RedirectURI: (func(x *URLStringInternal__) (ret URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.RedirectURI),
	}
}

func (o OAuth2Config) Export() *OAuth2ConfigInternal__ {
	return &OAuth2ConfigInternal__{
		Id:           o.Id.Export(),
		ConfigURI:    o.ConfigURI.Export(),
		ClientID:     o.ClientID.Export(),
		ClientSecret: o.ClientSecret.Export(),
		RedirectURI:  o.RedirectURI.Export(),
	}
}

func (o *OAuth2Config) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Config) Decode(dec rpc.Decoder) error {
	var tmp OAuth2ConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2Config) Bytes() []byte { return nil }

type SSOProtocolType int

const (
	SSOProtocolType_None   SSOProtocolType = 0
	SSOProtocolType_Oauth2 SSOProtocolType = 1
	SSOProtocolType_SAML   SSOProtocolType = 2
)

var SSOProtocolTypeMap = map[string]SSOProtocolType{
	"None":   0,
	"Oauth2": 1,
	"SAML":   2,
}

var SSOProtocolTypeRevMap = map[SSOProtocolType]string{
	0: "None",
	1: "Oauth2",
	2: "SAML",
}

type SSOProtocolTypeInternal__ SSOProtocolType

func (s SSOProtocolTypeInternal__) Import() SSOProtocolType {
	return SSOProtocolType(s)
}

func (s SSOProtocolType) Export() *SSOProtocolTypeInternal__ {
	return ((*SSOProtocolTypeInternal__)(&s))
}

type SSOConfig struct {
	Active SSOProtocolType
	Oauth2 *OAuth2Config
}

type SSOConfigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Active  *SSOProtocolTypeInternal__
	Oauth2  *OAuth2ConfigInternal__
}

func (s SSOConfigInternal__) Import() SSOConfig {
	return SSOConfig{
		Active: (func(x *SSOProtocolTypeInternal__) (ret SSOProtocolType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Active),
		Oauth2: (func(x *OAuth2ConfigInternal__) *OAuth2Config {
			if x == nil {
				return nil
			}
			tmp := (func(x *OAuth2ConfigInternal__) (ret OAuth2Config) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Oauth2),
	}
}

func (s SSOConfig) Export() *SSOConfigInternal__ {
	return &SSOConfigInternal__{
		Active: s.Active.Export(),
		Oauth2: (func(x *OAuth2Config) *OAuth2ConfigInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Oauth2),
	}
}

func (s *SSOConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SSOConfig) Decode(dec rpc.Decoder) error {
	var tmp SSOConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SSOConfig) Bytes() []byte { return nil }

type OAuth2TokenSet struct {
	AccessToken OAuth2AccessToken
	IdToken     OAuth2IDToken
	Expires     Time
	Username    NameUtf8
}

type OAuth2TokenSetInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AccessToken *OAuth2AccessTokenInternal__
	IdToken     *OAuth2IDTokenInternal__
	Expires     *TimeInternal__
	Username    *NameUtf8Internal__
}

func (o OAuth2TokenSetInternal__) Import() OAuth2TokenSet {
	return OAuth2TokenSet{
		AccessToken: (func(x *OAuth2AccessTokenInternal__) (ret OAuth2AccessToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.AccessToken),
		IdToken: (func(x *OAuth2IDTokenInternal__) (ret OAuth2IDToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.IdToken),
		Expires: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Expires),
		Username: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Username),
	}
}

func (o OAuth2TokenSet) Export() *OAuth2TokenSetInternal__ {
	return &OAuth2TokenSetInternal__{
		AccessToken: o.AccessToken.Export(),
		IdToken:     o.IdToken.Export(),
		Expires:     o.Expires.Export(),
		Username:    o.Username.Export(),
	}
}

func (o *OAuth2TokenSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2TokenSet) Decode(dec rpc.Decoder) error {
	var tmp OAuth2TokenSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

var OAuth2TokenSetTypeUniqueID = rpc.TypeUniqueID(0x9c72432bd3f5bfc8)

func (o *OAuth2TokenSet) GetTypeUniqueID() rpc.TypeUniqueID {
	return OAuth2TokenSetTypeUniqueID
}

func (o *OAuth2TokenSet) Bytes() []byte { return nil }

type OAuth2Random [16]byte
type OAuth2RandomInternal__ [16]byte

func (o OAuth2Random) Export() *OAuth2RandomInternal__ {
	tmp := (([16]byte)(o))
	return ((*OAuth2RandomInternal__)(&tmp))
}

func (o OAuth2RandomInternal__) Import() OAuth2Random {
	tmp := ([16]byte)(o)
	return OAuth2Random((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2Random) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Random) Decode(dec rpc.Decoder) error {
	var tmp OAuth2RandomInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2Random) Bytes() []byte {
	return (o)[:]
}

type OAuth2Nonce string
type OAuth2NonceInternal__ string

func (o OAuth2Nonce) Export() *OAuth2NonceInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2NonceInternal__)(&tmp))
}

func (o OAuth2NonceInternal__) Import() OAuth2Nonce {
	tmp := (string)(o)
	return OAuth2Nonce((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2Nonce) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Nonce) Decode(dec rpc.Decoder) error {
	var tmp OAuth2NonceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2Nonce) Bytes() []byte {
	return nil
}

type OAuth2PKCEChallengeCode string
type OAuth2PKCEChallengeCodeInternal__ string

func (o OAuth2PKCEChallengeCode) Export() *OAuth2PKCEChallengeCodeInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2PKCEChallengeCodeInternal__)(&tmp))
}

func (o OAuth2PKCEChallengeCodeInternal__) Import() OAuth2PKCEChallengeCode {
	tmp := (string)(o)
	return OAuth2PKCEChallengeCode((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2PKCEChallengeCode) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2PKCEChallengeCode) Decode(dec rpc.Decoder) error {
	var tmp OAuth2PKCEChallengeCodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2PKCEChallengeCode) Bytes() []byte {
	return nil
}

type OAuth2PKCEVerifier string
type OAuth2PKCEVerifierInternal__ string

func (o OAuth2PKCEVerifier) Export() *OAuth2PKCEVerifierInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2PKCEVerifierInternal__)(&tmp))
}

func (o OAuth2PKCEVerifierInternal__) Import() OAuth2PKCEVerifier {
	tmp := (string)(o)
	return OAuth2PKCEVerifier((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2PKCEVerifier) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2PKCEVerifier) Decode(dec rpc.Decoder) error {
	var tmp OAuth2PKCEVerifierInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2PKCEVerifier) Bytes() []byte {
	return nil
}

type OAuth2Code string
type OAuth2CodeInternal__ string

func (o OAuth2Code) Export() *OAuth2CodeInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2CodeInternal__)(&tmp))
}

func (o OAuth2CodeInternal__) Import() OAuth2Code {
	tmp := (string)(o)
	return OAuth2Code((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2Code) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Code) Decode(dec rpc.Decoder) error {
	var tmp OAuth2CodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2Code) Bytes() []byte {
	return nil
}

type OAuth2AccessToken string
type OAuth2AccessTokenInternal__ string

func (o OAuth2AccessToken) Export() *OAuth2AccessTokenInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2AccessTokenInternal__)(&tmp))
}

func (o OAuth2AccessTokenInternal__) Import() OAuth2AccessToken {
	tmp := (string)(o)
	return OAuth2AccessToken((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2AccessToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2AccessToken) Decode(dec rpc.Decoder) error {
	var tmp OAuth2AccessTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2AccessToken) Bytes() []byte {
	return nil
}

type OAuth2RefreshToken string
type OAuth2RefreshTokenInternal__ string

func (o OAuth2RefreshToken) Export() *OAuth2RefreshTokenInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2RefreshTokenInternal__)(&tmp))
}

func (o OAuth2RefreshTokenInternal__) Import() OAuth2RefreshToken {
	tmp := (string)(o)
	return OAuth2RefreshToken((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2RefreshToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2RefreshToken) Decode(dec rpc.Decoder) error {
	var tmp OAuth2RefreshTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2RefreshToken) Bytes() []byte {
	return nil
}

type OAuth2IDToken string
type OAuth2IDTokenInternal__ string

func (o OAuth2IDToken) Export() *OAuth2IDTokenInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2IDTokenInternal__)(&tmp))
}

func (o OAuth2IDTokenInternal__) Import() OAuth2IDToken {
	tmp := (string)(o)
	return OAuth2IDToken((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2IDToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2IDToken) Decode(dec rpc.Decoder) error {
	var tmp OAuth2IDTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2IDToken) Bytes() []byte {
	return nil
}

type OAuth2ClientID string
type OAuth2ClientIDInternal__ string

func (o OAuth2ClientID) Export() *OAuth2ClientIDInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2ClientIDInternal__)(&tmp))
}

func (o OAuth2ClientIDInternal__) Import() OAuth2ClientID {
	tmp := (string)(o)
	return OAuth2ClientID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2ClientID) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2ClientID) Decode(dec rpc.Decoder) error {
	var tmp OAuth2ClientIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2ClientID) Bytes() []byte {
	return nil
}

type OAuth2ClientSecret string
type OAuth2ClientSecretInternal__ string

func (o OAuth2ClientSecret) Export() *OAuth2ClientSecretInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2ClientSecretInternal__)(&tmp))
}

func (o OAuth2ClientSecretInternal__) Import() OAuth2ClientSecret {
	tmp := (string)(o)
	return OAuth2ClientSecret((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2ClientSecret) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2ClientSecret) Decode(dec rpc.Decoder) error {
	var tmp OAuth2ClientSecretInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2ClientSecret) Bytes() []byte {
	return nil
}

type OAuth2Subject string
type OAuth2SubjectInternal__ string

func (o OAuth2Subject) Export() *OAuth2SubjectInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2SubjectInternal__)(&tmp))
}

func (o OAuth2SubjectInternal__) Import() OAuth2Subject {
	tmp := (string)(o)
	return OAuth2Subject((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2Subject) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Subject) Decode(dec rpc.Decoder) error {
	var tmp OAuth2SubjectInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2Subject) Bytes() []byte {
	return nil
}

type OAuth2Binding struct {
	Fqu  FQUser
	Root TreeRoot
	Rand OAuth2Random
}

type OAuth2BindingInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *FQUserInternal__
	Root    *TreeRootInternal__
	Rand    *OAuth2RandomInternal__
}

func (o OAuth2BindingInternal__) Import() OAuth2Binding {
	return OAuth2Binding{
		Fqu: (func(x *FQUserInternal__) (ret FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Fqu),
		Root: (func(x *TreeRootInternal__) (ret TreeRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Root),
		Rand: (func(x *OAuth2RandomInternal__) (ret OAuth2Random) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Rand),
	}
}

func (o OAuth2Binding) Export() *OAuth2BindingInternal__ {
	return &OAuth2BindingInternal__{
		Fqu:  o.Fqu.Export(),
		Root: o.Root.Export(),
		Rand: o.Rand.Export(),
	}
}

func (o *OAuth2Binding) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Binding) Decode(dec rpc.Decoder) error {
	var tmp OAuth2BindingInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

var OAuth2BindingTypeUniqueID = rpc.TypeUniqueID(0xa785bb21f4d713b6)

func (o *OAuth2Binding) GetTypeUniqueID() rpc.TypeUniqueID {
	return OAuth2BindingTypeUniqueID
}

func (o *OAuth2Binding) Bytes() []byte { return nil }

type OAuth2Session struct {
	Id            OAuth2SessionID
	Binding       OAuth2Binding
	Nonce         OAuth2Nonce
	ChallengeCode OAuth2PKCEChallengeCode
	Verifier      OAuth2PKCEVerifier
	AuthURI       URLString
	Idtok         *OAuth2ParsedIDToken
}

type OAuth2SessionInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id            *OAuth2SessionIDInternal__
	Binding       *OAuth2BindingInternal__
	Nonce         *OAuth2NonceInternal__
	ChallengeCode *OAuth2PKCEChallengeCodeInternal__
	Verifier      *OAuth2PKCEVerifierInternal__
	AuthURI       *URLStringInternal__
	Idtok         *OAuth2ParsedIDTokenInternal__
}

func (o OAuth2SessionInternal__) Import() OAuth2Session {
	return OAuth2Session{
		Id: (func(x *OAuth2SessionIDInternal__) (ret OAuth2SessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Id),
		Binding: (func(x *OAuth2BindingInternal__) (ret OAuth2Binding) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Binding),
		Nonce: (func(x *OAuth2NonceInternal__) (ret OAuth2Nonce) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Nonce),
		ChallengeCode: (func(x *OAuth2PKCEChallengeCodeInternal__) (ret OAuth2PKCEChallengeCode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.ChallengeCode),
		Verifier: (func(x *OAuth2PKCEVerifierInternal__) (ret OAuth2PKCEVerifier) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Verifier),
		AuthURI: (func(x *URLStringInternal__) (ret URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.AuthURI),
		Idtok: (func(x *OAuth2ParsedIDTokenInternal__) *OAuth2ParsedIDToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *OAuth2ParsedIDTokenInternal__) (ret OAuth2ParsedIDToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(o.Idtok),
	}
}

func (o OAuth2Session) Export() *OAuth2SessionInternal__ {
	return &OAuth2SessionInternal__{
		Id:            o.Id.Export(),
		Binding:       o.Binding.Export(),
		Nonce:         o.Nonce.Export(),
		ChallengeCode: o.ChallengeCode.Export(),
		Verifier:      o.Verifier.Export(),
		AuthURI:       o.AuthURI.Export(),
		Idtok: (func(x *OAuth2ParsedIDToken) *OAuth2ParsedIDTokenInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(o.Idtok),
	}
}

func (o *OAuth2Session) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2Session) Decode(dec rpc.Decoder) error {
	var tmp OAuth2SessionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2Session) Bytes() []byte { return nil }

type OAuth2ParsedIDToken struct {
	Raw         OAuth2IDToken
	Issuer      URLString
	Username    NameUtf8
	Email       Email
	Issued      Time
	Expires     Time
	DisplayName NameUtf8
	Subject     OAuth2Subject
}

type OAuth2ParsedIDTokenInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Raw         *OAuth2IDTokenInternal__
	Issuer      *URLStringInternal__
	Username    *NameUtf8Internal__
	Email       *EmailInternal__
	Issued      *TimeInternal__
	Expires     *TimeInternal__
	DisplayName *NameUtf8Internal__
	Subject     *OAuth2SubjectInternal__
}

func (o OAuth2ParsedIDTokenInternal__) Import() OAuth2ParsedIDToken {
	return OAuth2ParsedIDToken{
		Raw: (func(x *OAuth2IDTokenInternal__) (ret OAuth2IDToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Raw),
		Issuer: (func(x *URLStringInternal__) (ret URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Issuer),
		Username: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Username),
		Email: (func(x *EmailInternal__) (ret Email) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Email),
		Issued: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Issued),
		Expires: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Expires),
		DisplayName: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.DisplayName),
		Subject: (func(x *OAuth2SubjectInternal__) (ret OAuth2Subject) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Subject),
	}
}

func (o OAuth2ParsedIDToken) Export() *OAuth2ParsedIDTokenInternal__ {
	return &OAuth2ParsedIDTokenInternal__{
		Raw:         o.Raw.Export(),
		Issuer:      o.Issuer.Export(),
		Username:    o.Username.Export(),
		Email:       o.Email.Export(),
		Issued:      o.Issued.Export(),
		Expires:     o.Expires.Export(),
		DisplayName: o.DisplayName.Export(),
		Subject:     o.Subject.Export(),
	}
}

func (o *OAuth2ParsedIDToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2ParsedIDToken) Decode(dec rpc.Decoder) error {
	var tmp OAuth2ParsedIDTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2ParsedIDToken) Bytes() []byte { return nil }

type OAuth2IDTokenBindingPayload struct {
	IdToken OAuth2IDToken
	Binding OAuth2Binding
}

type OAuth2IDTokenBindingPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	IdToken *OAuth2IDTokenInternal__
	Binding *OAuth2BindingInternal__
}

func (o OAuth2IDTokenBindingPayloadInternal__) Import() OAuth2IDTokenBindingPayload {
	return OAuth2IDTokenBindingPayload{
		IdToken: (func(x *OAuth2IDTokenInternal__) (ret OAuth2IDToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.IdToken),
		Binding: (func(x *OAuth2BindingInternal__) (ret OAuth2Binding) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Binding),
	}
}

func (o OAuth2IDTokenBindingPayload) Export() *OAuth2IDTokenBindingPayloadInternal__ {
	return &OAuth2IDTokenBindingPayloadInternal__{
		IdToken: o.IdToken.Export(),
		Binding: o.Binding.Export(),
	}
}

func (o *OAuth2IDTokenBindingPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2IDTokenBindingPayload) Decode(dec rpc.Decoder) error {
	var tmp OAuth2IDTokenBindingPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2IDTokenBindingPayload) Bytes() []byte { return nil }

type OAuth2IDTokenBindingBlob []byte
type OAuth2IDTokenBindingBlobInternal__ []byte

func (o OAuth2IDTokenBindingBlob) Export() *OAuth2IDTokenBindingBlobInternal__ {
	tmp := (([]byte)(o))
	return ((*OAuth2IDTokenBindingBlobInternal__)(&tmp))
}

func (o OAuth2IDTokenBindingBlobInternal__) Import() OAuth2IDTokenBindingBlob {
	tmp := ([]byte)(o)
	return OAuth2IDTokenBindingBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2IDTokenBindingBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2IDTokenBindingBlob) Decode(dec rpc.Decoder) error {
	var tmp OAuth2IDTokenBindingBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

var OAuth2IDTokenBindingBlobTypeUniqueID = rpc.TypeUniqueID(0x81c5c0695efde1c9)

func (o *OAuth2IDTokenBindingBlob) GetTypeUniqueID() rpc.TypeUniqueID {
	return OAuth2IDTokenBindingBlobTypeUniqueID
}

func (o OAuth2IDTokenBindingBlob) Bytes() []byte {
	return (o)[:]
}

func (o *OAuth2IDTokenBindingBlob) AllocAndDecode(f rpc.DecoderFactory) (*OAuth2IDTokenBindingPayload, error) {
	var ret OAuth2IDTokenBindingPayload
	src := f.NewDecoderBytes(&ret, o.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (o *OAuth2IDTokenBindingBlob) AssertNormalized() error { return nil }

func (o *OAuth2IDTokenBindingPayload) EncodeTyped(f rpc.EncoderFactory) (*OAuth2IDTokenBindingBlob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := o.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := OAuth2IDTokenBindingBlob(tmp)
	return &ret, nil
}

func (o *OAuth2IDTokenBindingPayload) ChildBlob(_b []byte) OAuth2IDTokenBindingBlob {
	return OAuth2IDTokenBindingBlob(_b)
}

type OAuth2IDTokenBinding struct {
	Inner OAuth2IDTokenBindingBlob
	Sig   Signature
	Key   EntityID
}

type OAuth2IDTokenBindingInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner   *OAuth2IDTokenBindingBlobInternal__
	Sig     *SignatureInternal__
	Key     *EntityIDInternal__
}

func (o OAuth2IDTokenBindingInternal__) Import() OAuth2IDTokenBinding {
	return OAuth2IDTokenBinding{
		Inner: (func(x *OAuth2IDTokenBindingBlobInternal__) (ret OAuth2IDTokenBindingBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Inner),
		Sig: (func(x *SignatureInternal__) (ret Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Sig),
		Key: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Key),
	}
}

func (o OAuth2IDTokenBinding) Export() *OAuth2IDTokenBindingInternal__ {
	return &OAuth2IDTokenBindingInternal__{
		Inner: o.Inner.Export(),
		Sig:   o.Sig.Export(),
		Key:   o.Key.Export(),
	}
}

func (o *OAuth2IDTokenBinding) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2IDTokenBinding) Decode(dec rpc.Decoder) error {
	var tmp OAuth2IDTokenBindingInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2IDTokenBinding) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(OAuth2TokenSetTypeUniqueID)
	rpc.AddUnique(OAuth2BindingTypeUniqueID)
	rpc.AddUnique(OAuth2IDTokenBindingBlobTypeUniqueID)
}
