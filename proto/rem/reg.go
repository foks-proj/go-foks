// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/reg.snowp

package rem

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type ChallengePayload struct {
	HmacKeyID lib.HMACKeyID
	EntityID  lib.EntityID
	HostID    lib.HostID
	Rand      lib.Random16
	Time      lib.Time
}

type ChallengePayloadInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HmacKeyID *lib.HMACKeyIDInternal__
	EntityID  *lib.EntityIDInternal__
	HostID    *lib.HostIDInternal__
	Rand      *lib.Random16Internal__
	Time      *lib.TimeInternal__
}

func (c ChallengePayloadInternal__) Import() ChallengePayload {
	return ChallengePayload{
		HmacKeyID: (func(x *lib.HMACKeyIDInternal__) (ret lib.HMACKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.HmacKeyID),
		EntityID: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.EntityID),
		HostID: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.HostID),
		Rand: (func(x *lib.Random16Internal__) (ret lib.Random16) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Rand),
		Time: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Time),
	}
}

func (c ChallengePayload) Export() *ChallengePayloadInternal__ {
	return &ChallengePayloadInternal__{
		HmacKeyID: c.HmacKeyID.Export(),
		EntityID:  c.EntityID.Export(),
		HostID:    c.HostID.Export(),
		Rand:      c.Rand.Export(),
		Time:      c.Time.Export(),
	}
}

func (c *ChallengePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChallengePayload) Decode(dec rpc.Decoder) error {
	var tmp ChallengePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChallengePayloadTypeUniqueID = rpc.TypeUniqueID(0x92bb9122e9d5ae59)

func (c *ChallengePayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChallengePayloadTypeUniqueID
}

func (c *ChallengePayload) Bytes() []byte { return nil }

type NameType int

const (
	NameType_User NameType = 1
	NameType_Team NameType = 2
)

var NameTypeMap = map[string]NameType{
	"User": 1,
	"Team": 2,
}

var NameTypeRevMap = map[NameType]string{
	1: "User",
	2: "Team",
}

type NameTypeInternal__ NameType

func (n NameTypeInternal__) Import() NameType {
	return NameType(n)
}

func (n NameType) Export() *NameTypeInternal__ {
	return ((*NameTypeInternal__)(&n))
}

type Challenge struct {
	Payload ChallengePayload
	Mac     lib.HMAC
}

type ChallengeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Payload *ChallengePayloadInternal__
	Mac     *lib.HMACInternal__
}

func (c ChallengeInternal__) Import() Challenge {
	return Challenge{
		Payload: (func(x *ChallengePayloadInternal__) (ret ChallengePayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Payload),
		Mac: (func(x *lib.HMACInternal__) (ret lib.HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Mac),
	}
}

func (c Challenge) Export() *ChallengeInternal__ {
	return &ChallengeInternal__{
		Payload: c.Payload.Export(),
		Mac:     c.Mac.Export(),
	}
}

func (c *Challenge) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Challenge) Decode(dec rpc.Decoder) error {
	var tmp ChallengeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *Challenge) Bytes() []byte { return nil }

type LoginRes struct {
	PpGen         lib.PassphraseGeneration
	SkwkBox       lib.SecretBox
	PassphraseBox lib.PpePassphraseBox
}

type LoginResInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PpGen         *lib.PassphraseGenerationInternal__
	SkwkBox       *lib.SecretBoxInternal__
	PassphraseBox *lib.PpePassphraseBoxInternal__
}

func (l LoginResInternal__) Import() LoginRes {
	return LoginRes{
		PpGen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.PpGen),
		SkwkBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SkwkBox),
		PassphraseBox: (func(x *lib.PpePassphraseBoxInternal__) (ret lib.PpePassphraseBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.PassphraseBox),
	}
}

func (l LoginRes) Export() *LoginResInternal__ {
	return &LoginResInternal__{
		PpGen:         l.PpGen.Export(),
		SkwkBox:       l.SkwkBox.Export(),
		PassphraseBox: l.PassphraseBox.Export(),
	}
}

func (l *LoginRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoginRes) Decode(dec rpc.Decoder) error {
	var tmp LoginResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoginRes) Bytes() []byte { return nil }

type ReserveNameRes struct {
	Tok   lib.ReservationToken
	Seq   lib.NameSeqno
	Etime lib.Time
}

type ReserveNameResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *lib.ReservationTokenInternal__
	Seq     *lib.NameSeqnoInternal__
	Etime   *lib.TimeInternal__
}

func (r ReserveNameResInternal__) Import() ReserveNameRes {
	return ReserveNameRes{
		Tok: (func(x *lib.ReservationTokenInternal__) (ret lib.ReservationToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Tok),
		Seq: (func(x *lib.NameSeqnoInternal__) (ret lib.NameSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		Etime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Etime),
	}
}

func (r ReserveNameRes) Export() *ReserveNameResInternal__ {
	return &ReserveNameResInternal__{
		Tok:   r.Tok.Export(),
		Seq:   r.Seq.Export(),
		Etime: r.Etime.Export(),
	}
}

func (r *ReserveNameRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReserveNameRes) Decode(dec rpc.Decoder) error {
	var tmp ReserveNameResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReserveNameRes) Bytes() []byte { return nil }

type NameCommitment struct {
	Name lib.Name
	Seq  lib.NameSeqno
}

type NameCommitmentInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *lib.NameInternal__
	Seq     *lib.NameSeqnoInternal__
}

func (n NameCommitmentInternal__) Import() NameCommitment {
	return NameCommitment{
		Name: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Name),
		Seq: (func(x *lib.NameSeqnoInternal__) (ret lib.NameSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Seq),
	}
}

func (n NameCommitment) Export() *NameCommitmentInternal__ {
	return &NameCommitmentInternal__{
		Name: n.Name.Export(),
		Seq:  n.Seq.Export(),
	}
}

func (n *NameCommitment) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameCommitment) Decode(dec rpc.Decoder) error {
	var tmp NameCommitmentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

var NameCommitmentTypeUniqueID = rpc.TypeUniqueID(0xe37b1fcfba972353)

func (n *NameCommitment) GetTypeUniqueID() rpc.TypeUniqueID {
	return NameCommitmentTypeUniqueID
}

func (n *NameCommitment) Bytes() []byte { return nil }

type LookupUserRes struct {
	Fqu          lib.FQUser
	Username     lib.Name
	UsernameUtf8 lib.NameUtf8
	Role         lib.Role
	YubiPQHint   *lib.YubiSlotAndPQKeyID
}

type LookupUserResInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu          *lib.FQUserInternal__
	Username     *lib.NameInternal__
	UsernameUtf8 *lib.NameUtf8Internal__
	Role         *lib.RoleInternal__
	YubiPQHint   *lib.YubiSlotAndPQKeyIDInternal__
}

func (l LookupUserResInternal__) Import() LookupUserRes {
	return LookupUserRes{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Fqu),
		Username: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Username),
		UsernameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.UsernameUtf8),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Role),
		YubiPQHint: (func(x *lib.YubiSlotAndPQKeyIDInternal__) *lib.YubiSlotAndPQKeyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.YubiSlotAndPQKeyIDInternal__) (ret lib.YubiSlotAndPQKeyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.YubiPQHint),
	}
}

func (l LookupUserRes) Export() *LookupUserResInternal__ {
	return &LookupUserResInternal__{
		Fqu:          l.Fqu.Export(),
		Username:     l.Username.Export(),
		UsernameUtf8: l.UsernameUtf8.Export(),
		Role:         l.Role.Export(),
		YubiPQHint: (func(x *lib.YubiSlotAndPQKeyID) *lib.YubiSlotAndPQKeyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.YubiPQHint),
	}
}

func (l *LookupUserRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LookupUserRes) Decode(dec rpc.Decoder) error {
	var tmp LookupUserResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LookupUserRes) Bytes() []byte { return nil }

type OAuth2PollRes struct {
	Toks lib.OAuth2TokenSet
	Res  ReserveNameRes
}

type OAuth2PollResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Toks    *lib.OAuth2TokenSetInternal__
	Res     *ReserveNameResInternal__
}

func (o OAuth2PollResInternal__) Import() OAuth2PollRes {
	return OAuth2PollRes{
		Toks: (func(x *lib.OAuth2TokenSetInternal__) (ret lib.OAuth2TokenSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Toks),
		Res: (func(x *ReserveNameResInternal__) (ret ReserveNameRes) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Res),
	}
}

func (o OAuth2PollRes) Export() *OAuth2PollResInternal__ {
	return &OAuth2PollResInternal__{
		Toks: o.Toks.Export(),
		Res:  o.Res.Export(),
	}
}

func (o *OAuth2PollRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2PollRes) Decode(dec rpc.Decoder) error {
	var tmp OAuth2PollResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OAuth2PollRes) Bytes() []byte { return nil }

type RegSSOArgs struct {
	T     lib.SSOProtocolType
	F_1__ *RegSSOArgsOAuth2 `json:"f1,omitempty"`
}

type RegSSOArgsInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.SSOProtocolType
	Switch__ RegSSOArgsInternalSwitch__
}

type RegSSOArgsInternalSwitch__ struct {
	_struct struct{}                    `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *RegSSOArgsOAuth2Internal__ `codec:"1"`
}

func (r RegSSOArgs) GetT() (ret lib.SSOProtocolType, err error) {
	switch r.T {
	case lib.SSOProtocolType_None:
		break
	case lib.SSOProtocolType_Oauth2:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return r.T, nil
}

func (r RegSSOArgs) Oauth2() RegSSOArgsOAuth2 {
	if r.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if r.T != lib.SSOProtocolType_Oauth2 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oauth2 is called", r.T))
	}
	return *r.F_1__
}

func NewRegSSOArgsWithNone() RegSSOArgs {
	return RegSSOArgs{
		T: lib.SSOProtocolType_None,
	}
}

func NewRegSSOArgsWithOauth2(v RegSSOArgsOAuth2) RegSSOArgs {
	return RegSSOArgs{
		T:     lib.SSOProtocolType_Oauth2,
		F_1__: &v,
	}
}

func (r RegSSOArgsInternal__) Import() RegSSOArgs {
	return RegSSOArgs{
		T: r.T,
		F_1__: (func(x *RegSSOArgsOAuth2Internal__) *RegSSOArgsOAuth2 {
			if x == nil {
				return nil
			}
			tmp := (func(x *RegSSOArgsOAuth2Internal__) (ret RegSSOArgsOAuth2) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
	}
}

func (r RegSSOArgs) Export() *RegSSOArgsInternal__ {
	return &RegSSOArgsInternal__{
		T: r.T,
		Switch__: RegSSOArgsInternalSwitch__{
			F_1__: (func(x *RegSSOArgsOAuth2) *RegSSOArgsOAuth2Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
		},
	}
}

func (r *RegSSOArgs) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegSSOArgs) Decode(dec rpc.Decoder) error {
	var tmp RegSSOArgsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegSSOArgs) Bytes() []byte { return nil }

type RegSSOArgsOAuth2 struct {
	Id  lib.OAuth2SessionID
	Sig lib.OAuth2IDTokenBinding
}

type RegSSOArgsOAuth2Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.OAuth2SessionIDInternal__
	Sig     *lib.OAuth2IDTokenBindingInternal__
}

func (r RegSSOArgsOAuth2Internal__) Import() RegSSOArgsOAuth2 {
	return RegSSOArgsOAuth2{
		Id: (func(x *lib.OAuth2SessionIDInternal__) (ret lib.OAuth2SessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Id),
		Sig: (func(x *lib.OAuth2IDTokenBindingInternal__) (ret lib.OAuth2IDTokenBinding) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Sig),
	}
}

func (r RegSSOArgsOAuth2) Export() *RegSSOArgsOAuth2Internal__ {
	return &RegSSOArgsOAuth2Internal__{
		Id:  r.Id.Export(),
		Sig: r.Sig.Export(),
	}
}

func (r *RegSSOArgsOAuth2) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegSSOArgsOAuth2) Decode(dec rpc.Decoder) error {
	var tmp RegSSOArgsOAuth2Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegSSOArgsOAuth2) Bytes() []byte { return nil }

type SignupRes struct {
}

type SignupResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (s SignupResInternal__) Import() SignupRes {
	return SignupRes{}
}

func (s SignupRes) Export() *SignupResInternal__ {
	return &SignupResInternal__{}
}

func (s *SignupRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignupRes) Decode(dec rpc.Decoder) error {
	var tmp SignupResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignupRes) Bytes() []byte { return nil }

var RegProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf7ab85f3)

type ReserveUsernameArg struct {
	N lib.Name
}

type ReserveUsernameArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	N       *lib.NameInternal__
}

func (r ReserveUsernameArgInternal__) Import() ReserveUsernameArg {
	return ReserveUsernameArg{
		N: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.N),
	}
}

func (r ReserveUsernameArg) Export() *ReserveUsernameArgInternal__ {
	return &ReserveUsernameArgInternal__{
		N: r.N.Export(),
	}
}

func (r *ReserveUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReserveUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp ReserveUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReserveUsernameArg) Bytes() []byte { return nil }

type GetClientCertChainArg struct {
	Uid lib.UID
	Key lib.EntityID
}

type GetClientCertChainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *lib.UIDInternal__
	Key     *lib.EntityIDInternal__
}

func (g GetClientCertChainArgInternal__) Import() GetClientCertChainArg {
	return GetClientCertChainArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Uid),
		Key: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Key),
	}
}

func (g GetClientCertChainArg) Export() *GetClientCertChainArgInternal__ {
	return &GetClientCertChainArgInternal__{
		Uid: g.Uid.Export(),
		Key: g.Key.Export(),
	}
}

func (g *GetClientCertChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetClientCertChainArg) Decode(dec rpc.Decoder) error {
	var tmp GetClientCertChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetClientCertChainArg) Bytes() []byte { return nil }

type SignupArg struct {
	UsernameUtf8             lib.NameUtf8
	Rur                      ReserveNameRes
	Link                     lib.LinkOuter
	PukBox                   lib.SharedKeyBoxSet
	UsernameCommitmentKey    lib.RandomCommitmentKey
	Dlnck                    DeviceLabelNameAndCommitmentKey
	NextTreeLocation         lib.TreeLocation
	InviteCode               InviteCode
	Email                    lib.Email
	SubkeyBox                *lib.Box
	Passphrase               *SetPassphraseArg
	SubchainTreeLocationSeed lib.TreeLocation
	SelfToken                lib.PermissionToken
	Hepks                    lib.HEPKSet
	YubiPQhint               *lib.YubiSlotAndPQKeyID
	Sso                      RegSSOArgs
}

type SignupArgInternal__ struct {
	_struct                  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	UsernameUtf8             *lib.NameUtf8Internal__
	Rur                      *ReserveNameResInternal__
	Link                     *lib.LinkOuterInternal__
	PukBox                   *lib.SharedKeyBoxSetInternal__
	UsernameCommitmentKey    *lib.RandomCommitmentKeyInternal__
	Dlnck                    *DeviceLabelNameAndCommitmentKeyInternal__
	NextTreeLocation         *lib.TreeLocationInternal__
	InviteCode               *InviteCodeInternal__
	Email                    *lib.EmailInternal__
	SubkeyBox                *lib.BoxInternal__
	Passphrase               *SetPassphraseArgInternal__
	SubchainTreeLocationSeed *lib.TreeLocationInternal__
	SelfToken                *lib.PermissionTokenInternal__
	Hepks                    *lib.HEPKSetInternal__
	YubiPQhint               *lib.YubiSlotAndPQKeyIDInternal__
	Sso                      *RegSSOArgsInternal__
}

func (s SignupArgInternal__) Import() SignupArg {
	return SignupArg{
		UsernameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.UsernameUtf8),
		Rur: (func(x *ReserveNameResInternal__) (ret ReserveNameRes) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Rur),
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Link),
		PukBox: (func(x *lib.SharedKeyBoxSetInternal__) (ret lib.SharedKeyBoxSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.PukBox),
		UsernameCommitmentKey: (func(x *lib.RandomCommitmentKeyInternal__) (ret lib.RandomCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.UsernameCommitmentKey),
		Dlnck: (func(x *DeviceLabelNameAndCommitmentKeyInternal__) (ret DeviceLabelNameAndCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Dlnck),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.NextTreeLocation),
		InviteCode: (func(x *InviteCodeInternal__) (ret InviteCode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.InviteCode),
		Email: (func(x *lib.EmailInternal__) (ret lib.Email) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Email),
		SubkeyBox: (func(x *lib.BoxInternal__) *lib.Box {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.BoxInternal__) (ret lib.Box) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.SubkeyBox),
		Passphrase: (func(x *SetPassphraseArgInternal__) *SetPassphraseArg {
			if x == nil {
				return nil
			}
			tmp := (func(x *SetPassphraseArgInternal__) (ret SetPassphraseArg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Passphrase),
		SubchainTreeLocationSeed: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SubchainTreeLocationSeed),
		SelfToken: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SelfToken),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Hepks),
		YubiPQhint: (func(x *lib.YubiSlotAndPQKeyIDInternal__) *lib.YubiSlotAndPQKeyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.YubiSlotAndPQKeyIDInternal__) (ret lib.YubiSlotAndPQKeyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.YubiPQhint),
		Sso: (func(x *RegSSOArgsInternal__) (ret RegSSOArgs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sso),
	}
}

func (s SignupArg) Export() *SignupArgInternal__ {
	return &SignupArgInternal__{
		UsernameUtf8:          s.UsernameUtf8.Export(),
		Rur:                   s.Rur.Export(),
		Link:                  s.Link.Export(),
		PukBox:                s.PukBox.Export(),
		UsernameCommitmentKey: s.UsernameCommitmentKey.Export(),
		Dlnck:                 s.Dlnck.Export(),
		NextTreeLocation:      s.NextTreeLocation.Export(),
		InviteCode:            s.InviteCode.Export(),
		Email:                 s.Email.Export(),
		SubkeyBox: (func(x *lib.Box) *lib.BoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.SubkeyBox),
		Passphrase: (func(x *SetPassphraseArg) *SetPassphraseArgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Passphrase),
		SubchainTreeLocationSeed: s.SubchainTreeLocationSeed.Export(),
		SelfToken:                s.SelfToken.Export(),
		Hepks:                    s.Hepks.Export(),
		YubiPQhint: (func(x *lib.YubiSlotAndPQKeyID) *lib.YubiSlotAndPQKeyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.YubiPQhint),
		Sso: s.Sso.Export(),
	}
}

func (s *SignupArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignupArg) Decode(dec rpc.Decoder) error {
	var tmp SignupArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignupArg) Bytes() []byte { return nil }

type GetHostIDArg struct {
}

type GetHostIDArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetHostIDArgInternal__) Import() GetHostIDArg {
	return GetHostIDArg{}
}

func (g GetHostIDArg) Export() *GetHostIDArgInternal__ {
	return &GetHostIDArgInternal__{}
}

func (g *GetHostIDArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetHostIDArg) Decode(dec rpc.Decoder) error {
	var tmp GetHostIDArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetHostIDArg) Bytes() []byte { return nil }

type GetLoginChallengeArg struct {
	Uid lib.UID
}

type GetLoginChallengeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *lib.UIDInternal__
}

func (g GetLoginChallengeArgInternal__) Import() GetLoginChallengeArg {
	return GetLoginChallengeArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Uid),
	}
}

func (g GetLoginChallengeArg) Export() *GetLoginChallengeArgInternal__ {
	return &GetLoginChallengeArgInternal__{
		Uid: g.Uid.Export(),
	}
}

func (g *GetLoginChallengeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetLoginChallengeArg) Decode(dec rpc.Decoder) error {
	var tmp GetLoginChallengeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetLoginChallengeArg) Bytes() []byte { return nil }

type LoginArg struct {
	Uid       lib.UID
	Challenge Challenge
	Signature lib.Signature
}

type LoginArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid       *lib.UIDInternal__
	Challenge *ChallengeInternal__
	Signature *lib.SignatureInternal__
}

func (l LoginArgInternal__) Import() LoginArg {
	return LoginArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Uid),
		Challenge: (func(x *ChallengeInternal__) (ret Challenge) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Challenge),
		Signature: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Signature),
	}
}

func (l LoginArg) Export() *LoginArgInternal__ {
	return &LoginArgInternal__{
		Uid:       l.Uid.Export(),
		Challenge: l.Challenge.Export(),
		Signature: l.Signature.Export(),
	}
}

func (l *LoginArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoginArg) Decode(dec rpc.Decoder) error {
	var tmp LoginArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoginArg) Bytes() []byte { return nil }

type GetUIDLookupChallegeArg struct {
	EntityID lib.EntityID
}

type GetUIDLookupChallegeArgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	EntityID *lib.EntityIDInternal__
}

func (g GetUIDLookupChallegeArgInternal__) Import() GetUIDLookupChallegeArg {
	return GetUIDLookupChallegeArg{
		EntityID: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.EntityID),
	}
}

func (g GetUIDLookupChallegeArg) Export() *GetUIDLookupChallegeArgInternal__ {
	return &GetUIDLookupChallegeArgInternal__{
		EntityID: g.EntityID.Export(),
	}
}

func (g *GetUIDLookupChallegeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetUIDLookupChallegeArg) Decode(dec rpc.Decoder) error {
	var tmp GetUIDLookupChallegeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetUIDLookupChallegeArg) Bytes() []byte { return nil }

type LookupUIDByDeviceArg struct {
	EntityID  lib.EntityID
	Challenge Challenge
	Signature lib.Signature
}

type LookupUIDByDeviceArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	EntityID  *lib.EntityIDInternal__
	Challenge *ChallengeInternal__
	Signature *lib.SignatureInternal__
}

func (l LookupUIDByDeviceArgInternal__) Import() LookupUIDByDeviceArg {
	return LookupUIDByDeviceArg{
		EntityID: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.EntityID),
		Challenge: (func(x *ChallengeInternal__) (ret Challenge) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Challenge),
		Signature: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Signature),
	}
}

func (l LookupUIDByDeviceArg) Export() *LookupUIDByDeviceArgInternal__ {
	return &LookupUIDByDeviceArgInternal__{
		EntityID:  l.EntityID.Export(),
		Challenge: l.Challenge.Export(),
		Signature: l.Signature.Export(),
	}
}

func (l *LookupUIDByDeviceArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LookupUIDByDeviceArg) Decode(dec rpc.Decoder) error {
	var tmp LookupUIDByDeviceArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LookupUIDByDeviceArg) Bytes() []byte { return nil }

type CheckInviteCodeArg struct {
	InviteCode InviteCode
}

type CheckInviteCodeArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	InviteCode *InviteCodeInternal__
}

func (c CheckInviteCodeArgInternal__) Import() CheckInviteCodeArg {
	return CheckInviteCodeArg{
		InviteCode: (func(x *InviteCodeInternal__) (ret InviteCode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InviteCode),
	}
}

func (c CheckInviteCodeArg) Export() *CheckInviteCodeArgInternal__ {
	return &CheckInviteCodeArgInternal__{
		InviteCode: c.InviteCode.Export(),
	}
}

func (c *CheckInviteCodeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckInviteCodeArg) Decode(dec rpc.Decoder) error {
	var tmp CheckInviteCodeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckInviteCodeArg) Bytes() []byte { return nil }

type JoinWaitListArg struct {
	Email lib.Email
}

type JoinWaitListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Email   *lib.EmailInternal__
}

func (j JoinWaitListArgInternal__) Import() JoinWaitListArg {
	return JoinWaitListArg{
		Email: (func(x *lib.EmailInternal__) (ret lib.Email) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(j.Email),
	}
}

func (j JoinWaitListArg) Export() *JoinWaitListArgInternal__ {
	return &JoinWaitListArgInternal__{
		Email: j.Email.Export(),
	}
}

func (j *JoinWaitListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(j.Export())
}

func (j *JoinWaitListArg) Decode(dec rpc.Decoder) error {
	var tmp JoinWaitListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*j = tmp.Import()
	return nil
}

func (j *JoinWaitListArg) Bytes() []byte { return nil }

type CheckNameExistsArg struct {
	Name lib.Name
}

type CheckNameExistsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *lib.NameInternal__
}

func (c CheckNameExistsArgInternal__) Import() CheckNameExistsArg {
	return CheckNameExistsArg{
		Name: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Name),
	}
}

func (c CheckNameExistsArg) Export() *CheckNameExistsArgInternal__ {
	return &CheckNameExistsArgInternal__{
		Name: c.Name.Export(),
	}
}

func (c *CheckNameExistsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckNameExistsArg) Decode(dec rpc.Decoder) error {
	var tmp CheckNameExistsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckNameExistsArg) Bytes() []byte { return nil }

type RegLoadUserChainArg struct {
	A LoadUserChainArg
}

type RegLoadUserChainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	A       *LoadUserChainArgInternal__
}

func (r RegLoadUserChainArgInternal__) Import() RegLoadUserChainArg {
	return RegLoadUserChainArg{
		A: (func(x *LoadUserChainArgInternal__) (ret LoadUserChainArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.A),
	}
}

func (r RegLoadUserChainArg) Export() *RegLoadUserChainArgInternal__ {
	return &RegLoadUserChainArgInternal__{
		A: r.A.Export(),
	}
}

func (r *RegLoadUserChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegLoadUserChainArg) Decode(dec rpc.Decoder) error {
	var tmp RegLoadUserChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegLoadUserChainArg) Bytes() []byte { return nil }

type GetSubkeyBoxChallengeArg struct {
	Parent lib.EntityID
}

type GetSubkeyBoxChallengeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Parent  *lib.EntityIDInternal__
}

func (g GetSubkeyBoxChallengeArgInternal__) Import() GetSubkeyBoxChallengeArg {
	return GetSubkeyBoxChallengeArg{
		Parent: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Parent),
	}
}

func (g GetSubkeyBoxChallengeArg) Export() *GetSubkeyBoxChallengeArgInternal__ {
	return &GetSubkeyBoxChallengeArgInternal__{
		Parent: g.Parent.Export(),
	}
}

func (g *GetSubkeyBoxChallengeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetSubkeyBoxChallengeArg) Decode(dec rpc.Decoder) error {
	var tmp GetSubkeyBoxChallengeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetSubkeyBoxChallengeArg) Bytes() []byte { return nil }

type LoadSubkeyBoxArg struct {
	Parent    lib.EntityID
	Challenge Challenge
	Signature lib.Signature
}

type LoadSubkeyBoxArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Parent    *lib.EntityIDInternal__
	Challenge *ChallengeInternal__
	Signature *lib.SignatureInternal__
}

func (l LoadSubkeyBoxArgInternal__) Import() LoadSubkeyBoxArg {
	return LoadSubkeyBoxArg{
		Parent: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Parent),
		Challenge: (func(x *ChallengeInternal__) (ret Challenge) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Challenge),
		Signature: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Signature),
	}
}

func (l LoadSubkeyBoxArg) Export() *LoadSubkeyBoxArgInternal__ {
	return &LoadSubkeyBoxArgInternal__{
		Parent:    l.Parent.Export(),
		Challenge: l.Challenge.Export(),
		Signature: l.Signature.Export(),
	}
}

func (l *LoadSubkeyBoxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadSubkeyBoxArg) Decode(dec rpc.Decoder) error {
	var tmp LoadSubkeyBoxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadSubkeyBoxArg) Bytes() []byte { return nil }

type RegStretchVersionArg struct {
}

type RegStretchVersionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (r RegStretchVersionArgInternal__) Import() RegStretchVersionArg {
	return RegStretchVersionArg{}
}

func (r RegStretchVersionArg) Export() *RegStretchVersionArgInternal__ {
	return &RegStretchVersionArgInternal__{}
}

func (r *RegStretchVersionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegStretchVersionArg) Decode(dec rpc.Decoder) error {
	var tmp RegStretchVersionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegStretchVersionArg) Bytes() []byte { return nil }

type RegSelectVhost struct {
	Host lib.HostID
}

type RegSelectVhostInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostIDInternal__
}

func (r RegSelectVhostInternal__) Import() RegSelectVhost {
	return RegSelectVhost{
		Host: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Host),
	}
}

func (r RegSelectVhost) Export() *RegSelectVhostInternal__ {
	return &RegSelectVhostInternal__{
		Host: r.Host.Export(),
	}
}

func (r *RegSelectVhost) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegSelectVhost) Decode(dec rpc.Decoder) error {
	var tmp RegSelectVhostInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegSelectVhost) Bytes() []byte { return nil }

type RegResolveUsernameArg struct {
	A ResolveUsernameArg
}

type RegResolveUsernameArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	A       *ResolveUsernameArgInternal__
}

func (r RegResolveUsernameArgInternal__) Import() RegResolveUsernameArg {
	return RegResolveUsernameArg{
		A: (func(x *ResolveUsernameArgInternal__) (ret ResolveUsernameArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.A),
	}
}

func (r RegResolveUsernameArg) Export() *RegResolveUsernameArgInternal__ {
	return &RegResolveUsernameArgInternal__{
		A: r.A.Export(),
	}
}

func (r *RegResolveUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegResolveUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp RegResolveUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegResolveUsernameArg) Bytes() []byte { return nil }

type GetServerConfigArg struct {
}

type GetServerConfigArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetServerConfigArgInternal__) Import() GetServerConfigArg {
	return GetServerConfigArg{}
}

func (g GetServerConfigArg) Export() *GetServerConfigArgInternal__ {
	return &GetServerConfigArgInternal__{}
}

func (g *GetServerConfigArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetServerConfigArg) Decode(dec rpc.Decoder) error {
	var tmp GetServerConfigArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetServerConfigArg) Bytes() []byte { return nil }

type InitOAuth2SessionArg struct {
	Id           lib.OAuth2SessionID
	PkceVerifier lib.OAuth2PKCEVerifier
	Nonce        lib.OAuth2Nonce
	Uid          *lib.UID
}

type InitOAuth2SessionArgInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id           *lib.OAuth2SessionIDInternal__
	PkceVerifier *lib.OAuth2PKCEVerifierInternal__
	Nonce        *lib.OAuth2NonceInternal__
	Uid          *lib.UIDInternal__
}

func (i InitOAuth2SessionArgInternal__) Import() InitOAuth2SessionArg {
	return InitOAuth2SessionArg{
		Id: (func(x *lib.OAuth2SessionIDInternal__) (ret lib.OAuth2SessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.Id),
		PkceVerifier: (func(x *lib.OAuth2PKCEVerifierInternal__) (ret lib.OAuth2PKCEVerifier) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.PkceVerifier),
		Nonce: (func(x *lib.OAuth2NonceInternal__) (ret lib.OAuth2Nonce) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.Nonce),
		Uid: (func(x *lib.UIDInternal__) *lib.UID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.UIDInternal__) (ret lib.UID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(i.Uid),
	}
}

func (i InitOAuth2SessionArg) Export() *InitOAuth2SessionArgInternal__ {
	return &InitOAuth2SessionArgInternal__{
		Id:           i.Id.Export(),
		PkceVerifier: i.PkceVerifier.Export(),
		Nonce:        i.Nonce.Export(),
		Uid: (func(x *lib.UID) *lib.UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(i.Uid),
	}
}

func (i *InitOAuth2SessionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *InitOAuth2SessionArg) Decode(dec rpc.Decoder) error {
	var tmp InitOAuth2SessionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i *InitOAuth2SessionArg) Bytes() []byte { return nil }

type PollOAuth2SessionCompletionArg struct {
	Id       lib.OAuth2SessionID
	Wait     lib.DurationMilli
	ForLogin bool
}

type PollOAuth2SessionCompletionArgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id       *lib.OAuth2SessionIDInternal__
	Wait     *lib.DurationMilliInternal__
	ForLogin *bool
}

func (p PollOAuth2SessionCompletionArgInternal__) Import() PollOAuth2SessionCompletionArg {
	return PollOAuth2SessionCompletionArg{
		Id: (func(x *lib.OAuth2SessionIDInternal__) (ret lib.OAuth2SessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Id),
		Wait: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Wait),
		ForLogin: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.ForLogin),
	}
}

func (p PollOAuth2SessionCompletionArg) Export() *PollOAuth2SessionCompletionArgInternal__ {
	return &PollOAuth2SessionCompletionArgInternal__{
		Id:       p.Id.Export(),
		Wait:     p.Wait.Export(),
		ForLogin: &p.ForLogin,
	}
}

func (p *PollOAuth2SessionCompletionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PollOAuth2SessionCompletionArg) Decode(dec rpc.Decoder) error {
	var tmp PollOAuth2SessionCompletionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PollOAuth2SessionCompletionArg) Bytes() []byte { return nil }

type SsoLoginArg struct {
	Uid  lib.UID
	Args RegSSOArgs
}

type SsoLoginArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *lib.UIDInternal__
	Args    *RegSSOArgsInternal__
}

func (s SsoLoginArgInternal__) Import() SsoLoginArg {
	return SsoLoginArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Uid),
		Args: (func(x *RegSSOArgsInternal__) (ret RegSSOArgs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Args),
	}
}

func (s SsoLoginArg) Export() *SsoLoginArgInternal__ {
	return &SsoLoginArgInternal__{
		Uid:  s.Uid.Export(),
		Args: s.Args.Export(),
	}
}

func (s *SsoLoginArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SsoLoginArg) Decode(dec rpc.Decoder) error {
	var tmp SsoLoginArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SsoLoginArg) Bytes() []byte { return nil }

type ProbeKeyExistsArg struct {
	Uid     lib.UID
	DevID   lib.DeviceID
	SelfTok lib.PermissionToken
}

type ProbeKeyExistsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *lib.UIDInternal__
	DevID   *lib.DeviceIDInternal__
	SelfTok *lib.PermissionTokenInternal__
}

func (p ProbeKeyExistsArgInternal__) Import() ProbeKeyExistsArg {
	return ProbeKeyExistsArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Uid),
		DevID: (func(x *lib.DeviceIDInternal__) (ret lib.DeviceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.DevID),
		SelfTok: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SelfTok),
	}
}

func (p ProbeKeyExistsArg) Export() *ProbeKeyExistsArgInternal__ {
	return &ProbeKeyExistsArgInternal__{
		Uid:     p.Uid.Export(),
		DevID:   p.DevID.Export(),
		SelfTok: p.SelfTok.Export(),
	}
}

func (p *ProbeKeyExistsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProbeKeyExistsArg) Decode(dec rpc.Decoder) error {
	var tmp ProbeKeyExistsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ProbeKeyExistsArg) Bytes() []byte { return nil }

type GetVHostMgmtHostArg struct {
}

type GetVHostMgmtHostArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetVHostMgmtHostArgInternal__) Import() GetVHostMgmtHostArg {
	return GetVHostMgmtHostArg{}
}

func (g GetVHostMgmtHostArg) Export() *GetVHostMgmtHostArgInternal__ {
	return &GetVHostMgmtHostArgInternal__{}
}

func (g *GetVHostMgmtHostArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetVHostMgmtHostArg) Decode(dec rpc.Decoder) error {
	var tmp GetVHostMgmtHostArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetVHostMgmtHostArg) Bytes() []byte { return nil }

type RegInterface interface {
	ReserveUsername(context.Context, lib.Name) (ReserveNameRes, error)
	GetClientCertChain(context.Context, GetClientCertChainArg) ([][]byte, error)
	Signup(context.Context, SignupArg) error
	GetHostID(context.Context) (lib.HostID, error)
	GetLoginChallenge(context.Context, lib.UID) (Challenge, error)
	Login(context.Context, LoginArg) (LoginRes, error)
	GetUIDLookupChallege(context.Context, lib.EntityID) (Challenge, error)
	LookupUIDByDevice(context.Context, LookupUIDByDeviceArg) (lib.LookupUserRes, error)
	CheckInviteCode(context.Context, InviteCode) error
	JoinWaitList(context.Context, lib.Email) (lib.WaitListID, error)
	CheckNameExists(context.Context, lib.Name) error
	LoadUserChain(context.Context, LoadUserChainArg) (UserChain, error)
	GetSubkeyBoxChallenge(context.Context, lib.EntityID) (Challenge, error)
	LoadSubkeyBox(context.Context, LoadSubkeyBoxArg) (lib.Box, error)
	StretchVersion(context.Context) (lib.StretchVersion, error)
	SelectVHost(context.Context, lib.HostID) error
	ResolveUsername(context.Context, ResolveUsernameArg) (lib.UID, error)
	GetServerConfig(context.Context) (lib.RegServerConfig, error)
	InitOAuth2Session(context.Context, InitOAuth2SessionArg) (lib.URLString, error)
	PollOAuth2SessionCompletion(context.Context, PollOAuth2SessionCompletionArg) (OAuth2PollRes, error)
	SsoLogin(context.Context, SsoLoginArg) error
	ProbeKeyExists(context.Context, ProbeKeyExistsArg) error
	GetVHostMgmtHost(context.Context) (lib.TCPAddr, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error

	MakeResHeader() lib.Header
}

func RegMakeGenericErrorWrapper(f RegErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type RegErrorUnwrapper func(lib.Status) error
type RegErrorWrapper func(error) lib.Status

type regErrorUnwrapperAdapter struct {
	h RegErrorUnwrapper
}

func (r regErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (r regErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return r.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = regErrorUnwrapperAdapter{}

type RegClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper RegErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c RegClient) ReserveUsername(ctx context.Context, n lib.Name) (res ReserveNameRes, err error) {
	arg := ReserveUsernameArg{
		N: n,
	}
	warg := &rpc.DataWrap[lib.Header, *ReserveUsernameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ReserveNameResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 0, "Reg.reserveUsername"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) GetClientCertChain(ctx context.Context, arg GetClientCertChainArg) (res [][]byte, err error) {
	warg := &rpc.DataWrap[lib.Header, *GetClientCertChainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, []([]byte)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 1, "Reg.getClientCertChain"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[]([]byte)) (ret [][]byte) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([][]byte, len(*x))
		for k, v := range *x {
			ret[k] = (func(x *[]byte) (ret []byte) {
				if x == nil {
					return ret
				}
				return *x
			})(&v)
		}
		return ret
	})(&tmp.Data)
	return
}

func (c RegClient) Signup(ctx context.Context, arg SignupArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *SignupArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 2, "Reg.signup"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) GetHostID(ctx context.Context) (res lib.HostID, err error) {
	var arg GetHostIDArg
	warg := &rpc.DataWrap[lib.Header, *GetHostIDArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.HostIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 3, "Reg.getHostID"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) GetLoginChallenge(ctx context.Context, uid lib.UID) (res Challenge, err error) {
	arg := GetLoginChallengeArg{
		Uid: uid,
	}
	warg := &rpc.DataWrap[lib.Header, *GetLoginChallengeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ChallengeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 4, "Reg.getLoginChallenge"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) Login(ctx context.Context, arg LoginArg) (res LoginRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *LoginArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, LoginResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 5, "Reg.login"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) GetUIDLookupChallege(ctx context.Context, entityID lib.EntityID) (res Challenge, err error) {
	arg := GetUIDLookupChallegeArg{
		EntityID: entityID,
	}
	warg := &rpc.DataWrap[lib.Header, *GetUIDLookupChallegeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ChallengeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 6, "Reg.getUIDLookupChallege"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) LookupUIDByDevice(ctx context.Context, arg LookupUIDByDeviceArg) (res lib.LookupUserRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *LookupUIDByDeviceArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.LookupUserResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 7, "Reg.lookupUIDByDevice"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) CheckInviteCode(ctx context.Context, inviteCode InviteCode) (err error) {
	arg := CheckInviteCodeArg{
		InviteCode: inviteCode,
	}
	warg := &rpc.DataWrap[lib.Header, *CheckInviteCodeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 8, "Reg.checkInviteCode"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) JoinWaitList(ctx context.Context, email lib.Email) (res lib.WaitListID, err error) {
	arg := JoinWaitListArg{
		Email: email,
	}
	warg := &rpc.DataWrap[lib.Header, *JoinWaitListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.WaitListIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 9, "Reg.joinWaitList"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) CheckNameExists(ctx context.Context, name lib.Name) (err error) {
	arg := CheckNameExistsArg{
		Name: name,
	}
	warg := &rpc.DataWrap[lib.Header, *CheckNameExistsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 10, "Reg.checkNameExists"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) LoadUserChain(ctx context.Context, a LoadUserChainArg) (res UserChain, err error) {
	arg := RegLoadUserChainArg{
		A: a,
	}
	warg := &rpc.DataWrap[lib.Header, *RegLoadUserChainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, UserChainInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 11, "Reg.loadUserChain"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) GetSubkeyBoxChallenge(ctx context.Context, parent lib.EntityID) (res Challenge, err error) {
	arg := GetSubkeyBoxChallengeArg{
		Parent: parent,
	}
	warg := &rpc.DataWrap[lib.Header, *GetSubkeyBoxChallengeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ChallengeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 12, "Reg.getSubkeyBoxChallenge"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) LoadSubkeyBox(ctx context.Context, arg LoadSubkeyBoxArg) (res lib.Box, err error) {
	warg := &rpc.DataWrap[lib.Header, *LoadSubkeyBoxArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.BoxInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 13, "Reg.loadSubkeyBox"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) StretchVersion(ctx context.Context) (res lib.StretchVersion, err error) {
	var arg RegStretchVersionArg
	warg := &rpc.DataWrap[lib.Header, *RegStretchVersionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.StretchVersionInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 14, "Reg.stretchVersion"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) SelectVHost(ctx context.Context, host lib.HostID) (err error) {
	arg := RegSelectVhost{
		Host: host,
	}
	warg := &rpc.DataWrap[lib.Header, *RegSelectVhostInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 15, "Reg.selectVHost"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) ResolveUsername(ctx context.Context, a ResolveUsernameArg) (res lib.UID, err error) {
	arg := RegResolveUsernameArg{
		A: a,
	}
	warg := &rpc.DataWrap[lib.Header, *RegResolveUsernameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.UIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 16, "Reg.resolveUsername"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) GetServerConfig(ctx context.Context) (res lib.RegServerConfig, err error) {
	var arg GetServerConfigArg
	warg := &rpc.DataWrap[lib.Header, *GetServerConfigArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RegServerConfigInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 17, "Reg.getServerConfig"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) InitOAuth2Session(ctx context.Context, arg InitOAuth2SessionArg) (res lib.URLString, err error) {
	warg := &rpc.DataWrap[lib.Header, *InitOAuth2SessionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.URLStringInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 18, "Reg.initOAuth2Session"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) PollOAuth2SessionCompletion(ctx context.Context, arg PollOAuth2SessionCompletionArg) (res OAuth2PollRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *PollOAuth2SessionCompletionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, OAuth2PollResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 19, "Reg.pollOAuth2SessionCompletion"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func (c RegClient) SsoLogin(ctx context.Context, arg SsoLoginArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *SsoLoginArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 20, "Reg.ssoLogin"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) ProbeKeyExists(ctx context.Context, arg ProbeKeyExistsArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ProbeKeyExistsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 21, "Reg.probeKeyExists"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c RegClient) GetVHostMgmtHost(ctx context.Context) (res lib.TCPAddr, err error) {
	var arg GetVHostMgmtHostArg
	warg := &rpc.DataWrap[lib.Header, *GetVHostMgmtHostArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.TCPAddrInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RegProtocolID, 22, "Reg.getVHostMgmtHost"), warg, &tmp, 0*time.Millisecond, regErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func RegProtocol(i RegInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Reg",
		ID:   RegProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ReserveUsernameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ReserveUsernameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ReserveUsernameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ReserveUsername(ctx, (typedArg.Import()).N)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ReserveNameResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "reserveUsername",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetClientCertChainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetClientCertChainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetClientCertChainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetClientCertChain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						lst := (func(x [][]byte) *[]([]byte) {
							if len(x) == 0 {
								return nil
							}
							ret := make([]([]byte), len(x))
							copy(ret, x)
							return &ret
						})(tmp)
						ret := rpc.DataWrap[lib.Header, []([]byte)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "getClientCertChain",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *SignupArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *SignupArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *SignupArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.Signup(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "signup",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetHostIDArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetHostIDArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetHostIDArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetHostID(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.HostIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getHostID",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetLoginChallengeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetLoginChallengeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetLoginChallengeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetLoginChallenge(ctx, (typedArg.Import()).Uid)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ChallengeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getLoginChallenge",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *LoginArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *LoginArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *LoginArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Login(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *LoginResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "login",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetUIDLookupChallegeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetUIDLookupChallegeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetUIDLookupChallegeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetUIDLookupChallege(ctx, (typedArg.Import()).EntityID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ChallengeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getUIDLookupChallege",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *LookupUIDByDeviceArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *LookupUIDByDeviceArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *LookupUIDByDeviceArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LookupUIDByDevice(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.LookupUserResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "lookupUIDByDevice",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CheckInviteCodeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CheckInviteCodeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CheckInviteCodeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.CheckInviteCode(ctx, (typedArg.Import()).InviteCode)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "checkInviteCode",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *JoinWaitListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *JoinWaitListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *JoinWaitListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.JoinWaitList(ctx, (typedArg.Import()).Email)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.WaitListIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "joinWaitList",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CheckNameExistsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CheckNameExistsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CheckNameExistsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.CheckNameExists(ctx, (typedArg.Import()).Name)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "checkNameExists",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RegLoadUserChainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RegLoadUserChainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RegLoadUserChainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoadUserChain(ctx, (typedArg.Import()).A)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *UserChainInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadUserChain",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetSubkeyBoxChallengeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetSubkeyBoxChallengeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetSubkeyBoxChallengeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetSubkeyBoxChallenge(ctx, (typedArg.Import()).Parent)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ChallengeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getSubkeyBoxChallenge",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *LoadSubkeyBoxArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *LoadSubkeyBoxArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *LoadSubkeyBoxArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoadSubkeyBox(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.BoxInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadSubkeyBox",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RegStretchVersionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RegStretchVersionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RegStretchVersionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.StretchVersion(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.StretchVersionInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "stretchVersion",
			},
			15: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RegSelectVhostInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RegSelectVhostInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RegSelectVhostInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SelectVHost(ctx, (typedArg.Import()).Host)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "selectVHost",
			},
			16: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RegResolveUsernameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RegResolveUsernameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RegResolveUsernameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ResolveUsername(ctx, (typedArg.Import()).A)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.UIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "resolveUsername",
			},
			17: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetServerConfigArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetServerConfigArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetServerConfigArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetServerConfig(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RegServerConfigInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getServerConfig",
			},
			18: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *InitOAuth2SessionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *InitOAuth2SessionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *InitOAuth2SessionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.InitOAuth2Session(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.URLStringInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "initOAuth2Session",
			},
			19: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *PollOAuth2SessionCompletionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *PollOAuth2SessionCompletionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *PollOAuth2SessionCompletionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.PollOAuth2SessionCompletion(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *OAuth2PollResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "pollOAuth2SessionCompletion",
			},
			20: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *SsoLoginArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *SsoLoginArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *SsoLoginArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SsoLogin(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "ssoLogin",
			},
			21: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ProbeKeyExistsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ProbeKeyExistsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ProbeKeyExistsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ProbeKeyExists(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "probeKeyExists",
			},
			22: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetVHostMgmtHostArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetVHostMgmtHostArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetVHostMgmtHostArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetVHostMgmtHost(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.TCPAddrInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getVHostMgmtHost",
			},
		},
		WrapError: RegMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(ChallengePayloadTypeUniqueID)
	rpc.AddUnique(NameCommitmentTypeUniqueID)
	rpc.AddUnique(RegProtocolID)
}
