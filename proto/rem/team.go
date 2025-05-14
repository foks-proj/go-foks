// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/team.snowp

package rem

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type TeamVOBearerToken [16]byte
type TeamVOBearerTokenInternal__ [16]byte

func (t TeamVOBearerToken) Export() *TeamVOBearerTokenInternal__ {
	tmp := (([16]byte)(t))
	return ((*TeamVOBearerTokenInternal__)(&tmp))
}

func (t TeamVOBearerTokenInternal__) Import() TeamVOBearerToken {
	tmp := ([16]byte)(t)
	return TeamVOBearerToken((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamVOBearerToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamVOBearerToken) Decode(dec rpc.Decoder) error {
	var tmp TeamVOBearerTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamVOBearerToken) Bytes() []byte {
	return (t)[:]
}

type TeamBearerToken [16]byte
type TeamBearerTokenInternal__ [16]byte

func (t TeamBearerToken) Export() *TeamBearerTokenInternal__ {
	tmp := (([16]byte)(t))
	return ((*TeamBearerTokenInternal__)(&tmp))
}

func (t TeamBearerTokenInternal__) Import() TeamBearerToken {
	tmp := ([16]byte)(t)
	return TeamBearerToken((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamBearerToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamBearerToken) Decode(dec rpc.Decoder) error {
	var tmp TeamBearerTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamBearerToken) Bytes() []byte {
	return (t)[:]
}

type SharedKeySig struct {
	Sig  lib.Signature
	Gen  lib.Generation
	Role lib.Role
}

type SharedKeySigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sig     *lib.SignatureInternal__
	Gen     *lib.GenerationInternal__
	Role    *lib.RoleInternal__
}

func (s SharedKeySigInternal__) Import() SharedKeySig {
	return SharedKeySig{
		Sig: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sig),
		Gen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Gen),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
	}
}

func (s SharedKeySig) Export() *SharedKeySigInternal__ {
	return &SharedKeySigInternal__{
		Sig:  s.Sig.Export(),
		Gen:  s.Gen.Export(),
		Role: s.Role.Export(),
	}
}

func (s *SharedKeySig) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeySig) Decode(dec rpc.Decoder) error {
	var tmp SharedKeySigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeySig) Bytes() []byte { return nil }

type TeamVOBearerTokenReq struct {
	Team    lib.FQTeamIDOrName
	Member  lib.FQParty
	SrcRole lib.Role
	Gen     lib.Generation
}

type TeamVOBearerTokenReqInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamIDOrNameInternal__
	Member  *lib.FQPartyInternal__
	SrcRole *lib.RoleInternal__
	Gen     *lib.GenerationInternal__
}

func (t TeamVOBearerTokenReqInternal__) Import() TeamVOBearerTokenReq {
	return TeamVOBearerTokenReq{
		Team: (func(x *lib.FQTeamIDOrNameInternal__) (ret lib.FQTeamIDOrName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Member: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Member),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Gen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Gen),
	}
}

func (t TeamVOBearerTokenReq) Export() *TeamVOBearerTokenReqInternal__ {
	return &TeamVOBearerTokenReqInternal__{
		Team:    t.Team.Export(),
		Member:  t.Member.Export(),
		SrcRole: t.SrcRole.Export(),
		Gen:     t.Gen.Export(),
	}
}

func (t *TeamVOBearerTokenReq) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamVOBearerTokenReq) Decode(dec rpc.Decoder) error {
	var tmp TeamVOBearerTokenReqInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamVOBearerTokenReq) Bytes() []byte { return nil }

type TeamVOBearerTokenChallengePayload struct {
	Req TeamVOBearerTokenReq
	Tm  lib.Time
	Tok TeamVOBearerToken
	Id  lib.HMACKeyID
}

type TeamVOBearerTokenChallengePayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Req     *TeamVOBearerTokenReqInternal__
	Tm      *lib.TimeInternal__
	Tok     *TeamVOBearerTokenInternal__
	Id      *lib.HMACKeyIDInternal__
}

func (t TeamVOBearerTokenChallengePayloadInternal__) Import() TeamVOBearerTokenChallengePayload {
	return TeamVOBearerTokenChallengePayload{
		Req: (func(x *TeamVOBearerTokenReqInternal__) (ret TeamVOBearerTokenReq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Req),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
		Tok: (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Id: (func(x *lib.HMACKeyIDInternal__) (ret lib.HMACKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Id),
	}
}

func (t TeamVOBearerTokenChallengePayload) Export() *TeamVOBearerTokenChallengePayloadInternal__ {
	return &TeamVOBearerTokenChallengePayloadInternal__{
		Req: t.Req.Export(),
		Tm:  t.Tm.Export(),
		Tok: t.Tok.Export(),
		Id:  t.Id.Export(),
	}
}

func (t *TeamVOBearerTokenChallengePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamVOBearerTokenChallengePayload) Decode(dec rpc.Decoder) error {
	var tmp TeamVOBearerTokenChallengePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamVOBearerTokenChallengePayloadTypeUniqueID = rpc.TypeUniqueID(0x81180183e3a318a9)

func (t *TeamVOBearerTokenChallengePayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamVOBearerTokenChallengePayloadTypeUniqueID
}

func (t *TeamVOBearerTokenChallengePayload) Bytes() []byte { return nil }

type TeamVOBearerTokenChallenge struct {
	Payload TeamVOBearerTokenChallengePayload
	Mac     lib.HMAC
}

type TeamVOBearerTokenChallengeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Payload *TeamVOBearerTokenChallengePayloadInternal__
	Mac     *lib.HMACInternal__
}

func (t TeamVOBearerTokenChallengeInternal__) Import() TeamVOBearerTokenChallenge {
	return TeamVOBearerTokenChallenge{
		Payload: (func(x *TeamVOBearerTokenChallengePayloadInternal__) (ret TeamVOBearerTokenChallengePayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Payload),
		Mac: (func(x *lib.HMACInternal__) (ret lib.HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Mac),
	}
}

func (t TeamVOBearerTokenChallenge) Export() *TeamVOBearerTokenChallengeInternal__ {
	return &TeamVOBearerTokenChallengeInternal__{
		Payload: t.Payload.Export(),
		Mac:     t.Mac.Export(),
	}
}

func (t *TeamVOBearerTokenChallenge) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamVOBearerTokenChallenge) Decode(dec rpc.Decoder) error {
	var tmp TeamVOBearerTokenChallengeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamVOBearerTokenChallengeTypeUniqueID = rpc.TypeUniqueID(0x96861830ffa96bff)

func (t *TeamVOBearerTokenChallenge) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamVOBearerTokenChallengeTypeUniqueID
}

func (t *TeamVOBearerTokenChallenge) Bytes() []byte { return nil }

type ActivatedVOBearerToken struct {
	Tok TeamVOBearerToken
	Id  lib.TeamID
}

type ActivatedVOBearerTokenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamVOBearerTokenInternal__
	Id      *lib.TeamIDInternal__
}

func (a ActivatedVOBearerTokenInternal__) Import() ActivatedVOBearerToken {
	return ActivatedVOBearerToken{
		Tok: (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Tok),
		Id: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
	}
}

func (a ActivatedVOBearerToken) Export() *ActivatedVOBearerTokenInternal__ {
	return &ActivatedVOBearerTokenInternal__{
		Tok: a.Tok.Export(),
		Id:  a.Id.Export(),
	}
}

func (a *ActivatedVOBearerToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActivatedVOBearerToken) Decode(dec rpc.Decoder) error {
	var tmp ActivatedVOBearerTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActivatedVOBearerToken) Bytes() []byte { return nil }

type TokenVariant struct {
	T     TokenType
	F_0__ *TeamVOBearerToken   `json:"f0,omitempty"`
	F_1__ *lib.PermissionToken `json:"f1,omitempty"`
	F_2__ *TeamVOBearerToken   `json:"f2,omitempty"`
}

type TokenVariantInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        TokenType
	Switch__ TokenVariantInternalSwitch__
}

type TokenVariantInternalSwitch__ struct {
	_struct struct{}                       `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *TeamVOBearerTokenInternal__   `codec:"0"`
	F_1__   *lib.PermissionTokenInternal__ `codec:"1"`
	F_2__   *TeamVOBearerTokenInternal__   `codec:"2"`
}

func (t TokenVariant) GetT() (ret TokenType, err error) {
	switch t.T {
	case TokenType_TeamVOBearer:
		if t.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case TokenType_Permission:
		if t.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case TokenType_LocalParentTeam:
		if t.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	default:
		break
	}
	return t.T, nil
}

func (t TokenVariant) Teamvobearer() TeamVOBearerToken {
	if t.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TokenType_TeamVOBearer {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teamvobearer is called", t.T))
	}
	return *t.F_0__
}

func (t TokenVariant) Permission() lib.PermissionToken {
	if t.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TokenType_Permission {
		panic(fmt.Sprintf("unexpected switch value (%v) when Permission is called", t.T))
	}
	return *t.F_1__
}

func (t TokenVariant) Localparentteam() TeamVOBearerToken {
	if t.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TokenType_LocalParentTeam {
		panic(fmt.Sprintf("unexpected switch value (%v) when Localparentteam is called", t.T))
	}
	return *t.F_2__
}

func NewTokenVariantWithTeamvobearer(v TeamVOBearerToken) TokenVariant {
	return TokenVariant{
		T:     TokenType_TeamVOBearer,
		F_0__: &v,
	}
}

func NewTokenVariantWithPermission(v lib.PermissionToken) TokenVariant {
	return TokenVariant{
		T:     TokenType_Permission,
		F_1__: &v,
	}
}

func NewTokenVariantWithLocalparentteam(v TeamVOBearerToken) TokenVariant {
	return TokenVariant{
		T:     TokenType_LocalParentTeam,
		F_2__: &v,
	}
}

func NewTokenVariantDefault(s TokenType) TokenVariant {
	return TokenVariant{
		T: s,
	}
}

func (t TokenVariantInternal__) Import() TokenVariant {
	return TokenVariant{
		T: t.T,
		F_0__: (func(x *TeamVOBearerTokenInternal__) *TeamVOBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_0__),
		F_1__: (func(x *lib.PermissionTokenInternal__) *lib.PermissionToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_1__),
		F_2__: (func(x *TeamVOBearerTokenInternal__) *TeamVOBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_2__),
	}
}

func (t TokenVariant) Export() *TokenVariantInternal__ {
	return &TokenVariantInternal__{
		T: t.T,
		Switch__: TokenVariantInternalSwitch__{
			F_0__: (func(x *TeamVOBearerToken) *TeamVOBearerTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_0__),
			F_1__: (func(x *lib.PermissionToken) *lib.PermissionTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_1__),
			F_2__: (func(x *TeamVOBearerToken) *TeamVOBearerTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_2__),
		},
	}
}

func (t *TokenVariant) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TokenVariant) Decode(dec rpc.Decoder) error {
	var tmp TokenVariantInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TokenVariant) Bytes() []byte { return nil }

type TeamRemovalKey [32]byte
type TeamRemovalKeyInternal__ [32]byte

func (t TeamRemovalKey) Export() *TeamRemovalKeyInternal__ {
	tmp := (([32]byte)(t))
	return ((*TeamRemovalKeyInternal__)(&tmp))
}

func (t TeamRemovalKeyInternal__) Import() TeamRemovalKey {
	tmp := ([32]byte)(t)
	return TeamRemovalKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamRemovalKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalKey) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamRemovalKeyTypeUniqueID = rpc.TypeUniqueID(0xb058740fe7e9fdb5)

func (t *TeamRemovalKey) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamRemovalKeyTypeUniqueID
}

func (t TeamRemovalKey) Bytes() []byte {
	return (t)[:]
}

type TeamRemovalKeyBoxPayload struct {
	Key TeamRemovalKey
	Md  TeamRemovalKeyMetadata
}

type TeamRemovalKeyBoxPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *TeamRemovalKeyInternal__
	Md      *TeamRemovalKeyMetadataInternal__
}

func (t TeamRemovalKeyBoxPayloadInternal__) Import() TeamRemovalKeyBoxPayload {
	return TeamRemovalKeyBoxPayload{
		Key: (func(x *TeamRemovalKeyInternal__) (ret TeamRemovalKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Key),
		Md: (func(x *TeamRemovalKeyMetadataInternal__) (ret TeamRemovalKeyMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Md),
	}
}

func (t TeamRemovalKeyBoxPayload) Export() *TeamRemovalKeyBoxPayloadInternal__ {
	return &TeamRemovalKeyBoxPayloadInternal__{
		Key: t.Key.Export(),
		Md:  t.Md.Export(),
	}
}

func (t *TeamRemovalKeyBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalKeyBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalKeyBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamRemovalKeyBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0xeeae1230be48267f)

func (t *TeamRemovalKeyBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamRemovalKeyBoxPayloadTypeUniqueID
}

func (t *TeamRemovalKeyBoxPayload) Bytes() []byte { return nil }

type TeamRemovalKeyMetadata struct {
	Tm      lib.FQTeam
	Member  lib.FQParty
	SrcRole lib.Role
	Dst     lib.RoleAndSeqno
}

type TeamRemovalKeyMetadataInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tm      *lib.FQTeamInternal__
	Member  *lib.FQPartyInternal__
	SrcRole *lib.RoleInternal__
	Dst     *lib.RoleAndSeqnoInternal__
}

func (t TeamRemovalKeyMetadataInternal__) Import() TeamRemovalKeyMetadata {
	return TeamRemovalKeyMetadata{
		Tm: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
		Member: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Member),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Dst: (func(x *lib.RoleAndSeqnoInternal__) (ret lib.RoleAndSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Dst),
	}
}

func (t TeamRemovalKeyMetadata) Export() *TeamRemovalKeyMetadataInternal__ {
	return &TeamRemovalKeyMetadataInternal__{
		Tm:      t.Tm.Export(),
		Member:  t.Member.Export(),
		SrcRole: t.SrcRole.Export(),
		Dst:     t.Dst.Export(),
	}
}

func (t *TeamRemovalKeyMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalKeyMetadata) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalKeyMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemovalKeyMetadata) Bytes() []byte { return nil }

type TeamRemovalMACPayload struct {
	Team    lib.FQTeam
	Member  lib.FQParty
	SrcRole lib.Role
	Admin   lib.FQParty
	Root    lib.TreeRoot
	Tm      lib.Time
}

type TeamRemovalMACPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Member  *lib.FQPartyInternal__
	SrcRole *lib.RoleInternal__
	Admin   *lib.FQPartyInternal__
	Root    *lib.TreeRootInternal__
	Tm      *lib.TimeInternal__
}

func (t TeamRemovalMACPayloadInternal__) Import() TeamRemovalMACPayload {
	return TeamRemovalMACPayload{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Member: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Member),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Admin: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Admin),
		Root: (func(x *lib.TreeRootInternal__) (ret lib.TreeRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Root),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
	}
}

func (t TeamRemovalMACPayload) Export() *TeamRemovalMACPayloadInternal__ {
	return &TeamRemovalMACPayloadInternal__{
		Team:    t.Team.Export(),
		Member:  t.Member.Export(),
		SrcRole: t.SrcRole.Export(),
		Admin:   t.Admin.Export(),
		Root:    t.Root.Export(),
		Tm:      t.Tm.Export(),
	}
}

func (t *TeamRemovalMACPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalMACPayload) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalMACPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamRemovalMACPayloadTypeUniqueID = rpc.TypeUniqueID(0x8d006be42c05ec34)

func (t *TeamRemovalMACPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamRemovalMACPayloadTypeUniqueID
}

func (t *TeamRemovalMACPayload) Bytes() []byte { return nil }

type TeamRemovalBoxData struct {
	Comm   lib.KeyCommitment
	Team   lib.TeamRemovalKeyBox
	Member lib.TeamRemovalKeyBox
	Md     TeamRemovalKeyMetadata
}

type TeamRemovalBoxDataInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Comm    *lib.KeyCommitmentInternal__
	Team    *lib.TeamRemovalKeyBoxInternal__
	Member  *lib.TeamRemovalKeyBoxInternal__
	Md      *TeamRemovalKeyMetadataInternal__
}

func (t TeamRemovalBoxDataInternal__) Import() TeamRemovalBoxData {
	return TeamRemovalBoxData{
		Comm: (func(x *lib.KeyCommitmentInternal__) (ret lib.KeyCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Comm),
		Team: (func(x *lib.TeamRemovalKeyBoxInternal__) (ret lib.TeamRemovalKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Member: (func(x *lib.TeamRemovalKeyBoxInternal__) (ret lib.TeamRemovalKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Member),
		Md: (func(x *TeamRemovalKeyMetadataInternal__) (ret TeamRemovalKeyMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Md),
	}
}

func (t TeamRemovalBoxData) Export() *TeamRemovalBoxDataInternal__ {
	return &TeamRemovalBoxDataInternal__{
		Comm:   t.Comm.Export(),
		Team:   t.Team.Export(),
		Member: t.Member.Export(),
		Md:     t.Md.Export(),
	}
}

func (t *TeamRemovalBoxData) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalBoxData) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalBoxDataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemovalBoxData) Bytes() []byte { return nil }

type TeamRemoval struct {
	Mac     lib.HMAC
	Payload TeamRemovalMACPayload
}

type TeamRemovalInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Mac     *lib.HMACInternal__
	Payload *TeamRemovalMACPayloadInternal__
}

func (t TeamRemovalInternal__) Import() TeamRemoval {
	return TeamRemoval{
		Mac: (func(x *lib.HMACInternal__) (ret lib.HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Mac),
		Payload: (func(x *TeamRemovalMACPayloadInternal__) (ret TeamRemovalMACPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Payload),
	}
}

func (t TeamRemoval) Export() *TeamRemovalInternal__ {
	return &TeamRemovalInternal__{
		Mac:     t.Mac.Export(),
		Payload: t.Payload.Export(),
	}
}

func (t *TeamRemoval) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoval) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoval) Bytes() []byte { return nil }

type TeamChain struct {
	Links            []lib.LinkOuter
	Locations        []lib.TreeLocation
	Teamnames        []NameCommitmentAndKey
	Merkle           lib.MerklePathsCompressed
	TeamnameUtf8     lib.NameUtf8
	NumTeamnameLinks uint64
	Boxes            []lib.SharedKeyParcel
	RemovalKey       *lib.TeamRemovalKeyBox
	RemoteViewTokens []lib.TeamRemoteMemberViewTokenInner
	Hepks            lib.HEPKSet
}

type TeamChainInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Links            *[](*lib.LinkOuterInternal__)
	Locations        *[](*lib.TreeLocationInternal__)
	Teamnames        *[](*NameCommitmentAndKeyInternal__)
	Merkle           *lib.MerklePathsCompressedInternal__
	TeamnameUtf8     *lib.NameUtf8Internal__
	NumTeamnameLinks *uint64
	Boxes            *[](*lib.SharedKeyParcelInternal__)
	RemovalKey       *lib.TeamRemovalKeyBoxInternal__
	RemoteViewTokens *[](*lib.TeamRemoteMemberViewTokenInnerInternal__)
	Hepks            *lib.HEPKSetInternal__
}

func (t TeamChainInternal__) Import() TeamChain {
	return TeamChain{
		Links: (func(x *[](*lib.LinkOuterInternal__)) (ret []lib.LinkOuter) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.LinkOuter, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Links),
		Locations: (func(x *[](*lib.TreeLocationInternal__)) (ret []lib.TreeLocation) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TreeLocation, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Locations),
		Teamnames: (func(x *[](*NameCommitmentAndKeyInternal__)) (ret []NameCommitmentAndKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]NameCommitmentAndKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *NameCommitmentAndKeyInternal__) (ret NameCommitmentAndKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Teamnames),
		Merkle: (func(x *lib.MerklePathsCompressedInternal__) (ret lib.MerklePathsCompressed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Merkle),
		TeamnameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.TeamnameUtf8),
		NumTeamnameLinks: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(t.NumTeamnameLinks),
		Boxes: (func(x *[](*lib.SharedKeyParcelInternal__)) (ret []lib.SharedKeyParcel) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SharedKeyParcel, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SharedKeyParcelInternal__) (ret lib.SharedKeyParcel) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Boxes),
		RemovalKey: (func(x *lib.TeamRemovalKeyBoxInternal__) *lib.TeamRemovalKeyBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.TeamRemovalKeyBoxInternal__) (ret lib.TeamRemovalKeyBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.RemovalKey),
		RemoteViewTokens: (func(x *[](*lib.TeamRemoteMemberViewTokenInnerInternal__)) (ret []lib.TeamRemoteMemberViewTokenInner) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TeamRemoteMemberViewTokenInner, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TeamRemoteMemberViewTokenInnerInternal__) (ret lib.TeamRemoteMemberViewTokenInner) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.RemoteViewTokens),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hepks),
	}
}

func (t TeamChain) Export() *TeamChainInternal__ {
	return &TeamChainInternal__{
		Links: (func(x []lib.LinkOuter) *[](*lib.LinkOuterInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.LinkOuterInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Links),
		Locations: (func(x []lib.TreeLocation) *[](*lib.TreeLocationInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TreeLocationInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Locations),
		Teamnames: (func(x []NameCommitmentAndKey) *[](*NameCommitmentAndKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*NameCommitmentAndKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Teamnames),
		Merkle:           t.Merkle.Export(),
		TeamnameUtf8:     t.TeamnameUtf8.Export(),
		NumTeamnameLinks: &t.NumTeamnameLinks,
		Boxes: (func(x []lib.SharedKeyParcel) *[](*lib.SharedKeyParcelInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SharedKeyParcelInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Boxes),
		RemovalKey: (func(x *lib.TeamRemovalKeyBox) *lib.TeamRemovalKeyBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.RemovalKey),
		RemoteViewTokens: (func(x []lib.TeamRemoteMemberViewTokenInner) *[](*lib.TeamRemoteMemberViewTokenInnerInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TeamRemoteMemberViewTokenInnerInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.RemoteViewTokens),
		Hepks: t.Hepks.Export(),
	}
}

func (t *TeamChain) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamChain) Decode(dec rpc.Decoder) error {
	var tmp TeamChainInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamChain) Bytes() []byte { return nil }

type TeamRemoteViewTokenSet struct {
	Tokens []lib.TeamRemoteMemberViewTokenInner
}

type TeamRemoteViewTokenSetInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tokens  *[](*lib.TeamRemoteMemberViewTokenInnerInternal__)
}

func (t TeamRemoteViewTokenSetInternal__) Import() TeamRemoteViewTokenSet {
	return TeamRemoteViewTokenSet{
		Tokens: (func(x *[](*lib.TeamRemoteMemberViewTokenInnerInternal__)) (ret []lib.TeamRemoteMemberViewTokenInner) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TeamRemoteMemberViewTokenInner, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TeamRemoteMemberViewTokenInnerInternal__) (ret lib.TeamRemoteMemberViewTokenInner) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Tokens),
	}
}

func (t TeamRemoteViewTokenSet) Export() *TeamRemoteViewTokenSetInternal__ {
	return &TeamRemoteViewTokenSetInternal__{
		Tokens: (func(x []lib.TeamRemoteMemberViewTokenInner) *[](*lib.TeamRemoteMemberViewTokenInnerInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TeamRemoteMemberViewTokenInnerInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Tokens),
	}
}

func (t *TeamRemoteViewTokenSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteViewTokenSet) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteViewTokenSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoteViewTokenSet) Bytes() []byte { return nil }

type TokenType int

const (
	TokenType_None            TokenType = 0
	TokenType_TeamVOBearer    TokenType = 1
	TokenType_Permission      TokenType = 2
	TokenType_LocalParentTeam TokenType = 3
)

var TokenTypeMap = map[string]TokenType{
	"None":            0,
	"TeamVOBearer":    1,
	"Permission":      2,
	"LocalParentTeam": 3,
}

var TokenTypeRevMap = map[TokenType]string{
	0: "None",
	1: "TeamVOBearer",
	2: "Permission",
	3: "LocalParentTeam",
}

type TokenTypeInternal__ TokenType

func (t TokenTypeInternal__) Import() TokenType {
	return TokenType(t)
}

func (t TokenType) Export() *TokenTypeInternal__ {
	return ((*TokenTypeInternal__)(&t))
}

type TeamRemovalAndKeyBox struct {
	KeyBox  lib.TeamRemovalKeyBox
	Removal TeamRemoval
}

type TeamRemovalAndKeyBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	KeyBox  *lib.TeamRemovalKeyBoxInternal__
	Removal *TeamRemovalInternal__
}

func (t TeamRemovalAndKeyBoxInternal__) Import() TeamRemovalAndKeyBox {
	return TeamRemovalAndKeyBox{
		KeyBox: (func(x *lib.TeamRemovalKeyBoxInternal__) (ret lib.TeamRemovalKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.KeyBox),
		Removal: (func(x *TeamRemovalInternal__) (ret TeamRemoval) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Removal),
	}
}

func (t TeamRemovalAndKeyBox) Export() *TeamRemovalAndKeyBoxInternal__ {
	return &TeamRemovalAndKeyBoxInternal__{
		KeyBox:  t.KeyBox.Export(),
		Removal: t.Removal.Export(),
	}
}

func (t *TeamRemovalAndKeyBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalAndKeyBox) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalAndKeyBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemovalAndKeyBox) Bytes() []byte { return nil }

type TeamRemovalAndComm struct {
	Rm   TeamRemoval
	Comm lib.KeyCommitment
}

type TeamRemovalAndCommInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rm      *TeamRemovalInternal__
	Comm    *lib.KeyCommitmentInternal__
}

func (t TeamRemovalAndCommInternal__) Import() TeamRemovalAndComm {
	return TeamRemovalAndComm{
		Rm: (func(x *TeamRemovalInternal__) (ret TeamRemoval) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Rm),
		Comm: (func(x *lib.KeyCommitmentInternal__) (ret lib.KeyCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Comm),
	}
}

func (t TeamRemovalAndComm) Export() *TeamRemovalAndCommInternal__ {
	return &TeamRemovalAndCommInternal__{
		Rm:   t.Rm.Export(),
		Comm: t.Comm.Export(),
	}
}

func (t *TeamRemovalAndComm) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalAndComm) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalAndCommInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemovalAndComm) Bytes() []byte { return nil }

type OffchainBoxData struct {
	PtkBoxes               lib.SharedKeyBoxSet
	SeedChain              []lib.SeedChainBox
	RemoteMemberViewTokens []lib.TeamRemoteMemberViewToken
	RemovalKeys            []TeamRemovalBoxData
	Removals               []TeamRemovalAndComm
	Hepks                  lib.HEPKSet
	NewKeyOnRotate         lib.EntityID
}

type OffchainBoxDataInternal__ struct {
	_struct                struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PtkBoxes               *lib.SharedKeyBoxSetInternal__
	SeedChain              *[](*lib.SeedChainBoxInternal__)
	RemoteMemberViewTokens *[](*lib.TeamRemoteMemberViewTokenInternal__)
	RemovalKeys            *[](*TeamRemovalBoxDataInternal__)
	Removals               *[](*TeamRemovalAndCommInternal__)
	Hepks                  *lib.HEPKSetInternal__
	NewKeyOnRotate         *lib.EntityIDInternal__
}

func (o OffchainBoxDataInternal__) Import() OffchainBoxData {
	return OffchainBoxData{
		PtkBoxes: (func(x *lib.SharedKeyBoxSetInternal__) (ret lib.SharedKeyBoxSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.PtkBoxes),
		SeedChain: (func(x *[](*lib.SeedChainBoxInternal__)) (ret []lib.SeedChainBox) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SeedChainBox, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SeedChainBoxInternal__) (ret lib.SeedChainBox) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(o.SeedChain),
		RemoteMemberViewTokens: (func(x *[](*lib.TeamRemoteMemberViewTokenInternal__)) (ret []lib.TeamRemoteMemberViewToken) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TeamRemoteMemberViewToken, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TeamRemoteMemberViewTokenInternal__) (ret lib.TeamRemoteMemberViewToken) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(o.RemoteMemberViewTokens),
		RemovalKeys: (func(x *[](*TeamRemovalBoxDataInternal__)) (ret []TeamRemovalBoxData) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamRemovalBoxData, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamRemovalBoxDataInternal__) (ret TeamRemovalBoxData) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(o.RemovalKeys),
		Removals: (func(x *[](*TeamRemovalAndCommInternal__)) (ret []TeamRemovalAndComm) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamRemovalAndComm, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamRemovalAndCommInternal__) (ret TeamRemovalAndComm) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(o.Removals),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Hepks),
		NewKeyOnRotate: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.NewKeyOnRotate),
	}
}

func (o OffchainBoxData) Export() *OffchainBoxDataInternal__ {
	return &OffchainBoxDataInternal__{
		PtkBoxes: o.PtkBoxes.Export(),
		SeedChain: (func(x []lib.SeedChainBox) *[](*lib.SeedChainBoxInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SeedChainBoxInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(o.SeedChain),
		RemoteMemberViewTokens: (func(x []lib.TeamRemoteMemberViewToken) *[](*lib.TeamRemoteMemberViewTokenInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TeamRemoteMemberViewTokenInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(o.RemoteMemberViewTokens),
		RemovalKeys: (func(x []TeamRemovalBoxData) *[](*TeamRemovalBoxDataInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamRemovalBoxDataInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(o.RemovalKeys),
		Removals: (func(x []TeamRemovalAndComm) *[](*TeamRemovalAndCommInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamRemovalAndCommInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(o.Removals),
		Hepks:          o.Hepks.Export(),
		NewKeyOnRotate: o.NewKeyOnRotate.Export(),
	}
}

func (o *OffchainBoxData) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OffchainBoxData) Decode(dec rpc.Decoder) error {
	var tmp OffchainBoxDataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OffchainBoxData) Bytes() []byte { return nil }

var TeamLoaderProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf9128579)

type GetTeamVOBearerTokenChallengeArg struct {
	Req TeamVOBearerTokenReq
}

type GetTeamVOBearerTokenChallengeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Req     *TeamVOBearerTokenReqInternal__
}

func (g GetTeamVOBearerTokenChallengeArgInternal__) Import() GetTeamVOBearerTokenChallengeArg {
	return GetTeamVOBearerTokenChallengeArg{
		Req: (func(x *TeamVOBearerTokenReqInternal__) (ret TeamVOBearerTokenReq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Req),
	}
}

func (g GetTeamVOBearerTokenChallengeArg) Export() *GetTeamVOBearerTokenChallengeArgInternal__ {
	return &GetTeamVOBearerTokenChallengeArgInternal__{
		Req: g.Req.Export(),
	}
}

func (g *GetTeamVOBearerTokenChallengeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetTeamVOBearerTokenChallengeArg) Decode(dec rpc.Decoder) error {
	var tmp GetTeamVOBearerTokenChallengeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetTeamVOBearerTokenChallengeArg) Bytes() []byte { return nil }

type ActivateTeamVOBearerTokenArg struct {
	Ch  TeamVOBearerTokenChallenge
	Sig lib.Signature
}

type ActivateTeamVOBearerTokenArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ch      *TeamVOBearerTokenChallengeInternal__
	Sig     *lib.SignatureInternal__
}

func (a ActivateTeamVOBearerTokenArgInternal__) Import() ActivateTeamVOBearerTokenArg {
	return ActivateTeamVOBearerTokenArg{
		Ch: (func(x *TeamVOBearerTokenChallengeInternal__) (ret TeamVOBearerTokenChallenge) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Ch),
		Sig: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Sig),
	}
}

func (a ActivateTeamVOBearerTokenArg) Export() *ActivateTeamVOBearerTokenArgInternal__ {
	return &ActivateTeamVOBearerTokenArgInternal__{
		Ch:  a.Ch.Export(),
		Sig: a.Sig.Export(),
	}
}

func (a *ActivateTeamVOBearerTokenArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActivateTeamVOBearerTokenArg) Decode(dec rpc.Decoder) error {
	var tmp ActivateTeamVOBearerTokenArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActivateTeamVOBearerTokenArg) Bytes() []byte { return nil }

type CheckTeamVOBearerTokenArg struct {
	Host lib.HostID
	Tok  TeamVOBearerToken
}

type CheckTeamVOBearerTokenArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostIDInternal__
	Tok     *TeamVOBearerTokenInternal__
}

func (c CheckTeamVOBearerTokenArgInternal__) Import() CheckTeamVOBearerTokenArg {
	return CheckTeamVOBearerTokenArg{
		Host: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Host),
		Tok: (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Tok),
	}
}

func (c CheckTeamVOBearerTokenArg) Export() *CheckTeamVOBearerTokenArgInternal__ {
	return &CheckTeamVOBearerTokenArgInternal__{
		Host: c.Host.Export(),
		Tok:  c.Tok.Export(),
	}
}

func (c *CheckTeamVOBearerTokenArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckTeamVOBearerTokenArg) Decode(dec rpc.Decoder) error {
	var tmp CheckTeamVOBearerTokenArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckTeamVOBearerTokenArg) Bytes() []byte { return nil }

type LoadTeamChainArg struct {
	Team                 lib.FQTeam
	Tok                  TokenVariant
	Start                lib.Seqno
	HavePtkGens          []lib.SharedKeyGen
	Name                 *NameSeqnoPair
	LoadRemovalKey       bool
	LoadRemoteViewTokens bool
}

type LoadTeamChainArgInternal__ struct {
	_struct              struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team                 *lib.FQTeamInternal__
	Tok                  *TokenVariantInternal__
	Start                *lib.SeqnoInternal__
	HavePtkGens          *[](*lib.SharedKeyGenInternal__)
	Name                 *NameSeqnoPairInternal__
	LoadRemovalKey       *bool
	LoadRemoteViewTokens *bool
}

func (l LoadTeamChainArgInternal__) Import() LoadTeamChainArg {
	return LoadTeamChainArg{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Team),
		Tok: (func(x *TokenVariantInternal__) (ret TokenVariant) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Start: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Start),
		HavePtkGens: (func(x *[](*lib.SharedKeyGenInternal__)) (ret []lib.SharedKeyGen) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SharedKeyGen, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SharedKeyGenInternal__) (ret lib.SharedKeyGen) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(l.HavePtkGens),
		Name: (func(x *NameSeqnoPairInternal__) *NameSeqnoPair {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameSeqnoPairInternal__) (ret NameSeqnoPair) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Name),
		LoadRemovalKey: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(l.LoadRemovalKey),
		LoadRemoteViewTokens: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(l.LoadRemoteViewTokens),
	}
}

func (l LoadTeamChainArg) Export() *LoadTeamChainArgInternal__ {
	return &LoadTeamChainArgInternal__{
		Team:  l.Team.Export(),
		Tok:   l.Tok.Export(),
		Start: l.Start.Export(),
		HavePtkGens: (func(x []lib.SharedKeyGen) *[](*lib.SharedKeyGenInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SharedKeyGenInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(l.HavePtkGens),
		Name: (func(x *NameSeqnoPair) *NameSeqnoPairInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.Name),
		LoadRemovalKey:       &l.LoadRemovalKey,
		LoadRemoteViewTokens: &l.LoadRemoteViewTokens,
	}
}

func (l *LoadTeamChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadTeamChainArg) Decode(dec rpc.Decoder) error {
	var tmp LoadTeamChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadTeamChainArg) Bytes() []byte { return nil }

type LoadTeamMembershipChainArg struct {
	Team  lib.FQTeam
	Tok   TeamVOBearerToken
	Start lib.Seqno
}

type LoadTeamMembershipChainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Tok     *TeamVOBearerTokenInternal__
	Start   *lib.SeqnoInternal__
}

func (l LoadTeamMembershipChainArgInternal__) Import() LoadTeamMembershipChainArg {
	return LoadTeamMembershipChainArg{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Team),
		Tok: (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Start: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Start),
	}
}

func (l LoadTeamMembershipChainArg) Export() *LoadTeamMembershipChainArgInternal__ {
	return &LoadTeamMembershipChainArgInternal__{
		Team:  l.Team.Export(),
		Tok:   l.Tok.Export(),
		Start: l.Start.Export(),
	}
}

func (l *LoadTeamMembershipChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadTeamMembershipChainArg) Decode(dec rpc.Decoder) error {
	var tmp LoadTeamMembershipChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadTeamMembershipChainArg) Bytes() []byte { return nil }

type LoadRemovalForMemberArg struct {
	Team lib.FQTeam
	Comm lib.KeyCommitment
}

type LoadRemovalForMemberArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Comm    *lib.KeyCommitmentInternal__
}

func (l LoadRemovalForMemberArgInternal__) Import() LoadRemovalForMemberArg {
	return LoadRemovalForMemberArg{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Team),
		Comm: (func(x *lib.KeyCommitmentInternal__) (ret lib.KeyCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Comm),
	}
}

func (l LoadRemovalForMemberArg) Export() *LoadRemovalForMemberArgInternal__ {
	return &LoadRemovalForMemberArgInternal__{
		Team: l.Team.Export(),
		Comm: l.Comm.Export(),
	}
}

func (l *LoadRemovalForMemberArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadRemovalForMemberArg) Decode(dec rpc.Decoder) error {
	var tmp LoadRemovalForMemberArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadRemovalForMemberArg) Bytes() []byte { return nil }

type LoadTeamRemoteViewTokensArg struct {
	Team    lib.FQTeam
	Tok     TeamVOBearerToken
	Members []lib.FQParty
}

type LoadTeamRemoteViewTokensArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Tok     *TeamVOBearerTokenInternal__
	Members *[](*lib.FQPartyInternal__)
}

func (l LoadTeamRemoteViewTokensArgInternal__) Import() LoadTeamRemoteViewTokensArg {
	return LoadTeamRemoteViewTokensArg{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Team),
		Tok: (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Members: (func(x *[](*lib.FQPartyInternal__)) (ret []lib.FQParty) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.FQParty, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(l.Members),
	}
}

func (l LoadTeamRemoteViewTokensArg) Export() *LoadTeamRemoteViewTokensArgInternal__ {
	return &LoadTeamRemoteViewTokensArgInternal__{
		Team: l.Team.Export(),
		Tok:  l.Tok.Export(),
		Members: (func(x []lib.FQParty) *[](*lib.FQPartyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.FQPartyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(l.Members),
	}
}

func (l *LoadTeamRemoteViewTokensArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadTeamRemoteViewTokensArg) Decode(dec rpc.Decoder) error {
	var tmp LoadTeamRemoteViewTokensArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadTeamRemoteViewTokensArg) Bytes() []byte { return nil }

type TeamLoaderInterface interface {
	GetTeamVOBearerTokenChallenge(context.Context, TeamVOBearerTokenReq) (TeamVOBearerTokenChallenge, error)
	ActivateTeamVOBearerToken(context.Context, ActivateTeamVOBearerTokenArg) (ActivatedVOBearerToken, error)
	CheckTeamVOBearerToken(context.Context, CheckTeamVOBearerTokenArg) (lib.TeamID, error)
	LoadTeamChain(context.Context, LoadTeamChainArg) (TeamChain, error)
	LoadTeamMembershipChain(context.Context, LoadTeamMembershipChainArg) (GenericChain, error)
	LoadRemovalForMember(context.Context, LoadRemovalForMemberArg) (TeamRemovalAndKeyBox, error)
	LoadTeamRemoteViewTokens(context.Context, LoadTeamRemoteViewTokensArg) (TeamRemoteViewTokenSet, error)
	ErrorWrapper() func(error) lib.Status
}

func TeamLoaderMakeGenericErrorWrapper(f TeamLoaderErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TeamLoaderErrorUnwrapper func(lib.Status) error
type TeamLoaderErrorWrapper func(error) lib.Status

type teamLoaderErrorUnwrapperAdapter struct {
	h TeamLoaderErrorUnwrapper
}

func (t teamLoaderErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t teamLoaderErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = teamLoaderErrorUnwrapperAdapter{}

type TeamLoaderClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TeamLoaderErrorUnwrapper
}

func (c TeamLoaderClient) GetTeamVOBearerTokenChallenge(ctx context.Context, req TeamVOBearerTokenReq) (res TeamVOBearerTokenChallenge, err error) {
	arg := GetTeamVOBearerTokenChallengeArg{
		Req: req,
	}
	warg := arg.Export()
	var tmp TeamVOBearerTokenChallengeInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 0, "TeamLoader.getTeamVOBearerTokenChallenge"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) ActivateTeamVOBearerToken(ctx context.Context, arg ActivateTeamVOBearerTokenArg) (res ActivatedVOBearerToken, err error) {
	warg := arg.Export()
	var tmp ActivatedVOBearerTokenInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 1, "TeamLoader.activateTeamVOBearerToken"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) CheckTeamVOBearerToken(ctx context.Context, arg CheckTeamVOBearerTokenArg) (res lib.TeamID, err error) {
	warg := arg.Export()
	var tmp lib.TeamIDInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 2, "TeamLoader.checkTeamVOBearerToken"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) LoadTeamChain(ctx context.Context, arg LoadTeamChainArg) (res TeamChain, err error) {
	warg := arg.Export()
	var tmp TeamChainInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 3, "TeamLoader.loadTeamChain"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) LoadTeamMembershipChain(ctx context.Context, arg LoadTeamMembershipChainArg) (res GenericChain, err error) {
	warg := arg.Export()
	var tmp GenericChainInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 4, "TeamLoader.loadTeamMembershipChain"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) LoadRemovalForMember(ctx context.Context, arg LoadRemovalForMemberArg) (res TeamRemovalAndKeyBox, err error) {
	warg := arg.Export()
	var tmp TeamRemovalAndKeyBoxInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 5, "TeamLoader.loadRemovalForMember"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamLoaderClient) LoadTeamRemoteViewTokens(ctx context.Context, arg LoadTeamRemoteViewTokensArg) (res TeamRemoteViewTokenSet, err error) {
	warg := arg.Export()
	var tmp TeamRemoteViewTokenSetInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamLoaderProtocolID, 6, "TeamLoader.loadTeamRemoteViewTokens"), warg, &tmp, 0*time.Millisecond, teamLoaderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func TeamLoaderProtocol(i TeamLoaderInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TeamLoader",
		ID:   TeamLoaderProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GetTeamVOBearerTokenChallengeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GetTeamVOBearerTokenChallengeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GetTeamVOBearerTokenChallengeArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GetTeamVOBearerTokenChallenge(ctx, (typedArg.Import()).Req)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "getTeamVOBearerTokenChallenge",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret ActivateTeamVOBearerTokenArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*ActivateTeamVOBearerTokenArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*ActivateTeamVOBearerTokenArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.ActivateTeamVOBearerToken(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "activateTeamVOBearerToken",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret CheckTeamVOBearerTokenArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*CheckTeamVOBearerTokenArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*CheckTeamVOBearerTokenArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.CheckTeamVOBearerToken(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "checkTeamVOBearerToken",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadTeamChainArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadTeamChainArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadTeamChainArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadTeamChain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadTeamChain",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadTeamMembershipChainArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadTeamMembershipChainArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadTeamMembershipChainArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadTeamMembershipChain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadTeamMembershipChain",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadRemovalForMemberArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadRemovalForMemberArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadRemovalForMemberArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadRemovalForMember(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadRemovalForMember",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadTeamRemoteViewTokensArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadTeamRemoteViewTokensArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadTeamRemoteViewTokensArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadTeamRemoteViewTokens(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadTeamRemoteViewTokens",
			},
		},
		WrapError: TeamLoaderMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var TeamMemberProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xbda3b9d3)

type AcceptInviteLocalArg struct {
	I                  lib.TeamInvite
	SrcRole            lib.Role
	Tok                *TeamBearerToken
	TeamMembershipLink *PostGenericLinkArg
}

type AcceptInviteLocalArgInternal__ struct {
	_struct            struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	I                  *lib.TeamInviteInternal__
	SrcRole            *lib.RoleInternal__
	Tok                *TeamBearerTokenInternal__
	TeamMembershipLink *PostGenericLinkArgInternal__
}

func (a AcceptInviteLocalArgInternal__) Import() AcceptInviteLocalArg {
	return AcceptInviteLocalArg{
		I: (func(x *lib.TeamInviteInternal__) (ret lib.TeamInvite) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.I),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.SrcRole),
		Tok: (func(x *TeamBearerTokenInternal__) *TeamBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(a.Tok),
		TeamMembershipLink: (func(x *PostGenericLinkArgInternal__) *PostGenericLinkArg {
			if x == nil {
				return nil
			}
			tmp := (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(a.TeamMembershipLink),
	}
}

func (a AcceptInviteLocalArg) Export() *AcceptInviteLocalArgInternal__ {
	return &AcceptInviteLocalArgInternal__{
		I:       a.I.Export(),
		SrcRole: a.SrcRole.Export(),
		Tok: (func(x *TeamBearerToken) *TeamBearerTokenInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(a.Tok),
		TeamMembershipLink: (func(x *PostGenericLinkArg) *PostGenericLinkArgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(a.TeamMembershipLink),
	}
}

func (a *AcceptInviteLocalArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AcceptInviteLocalArg) Decode(dec rpc.Decoder) error {
	var tmp AcceptInviteLocalArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AcceptInviteLocalArg) Bytes() []byte { return nil }

type GrantRemoteViewPermissionForTeamArg struct {
	P   GrantRemoteViewPermissionPayload
	Sig SharedKeySig
}

type GrantRemoteViewPermissionForTeamArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	P       *GrantRemoteViewPermissionPayloadInternal__
	Sig     *SharedKeySigInternal__
}

func (g GrantRemoteViewPermissionForTeamArgInternal__) Import() GrantRemoteViewPermissionForTeamArg {
	return GrantRemoteViewPermissionForTeamArg{
		P: (func(x *GrantRemoteViewPermissionPayloadInternal__) (ret GrantRemoteViewPermissionPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.P),
		Sig: (func(x *SharedKeySigInternal__) (ret SharedKeySig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Sig),
	}
}

func (g GrantRemoteViewPermissionForTeamArg) Export() *GrantRemoteViewPermissionForTeamArgInternal__ {
	return &GrantRemoteViewPermissionForTeamArgInternal__{
		P:   g.P.Export(),
		Sig: g.Sig.Export(),
	}
}

func (g *GrantRemoteViewPermissionForTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantRemoteViewPermissionForTeamArg) Decode(dec rpc.Decoder) error {
	var tmp GrantRemoteViewPermissionForTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GrantRemoteViewPermissionForTeamArg) Bytes() []byte { return nil }

type GrantLocalViewPermissionForTeamArg struct {
	P   GrantLocalViewPermissionPayload
	Sig SharedKeySig
}

type GrantLocalViewPermissionForTeamArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	P       *GrantLocalViewPermissionPayloadInternal__
	Sig     *SharedKeySigInternal__
}

func (g GrantLocalViewPermissionForTeamArgInternal__) Import() GrantLocalViewPermissionForTeamArg {
	return GrantLocalViewPermissionForTeamArg{
		P: (func(x *GrantLocalViewPermissionPayloadInternal__) (ret GrantLocalViewPermissionPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.P),
		Sig: (func(x *SharedKeySigInternal__) (ret SharedKeySig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Sig),
	}
}

func (g GrantLocalViewPermissionForTeamArg) Export() *GrantLocalViewPermissionForTeamArgInternal__ {
	return &GrantLocalViewPermissionForTeamArgInternal__{
		P:   g.P.Export(),
		Sig: g.Sig.Export(),
	}
}

func (g *GrantLocalViewPermissionForTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantLocalViewPermissionForTeamArg) Decode(dec rpc.Decoder) error {
	var tmp GrantLocalViewPermissionForTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GrantLocalViewPermissionForTeamArg) Bytes() []byte { return nil }

type TeamMemberInterface interface {
	AcceptInviteLocal(context.Context, AcceptInviteLocalArg) (lib.TeamRSVPLocal, error)
	GrantRemoteViewPermissionForTeam(context.Context, GrantRemoteViewPermissionForTeamArg) (lib.PermissionToken, error)
	GrantLocalViewPermissionForTeam(context.Context, GrantLocalViewPermissionForTeamArg) (lib.PermissionToken, error)
	ErrorWrapper() func(error) lib.Status
}

func TeamMemberMakeGenericErrorWrapper(f TeamMemberErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TeamMemberErrorUnwrapper func(lib.Status) error
type TeamMemberErrorWrapper func(error) lib.Status

type teamMemberErrorUnwrapperAdapter struct {
	h TeamMemberErrorUnwrapper
}

func (t teamMemberErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t teamMemberErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = teamMemberErrorUnwrapperAdapter{}

type TeamMemberClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TeamMemberErrorUnwrapper
}

func (c TeamMemberClient) AcceptInviteLocal(ctx context.Context, arg AcceptInviteLocalArg) (res lib.TeamRSVPLocal, err error) {
	warg := arg.Export()
	var tmp lib.TeamRSVPLocalInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamMemberProtocolID, 0, "TeamMember.acceptInviteLocal"), warg, &tmp, 0*time.Millisecond, teamMemberErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamMemberClient) GrantRemoteViewPermissionForTeam(ctx context.Context, arg GrantRemoteViewPermissionForTeamArg) (res lib.PermissionToken, err error) {
	warg := arg.Export()
	var tmp lib.PermissionTokenInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamMemberProtocolID, 1, "TeamMember.grantRemoteViewPermissionForTeam"), warg, &tmp, 0*time.Millisecond, teamMemberErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamMemberClient) GrantLocalViewPermissionForTeam(ctx context.Context, arg GrantLocalViewPermissionForTeamArg) (res lib.PermissionToken, err error) {
	warg := arg.Export()
	var tmp lib.PermissionTokenInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamMemberProtocolID, 2, "TeamMember.grantLocalViewPermissionForTeam"), warg, &tmp, 0*time.Millisecond, teamMemberErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func TeamMemberProtocol(i TeamMemberInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TeamMember",
		ID:   TeamMemberProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret AcceptInviteLocalArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*AcceptInviteLocalArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*AcceptInviteLocalArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.AcceptInviteLocal(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "acceptInviteLocal",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GrantRemoteViewPermissionForTeamArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GrantRemoteViewPermissionForTeamArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GrantRemoteViewPermissionForTeamArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GrantRemoteViewPermissionForTeam(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "grantRemoteViewPermissionForTeam",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GrantLocalViewPermissionForTeamArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GrantLocalViewPermissionForTeamArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GrantLocalViewPermissionForTeamArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GrantLocalViewPermissionForTeam(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "grantLocalViewPermissionForTeam",
			},
		},
		WrapError: TeamMemberMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

type LocalPartyRole struct {
	Party lib.PartyID
	Role  lib.Role
}

type LocalPartyRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Party   *lib.PartyIDInternal__
	Role    *lib.RoleInternal__
}

func (l LocalPartyRoleInternal__) Import() LocalPartyRole {
	return LocalPartyRole{
		Party: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Party),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Role),
	}
}

func (l LocalPartyRole) Export() *LocalPartyRoleInternal__ {
	return &LocalPartyRoleInternal__{
		Party: l.Party.Export(),
		Role:  l.Role.Export(),
	}
}

func (l *LocalPartyRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalPartyRole) Decode(dec rpc.Decoder) error {
	var tmp LocalPartyRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LocalPartyRole) Bytes() []byte { return nil }

type EditTeamRes struct {
	LocalInvitees []LocalPartyRole
}

type EditTeamResInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	LocalInvitees *[](*LocalPartyRoleInternal__)
}

func (e EditTeamResInternal__) Import() EditTeamRes {
	return EditTeamRes{
		LocalInvitees: (func(x *[](*LocalPartyRoleInternal__)) (ret []LocalPartyRole) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]LocalPartyRole, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *LocalPartyRoleInternal__) (ret LocalPartyRole) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(e.LocalInvitees),
	}
}

func (e EditTeamRes) Export() *EditTeamResInternal__ {
	return &EditTeamResInternal__{
		LocalInvitees: (func(x []LocalPartyRole) *[](*LocalPartyRoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*LocalPartyRoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(e.LocalInvitees),
	}
}

func (e *EditTeamRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EditTeamRes) Decode(dec rpc.Decoder) error {
	var tmp EditTeamResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e *EditTeamRes) Bytes() []byte { return nil }

type TeamBearerTokenChallengePayload struct {
	User lib.FQUser
	Team lib.TeamID
	Role lib.Role
	Gen  lib.Generation
	Tok  TeamBearerToken
	Tm   lib.Time
}

type TeamBearerTokenChallengePayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	User    *lib.FQUserInternal__
	Team    *lib.TeamIDInternal__
	Role    *lib.RoleInternal__
	Gen     *lib.GenerationInternal__
	Tok     *TeamBearerTokenInternal__
	Tm      *lib.TimeInternal__
}

func (t TeamBearerTokenChallengePayloadInternal__) Import() TeamBearerTokenChallengePayload {
	return TeamBearerTokenChallengePayload{
		User: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.User),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Role),
		Gen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Gen),
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
	}
}

func (t TeamBearerTokenChallengePayload) Export() *TeamBearerTokenChallengePayloadInternal__ {
	return &TeamBearerTokenChallengePayloadInternal__{
		User: t.User.Export(),
		Team: t.Team.Export(),
		Role: t.Role.Export(),
		Gen:  t.Gen.Export(),
		Tok:  t.Tok.Export(),
		Tm:   t.Tm.Export(),
	}
}

func (t *TeamBearerTokenChallengePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamBearerTokenChallengePayload) Decode(dec rpc.Decoder) error {
	var tmp TeamBearerTokenChallengePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamBearerTokenChallengePayloadTypeUniqueID = rpc.TypeUniqueID(0xa85de1ca0ab0c9a5)

func (t *TeamBearerTokenChallengePayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamBearerTokenChallengePayloadTypeUniqueID
}

func (t *TeamBearerTokenChallengePayload) Bytes() []byte { return nil }

type TeamBearerTokenChallengeBlob []byte
type TeamBearerTokenChallengeBlobInternal__ []byte

func (t TeamBearerTokenChallengeBlob) Export() *TeamBearerTokenChallengeBlobInternal__ {
	tmp := (([]byte)(t))
	return ((*TeamBearerTokenChallengeBlobInternal__)(&tmp))
}

func (t TeamBearerTokenChallengeBlobInternal__) Import() TeamBearerTokenChallengeBlob {
	tmp := ([]byte)(t)
	return TeamBearerTokenChallengeBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamBearerTokenChallengeBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamBearerTokenChallengeBlob) Decode(dec rpc.Decoder) error {
	var tmp TeamBearerTokenChallengeBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamBearerTokenChallengeBlobTypeUniqueID = rpc.TypeUniqueID(0xcd0d4cbadda50eef)

func (t *TeamBearerTokenChallengeBlob) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamBearerTokenChallengeBlobTypeUniqueID
}

func (t TeamBearerTokenChallengeBlob) Bytes() []byte {
	return (t)[:]
}

func (t *TeamBearerTokenChallengeBlob) AllocAndDecode(f rpc.DecoderFactory) (*TeamBearerTokenChallengePayload, error) {
	var ret TeamBearerTokenChallengePayload
	src := f.NewDecoderBytes(&ret, t.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (t *TeamBearerTokenChallengeBlob) AssertNormalized() error { return nil }

func (t *TeamBearerTokenChallengePayload) EncodeTyped(f rpc.EncoderFactory) (*TeamBearerTokenChallengeBlob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := t.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := TeamBearerTokenChallengeBlob(tmp)
	return &ret, nil
}

func (t *TeamBearerTokenChallengePayload) ChildBlob(_b []byte) TeamBearerTokenChallengeBlob {
	return TeamBearerTokenChallengeBlob(_b)
}

type TeamCertV1Payload struct {
	Team lib.FQTeam
	Ptk  lib.SharedKey
	Tm   lib.Time
	Hepk lib.HEPK
	Name lib.NameUtf8
}

type TeamCertV1PayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Ptk     *lib.SharedKeyInternal__
	Tm      *lib.TimeInternal__
	Hepk    *lib.HEPKInternal__
	Name    *lib.NameUtf8Internal__
}

func (t TeamCertV1PayloadInternal__) Import() TeamCertV1Payload {
	return TeamCertV1Payload{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Ptk: (func(x *lib.SharedKeyInternal__) (ret lib.SharedKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Ptk),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
		Hepk: (func(x *lib.HEPKInternal__) (ret lib.HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hepk),
		Name: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Name),
	}
}

func (t TeamCertV1Payload) Export() *TeamCertV1PayloadInternal__ {
	return &TeamCertV1PayloadInternal__{
		Team: t.Team.Export(),
		Ptk:  t.Ptk.Export(),
		Tm:   t.Tm.Export(),
		Hepk: t.Hepk.Export(),
		Name: t.Name.Export(),
	}
}

func (t *TeamCertV1Payload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCertV1Payload) Decode(dec rpc.Decoder) error {
	var tmp TeamCertV1PayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamCertV1PayloadTypeUniqueID = rpc.TypeUniqueID(0xf88913d42ea72d2a)

func (t *TeamCertV1Payload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamCertV1PayloadTypeUniqueID
}

func (t *TeamCertV1Payload) Bytes() []byte { return nil }

type TeamCertVersion int

const (
	TeamCertVersion_V1 TeamCertVersion = 1
)

var TeamCertVersionMap = map[string]TeamCertVersion{
	"V1": 1,
}

var TeamCertVersionRevMap = map[TeamCertVersion]string{
	1: "V1",
}

type TeamCertVersionInternal__ TeamCertVersion

func (t TeamCertVersionInternal__) Import() TeamCertVersion {
	return TeamCertVersion(t)
}

func (t TeamCertVersion) Export() *TeamCertVersionInternal__ {
	return ((*TeamCertVersionInternal__)(&t))
}

type TeamCertV1Blob []byte
type TeamCertV1BlobInternal__ []byte

func (t TeamCertV1Blob) Export() *TeamCertV1BlobInternal__ {
	tmp := (([]byte)(t))
	return ((*TeamCertV1BlobInternal__)(&tmp))
}

func (t TeamCertV1BlobInternal__) Import() TeamCertV1Blob {
	tmp := ([]byte)(t)
	return TeamCertV1Blob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamCertV1Blob) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCertV1Blob) Decode(dec rpc.Decoder) error {
	var tmp TeamCertV1BlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamCertV1BlobTypeUniqueID = rpc.TypeUniqueID(0xa8382502cf0873b4)

func (t *TeamCertV1Blob) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamCertV1BlobTypeUniqueID
}

func (t TeamCertV1Blob) Bytes() []byte {
	return (t)[:]
}

func (t *TeamCertV1Blob) AllocAndDecode(f rpc.DecoderFactory) (*TeamCertV1Payload, error) {
	var ret TeamCertV1Payload
	src := f.NewDecoderBytes(&ret, t.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (t *TeamCertV1Blob) AssertNormalized() error { return nil }

func (t *TeamCertV1Payload) EncodeTyped(f rpc.EncoderFactory) (*TeamCertV1Blob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := t.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := TeamCertV1Blob(tmp)
	return &ret, nil
}

func (t *TeamCertV1Payload) ChildBlob(_b []byte) TeamCertV1Blob {
	return TeamCertV1Blob(_b)
}

type TeamCertV1Signed struct {
	Payload    TeamCertV1Blob
	Signatures []lib.Signature
}

type TeamCertV1SignedInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Payload    *TeamCertV1BlobInternal__
	Signatures *[](*lib.SignatureInternal__)
}

func (t TeamCertV1SignedInternal__) Import() TeamCertV1Signed {
	return TeamCertV1Signed{
		Payload: (func(x *TeamCertV1BlobInternal__) (ret TeamCertV1Blob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Payload),
		Signatures: (func(x *[](*lib.SignatureInternal__)) (ret []lib.Signature) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.Signature, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SignatureInternal__) (ret lib.Signature) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Signatures),
	}
}

func (t TeamCertV1Signed) Export() *TeamCertV1SignedInternal__ {
	return &TeamCertV1SignedInternal__{
		Payload: t.Payload.Export(),
		Signatures: (func(x []lib.Signature) *[](*lib.SignatureInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SignatureInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Signatures),
	}
}

func (t *TeamCertV1Signed) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCertV1Signed) Decode(dec rpc.Decoder) error {
	var tmp TeamCertV1SignedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamCertV1SignedTypeUniqueID = rpc.TypeUniqueID(0xd7e2d164a441663b)

func (t *TeamCertV1Signed) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamCertV1SignedTypeUniqueID
}

func (t *TeamCertV1Signed) Bytes() []byte { return nil }

type TeamCert struct {
	V     TeamCertVersion
	F_0__ *TeamCertV1Signed `json:"f0,omitempty"`
}

type TeamCertInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        TeamCertVersion
	Switch__ TeamCertInternalSwitch__
}

type TeamCertInternalSwitch__ struct {
	_struct struct{}                    `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *TeamCertV1SignedInternal__ `codec:"0"`
}

func (t TeamCert) GetV() (ret TeamCertVersion, err error) {
	switch t.V {
	case TeamCertVersion_V1:
		if t.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return t.V, nil
}

func (t TeamCert) V1() TeamCertV1Signed {
	if t.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.V != TeamCertVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", t.V))
	}
	return *t.F_0__
}

func NewTeamCertWithV1(v TeamCertV1Signed) TeamCert {
	return TeamCert{
		V:     TeamCertVersion_V1,
		F_0__: &v,
	}
}

func (t TeamCertInternal__) Import() TeamCert {
	return TeamCert{
		V: t.V,
		F_0__: (func(x *TeamCertV1SignedInternal__) *TeamCertV1Signed {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamCertV1SignedInternal__) (ret TeamCertV1Signed) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_0__),
	}
}

func (t TeamCert) Export() *TeamCertInternal__ {
	return &TeamCertInternal__{
		V: t.V,
		Switch__: TeamCertInternalSwitch__{
			F_0__: (func(x *TeamCertV1Signed) *TeamCertV1SignedInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_0__),
		},
	}
}

func (t *TeamCert) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCert) Decode(dec rpc.Decoder) error {
	var tmp TeamCertInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamCertTypeUniqueID = rpc.TypeUniqueID(0xbfde7f0ac7a3b707)

func (t *TeamCert) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamCertTypeUniqueID
}

func (t *TeamCert) Bytes() []byte { return nil }

type TeamCertAndMetadata struct {
	Cert TeamCert
	Tir  lib.RationalRange
}

type TeamCertAndMetadataInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cert    *TeamCertInternal__
	Tir     *lib.RationalRangeInternal__
}

func (t TeamCertAndMetadataInternal__) Import() TeamCertAndMetadata {
	return TeamCertAndMetadata{
		Cert: (func(x *TeamCertInternal__) (ret TeamCert) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Cert),
		Tir: (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tir),
	}
}

func (t TeamCertAndMetadata) Export() *TeamCertAndMetadataInternal__ {
	return &TeamCertAndMetadataInternal__{
		Cert: t.Cert.Export(),
		Tir:  t.Tir.Export(),
	}
}

func (t *TeamCertAndMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCertAndMetadata) Decode(dec rpc.Decoder) error {
	var tmp TeamCertAndMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamCertAndMetadata) Bytes() []byte { return nil }

type TeamCertHash lib.StdHash
type TeamCertHashInternal__ lib.StdHashInternal__

func (t TeamCertHash) Export() *TeamCertHashInternal__ {
	tmp := ((lib.StdHash)(t))
	return ((*TeamCertHashInternal__)(tmp.Export()))
}

func (t TeamCertHashInternal__) Import() TeamCertHash {
	tmp := (lib.StdHashInternal__)(t)
	return TeamCertHash((func(x *lib.StdHashInternal__) (ret lib.StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (t *TeamCertHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCertHash) Decode(dec rpc.Decoder) error {
	var tmp TeamCertHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamCertHash) Bytes() []byte {
	return ((lib.StdHash)(t)).Bytes()
}

type TeamRemoteJoinReqVisibleData struct {
	Tir *lib.RationalRange
}

type TeamRemoteJoinReqVisibleDataInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tir     *lib.RationalRangeInternal__
}

func (t TeamRemoteJoinReqVisibleDataInternal__) Import() TeamRemoteJoinReqVisibleData {
	return TeamRemoteJoinReqVisibleData{
		Tir: (func(x *lib.RationalRangeInternal__) *lib.RationalRange {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Tir),
	}
}

func (t TeamRemoteJoinReqVisibleData) Export() *TeamRemoteJoinReqVisibleDataInternal__ {
	return &TeamRemoteJoinReqVisibleDataInternal__{
		Tir: (func(x *lib.RationalRange) *lib.RationalRangeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Tir),
	}
}

func (t *TeamRemoteJoinReqVisibleData) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteJoinReqVisibleData) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteJoinReqVisibleDataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoteJoinReqVisibleData) Bytes() []byte { return nil }

type TeamRemoteJoinReq struct {
	HepkFp lib.HEPKFingerprint
	Box    lib.Box
	Vd     TeamRemoteJoinReqVisibleData
}

type TeamRemoteJoinReqInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HepkFp  *lib.HEPKFingerprintInternal__
	Box     *lib.BoxInternal__
	Vd      *TeamRemoteJoinReqVisibleDataInternal__
}

func (t TeamRemoteJoinReqInternal__) Import() TeamRemoteJoinReq {
	return TeamRemoteJoinReq{
		HepkFp: (func(x *lib.HEPKFingerprintInternal__) (ret lib.HEPKFingerprint) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.HepkFp),
		Box: (func(x *lib.BoxInternal__) (ret lib.Box) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Box),
		Vd: (func(x *TeamRemoteJoinReqVisibleDataInternal__) (ret TeamRemoteJoinReqVisibleData) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Vd),
	}
}

func (t TeamRemoteJoinReq) Export() *TeamRemoteJoinReqInternal__ {
	return &TeamRemoteJoinReqInternal__{
		HepkFp: t.HepkFp.Export(),
		Box:    t.Box.Export(),
		Vd:     t.Vd.Export(),
	}
}

func (t *TeamRemoteJoinReq) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteJoinReq) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteJoinReqInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoteJoinReq) Bytes() []byte { return nil }

type InboxPagination struct {
	Start lib.Time
	End   lib.Time
	Limit uint64
}

type InboxPaginationInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Start   *lib.TimeInternal__
	End     *lib.TimeInternal__
	Limit   *uint64
}

func (i InboxPaginationInternal__) Import() InboxPagination {
	return InboxPagination{
		Start: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.Start),
		End: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.End),
		Limit: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(i.Limit),
	}
}

func (i InboxPagination) Export() *InboxPaginationInternal__ {
	return &InboxPaginationInternal__{
		Start: i.Start.Export(),
		End:   i.End.Export(),
		Limit: &i.Limit,
	}
}

func (i *InboxPagination) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *InboxPagination) Decode(dec rpc.Decoder) error {
	var tmp InboxPaginationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i *InboxPagination) Bytes() []byte { return nil }

type JoinreqState int

const (
	JoinreqState_Pending   JoinreqState = 0
	JoinreqState_Approved  JoinreqState = 1
	JoinreqState_Rejected  JoinreqState = 2
	JoinreqState_Withdrawn JoinreqState = 3
)

var JoinreqStateMap = map[string]JoinreqState{
	"Pending":   0,
	"Approved":  1,
	"Rejected":  2,
	"Withdrawn": 3,
}

var JoinreqStateRevMap = map[JoinreqState]string{
	0: "Pending",
	1: "Approved",
	2: "Rejected",
	3: "Withdrawn",
}

type JoinreqStateInternal__ JoinreqState

func (j JoinreqStateInternal__) Import() JoinreqState {
	return JoinreqState(j)
}

func (j JoinreqState) Export() *JoinreqStateInternal__ {
	return ((*JoinreqStateInternal__)(&j))
}

type TeamRawInboxRowLocal struct {
	Tok     lib.TeamRSVPLocal
	Joiner  lib.PartyID
	SrcRole lib.Role
	Perm    lib.PermissionToken
}

type TeamRawInboxRowLocalInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *lib.TeamRSVPLocalInternal__
	Joiner  *lib.PartyIDInternal__
	SrcRole *lib.RoleInternal__
	Perm    *lib.PermissionTokenInternal__
}

func (t TeamRawInboxRowLocalInternal__) Import() TeamRawInboxRowLocal {
	return TeamRawInboxRowLocal{
		Tok: (func(x *lib.TeamRSVPLocalInternal__) (ret lib.TeamRSVPLocal) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Joiner: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Joiner),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Perm: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Perm),
	}
}

func (t TeamRawInboxRowLocal) Export() *TeamRawInboxRowLocalInternal__ {
	return &TeamRawInboxRowLocalInternal__{
		Tok:     t.Tok.Export(),
		Joiner:  t.Joiner.Export(),
		SrcRole: t.SrcRole.Export(),
		Perm:    t.Perm.Export(),
	}
}

func (t *TeamRawInboxRowLocal) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRawInboxRowLocal) Decode(dec rpc.Decoder) error {
	var tmp TeamRawInboxRowLocalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRawInboxRowLocal) Bytes() []byte { return nil }

type TeamRawInboxRowRemote struct {
	Tok lib.TeamRSVPRemote
	Req TeamRemoteJoinReq
}

type TeamRawInboxRowRemoteInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *lib.TeamRSVPRemoteInternal__
	Req     *TeamRemoteJoinReqInternal__
}

func (t TeamRawInboxRowRemoteInternal__) Import() TeamRawInboxRowRemote {
	return TeamRawInboxRowRemote{
		Tok: (func(x *lib.TeamRSVPRemoteInternal__) (ret lib.TeamRSVPRemote) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Req: (func(x *TeamRemoteJoinReqInternal__) (ret TeamRemoteJoinReq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Req),
	}
}

func (t TeamRawInboxRowRemote) Export() *TeamRawInboxRowRemoteInternal__ {
	return &TeamRawInboxRowRemoteInternal__{
		Tok: t.Tok.Export(),
		Req: t.Req.Export(),
	}
}

func (t *TeamRawInboxRowRemote) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRawInboxRowRemote) Decode(dec rpc.Decoder) error {
	var tmp TeamRawInboxRowRemoteInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRawInboxRowRemote) Bytes() []byte { return nil }

type TeamRawInboxRowVar struct {
	T     TeamJoinReqType
	F_1__ *TeamRawInboxRowLocal  `json:"f1,omitempty"`
	F_2__ *TeamRawInboxRowRemote `json:"f2,omitempty"`
}

type TeamRawInboxRowVarInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        TeamJoinReqType
	Switch__ TeamRawInboxRowVarInternalSwitch__
}

type TeamRawInboxRowVarInternalSwitch__ struct {
	_struct struct{}                         `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *TeamRawInboxRowLocalInternal__  `codec:"1"`
	F_2__   *TeamRawInboxRowRemoteInternal__ `codec:"2"`
}

func (t TeamRawInboxRowVar) GetT() (ret TeamJoinReqType, err error) {
	switch t.T {
	case TeamJoinReqType_Local:
		if t.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case TeamJoinReqType_Remote:
		if t.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return t.T, nil
}

func (t TeamRawInboxRowVar) Local() TeamRawInboxRowLocal {
	if t.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TeamJoinReqType_Local {
		panic(fmt.Sprintf("unexpected switch value (%v) when Local is called", t.T))
	}
	return *t.F_1__
}

func (t TeamRawInboxRowVar) Remote() TeamRawInboxRowRemote {
	if t.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TeamJoinReqType_Remote {
		panic(fmt.Sprintf("unexpected switch value (%v) when Remote is called", t.T))
	}
	return *t.F_2__
}

func NewTeamRawInboxRowVarWithLocal(v TeamRawInboxRowLocal) TeamRawInboxRowVar {
	return TeamRawInboxRowVar{
		T:     TeamJoinReqType_Local,
		F_1__: &v,
	}
}

func NewTeamRawInboxRowVarWithRemote(v TeamRawInboxRowRemote) TeamRawInboxRowVar {
	return TeamRawInboxRowVar{
		T:     TeamJoinReqType_Remote,
		F_2__: &v,
	}
}

func (t TeamRawInboxRowVarInternal__) Import() TeamRawInboxRowVar {
	return TeamRawInboxRowVar{
		T: t.T,
		F_1__: (func(x *TeamRawInboxRowLocalInternal__) *TeamRawInboxRowLocal {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamRawInboxRowLocalInternal__) (ret TeamRawInboxRowLocal) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_1__),
		F_2__: (func(x *TeamRawInboxRowRemoteInternal__) *TeamRawInboxRowRemote {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamRawInboxRowRemoteInternal__) (ret TeamRawInboxRowRemote) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_2__),
	}
}

func (t TeamRawInboxRowVar) Export() *TeamRawInboxRowVarInternal__ {
	return &TeamRawInboxRowVarInternal__{
		T: t.T,
		Switch__: TeamRawInboxRowVarInternalSwitch__{
			F_1__: (func(x *TeamRawInboxRowLocal) *TeamRawInboxRowLocalInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_1__),
			F_2__: (func(x *TeamRawInboxRowRemote) *TeamRawInboxRowRemoteInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_2__),
		},
	}
}

func (t *TeamRawInboxRowVar) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRawInboxRowVar) Decode(dec rpc.Decoder) error {
	var tmp TeamRawInboxRowVarInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRawInboxRowVar) Bytes() []byte { return nil }

type TeamRawInboxRow struct {
	Time  lib.Time
	State JoinreqState
	Row   TeamRawInboxRowVar
}

type TeamRawInboxRowInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Time    *lib.TimeInternal__
	State   *JoinreqStateInternal__
	Row     *TeamRawInboxRowVarInternal__
}

func (t TeamRawInboxRowInternal__) Import() TeamRawInboxRow {
	return TeamRawInboxRow{
		Time: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Time),
		State: (func(x *JoinreqStateInternal__) (ret JoinreqState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.State),
		Row: (func(x *TeamRawInboxRowVarInternal__) (ret TeamRawInboxRowVar) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Row),
	}
}

func (t TeamRawInboxRow) Export() *TeamRawInboxRowInternal__ {
	return &TeamRawInboxRowInternal__{
		Time:  t.Time.Export(),
		State: t.State.Export(),
		Row:   t.Row.Export(),
	}
}

func (t *TeamRawInboxRow) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRawInboxRow) Decode(dec rpc.Decoder) error {
	var tmp TeamRawInboxRowInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRawInboxRow) Bytes() []byte { return nil }

type TeamJoinReqType int

const (
	TeamJoinReqType_Local  TeamJoinReqType = 1
	TeamJoinReqType_Remote TeamJoinReqType = 2
)

var TeamJoinReqTypeMap = map[string]TeamJoinReqType{
	"Local":  1,
	"Remote": 2,
}

var TeamJoinReqTypeRevMap = map[TeamJoinReqType]string{
	1: "Local",
	2: "Remote",
}

type TeamJoinReqTypeInternal__ TeamJoinReqType

func (t TeamJoinReqTypeInternal__) Import() TeamJoinReqType {
	return TeamJoinReqType(t)
}

func (t TeamJoinReqType) Export() *TeamJoinReqTypeInternal__ {
	return ((*TeamJoinReqTypeInternal__)(&t))
}

type TeamRawInbox struct {
	Rows []TeamRawInboxRow
}

type TeamRawInboxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rows    *[](*TeamRawInboxRowInternal__)
}

func (t TeamRawInboxInternal__) Import() TeamRawInbox {
	return TeamRawInbox{
		Rows: (func(x *[](*TeamRawInboxRowInternal__)) (ret []TeamRawInboxRow) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamRawInboxRow, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamRawInboxRowInternal__) (ret TeamRawInboxRow) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Rows),
	}
}

func (t TeamRawInbox) Export() *TeamRawInboxInternal__ {
	return &TeamRawInboxInternal__{
		Rows: (func(x []TeamRawInboxRow) *[](*TeamRawInboxRowInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamRawInboxRowInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Rows),
	}
}

func (t *TeamRawInbox) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRawInbox) Decode(dec rpc.Decoder) error {
	var tmp TeamRawInboxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRawInbox) Bytes() []byte { return nil }

type TeamRemoteJoinReqPayload struct {
	Joiner  lib.FQParty
	Tok     lib.PermissionToken
	Tm      lib.Time
	SrcRole lib.Role
	Vd      TeamRemoteJoinReqVisibleData
}

type TeamRemoteJoinReqPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Joiner  *lib.FQPartyInternal__
	Tok     *lib.PermissionTokenInternal__
	Tm      *lib.TimeInternal__
	SrcRole *lib.RoleInternal__
	Vd      *TeamRemoteJoinReqVisibleDataInternal__
}

func (t TeamRemoteJoinReqPayloadInternal__) Import() TeamRemoteJoinReqPayload {
	return TeamRemoteJoinReqPayload{
		Joiner: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Joiner),
		Tok: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Vd: (func(x *TeamRemoteJoinReqVisibleDataInternal__) (ret TeamRemoteJoinReqVisibleData) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Vd),
	}
}

func (t TeamRemoteJoinReqPayload) Export() *TeamRemoteJoinReqPayloadInternal__ {
	return &TeamRemoteJoinReqPayloadInternal__{
		Joiner:  t.Joiner.Export(),
		Tok:     t.Tok.Export(),
		Tm:      t.Tm.Export(),
		SrcRole: t.SrcRole.Export(),
		Vd:      t.Vd.Export(),
	}
}

func (t *TeamRemoteJoinReqPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteJoinReqPayload) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteJoinReqPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamRemoteJoinReqPayloadTypeUniqueID = rpc.TypeUniqueID(0xae6970de2a147061)

func (t *TeamRemoteJoinReqPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamRemoteJoinReqPayloadTypeUniqueID
}

func (t *TeamRemoteJoinReqPayload) Bytes() []byte { return nil }

type TeamVOBearerTokenReqAndRole struct {
	Req  TeamVOBearerTokenReq
	Role lib.Role
}

type TeamVOBearerTokenReqAndRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Req     *TeamVOBearerTokenReqInternal__
	Role    *lib.RoleInternal__
}

func (t TeamVOBearerTokenReqAndRoleInternal__) Import() TeamVOBearerTokenReqAndRole {
	return TeamVOBearerTokenReqAndRole{
		Req: (func(x *TeamVOBearerTokenReqInternal__) (ret TeamVOBearerTokenReq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Req),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Role),
	}
}

func (t TeamVOBearerTokenReqAndRole) Export() *TeamVOBearerTokenReqAndRoleInternal__ {
	return &TeamVOBearerTokenReqAndRoleInternal__{
		Req:  t.Req.Export(),
		Role: t.Role.Export(),
	}
}

func (t *TeamVOBearerTokenReqAndRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamVOBearerTokenReqAndRole) Decode(dec rpc.Decoder) error {
	var tmp TeamVOBearerTokenReqAndRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamVOBearerTokenReqAndRole) Bytes() []byte { return nil }

type TeamConfig struct {
	MaxRoles uint64
}

type TeamConfigInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	MaxRoles *uint64
}

func (t TeamConfigInternal__) Import() TeamConfig {
	return TeamConfig{
		MaxRoles: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(t.MaxRoles),
	}
}

func (t TeamConfig) Export() *TeamConfigInternal__ {
	return &TeamConfigInternal__{
		MaxRoles: &t.MaxRoles,
	}
}

func (t *TeamConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamConfig) Decode(dec rpc.Decoder) error {
	var tmp TeamConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamConfig) Bytes() []byte { return nil }

var TeamAdminProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xdbe1ddbe)

type ReserveTeamnameArg struct {
	N lib.Name
}

type ReserveTeamnameArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	N       *lib.NameInternal__
}

func (r ReserveTeamnameArgInternal__) Import() ReserveTeamnameArg {
	return ReserveTeamnameArg{
		N: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.N),
	}
}

func (r ReserveTeamnameArg) Export() *ReserveTeamnameArgInternal__ {
	return &ReserveTeamnameArgInternal__{
		N: r.N.Export(),
	}
}

func (r *ReserveTeamnameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReserveTeamnameArg) Decode(dec rpc.Decoder) error {
	var tmp ReserveTeamnameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReserveTeamnameArg) Bytes() []byte { return nil }

type CreateTeamArg struct {
	NameUtf8                 lib.NameUtf8
	TeamnameCommitmentKey    lib.RandomCommitmentKey
	SubchainTreeLocationSeed lib.TreeLocation
	Rnr                      ReserveNameRes
	Eta                      EditTeamArg
	TeamMembershipLink       PostGenericLinkArg
}

type CreateTeamArgInternal__ struct {
	_struct                  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	NameUtf8                 *lib.NameUtf8Internal__
	TeamnameCommitmentKey    *lib.RandomCommitmentKeyInternal__
	SubchainTreeLocationSeed *lib.TreeLocationInternal__
	Rnr                      *ReserveNameResInternal__
	Eta                      *EditTeamArgInternal__
	TeamMembershipLink       *PostGenericLinkArgInternal__
}

func (c CreateTeamArgInternal__) Import() CreateTeamArg {
	return CreateTeamArg{
		NameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.NameUtf8),
		TeamnameCommitmentKey: (func(x *lib.RandomCommitmentKeyInternal__) (ret lib.RandomCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.TeamnameCommitmentKey),
		SubchainTreeLocationSeed: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SubchainTreeLocationSeed),
		Rnr: (func(x *ReserveNameResInternal__) (ret ReserveNameRes) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Rnr),
		Eta: (func(x *EditTeamArgInternal__) (ret EditTeamArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Eta),
		TeamMembershipLink: (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.TeamMembershipLink),
	}
}

func (c CreateTeamArg) Export() *CreateTeamArgInternal__ {
	return &CreateTeamArgInternal__{
		NameUtf8:                 c.NameUtf8.Export(),
		TeamnameCommitmentKey:    c.TeamnameCommitmentKey.Export(),
		SubchainTreeLocationSeed: c.SubchainTreeLocationSeed.Export(),
		Rnr:                      c.Rnr.Export(),
		Eta:                      c.Eta.Export(),
		TeamMembershipLink:       c.TeamMembershipLink.Export(),
	}
}

func (c *CreateTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CreateTeamArg) Decode(dec rpc.Decoder) error {
	var tmp CreateTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CreateTeamArg) Bytes() []byte { return nil }

type EditTeamArg struct {
	Link             lib.LinkOuter
	NextTreeLocation lib.TreeLocation
	Obd              OffchainBoxData
	Tok              *TeamBearerToken
	InsLocalPermsFor []lib.PartyID
}

type EditTeamArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link             *lib.LinkOuterInternal__
	NextTreeLocation *lib.TreeLocationInternal__
	Obd              *OffchainBoxDataInternal__
	Tok              *TeamBearerTokenInternal__
	InsLocalPermsFor *[](*lib.PartyIDInternal__)
}

func (e EditTeamArgInternal__) Import() EditTeamArg {
	return EditTeamArg{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.Link),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.NextTreeLocation),
		Obd: (func(x *OffchainBoxDataInternal__) (ret OffchainBoxData) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.Obd),
		Tok: (func(x *TeamBearerTokenInternal__) *TeamBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(e.Tok),
		InsLocalPermsFor: (func(x *[](*lib.PartyIDInternal__)) (ret []lib.PartyID) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.PartyID, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(e.InsLocalPermsFor),
	}
}

func (e EditTeamArg) Export() *EditTeamArgInternal__ {
	return &EditTeamArgInternal__{
		Link:             e.Link.Export(),
		NextTreeLocation: e.NextTreeLocation.Export(),
		Obd:              e.Obd.Export(),
		Tok: (func(x *TeamBearerToken) *TeamBearerTokenInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(e.Tok),
		InsLocalPermsFor: (func(x []lib.PartyID) *[](*lib.PartyIDInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.PartyIDInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(e.InsLocalPermsFor),
	}
}

func (e *EditTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EditTeamArg) Decode(dec rpc.Decoder) error {
	var tmp EditTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e *EditTeamArg) Bytes() []byte { return nil }

type MakeInertTeamBearerTokenArg struct {
	Team lib.TeamID
	Role lib.Role
	Gen  lib.Generation
}

type MakeInertTeamBearerTokenArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.TeamIDInternal__
	Role    *lib.RoleInternal__
	Gen     *lib.GenerationInternal__
}

func (m MakeInertTeamBearerTokenArgInternal__) Import() MakeInertTeamBearerTokenArg {
	return MakeInertTeamBearerTokenArg{
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Team),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Role),
		Gen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Gen),
	}
}

func (m MakeInertTeamBearerTokenArg) Export() *MakeInertTeamBearerTokenArgInternal__ {
	return &MakeInertTeamBearerTokenArgInternal__{
		Team: m.Team.Export(),
		Role: m.Role.Export(),
		Gen:  m.Gen.Export(),
	}
}

func (m *MakeInertTeamBearerTokenArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MakeInertTeamBearerTokenArg) Decode(dec rpc.Decoder) error {
	var tmp MakeInertTeamBearerTokenArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MakeInertTeamBearerTokenArg) Bytes() []byte { return nil }

type ActivateTeamBearerTokenArg struct {
	Bl  TeamBearerTokenChallengeBlob
	Sig lib.Signature
}

type ActivateTeamBearerTokenArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Bl      *TeamBearerTokenChallengeBlobInternal__
	Sig     *lib.SignatureInternal__
}

func (a ActivateTeamBearerTokenArgInternal__) Import() ActivateTeamBearerTokenArg {
	return ActivateTeamBearerTokenArg{
		Bl: (func(x *TeamBearerTokenChallengeBlobInternal__) (ret TeamBearerTokenChallengeBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Bl),
		Sig: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Sig),
	}
}

func (a ActivateTeamBearerTokenArg) Export() *ActivateTeamBearerTokenArgInternal__ {
	return &ActivateTeamBearerTokenArgInternal__{
		Bl:  a.Bl.Export(),
		Sig: a.Sig.Export(),
	}
}

func (a *ActivateTeamBearerTokenArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActivateTeamBearerTokenArg) Decode(dec rpc.Decoder) error {
	var tmp ActivateTeamBearerTokenArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActivateTeamBearerTokenArg) Bytes() []byte { return nil }

type CheckTeamBearerTokenArg struct {
	Tok TeamBearerToken
}

type CheckTeamBearerTokenArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
}

func (c CheckTeamBearerTokenArgInternal__) Import() CheckTeamBearerTokenArg {
	return CheckTeamBearerTokenArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Tok),
	}
}

func (c CheckTeamBearerTokenArg) Export() *CheckTeamBearerTokenArgInternal__ {
	return &CheckTeamBearerTokenArgInternal__{
		Tok: c.Tok.Export(),
	}
}

func (c *CheckTeamBearerTokenArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckTeamBearerTokenArg) Decode(dec rpc.Decoder) error {
	var tmp CheckTeamBearerTokenArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckTeamBearerTokenArg) Bytes() []byte { return nil }

type PutTeamCertArg struct {
	Tok  TeamBearerToken
	Cert TeamCert
}

type PutTeamCertArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Cert    *TeamCertInternal__
}

func (p PutTeamCertArgInternal__) Import() PutTeamCertArg {
	return PutTeamCertArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Tok),
		Cert: (func(x *TeamCertInternal__) (ret TeamCert) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Cert),
	}
}

func (p PutTeamCertArg) Export() *PutTeamCertArgInternal__ {
	return &PutTeamCertArgInternal__{
		Tok:  p.Tok.Export(),
		Cert: p.Cert.Export(),
	}
}

func (p *PutTeamCertArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutTeamCertArg) Decode(dec rpc.Decoder) error {
	var tmp PutTeamCertArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutTeamCertArg) Bytes() []byte { return nil }

type GetCurrentTeamCertsArg struct {
	Tok TeamBearerToken
}

type GetCurrentTeamCertsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
}

func (g GetCurrentTeamCertsArgInternal__) Import() GetCurrentTeamCertsArg {
	return GetCurrentTeamCertsArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Tok),
	}
}

func (g GetCurrentTeamCertsArg) Export() *GetCurrentTeamCertsArgInternal__ {
	return &GetCurrentTeamCertsArgInternal__{
		Tok: g.Tok.Export(),
	}
}

func (g *GetCurrentTeamCertsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetCurrentTeamCertsArg) Decode(dec rpc.Decoder) error {
	var tmp GetCurrentTeamCertsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetCurrentTeamCertsArg) Bytes() []byte { return nil }

type LoadTeamRemoteJoinReqArg struct {
	Tok TeamBearerToken
	Jrt lib.TeamRSVPRemote
}

type LoadTeamRemoteJoinReqArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Jrt     *lib.TeamRSVPRemoteInternal__
}

func (l LoadTeamRemoteJoinReqArgInternal__) Import() LoadTeamRemoteJoinReqArg {
	return LoadTeamRemoteJoinReqArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Jrt: (func(x *lib.TeamRSVPRemoteInternal__) (ret lib.TeamRSVPRemote) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Jrt),
	}
}

func (l LoadTeamRemoteJoinReqArg) Export() *LoadTeamRemoteJoinReqArgInternal__ {
	return &LoadTeamRemoteJoinReqArgInternal__{
		Tok: l.Tok.Export(),
		Jrt: l.Jrt.Export(),
	}
}

func (l *LoadTeamRemoteJoinReqArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadTeamRemoteJoinReqArg) Decode(dec rpc.Decoder) error {
	var tmp LoadTeamRemoteJoinReqArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadTeamRemoteJoinReqArg) Bytes() []byte { return nil }

type PostTeamMembershipLinkArg struct {
	Tok  TeamBearerToken
	Link PostGenericLinkArg
}

type PostTeamMembershipLinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Link    *PostGenericLinkArgInternal__
}

func (p PostTeamMembershipLinkArgInternal__) Import() PostTeamMembershipLinkArg {
	return PostTeamMembershipLinkArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Tok),
		Link: (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Link),
	}
}

func (p PostTeamMembershipLinkArg) Export() *PostTeamMembershipLinkArgInternal__ {
	return &PostTeamMembershipLinkArgInternal__{
		Tok:  p.Tok.Export(),
		Link: p.Link.Export(),
	}
}

func (p *PostTeamMembershipLinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PostTeamMembershipLinkArg) Decode(dec rpc.Decoder) error {
	var tmp PostTeamMembershipLinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PostTeamMembershipLinkArg) Bytes() []byte { return nil }

type LoadRemovalKeyBoxForTeamAdminArg struct {
	Tok     TeamBearerToken
	Member  lib.FQParty
	SrcRole lib.Role
}

type LoadRemovalKeyBoxForTeamAdminArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Member  *lib.FQPartyInternal__
	SrcRole *lib.RoleInternal__
}

func (l LoadRemovalKeyBoxForTeamAdminArgInternal__) Import() LoadRemovalKeyBoxForTeamAdminArg {
	return LoadRemovalKeyBoxForTeamAdminArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Member: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Member),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SrcRole),
	}
}

func (l LoadRemovalKeyBoxForTeamAdminArg) Export() *LoadRemovalKeyBoxForTeamAdminArgInternal__ {
	return &LoadRemovalKeyBoxForTeamAdminArgInternal__{
		Tok:     l.Tok.Export(),
		Member:  l.Member.Export(),
		SrcRole: l.SrcRole.Export(),
	}
}

func (l *LoadRemovalKeyBoxForTeamAdminArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadRemovalKeyBoxForTeamAdminArg) Decode(dec rpc.Decoder) error {
	var tmp LoadRemovalKeyBoxForTeamAdminArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadRemovalKeyBoxForTeamAdminArg) Bytes() []byte { return nil }

type PostTeamRemovalArg struct {
	Tok TeamBearerToken
	Rm  TeamRemovalAndComm
}

type PostTeamRemovalArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Rm      *TeamRemovalAndCommInternal__
}

func (p PostTeamRemovalArgInternal__) Import() PostTeamRemovalArg {
	return PostTeamRemovalArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Tok),
		Rm: (func(x *TeamRemovalAndCommInternal__) (ret TeamRemovalAndComm) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Rm),
	}
}

func (p PostTeamRemovalArg) Export() *PostTeamRemovalArgInternal__ {
	return &PostTeamRemovalArgInternal__{
		Tok: p.Tok.Export(),
		Rm:  p.Rm.Export(),
	}
}

func (p *PostTeamRemovalArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PostTeamRemovalArg) Decode(dec rpc.Decoder) error {
	var tmp PostTeamRemovalArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PostTeamRemovalArg) Bytes() []byte { return nil }

type LoadTeamRawInboxArg struct {
	Tok        TeamBearerToken
	Pagination *InboxPagination
}

type LoadTeamRawInboxArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok        *TeamBearerTokenInternal__
	Pagination *InboxPaginationInternal__
}

func (l LoadTeamRawInboxArgInternal__) Import() LoadTeamRawInboxArg {
	return LoadTeamRawInboxArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Tok),
		Pagination: (func(x *InboxPaginationInternal__) *InboxPagination {
			if x == nil {
				return nil
			}
			tmp := (func(x *InboxPaginationInternal__) (ret InboxPagination) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Pagination),
	}
}

func (l LoadTeamRawInboxArg) Export() *LoadTeamRawInboxArgInternal__ {
	return &LoadTeamRawInboxArgInternal__{
		Tok: l.Tok.Export(),
		Pagination: (func(x *InboxPagination) *InboxPaginationInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.Pagination),
	}
}

func (l *LoadTeamRawInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadTeamRawInboxArg) Decode(dec rpc.Decoder) error {
	var tmp LoadTeamRawInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadTeamRawInboxArg) Bytes() []byte { return nil }

type RejectJoinReqArg struct {
	Tok TeamBearerToken
	Req lib.TeamRSVP
}

type RejectJoinReqArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *TeamBearerTokenInternal__
	Req     *lib.TeamRSVPInternal__
}

func (r RejectJoinReqArgInternal__) Import() RejectJoinReqArg {
	return RejectJoinReqArg{
		Tok: (func(x *TeamBearerTokenInternal__) (ret TeamBearerToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Tok),
		Req: (func(x *lib.TeamRSVPInternal__) (ret lib.TeamRSVP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Req),
	}
}

func (r RejectJoinReqArg) Export() *RejectJoinReqArgInternal__ {
	return &RejectJoinReqArgInternal__{
		Tok: r.Tok.Export(),
		Req: r.Req.Export(),
	}
}

func (r *RejectJoinReqArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RejectJoinReqArg) Decode(dec rpc.Decoder) error {
	var tmp RejectJoinReqArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RejectJoinReqArg) Bytes() []byte { return nil }

type GetTeamConfigArg struct {
}

type GetTeamConfigArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetTeamConfigArgInternal__) Import() GetTeamConfigArg {
	return GetTeamConfigArg{}
}

func (g GetTeamConfigArg) Export() *GetTeamConfigArgInternal__ {
	return &GetTeamConfigArgInternal__{}
}

func (g *GetTeamConfigArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetTeamConfigArg) Decode(dec rpc.Decoder) error {
	var tmp GetTeamConfigArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetTeamConfigArg) Bytes() []byte { return nil }

type TeamAdminInterface interface {
	ReserveTeamname(context.Context, lib.Name) (ReserveNameRes, error)
	CreateTeam(context.Context, CreateTeamArg) error
	EditTeam(context.Context, EditTeamArg) (EditTeamRes, error)
	MakeInertTeamBearerToken(context.Context, MakeInertTeamBearerTokenArg) (TeamBearerToken, error)
	ActivateTeamBearerToken(context.Context, ActivateTeamBearerTokenArg) error
	CheckTeamBearerToken(context.Context, TeamBearerToken) (lib.TeamID, error)
	PutTeamCert(context.Context, PutTeamCertArg) error
	GetCurrentTeamCerts(context.Context, TeamBearerToken) ([]TeamCert, error)
	LoadTeamRemoteJoinReq(context.Context, LoadTeamRemoteJoinReqArg) (TeamRemoteJoinReq, error)
	PostTeamMembershipLink(context.Context, PostTeamMembershipLinkArg) error
	LoadRemovalKeyBoxForTeamAdmin(context.Context, LoadRemovalKeyBoxForTeamAdminArg) (lib.TeamRemovalKeyBox, error)
	PostTeamRemoval(context.Context, PostTeamRemovalArg) error
	LoadTeamRawInbox(context.Context, LoadTeamRawInboxArg) (TeamRawInbox, error)
	RejectJoinReq(context.Context, RejectJoinReqArg) error
	GetTeamConfig(context.Context) (TeamConfig, error)
	ErrorWrapper() func(error) lib.Status
}

func TeamAdminMakeGenericErrorWrapper(f TeamAdminErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TeamAdminErrorUnwrapper func(lib.Status) error
type TeamAdminErrorWrapper func(error) lib.Status

type teamAdminErrorUnwrapperAdapter struct {
	h TeamAdminErrorUnwrapper
}

func (t teamAdminErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t teamAdminErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = teamAdminErrorUnwrapperAdapter{}

type TeamAdminClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TeamAdminErrorUnwrapper
}

func (c TeamAdminClient) ReserveTeamname(ctx context.Context, n lib.Name) (res ReserveNameRes, err error) {
	arg := ReserveTeamnameArg{
		N: n,
	}
	warg := arg.Export()
	var tmp ReserveNameResInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 0, "TeamAdmin.reserveTeamname"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) CreateTeam(ctx context.Context, arg CreateTeamArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 1, "TeamAdmin.createTeam"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) EditTeam(ctx context.Context, arg EditTeamArg) (res EditTeamRes, err error) {
	warg := arg.Export()
	var tmp EditTeamResInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 2, "TeamAdmin.editTeam"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) MakeInertTeamBearerToken(ctx context.Context, arg MakeInertTeamBearerTokenArg) (res TeamBearerToken, err error) {
	warg := arg.Export()
	var tmp TeamBearerTokenInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 3, "TeamAdmin.makeInertTeamBearerToken"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) ActivateTeamBearerToken(ctx context.Context, arg ActivateTeamBearerTokenArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 4, "TeamAdmin.activateTeamBearerToken"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) CheckTeamBearerToken(ctx context.Context, tok TeamBearerToken) (res lib.TeamID, err error) {
	arg := CheckTeamBearerTokenArg{
		Tok: tok,
	}
	warg := arg.Export()
	var tmp lib.TeamIDInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 5, "TeamAdmin.checkTeamBearerToken"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) PutTeamCert(ctx context.Context, arg PutTeamCertArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 6, "TeamAdmin.putTeamCert"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) GetCurrentTeamCerts(ctx context.Context, tok TeamBearerToken) (res []TeamCert, err error) {
	arg := GetCurrentTeamCertsArg{
		Tok: tok,
	}
	warg := arg.Export()
	var tmp [](*TeamCertInternal__)
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 7, "TeamAdmin.getCurrentTeamCerts"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = (func(x *[](*TeamCertInternal__)) (ret []TeamCert) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]TeamCert, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *TeamCertInternal__) (ret TeamCert) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp)
	return
}

func (c TeamAdminClient) LoadTeamRemoteJoinReq(ctx context.Context, arg LoadTeamRemoteJoinReqArg) (res TeamRemoteJoinReq, err error) {
	warg := arg.Export()
	var tmp TeamRemoteJoinReqInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 8, "TeamAdmin.loadTeamRemoteJoinReq"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) PostTeamMembershipLink(ctx context.Context, arg PostTeamMembershipLinkArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 9, "TeamAdmin.postTeamMembershipLink"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) LoadRemovalKeyBoxForTeamAdmin(ctx context.Context, arg LoadRemovalKeyBoxForTeamAdminArg) (res lib.TeamRemovalKeyBox, err error) {
	warg := arg.Export()
	var tmp lib.TeamRemovalKeyBoxInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 10, "TeamAdmin.loadRemovalKeyBoxForTeamAdmin"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) PostTeamRemoval(ctx context.Context, arg PostTeamRemovalArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 11, "TeamAdmin.postTeamRemoval"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) LoadTeamRawInbox(ctx context.Context, arg LoadTeamRawInboxArg) (res TeamRawInbox, err error) {
	warg := arg.Export()
	var tmp TeamRawInboxInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 12, "TeamAdmin.loadTeamRawInbox"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamAdminClient) RejectJoinReq(ctx context.Context, arg RejectJoinReqArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 13, "TeamAdmin.rejectJoinReq"), warg, nil, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c TeamAdminClient) GetTeamConfig(ctx context.Context) (res TeamConfig, err error) {
	var arg GetTeamConfigArg
	warg := arg.Export()
	var tmp TeamConfigInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamAdminProtocolID, 14, "TeamAdmin.getTeamConfig"), warg, &tmp, 0*time.Millisecond, teamAdminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func TeamAdminProtocol(i TeamAdminInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TeamAdmin",
		ID:   TeamAdminProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret ReserveTeamnameArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*ReserveTeamnameArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*ReserveTeamnameArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.ReserveTeamname(ctx, (typedArg.Import()).N)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "reserveTeamname",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret CreateTeamArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*CreateTeamArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*CreateTeamArgInternal__)(nil), args)
							return nil, err
						}
						err := i.CreateTeam(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "createTeam",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret EditTeamArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*EditTeamArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*EditTeamArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.EditTeam(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "editTeam",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret MakeInertTeamBearerTokenArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*MakeInertTeamBearerTokenArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*MakeInertTeamBearerTokenArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.MakeInertTeamBearerToken(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "makeInertTeamBearerToken",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret ActivateTeamBearerTokenArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*ActivateTeamBearerTokenArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*ActivateTeamBearerTokenArgInternal__)(nil), args)
							return nil, err
						}
						err := i.ActivateTeamBearerToken(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "activateTeamBearerToken",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret CheckTeamBearerTokenArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*CheckTeamBearerTokenArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*CheckTeamBearerTokenArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.CheckTeamBearerToken(ctx, (typedArg.Import()).Tok)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "checkTeamBearerToken",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret PutTeamCertArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*PutTeamCertArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*PutTeamCertArgInternal__)(nil), args)
							return nil, err
						}
						err := i.PutTeamCert(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "putTeamCert",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GetCurrentTeamCertsArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GetCurrentTeamCertsArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GetCurrentTeamCertsArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GetCurrentTeamCerts(ctx, (typedArg.Import()).Tok)
						if err != nil {
							return nil, err
						}
						lst := (func(x []TeamCert) *[](*TeamCertInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*TeamCertInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						return lst, nil
					},
				},
				Name: "getCurrentTeamCerts",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadTeamRemoteJoinReqArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadTeamRemoteJoinReqArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadTeamRemoteJoinReqArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadTeamRemoteJoinReq(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadTeamRemoteJoinReq",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret PostTeamMembershipLinkArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*PostTeamMembershipLinkArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*PostTeamMembershipLinkArgInternal__)(nil), args)
							return nil, err
						}
						err := i.PostTeamMembershipLink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "postTeamMembershipLink",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadRemovalKeyBoxForTeamAdminArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadRemovalKeyBoxForTeamAdminArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadRemovalKeyBoxForTeamAdminArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadRemovalKeyBoxForTeamAdmin(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadRemovalKeyBoxForTeamAdmin",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret PostTeamRemovalArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*PostTeamRemovalArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*PostTeamRemovalArgInternal__)(nil), args)
							return nil, err
						}
						err := i.PostTeamRemoval(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "postTeamRemoval",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LoadTeamRawInboxArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LoadTeamRawInboxArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LoadTeamRawInboxArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LoadTeamRawInbox(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "loadTeamRawInbox",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret RejectJoinReqArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*RejectJoinReqArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*RejectJoinReqArgInternal__)(nil), args)
							return nil, err
						}
						err := i.RejectJoinReq(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "rejectJoinReq",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GetTeamConfigArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*GetTeamConfigArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GetTeamConfigArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GetTeamConfig(ctx)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "getTeamConfig",
			},
		},
		WrapError: TeamAdminMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var TeamGuestProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf6d7585c)

type LookupTeamCertByHashArg struct {
	I lib.TeamInvite
}

type LookupTeamCertByHashArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	I       *lib.TeamInviteInternal__
}

func (l LookupTeamCertByHashArgInternal__) Import() LookupTeamCertByHashArg {
	return LookupTeamCertByHashArg{
		I: (func(x *lib.TeamInviteInternal__) (ret lib.TeamInvite) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.I),
	}
}

func (l LookupTeamCertByHashArg) Export() *LookupTeamCertByHashArgInternal__ {
	return &LookupTeamCertByHashArgInternal__{
		I: l.I.Export(),
	}
}

func (l *LookupTeamCertByHashArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LookupTeamCertByHashArg) Decode(dec rpc.Decoder) error {
	var tmp LookupTeamCertByHashArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LookupTeamCertByHashArg) Bytes() []byte { return nil }

type AcceptInviteRemoteArg struct {
	I  lib.TeamInvite
	Jr TeamRemoteJoinReq
}

type AcceptInviteRemoteArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	I       *lib.TeamInviteInternal__
	Jr      *TeamRemoteJoinReqInternal__
}

func (a AcceptInviteRemoteArgInternal__) Import() AcceptInviteRemoteArg {
	return AcceptInviteRemoteArg{
		I: (func(x *lib.TeamInviteInternal__) (ret lib.TeamInvite) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.I),
		Jr: (func(x *TeamRemoteJoinReqInternal__) (ret TeamRemoteJoinReq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Jr),
	}
}

func (a AcceptInviteRemoteArg) Export() *AcceptInviteRemoteArgInternal__ {
	return &AcceptInviteRemoteArgInternal__{
		I:  a.I.Export(),
		Jr: a.Jr.Export(),
	}
}

func (a *AcceptInviteRemoteArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AcceptInviteRemoteArg) Decode(dec rpc.Decoder) error {
	var tmp AcceptInviteRemoteArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AcceptInviteRemoteArg) Bytes() []byte { return nil }

type TeamGuestInterface interface {
	LookupTeamCertByHash(context.Context, lib.TeamInvite) (TeamCertAndMetadata, error)
	AcceptInviteRemote(context.Context, AcceptInviteRemoteArg) (lib.TeamRSVPRemote, error)
	ErrorWrapper() func(error) lib.Status
}

func TeamGuestMakeGenericErrorWrapper(f TeamGuestErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TeamGuestErrorUnwrapper func(lib.Status) error
type TeamGuestErrorWrapper func(error) lib.Status

type teamGuestErrorUnwrapperAdapter struct {
	h TeamGuestErrorUnwrapper
}

func (t teamGuestErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t teamGuestErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = teamGuestErrorUnwrapperAdapter{}

type TeamGuestClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TeamGuestErrorUnwrapper
}

func (c TeamGuestClient) LookupTeamCertByHash(ctx context.Context, i lib.TeamInvite) (res TeamCertAndMetadata, err error) {
	arg := LookupTeamCertByHashArg{
		I: i,
	}
	warg := arg.Export()
	var tmp TeamCertAndMetadataInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamGuestProtocolID, 0, "TeamGuest.lookupTeamCertByHash"), warg, &tmp, 0*time.Millisecond, teamGuestErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func (c TeamGuestClient) AcceptInviteRemote(ctx context.Context, arg AcceptInviteRemoteArg) (res lib.TeamRSVPRemote, err error) {
	warg := arg.Export()
	var tmp lib.TeamRSVPRemoteInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamGuestProtocolID, 1, "TeamGuest.acceptInviteRemote"), warg, &tmp, 0*time.Millisecond, teamGuestErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}

func TeamGuestProtocol(i TeamGuestInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TeamGuest",
		ID:   TeamGuestProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret LookupTeamCertByHashArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*LookupTeamCertByHashArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*LookupTeamCertByHashArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.LookupTeamCertByHash(ctx, (typedArg.Import()).I)
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "lookupTeamCertByHash",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret AcceptInviteRemoteArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*AcceptInviteRemoteArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*AcceptInviteRemoteArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.AcceptInviteRemote(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "acceptInviteRemote",
			},
		},
		WrapError: TeamGuestMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(TeamVOBearerTokenChallengePayloadTypeUniqueID)
	rpc.AddUnique(TeamVOBearerTokenChallengeTypeUniqueID)
	rpc.AddUnique(TeamRemovalKeyTypeUniqueID)
	rpc.AddUnique(TeamRemovalKeyBoxPayloadTypeUniqueID)
	rpc.AddUnique(TeamRemovalMACPayloadTypeUniqueID)
	rpc.AddUnique(TeamLoaderProtocolID)
	rpc.AddUnique(TeamMemberProtocolID)
	rpc.AddUnique(TeamBearerTokenChallengePayloadTypeUniqueID)
	rpc.AddUnique(TeamBearerTokenChallengeBlobTypeUniqueID)
	rpc.AddUnique(TeamCertV1PayloadTypeUniqueID)
	rpc.AddUnique(TeamCertV1BlobTypeUniqueID)
	rpc.AddUnique(TeamCertV1SignedTypeUniqueID)
	rpc.AddUnique(TeamCertTypeUniqueID)
	rpc.AddUnique(TeamRemoteJoinReqPayloadTypeUniqueID)
	rpc.AddUnique(TeamAdminProtocolID)
	rpc.AddUnique(TeamGuestProtocolID)
}
