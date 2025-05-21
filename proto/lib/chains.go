// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/chains.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type TreeRoot struct {
	Epno MerkleEpno
	Hash MerkleRootHash
}
type TreeRootInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Epno    *MerkleEpnoInternal__
	Hash    *MerkleRootHashInternal__
}

func (t TreeRootInternal__) Import() TreeRoot {
	return TreeRoot{
		Epno: (func(x *MerkleEpnoInternal__) (ret MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Epno),
		Hash: (func(x *MerkleRootHashInternal__) (ret MerkleRootHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hash),
	}
}
func (t TreeRoot) Export() *TreeRootInternal__ {
	return &TreeRootInternal__{
		Epno: t.Epno.Export(),
		Hash: t.Hash.Export(),
	}
}
func (t *TreeRoot) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TreeRoot) Decode(dec rpc.Decoder) error {
	var tmp TreeRootInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TreeRoot) Bytes() []byte { return nil }

type BaseChainer struct {
	Seqno Seqno
	Prev  *LinkHash
	Root  TreeRoot
	Time  Time
}
type BaseChainerInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *SeqnoInternal__
	Prev    *LinkHashInternal__
	Root    *TreeRootInternal__
	Time    *TimeInternal__
}

func (b BaseChainerInternal__) Import() BaseChainer {
	return BaseChainer{
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Seqno),
		Prev: (func(x *LinkHashInternal__) *LinkHash {
			if x == nil {
				return nil
			}
			tmp := (func(x *LinkHashInternal__) (ret LinkHash) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Prev),
		Root: (func(x *TreeRootInternal__) (ret TreeRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Root),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Time),
	}
}
func (b BaseChainer) Export() *BaseChainerInternal__ {
	return &BaseChainerInternal__{
		Seqno: b.Seqno.Export(),
		Prev: (func(x *LinkHash) *LinkHashInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(b.Prev),
		Root: b.Root.Export(),
		Time: b.Time.Export(),
	}
}
func (b *BaseChainer) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BaseChainer) Decode(dec rpc.Decoder) error {
	var tmp BaseChainerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BaseChainer) Bytes() []byte { return nil }

type HidingChainer struct {
	Base                   BaseChainer
	NextLocationCommitment TreeLocationCommitment
}
type HidingChainerInternal__ struct {
	_struct                struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Base                   *BaseChainerInternal__
	NextLocationCommitment *TreeLocationCommitmentInternal__
}

func (h HidingChainerInternal__) Import() HidingChainer {
	return HidingChainer{
		Base: (func(x *BaseChainerInternal__) (ret BaseChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Base),
		NextLocationCommitment: (func(x *TreeLocationCommitmentInternal__) (ret TreeLocationCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.NextLocationCommitment),
	}
}
func (h HidingChainer) Export() *HidingChainerInternal__ {
	return &HidingChainerInternal__{
		Base:                   h.Base.Export(),
		NextLocationCommitment: h.NextLocationCommitment.Export(),
	}
}
func (h *HidingChainer) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HidingChainer) Decode(dec rpc.Decoder) error {
	var tmp HidingChainerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HidingChainer) Bytes() []byte { return nil }

type FQEntity struct {
	Entity EntityID
	Host   HostID
}
type FQEntityInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Entity  *EntityIDInternal__
	Host    *HostIDInternal__
}

func (f FQEntityInternal__) Import() FQEntity {
	return FQEntity{
		Entity: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Entity),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
	}
}
func (f FQEntity) Export() *FQEntityInternal__ {
	return &FQEntityInternal__{
		Entity: f.Entity.Export(),
		Host:   f.Host.Export(),
	}
}
func (f *FQEntity) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQEntity) Decode(dec rpc.Decoder) error {
	var tmp FQEntityInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQEntity) Bytes() []byte { return nil }

type FQParty struct {
	Party PartyID
	Host  HostID
}
type FQPartyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Party   *PartyIDInternal__
	Host    *HostIDInternal__
}

func (f FQPartyInternal__) Import() FQParty {
	return FQParty{
		Party: (func(x *PartyIDInternal__) (ret PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Party),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
	}
}
func (f FQParty) Export() *FQPartyInternal__ {
	return &FQPartyInternal__{
		Party: f.Party.Export(),
		Host:  f.Host.Export(),
	}
}
func (f *FQParty) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQParty) Decode(dec rpc.Decoder) error {
	var tmp FQPartyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FQPartyTypeUniqueID = rpc.TypeUniqueID(0xefcb2f00daad7a7c)

func (f *FQParty) GetTypeUniqueID() rpc.TypeUniqueID {
	return FQPartyTypeUniqueID
}
func (f *FQParty) Bytes() []byte { return nil }

type FQEntityFixed struct {
	Entity FixedEntityID
	Host   HostID
}
type FQEntityFixedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Entity  *FixedEntityIDInternal__
	Host    *HostIDInternal__
}

func (f FQEntityFixedInternal__) Import() FQEntityFixed {
	return FQEntityFixed{
		Entity: (func(x *FixedEntityIDInternal__) (ret FixedEntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Entity),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
	}
}
func (f FQEntityFixed) Export() *FQEntityFixedInternal__ {
	return &FQEntityFixedInternal__{
		Entity: f.Entity.Export(),
		Host:   f.Host.Export(),
	}
}
func (f *FQEntityFixed) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQEntityFixed) Decode(dec rpc.Decoder) error {
	var tmp FQEntityFixedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQEntityFixed) Bytes() []byte { return nil }

type FQEntityInHostScope struct {
	Entity EntityID
	Host   *HostID
}
type FQEntityInHostScopeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Entity  *EntityIDInternal__
	Host    *HostIDInternal__
}

func (f FQEntityInHostScopeInternal__) Import() FQEntityInHostScope {
	return FQEntityInHostScope{
		Entity: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Entity),
		Host: (func(x *HostIDInternal__) *HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostIDInternal__) (ret HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(f.Host),
	}
}
func (f FQEntityInHostScope) Export() *FQEntityInHostScopeInternal__ {
	return &FQEntityInHostScopeInternal__{
		Entity: f.Entity.Export(),
		Host: (func(x *HostID) *HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(f.Host),
	}
}
func (f *FQEntityInHostScope) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQEntityInHostScope) Decode(dec rpc.Decoder) error {
	var tmp FQEntityInHostScopeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQEntityInHostScope) Bytes() []byte { return nil }

type RoleType int

const (
	RoleType_NONE   RoleType = 0
	RoleType_MEMBER RoleType = 1
	RoleType_ADMIN  RoleType = 2
	RoleType_OWNER  RoleType = 3
)

var RoleTypeMap = map[string]RoleType{
	"NONE":   0,
	"MEMBER": 1,
	"ADMIN":  2,
	"OWNER":  3,
}
var RoleTypeRevMap = map[RoleType]string{
	0: "NONE",
	1: "MEMBER",
	2: "ADMIN",
	3: "OWNER",
}

type RoleTypeInternal__ RoleType

func (r RoleTypeInternal__) Import() RoleType {
	return RoleType(r)
}
func (r RoleType) Export() *RoleTypeInternal__ {
	return ((*RoleTypeInternal__)(&r))
}

type VizLevel int64
type VizLevelInternal__ int64

func (v VizLevel) Export() *VizLevelInternal__ {
	tmp := ((int64)(v))
	return ((*VizLevelInternal__)(&tmp))
}
func (v VizLevelInternal__) Import() VizLevel {
	tmp := (int64)(v)
	return VizLevel((func(x *int64) (ret int64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (v *VizLevel) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *VizLevel) Decode(dec rpc.Decoder) error {
	var tmp VizLevelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v VizLevel) Bytes() []byte {
	return nil
}

type Role struct {
	T     RoleType
	F_0__ *VizLevel `json:"f0,omitempty"`
}
type RoleInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RoleType
	Switch__ RoleInternalSwitch__
}
type RoleInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *VizLevelInternal__ `codec:"0"`
}

func (r Role) GetT() (ret RoleType, err error) {
	switch r.T {
	default:
		break
	case RoleType_MEMBER:
		if r.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return r.T, nil
}
func (r Role) Member() VizLevel {
	if r.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RoleType_MEMBER {
		panic(fmt.Sprintf("unexpected switch value (%v) when Member is called", r.T))
	}
	return *r.F_0__
}
func NewRoleDefault(s RoleType) Role {
	return Role{
		T: s,
	}
}
func NewRoleWithMember(v VizLevel) Role {
	return Role{
		T:     RoleType_MEMBER,
		F_0__: &v,
	}
}
func (r RoleInternal__) Import() Role {
	return Role{
		T: r.T,
		F_0__: (func(x *VizLevelInternal__) *VizLevel {
			if x == nil {
				return nil
			}
			tmp := (func(x *VizLevelInternal__) (ret VizLevel) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_0__),
	}
}
func (r Role) Export() *RoleInternal__ {
	return &RoleInternal__{
		T: r.T,
		Switch__: RoleInternalSwitch__{
			F_0__: (func(x *VizLevel) *VizLevelInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_0__),
		},
	}
}
func (r *Role) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *Role) Decode(dec rpc.Decoder) error {
	var tmp RoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *Role) Bytes() []byte { return nil }

type UserMemberKeys struct {
	HepkFp HEPKFingerprint
	SubKey *EntityID
}
type UserMemberKeysInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HepkFp  *HEPKFingerprintInternal__
	SubKey  *EntityIDInternal__
}

func (u UserMemberKeysInternal__) Import() UserMemberKeys {
	return UserMemberKeys{
		HepkFp: (func(x *HEPKFingerprintInternal__) (ret HEPKFingerprint) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.HepkFp),
		SubKey: (func(x *EntityIDInternal__) *EntityID {
			if x == nil {
				return nil
			}
			tmp := (func(x *EntityIDInternal__) (ret EntityID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.SubKey),
	}
}
func (u UserMemberKeys) Export() *UserMemberKeysInternal__ {
	return &UserMemberKeysInternal__{
		HepkFp: u.HepkFp.Export(),
		SubKey: (func(x *EntityID) *EntityIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(u.SubKey),
	}
}
func (u *UserMemberKeys) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserMemberKeys) Decode(dec rpc.Decoder) error {
	var tmp UserMemberKeysInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserMemberKeys) Bytes() []byte { return nil }

type TeamMemberKeys struct {
	VerifyKey EntityID
	HepkFp    HEPKFingerprint
	Gen       Generation
	Trkc      *KeyCommitment
	Tir       *RationalRange
}
type TeamMemberKeysInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	VerifyKey *EntityIDInternal__
	HepkFp    *HEPKFingerprintInternal__
	Gen       *GenerationInternal__
	Trkc      *KeyCommitmentInternal__
	Tir       *RationalRangeInternal__
}

func (t TeamMemberKeysInternal__) Import() TeamMemberKeys {
	return TeamMemberKeys{
		VerifyKey: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.VerifyKey),
		HepkFp: (func(x *HEPKFingerprintInternal__) (ret HEPKFingerprint) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.HepkFp),
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Gen),
		Trkc: (func(x *KeyCommitmentInternal__) *KeyCommitment {
			if x == nil {
				return nil
			}
			tmp := (func(x *KeyCommitmentInternal__) (ret KeyCommitment) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Trkc),
		Tir: (func(x *RationalRangeInternal__) *RationalRange {
			if x == nil {
				return nil
			}
			tmp := (func(x *RationalRangeInternal__) (ret RationalRange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Tir),
	}
}
func (t TeamMemberKeys) Export() *TeamMemberKeysInternal__ {
	return &TeamMemberKeysInternal__{
		VerifyKey: t.VerifyKey.Export(),
		HepkFp:    t.HepkFp.Export(),
		Gen:       t.Gen.Export(),
		Trkc: (func(x *KeyCommitment) *KeyCommitmentInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Trkc),
		Tir: (func(x *RationalRange) *RationalRangeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Tir),
	}
}
func (t *TeamMemberKeys) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMemberKeys) Decode(dec rpc.Decoder) error {
	var tmp TeamMemberKeysInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMemberKeys) Bytes() []byte { return nil }

type MemberKeysType int

const (
	MemberKeysType_None MemberKeysType = 0
	MemberKeysType_User MemberKeysType = 1
	MemberKeysType_Team MemberKeysType = 2
)

var MemberKeysTypeMap = map[string]MemberKeysType{
	"None": 0,
	"User": 1,
	"Team": 2,
}
var MemberKeysTypeRevMap = map[MemberKeysType]string{
	0: "None",
	1: "User",
	2: "Team",
}

type MemberKeysTypeInternal__ MemberKeysType

func (m MemberKeysTypeInternal__) Import() MemberKeysType {
	return MemberKeysType(m)
}
func (m MemberKeysType) Export() *MemberKeysTypeInternal__ {
	return ((*MemberKeysTypeInternal__)(&m))
}

type MemberKeys struct {
	T     MemberKeysType
	F_1__ *UserMemberKeys `json:"f1,omitempty"`
	F_2__ *TeamMemberKeys `json:"f2,omitempty"`
}
type MemberKeysInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        MemberKeysType
	Switch__ MemberKeysInternalSwitch__
}
type MemberKeysInternalSwitch__ struct {
	_struct struct{}                  `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *UserMemberKeysInternal__ `codec:"1"`
	F_2__   *TeamMemberKeysInternal__ `codec:"2"`
}

func (m MemberKeys) GetT() (ret MemberKeysType, err error) {
	switch m.T {
	case MemberKeysType_None:
		break
	case MemberKeysType_User:
		if m.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case MemberKeysType_Team:
		if m.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return m.T, nil
}
func (m MemberKeys) User() UserMemberKeys {
	if m.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.T != MemberKeysType_User {
		panic(fmt.Sprintf("unexpected switch value (%v) when User is called", m.T))
	}
	return *m.F_1__
}
func (m MemberKeys) Team() TeamMemberKeys {
	if m.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.T != MemberKeysType_Team {
		panic(fmt.Sprintf("unexpected switch value (%v) when Team is called", m.T))
	}
	return *m.F_2__
}
func NewMemberKeysWithNone() MemberKeys {
	return MemberKeys{
		T: MemberKeysType_None,
	}
}
func NewMemberKeysWithUser(v UserMemberKeys) MemberKeys {
	return MemberKeys{
		T:     MemberKeysType_User,
		F_1__: &v,
	}
}
func NewMemberKeysWithTeam(v TeamMemberKeys) MemberKeys {
	return MemberKeys{
		T:     MemberKeysType_Team,
		F_2__: &v,
	}
}
func (m MemberKeysInternal__) Import() MemberKeys {
	return MemberKeys{
		T: m.T,
		F_1__: (func(x *UserMemberKeysInternal__) *UserMemberKeys {
			if x == nil {
				return nil
			}
			tmp := (func(x *UserMemberKeysInternal__) (ret UserMemberKeys) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_1__),
		F_2__: (func(x *TeamMemberKeysInternal__) *TeamMemberKeys {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamMemberKeysInternal__) (ret TeamMemberKeys) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_2__),
	}
}
func (m MemberKeys) Export() *MemberKeysInternal__ {
	return &MemberKeysInternal__{
		T: m.T,
		Switch__: MemberKeysInternalSwitch__{
			F_1__: (func(x *UserMemberKeys) *UserMemberKeysInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_1__),
			F_2__: (func(x *TeamMemberKeys) *TeamMemberKeysInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_2__),
		},
	}
}
func (m *MemberKeys) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MemberKeys) Decode(dec rpc.Decoder) error {
	var tmp MemberKeysInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MemberKeys) Bytes() []byte { return nil }

type MemberRole struct {
	DstRole Role
	Member  Member
}
type MemberRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	DstRole *RoleInternal__
	Member  *MemberInternal__
}

func (m MemberRoleInternal__) Import() MemberRole {
	return MemberRole{
		DstRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.DstRole),
		Member: (func(x *MemberInternal__) (ret Member) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Member),
	}
}
func (m MemberRole) Export() *MemberRoleInternal__ {
	return &MemberRoleInternal__{
		DstRole: m.DstRole.Export(),
		Member:  m.Member.Export(),
	}
}
func (m *MemberRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MemberRole) Decode(dec rpc.Decoder) error {
	var tmp MemberRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MemberRole) Bytes() []byte { return nil }

type MemberRoleSeqno struct {
	Mr    MemberRole
	Seqno Seqno
	Time  Time
}
type MemberRoleSeqnoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Mr      *MemberRoleInternal__
	Seqno   *SeqnoInternal__
	Time    *TimeInternal__
}

func (m MemberRoleSeqnoInternal__) Import() MemberRoleSeqno {
	return MemberRoleSeqno{
		Mr: (func(x *MemberRoleInternal__) (ret MemberRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Mr),
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Seqno),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Time),
	}
}
func (m MemberRoleSeqno) Export() *MemberRoleSeqnoInternal__ {
	return &MemberRoleSeqnoInternal__{
		Mr:    m.Mr.Export(),
		Seqno: m.Seqno.Export(),
		Time:  m.Time.Export(),
	}
}
func (m *MemberRoleSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MemberRoleSeqno) Decode(dec rpc.Decoder) error {
	var tmp MemberRoleSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MemberRoleSeqno) Bytes() []byte { return nil }

type Member struct {
	Id      FQEntityInHostScope
	SrcRole Role
	Keys    MemberKeys
}
type MemberInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *FQEntityInHostScopeInternal__
	SrcRole *RoleInternal__
	Keys    *MemberKeysInternal__
}

func (m MemberInternal__) Import() Member {
	return Member{
		Id: (func(x *FQEntityInHostScopeInternal__) (ret FQEntityInHostScope) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Id),
		SrcRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.SrcRole),
		Keys: (func(x *MemberKeysInternal__) (ret MemberKeys) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Keys),
	}
}
func (m Member) Export() *MemberInternal__ {
	return &MemberInternal__{
		Id:      m.Id.Export(),
		SrcRole: m.SrcRole.Export(),
		Keys:    m.Keys.Export(),
	}
}
func (m *Member) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *Member) Decode(dec rpc.Decoder) error {
	var tmp MemberInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *Member) Bytes() []byte { return nil }

type SharedKey struct {
	Gen       Generation
	Role      Role
	VerifyKey EntityID
	HepkFp    HEPKFingerprint
}
type SharedKeyInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen       *GenerationInternal__
	Role      *RoleInternal__
	VerifyKey *EntityIDInternal__
	HepkFp    *HEPKFingerprintInternal__
}

func (s SharedKeyInternal__) Import() SharedKey {
	return SharedKey{
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Gen),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
		VerifyKey: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.VerifyKey),
		HepkFp: (func(x *HEPKFingerprintInternal__) (ret HEPKFingerprint) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.HepkFp),
	}
}
func (s SharedKey) Export() *SharedKeyInternal__ {
	return &SharedKeyInternal__{
		Gen:       s.Gen.Export(),
		Role:      s.Role.Export(),
		VerifyKey: s.VerifyKey.Export(),
		HepkFp:    s.HepkFp.Export(),
	}
}
func (s *SharedKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKey) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKey) Bytes() []byte { return nil }

type SharedKeyAndHEPK struct {
	Sk   SharedKey
	Hepk HEPK
}
type SharedKeyAndHEPKInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sk      *SharedKeyInternal__
	Hepk    *HEPKInternal__
}

func (s SharedKeyAndHEPKInternal__) Import() SharedKeyAndHEPK {
	return SharedKeyAndHEPK{
		Sk: (func(x *SharedKeyInternal__) (ret SharedKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sk),
		Hepk: (func(x *HEPKInternal__) (ret HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Hepk),
	}
}
func (s SharedKeyAndHEPK) Export() *SharedKeyAndHEPKInternal__ {
	return &SharedKeyAndHEPKInternal__{
		Sk:   s.Sk.Export(),
		Hepk: s.Hepk.Export(),
	}
}
func (s *SharedKeyAndHEPK) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyAndHEPK) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyAndHEPKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyAndHEPK) Bytes() []byte { return nil }

type KeyOwner struct {
	Party   PartyID
	SrcRole Role
}
type KeyOwnerInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Party   *PartyIDInternal__
	SrcRole *RoleInternal__
}

func (k KeyOwnerInternal__) Import() KeyOwner {
	return KeyOwner{
		Party: (func(x *PartyIDInternal__) (ret PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Party),
		SrcRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SrcRole),
	}
}
func (k KeyOwner) Export() *KeyOwnerInternal__ {
	return &KeyOwnerInternal__{
		Party:   k.Party.Export(),
		SrcRole: k.SrcRole.Export(),
	}
}
func (k *KeyOwner) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyOwner) Decode(dec rpc.Decoder) error {
	var tmp KeyOwnerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeyOwner) Bytes() []byte { return nil }

type GroupChangeSigner struct {
	Key      EntityID
	KeyOwner *KeyOwner
}
type GroupChangeSignerInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key      *EntityIDInternal__
	KeyOwner *KeyOwnerInternal__
}

func (g GroupChangeSignerInternal__) Import() GroupChangeSigner {
	return GroupChangeSigner{
		Key: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Key),
		KeyOwner: (func(x *KeyOwnerInternal__) *KeyOwner {
			if x == nil {
				return nil
			}
			tmp := (func(x *KeyOwnerInternal__) (ret KeyOwner) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.KeyOwner),
	}
}
func (g GroupChangeSigner) Export() *GroupChangeSignerInternal__ {
	return &GroupChangeSignerInternal__{
		Key: g.Key.Export(),
		KeyOwner: (func(x *KeyOwner) *KeyOwnerInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.KeyOwner),
	}
}
func (g *GroupChangeSigner) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GroupChangeSigner) Decode(dec rpc.Decoder) error {
	var tmp GroupChangeSignerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GroupChangeSigner) Bytes() []byte { return nil }

type GroupChange struct {
	Chainer       HidingChainer
	Entity        FQEntity
	Signer        GroupChangeSigner
	Changes       []MemberRole
	SharedKeys    []SharedKey
	Metadata      []ChangeMetadata
	LocationVRFID *LocationVRFID
}
type GroupChangeInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chainer       *HidingChainerInternal__
	Entity        *FQEntityInternal__
	Signer        *GroupChangeSignerInternal__
	Changes       *[](*MemberRoleInternal__)
	Deprecated4   *struct{}
	SharedKeys    *[](*SharedKeyInternal__)
	Metadata      *[](*ChangeMetadataInternal__)
	LocationVRFID *LocationVRFIDInternal__
}

func (g GroupChangeInternal__) Import() GroupChange {
	return GroupChange{
		Chainer: (func(x *HidingChainerInternal__) (ret HidingChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Chainer),
		Entity: (func(x *FQEntityInternal__) (ret FQEntity) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Entity),
		Signer: (func(x *GroupChangeSignerInternal__) (ret GroupChangeSigner) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Signer),
		Changes: (func(x *[](*MemberRoleInternal__)) (ret []MemberRole) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]MemberRole, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *MemberRoleInternal__) (ret MemberRole) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Changes),
		SharedKeys: (func(x *[](*SharedKeyInternal__)) (ret []SharedKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SharedKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SharedKeyInternal__) (ret SharedKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.SharedKeys),
		Metadata: (func(x *[](*ChangeMetadataInternal__)) (ret []ChangeMetadata) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]ChangeMetadata, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *ChangeMetadataInternal__) (ret ChangeMetadata) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Metadata),
		LocationVRFID: (func(x *LocationVRFIDInternal__) *LocationVRFID {
			if x == nil {
				return nil
			}
			tmp := (func(x *LocationVRFIDInternal__) (ret LocationVRFID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.LocationVRFID),
	}
}
func (g GroupChange) Export() *GroupChangeInternal__ {
	return &GroupChangeInternal__{
		Chainer: g.Chainer.Export(),
		Entity:  g.Entity.Export(),
		Signer:  g.Signer.Export(),
		Changes: (func(x []MemberRole) *[](*MemberRoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*MemberRoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Changes),
		SharedKeys: (func(x []SharedKey) *[](*SharedKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SharedKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.SharedKeys),
		Metadata: (func(x []ChangeMetadata) *[](*ChangeMetadataInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*ChangeMetadataInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Metadata),
		LocationVRFID: (func(x *LocationVRFID) *LocationVRFIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.LocationVRFID),
	}
}
func (g *GroupChange) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GroupChange) Decode(dec rpc.Decoder) error {
	var tmp GroupChangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

var GroupChangeTypeUniqueID = rpc.TypeUniqueID(0x8fbf37f586b0bc6e)

func (g *GroupChange) GetTypeUniqueID() rpc.TypeUniqueID {
	return GroupChangeTypeUniqueID
}
func (g *GroupChange) Bytes() []byte { return nil }

type GenericLink struct {
	Chainer HidingChainer
	Entity  FQEntity
	Signer  FQEntityInHostScope
	Payload GenericLinkPayload
}
type GenericLinkInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chainer *HidingChainerInternal__
	Entity  *FQEntityInternal__
	Signer  *FQEntityInHostScopeInternal__
	Payload *GenericLinkPayloadInternal__
}

func (g GenericLinkInternal__) Import() GenericLink {
	return GenericLink{
		Chainer: (func(x *HidingChainerInternal__) (ret HidingChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Chainer),
		Entity: (func(x *FQEntityInternal__) (ret FQEntity) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Entity),
		Signer: (func(x *FQEntityInHostScopeInternal__) (ret FQEntityInHostScope) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Signer),
		Payload: (func(x *GenericLinkPayloadInternal__) (ret GenericLinkPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Payload),
	}
}
func (g GenericLink) Export() *GenericLinkInternal__ {
	return &GenericLinkInternal__{
		Chainer: g.Chainer.Export(),
		Entity:  g.Entity.Export(),
		Signer:  g.Signer.Export(),
		Payload: g.Payload.Export(),
	}
}
func (g *GenericLink) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GenericLink) Decode(dec rpc.Decoder) error {
	var tmp GenericLinkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

var GenericLinkTypeUniqueID = rpc.TypeUniqueID(0xa23314d66e6e04f9)

func (g *GenericLink) GetTypeUniqueID() rpc.TypeUniqueID {
	return GenericLinkTypeUniqueID
}
func (g *GenericLink) Bytes() []byte { return nil }

type LinkType int

const (
	LinkType_GROUP_CHANGE LinkType = 1
	LinkType_GENERIC      LinkType = 2
)

var LinkTypeMap = map[string]LinkType{
	"GROUP_CHANGE": 1,
	"GENERIC":      2,
}
var LinkTypeRevMap = map[LinkType]string{
	1: "GROUP_CHANGE",
	2: "GENERIC",
}

type LinkTypeInternal__ LinkType

func (l LinkTypeInternal__) Import() LinkType {
	return LinkType(l)
}
func (l LinkType) Export() *LinkTypeInternal__ {
	return ((*LinkTypeInternal__)(&l))
}

type LinkInner struct {
	T     LinkType
	F_0__ *GroupChange `json:"f0,omitempty"`
	F_1__ *GenericLink `json:"f1,omitempty"`
}
type LinkInnerInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        LinkType
	Switch__ LinkInnerInternalSwitch__
}
type LinkInnerInternalSwitch__ struct {
	_struct struct{}               `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *GroupChangeInternal__ `codec:"0"`
	F_1__   *GenericLinkInternal__ `codec:"1"`
}

func (l LinkInner) GetT() (ret LinkType, err error) {
	switch l.T {
	case LinkType_GROUP_CHANGE:
		if l.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case LinkType_GENERIC:
		if l.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return l.T, nil
}
func (l LinkInner) GroupChange() GroupChange {
	if l.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if l.T != LinkType_GROUP_CHANGE {
		panic(fmt.Sprintf("unexpected switch value (%v) when GroupChange is called", l.T))
	}
	return *l.F_0__
}
func (l LinkInner) Generic() GenericLink {
	if l.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if l.T != LinkType_GENERIC {
		panic(fmt.Sprintf("unexpected switch value (%v) when Generic is called", l.T))
	}
	return *l.F_1__
}
func NewLinkInnerWithGroupChange(v GroupChange) LinkInner {
	return LinkInner{
		T:     LinkType_GROUP_CHANGE,
		F_0__: &v,
	}
}
func NewLinkInnerWithGeneric(v GenericLink) LinkInner {
	return LinkInner{
		T:     LinkType_GENERIC,
		F_1__: &v,
	}
}
func (l LinkInnerInternal__) Import() LinkInner {
	return LinkInner{
		T: l.T,
		F_0__: (func(x *GroupChangeInternal__) *GroupChange {
			if x == nil {
				return nil
			}
			tmp := (func(x *GroupChangeInternal__) (ret GroupChange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_0__),
		F_1__: (func(x *GenericLinkInternal__) *GenericLink {
			if x == nil {
				return nil
			}
			tmp := (func(x *GenericLinkInternal__) (ret GenericLink) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_1__),
	}
}
func (l LinkInner) Export() *LinkInnerInternal__ {
	return &LinkInnerInternal__{
		T: l.T,
		Switch__: LinkInnerInternalSwitch__{
			F_0__: (func(x *GroupChange) *GroupChangeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_0__),
			F_1__: (func(x *GenericLink) *GenericLinkInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_1__),
		},
	}
}
func (l *LinkInner) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LinkInner) Decode(dec rpc.Decoder) error {
	var tmp LinkInnerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

var LinkInnerTypeUniqueID = rpc.TypeUniqueID(0xacf9066572a9e7de)

func (l *LinkInner) GetTypeUniqueID() rpc.TypeUniqueID {
	return LinkInnerTypeUniqueID
}
func (l *LinkInner) Bytes() []byte { return nil }

type LinkInnerBlob []byte
type LinkInnerBlobInternal__ []byte

func (l LinkInnerBlob) Export() *LinkInnerBlobInternal__ {
	tmp := (([]byte)(l))
	return ((*LinkInnerBlobInternal__)(&tmp))
}
func (l LinkInnerBlobInternal__) Import() LinkInnerBlob {
	tmp := ([]byte)(l)
	return LinkInnerBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (l *LinkInnerBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LinkInnerBlob) Decode(dec rpc.Decoder) error {
	var tmp LinkInnerBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LinkInnerBlob) Bytes() []byte {
	return (l)[:]
}
func (l *LinkInnerBlob) AllocAndDecode(f rpc.DecoderFactory) (*LinkInner, error) {
	var ret LinkInner
	src := f.NewDecoderBytes(&ret, l.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}
func (l *LinkInnerBlob) AssertNormalized() error { return nil }
func (l *LinkInner) EncodeTyped(f rpc.EncoderFactory) (*LinkInnerBlob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := l.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := LinkInnerBlob(tmp)
	return &ret, nil
}
func (l *LinkInner) ChildBlob(__b []byte) LinkInnerBlob {
	return LinkInnerBlob(__b)
}

type LinkVersion int

const (
	LinkVersion_V1 LinkVersion = 1
)

var LinkVersionMap = map[string]LinkVersion{
	"V1": 1,
}
var LinkVersionRevMap = map[LinkVersion]string{
	1: "V1",
}

type LinkVersionInternal__ LinkVersion

func (l LinkVersionInternal__) Import() LinkVersion {
	return LinkVersion(l)
}
func (l LinkVersion) Export() *LinkVersionInternal__ {
	return ((*LinkVersionInternal__)(&l))
}

type LinkOuterV1 struct {
	Inner      LinkInnerBlob
	Signatures []Signature
}
type LinkOuterV1Internal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner      *LinkInnerBlobInternal__
	Signatures *[](*SignatureInternal__)
}

func (l LinkOuterV1Internal__) Import() LinkOuterV1 {
	return LinkOuterV1{
		Inner: (func(x *LinkInnerBlobInternal__) (ret LinkInnerBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Inner),
		Signatures: (func(x *[](*SignatureInternal__)) (ret []Signature) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]Signature, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SignatureInternal__) (ret Signature) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(l.Signatures),
	}
}
func (l LinkOuterV1) Export() *LinkOuterV1Internal__ {
	return &LinkOuterV1Internal__{
		Inner: l.Inner.Export(),
		Signatures: (func(x []Signature) *[](*SignatureInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SignatureInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(l.Signatures),
	}
}
func (l *LinkOuterV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LinkOuterV1) Decode(dec rpc.Decoder) error {
	var tmp LinkOuterV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

var LinkOuterV1TypeUniqueID = rpc.TypeUniqueID(0xc2745284af617745)

func (l *LinkOuterV1) GetTypeUniqueID() rpc.TypeUniqueID {
	return LinkOuterV1TypeUniqueID
}
func (l *LinkOuterV1) Bytes() []byte { return nil }

type ChangeType int

const (
	ChangeType_DeviceName     ChangeType = 0
	ChangeType_Username       ChangeType = 1
	ChangeType_Eldest         ChangeType = 2
	ChangeType_Teamname       ChangeType = 3
	ChangeType_TeamIndexRange ChangeType = 4
)

var ChangeTypeMap = map[string]ChangeType{
	"DeviceName":     0,
	"Username":       1,
	"Eldest":         2,
	"Teamname":       3,
	"TeamIndexRange": 4,
}
var ChangeTypeRevMap = map[ChangeType]string{
	0: "DeviceName",
	1: "Username",
	2: "Eldest",
	3: "Teamname",
	4: "TeamIndexRange",
}

type ChangeTypeInternal__ ChangeType

func (c ChangeTypeInternal__) Import() ChangeType {
	return ChangeType(c)
}
func (c ChangeType) Export() *ChangeTypeInternal__ {
	return ((*ChangeTypeInternal__)(&c))
}

type DeviceType int

const (
	DeviceType_Computer DeviceType = 0
	DeviceType_Mobile   DeviceType = 1
	DeviceType_YubiKey  DeviceType = 2
	DeviceType_Backup   DeviceType = 3
)

var DeviceTypeMap = map[string]DeviceType{
	"Computer": 0,
	"Mobile":   1,
	"YubiKey":  2,
	"Backup":   3,
}
var DeviceTypeRevMap = map[DeviceType]string{
	0: "Computer",
	1: "Mobile",
	2: "YubiKey",
	3: "Backup",
}

type DeviceTypeInternal__ DeviceType

func (d DeviceTypeInternal__) Import() DeviceType {
	return DeviceType(d)
}
func (d DeviceType) Export() *DeviceTypeInternal__ {
	return ((*DeviceTypeInternal__)(&d))
}

type SharedKeySeed struct {
	Fqe  FQEntity
	Gen  Generation
	Role Role
	Seed SecretSeed32
}
type SharedKeySeedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqe     *FQEntityInternal__
	Gen     *GenerationInternal__
	Role    *RoleInternal__
	Seed    *SecretSeed32Internal__
}

func (s SharedKeySeedInternal__) Import() SharedKeySeed {
	return SharedKeySeed{
		Fqe: (func(x *FQEntityInternal__) (ret FQEntity) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqe),
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Gen),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
		Seed: (func(x *SecretSeed32Internal__) (ret SecretSeed32) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
	}
}
func (s SharedKeySeed) Export() *SharedKeySeedInternal__ {
	return &SharedKeySeedInternal__{
		Fqe:  s.Fqe.Export(),
		Gen:  s.Gen.Export(),
		Role: s.Role.Export(),
		Seed: s.Seed.Export(),
	}
}
func (s *SharedKeySeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeySeed) Decode(dec rpc.Decoder) error {
	var tmp SharedKeySeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SharedKeySeedTypeUniqueID = rpc.TypeUniqueID(0xa9998e7a59e8ae25)

func (s *SharedKeySeed) GetTypeUniqueID() rpc.TypeUniqueID {
	return SharedKeySeedTypeUniqueID
}
func (s *SharedKeySeed) Bytes() []byte { return nil }

type SubkeySeed struct {
	Parent EntityID
	Subkey EntityID
	Seed   SecretSeed32
}
type SubkeySeedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Parent  *EntityIDInternal__
	Subkey  *EntityIDInternal__
	Seed    *SecretSeed32Internal__
}

func (s SubkeySeedInternal__) Import() SubkeySeed {
	return SubkeySeed{
		Parent: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Parent),
		Subkey: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Subkey),
		Seed: (func(x *SecretSeed32Internal__) (ret SecretSeed32) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
	}
}
func (s SubkeySeed) Export() *SubkeySeedInternal__ {
	return &SubkeySeedInternal__{
		Parent: s.Parent.Export(),
		Subkey: s.Subkey.Export(),
		Seed:   s.Seed.Export(),
	}
}
func (s *SubkeySeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SubkeySeed) Decode(dec rpc.Decoder) error {
	var tmp SubkeySeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SubkeySeedTypeUniqueID = rpc.TypeUniqueID(0x9bfca0e8fc32288f)

func (s *SubkeySeed) GetTypeUniqueID() rpc.TypeUniqueID {
	return SubkeySeedTypeUniqueID
}
func (s *SubkeySeed) Bytes() []byte { return nil }

type EldestMetadata struct {
	SubchainTreeLocationSeedCommitment TreeLocationCommitment
}
type EldestMetadataInternal__ struct {
	_struct                            struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SubchainTreeLocationSeedCommitment *TreeLocationCommitmentInternal__
}

func (e EldestMetadataInternal__) Import() EldestMetadata {
	return EldestMetadata{
		SubchainTreeLocationSeedCommitment: (func(x *TreeLocationCommitmentInternal__) (ret TreeLocationCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.SubchainTreeLocationSeedCommitment),
	}
}
func (e EldestMetadata) Export() *EldestMetadataInternal__ {
	return &EldestMetadataInternal__{
		SubchainTreeLocationSeedCommitment: e.SubchainTreeLocationSeedCommitment.Export(),
	}
}
func (e *EldestMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EldestMetadata) Decode(dec rpc.Decoder) error {
	var tmp EldestMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e *EldestMetadata) Bytes() []byte { return nil }

type Commitment HMAC
type CommitmentInternal__ HMACInternal__

func (c Commitment) Export() *CommitmentInternal__ {
	tmp := ((HMAC)(c))
	return ((*CommitmentInternal__)(tmp.Export()))
}
func (c CommitmentInternal__) Import() Commitment {
	tmp := (HMACInternal__)(c)
	return Commitment((func(x *HMACInternal__) (ret HMAC) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (c *Commitment) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Commitment) Decode(dec rpc.Decoder) error {
	var tmp CommitmentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c Commitment) Bytes() []byte {
	return ((HMAC)(c)).Bytes()
}

type ChangeMetadata struct {
	T     ChangeType
	F_0__ *Commitment     `json:"f0,omitempty"`
	F_1__ *EldestMetadata `json:"f1,omitempty"`
	F_2__ *RationalRange  `json:"f2,omitempty"`
}
type ChangeMetadataInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        ChangeType
	Switch__ ChangeMetadataInternalSwitch__
}
type ChangeMetadataInternalSwitch__ struct {
	_struct struct{}                  `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *CommitmentInternal__     `codec:"0"`
	F_1__   *EldestMetadataInternal__ `codec:"1"`
	F_2__   *RationalRangeInternal__  `codec:"2"`
}

func (c ChangeMetadata) GetT() (ret ChangeType, err error) {
	switch c.T {
	case ChangeType_DeviceName, ChangeType_Username, ChangeType_Teamname:
		if c.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case ChangeType_Eldest:
		if c.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case ChangeType_TeamIndexRange:
		if c.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return c.T, nil
}
func (c ChangeMetadata) Devicename() Commitment {
	if c.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChangeType_DeviceName {
		panic(fmt.Sprintf("unexpected switch value (%v) when Devicename is called", c.T))
	}
	return *c.F_0__
}
func (c ChangeMetadata) Username() Commitment {
	if c.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChangeType_Username {
		panic(fmt.Sprintf("unexpected switch value (%v) when Username is called", c.T))
	}
	return *c.F_0__
}
func (c ChangeMetadata) Teamname() Commitment {
	if c.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChangeType_Teamname {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teamname is called", c.T))
	}
	return *c.F_0__
}
func (c ChangeMetadata) Eldest() EldestMetadata {
	if c.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChangeType_Eldest {
		panic(fmt.Sprintf("unexpected switch value (%v) when Eldest is called", c.T))
	}
	return *c.F_1__
}
func (c ChangeMetadata) Teamindexrange() RationalRange {
	if c.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChangeType_TeamIndexRange {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teamindexrange is called", c.T))
	}
	return *c.F_2__
}
func NewChangeMetadataWithDevicename(v Commitment) ChangeMetadata {
	return ChangeMetadata{
		T:     ChangeType_DeviceName,
		F_0__: &v,
	}
}
func NewChangeMetadataWithUsername(v Commitment) ChangeMetadata {
	return ChangeMetadata{
		T:     ChangeType_Username,
		F_0__: &v,
	}
}
func NewChangeMetadataWithTeamname(v Commitment) ChangeMetadata {
	return ChangeMetadata{
		T:     ChangeType_Teamname,
		F_0__: &v,
	}
}
func NewChangeMetadataWithEldest(v EldestMetadata) ChangeMetadata {
	return ChangeMetadata{
		T:     ChangeType_Eldest,
		F_1__: &v,
	}
}
func NewChangeMetadataWithTeamindexrange(v RationalRange) ChangeMetadata {
	return ChangeMetadata{
		T:     ChangeType_TeamIndexRange,
		F_2__: &v,
	}
}
func (c ChangeMetadataInternal__) Import() ChangeMetadata {
	return ChangeMetadata{
		T: c.T,
		F_0__: (func(x *CommitmentInternal__) *Commitment {
			if x == nil {
				return nil
			}
			tmp := (func(x *CommitmentInternal__) (ret Commitment) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_0__),
		F_1__: (func(x *EldestMetadataInternal__) *EldestMetadata {
			if x == nil {
				return nil
			}
			tmp := (func(x *EldestMetadataInternal__) (ret EldestMetadata) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_1__),
		F_2__: (func(x *RationalRangeInternal__) *RationalRange {
			if x == nil {
				return nil
			}
			tmp := (func(x *RationalRangeInternal__) (ret RationalRange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_2__),
	}
}
func (c ChangeMetadata) Export() *ChangeMetadataInternal__ {
	return &ChangeMetadataInternal__{
		T: c.T,
		Switch__: ChangeMetadataInternalSwitch__{
			F_0__: (func(x *Commitment) *CommitmentInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_0__),
			F_1__: (func(x *EldestMetadata) *EldestMetadataInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_1__),
			F_2__: (func(x *RationalRange) *RationalRangeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_2__),
		},
	}
}
func (c *ChangeMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChangeMetadata) Decode(dec rpc.Decoder) error {
	var tmp ChangeMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChangeMetadata) Bytes() []byte { return nil }

type LinkOuter struct {
	V     LinkVersion
	F_1__ *LinkOuterV1 `json:"f1,omitempty"`
}
type LinkOuterInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        LinkVersion
	Switch__ LinkOuterInternalSwitch__
}
type LinkOuterInternalSwitch__ struct {
	_struct struct{}               `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *LinkOuterV1Internal__ `codec:"1"`
}

func (l LinkOuter) GetV() (ret LinkVersion, err error) {
	switch l.V {
	case LinkVersion_V1:
		if l.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return l.V, nil
}
func (l LinkOuter) V1() LinkOuterV1 {
	if l.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if l.V != LinkVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", l.V))
	}
	return *l.F_1__
}
func NewLinkOuterWithV1(v LinkOuterV1) LinkOuter {
	return LinkOuter{
		V:     LinkVersion_V1,
		F_1__: &v,
	}
}
func (l LinkOuterInternal__) Import() LinkOuter {
	return LinkOuter{
		V: l.V,
		F_1__: (func(x *LinkOuterV1Internal__) *LinkOuterV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *LinkOuterV1Internal__) (ret LinkOuterV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_1__),
	}
}
func (l LinkOuter) Export() *LinkOuterInternal__ {
	return &LinkOuterInternal__{
		V: l.V,
		Switch__: LinkOuterInternalSwitch__{
			F_1__: (func(x *LinkOuterV1) *LinkOuterV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_1__),
		},
	}
}
func (l *LinkOuter) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LinkOuter) Decode(dec rpc.Decoder) error {
	var tmp LinkOuterInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

var LinkOuterTypeUniqueID = rpc.TypeUniqueID(0xed4cc0f7081732b6)

func (l *LinkOuter) GetTypeUniqueID() rpc.TypeUniqueID {
	return LinkOuterTypeUniqueID
}
func (l *LinkOuter) Bytes() []byte { return nil }

type GenericLinkPayload struct {
	T     ChainType
	F_0__ *UserSettingsLink   `json:"f0,omitempty"`
	F_1__ *TeamMembershipLink `json:"f1,omitempty"`
}
type GenericLinkPayloadInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        ChainType
	Switch__ GenericLinkPayloadInternalSwitch__
}
type GenericLinkPayloadInternalSwitch__ struct {
	_struct struct{}                      `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *UserSettingsLinkInternal__   `codec:"0"`
	F_1__   *TeamMembershipLinkInternal__ `codec:"1"`
}

func (g GenericLinkPayload) GetT() (ret ChainType, err error) {
	switch g.T {
	case ChainType_UserSettings:
		if g.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case ChainType_TeamMembership:
		if g.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	default:
		break
	}
	return g.T, nil
}
func (g GenericLinkPayload) Usersettings() UserSettingsLink {
	if g.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if g.T != ChainType_UserSettings {
		panic(fmt.Sprintf("unexpected switch value (%v) when Usersettings is called", g.T))
	}
	return *g.F_0__
}
func (g GenericLinkPayload) Teammembership() TeamMembershipLink {
	if g.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if g.T != ChainType_TeamMembership {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teammembership is called", g.T))
	}
	return *g.F_1__
}
func NewGenericLinkPayloadWithUsersettings(v UserSettingsLink) GenericLinkPayload {
	return GenericLinkPayload{
		T:     ChainType_UserSettings,
		F_0__: &v,
	}
}
func NewGenericLinkPayloadWithTeammembership(v TeamMembershipLink) GenericLinkPayload {
	return GenericLinkPayload{
		T:     ChainType_TeamMembership,
		F_1__: &v,
	}
}
func NewGenericLinkPayloadDefault(s ChainType) GenericLinkPayload {
	return GenericLinkPayload{
		T: s,
	}
}
func (g GenericLinkPayloadInternal__) Import() GenericLinkPayload {
	return GenericLinkPayload{
		T: g.T,
		F_0__: (func(x *UserSettingsLinkInternal__) *UserSettingsLink {
			if x == nil {
				return nil
			}
			tmp := (func(x *UserSettingsLinkInternal__) (ret UserSettingsLink) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Switch__.F_0__),
		F_1__: (func(x *TeamMembershipLinkInternal__) *TeamMembershipLink {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamMembershipLinkInternal__) (ret TeamMembershipLink) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Switch__.F_1__),
	}
}
func (g GenericLinkPayload) Export() *GenericLinkPayloadInternal__ {
	return &GenericLinkPayloadInternal__{
		T: g.T,
		Switch__: GenericLinkPayloadInternalSwitch__{
			F_0__: (func(x *UserSettingsLink) *UserSettingsLinkInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(g.F_0__),
			F_1__: (func(x *TeamMembershipLink) *TeamMembershipLinkInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(g.F_1__),
		},
	}
}
func (g *GenericLinkPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GenericLinkPayload) Decode(dec rpc.Decoder) error {
	var tmp GenericLinkPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

var GenericLinkPayloadTypeUniqueID = rpc.TypeUniqueID(0xfc82ed34909b2f4c)

func (g *GenericLinkPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return GenericLinkPayloadTypeUniqueID
}
func (g *GenericLinkPayload) Bytes() []byte { return nil }

type SharedKeyGen struct {
	Role Role
	Gen  Generation
}
type SharedKeyGenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *RoleInternal__
	Gen     *GenerationInternal__
}

func (s SharedKeyGenInternal__) Import() SharedKeyGen {
	return SharedKeyGen{
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Gen),
	}
}
func (s SharedKeyGen) Export() *SharedKeyGenInternal__ {
	return &SharedKeyGenInternal__{
		Role: s.Role.Export(),
		Gen:  s.Gen.Export(),
	}
}
func (s *SharedKeyGen) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyGen) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyGenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyGen) Bytes() []byte { return nil }

type UserSettingsLink struct {
	T     UserSettingsType
	F_0__ *PassphraseInfo `json:"f0,omitempty"`
}
type UserSettingsLinkInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        UserSettingsType
	Switch__ UserSettingsLinkInternalSwitch__
}
type UserSettingsLinkInternalSwitch__ struct {
	_struct struct{}                  `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *PassphraseInfoInternal__ `codec:"0"`
}

func (u UserSettingsLink) GetT() (ret UserSettingsType, err error) {
	switch u.T {
	case UserSettingsType_Passphrase:
		if u.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return u.T, nil
}
func (u UserSettingsLink) Passphrase() PassphraseInfo {
	if u.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != UserSettingsType_Passphrase {
		panic(fmt.Sprintf("unexpected switch value (%v) when Passphrase is called", u.T))
	}
	return *u.F_0__
}
func NewUserSettingsLinkWithPassphrase(v PassphraseInfo) UserSettingsLink {
	return UserSettingsLink{
		T:     UserSettingsType_Passphrase,
		F_0__: &v,
	}
}
func (u UserSettingsLinkInternal__) Import() UserSettingsLink {
	return UserSettingsLink{
		T: u.T,
		F_0__: (func(x *PassphraseInfoInternal__) *PassphraseInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *PassphraseInfoInternal__) (ret PassphraseInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_0__),
	}
}
func (u UserSettingsLink) Export() *UserSettingsLinkInternal__ {
	return &UserSettingsLinkInternal__{
		T: u.T,
		Switch__: UserSettingsLinkInternalSwitch__{
			F_0__: (func(x *PassphraseInfo) *PassphraseInfoInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_0__),
		},
	}
}
func (u *UserSettingsLink) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserSettingsLink) Decode(dec rpc.Decoder) error {
	var tmp UserSettingsLinkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

var UserSettingsLinkTypeUniqueID = rpc.TypeUniqueID(0x99dfb82e9d34cb59)

func (u *UserSettingsLink) GetTypeUniqueID() rpc.TypeUniqueID {
	return UserSettingsLinkTypeUniqueID
}
func (u *UserSettingsLink) Bytes() []byte { return nil }

type RevokeInfo struct {
	Revoker EntityID
	Chain   BaseChainer
}
type RevokeInfoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Revoker *EntityIDInternal__
	Chain   *BaseChainerInternal__
}

func (r RevokeInfoInternal__) Import() RevokeInfo {
	return RevokeInfo{
		Revoker: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Revoker),
		Chain: (func(x *BaseChainerInternal__) (ret BaseChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Chain),
	}
}
func (r RevokeInfo) Export() *RevokeInfoInternal__ {
	return &RevokeInfoInternal__{
		Revoker: r.Revoker.Export(),
		Chain:   r.Chain.Export(),
	}
}
func (r *RevokeInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RevokeInfo) Decode(dec rpc.Decoder) error {
	var tmp RevokeInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RevokeInfo) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(FQPartyTypeUniqueID)
	rpc.AddUnique(GroupChangeTypeUniqueID)
	rpc.AddUnique(GenericLinkTypeUniqueID)
	rpc.AddUnique(LinkInnerTypeUniqueID)
	rpc.AddUnique(LinkOuterV1TypeUniqueID)
	rpc.AddUnique(SharedKeySeedTypeUniqueID)
	rpc.AddUnique(SubkeySeedTypeUniqueID)
	rpc.AddUnique(LinkOuterTypeUniqueID)
	rpc.AddUnique(GenericLinkPayloadTypeUniqueID)
	rpc.AddUnique(UserSettingsLinkTypeUniqueID)
}
