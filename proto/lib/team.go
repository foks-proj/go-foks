// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/team.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type TeamMembershipLinkState int

const (
	TeamMembershipLinkState_None      TeamMembershipLinkState = 0
	TeamMembershipLinkState_Requested TeamMembershipLinkState = 1
	TeamMembershipLinkState_Approved  TeamMembershipLinkState = 2
	TeamMembershipLinkState_Removed   TeamMembershipLinkState = 3
)

var TeamMembershipLinkStateMap = map[string]TeamMembershipLinkState{
	"None":      0,
	"Requested": 1,
	"Approved":  2,
	"Removed":   3,
}

var TeamMembershipLinkStateRevMap = map[TeamMembershipLinkState]string{
	0: "None",
	1: "Requested",
	2: "Approved",
	3: "Removed",
}

type TeamMembershipLinkStateInternal__ TeamMembershipLinkState

func (t TeamMembershipLinkStateInternal__) Import() TeamMembershipLinkState {
	return TeamMembershipLinkState(t)
}

func (t TeamMembershipLinkState) Export() *TeamMembershipLinkStateInternal__ {
	return ((*TeamMembershipLinkStateInternal__)(&t))
}

type KeyCommitment StdHash
type KeyCommitmentInternal__ StdHashInternal__

func (k KeyCommitment) Export() *KeyCommitmentInternal__ {
	tmp := ((StdHash)(k))
	return ((*KeyCommitmentInternal__)(tmp.Export()))
}

func (k KeyCommitmentInternal__) Import() KeyCommitment {
	tmp := (StdHashInternal__)(k)
	return KeyCommitment((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (k *KeyCommitment) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyCommitment) Decode(dec rpc.Decoder) error {
	var tmp KeyCommitmentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KeyCommitment) Bytes() []byte {
	return ((StdHash)(k)).Bytes()
}

type RoleAndSeqno struct {
	Role  Role
	Seqno Seqno
}

type RoleAndSeqnoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *RoleInternal__
	Seqno   *SeqnoInternal__
}

func (r RoleAndSeqnoInternal__) Import() RoleAndSeqno {
	return RoleAndSeqno{
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Role),
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seqno),
	}
}

func (r RoleAndSeqno) Export() *RoleAndSeqnoInternal__ {
	return &RoleAndSeqnoInternal__{
		Role:  r.Role.Export(),
		Seqno: r.Seqno.Export(),
	}
}

func (r *RoleAndSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleAndSeqno) Decode(dec rpc.Decoder) error {
	var tmp RoleAndSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RoleAndSeqno) Bytes() []byte { return nil }

type TeamMembershipApprovedDetails struct {
	Dst     RoleAndSeqno
	KeyComm KeyCommitment
}

type TeamMembershipApprovedDetailsInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Dst     *RoleAndSeqnoInternal__
	KeyComm *KeyCommitmentInternal__
}

func (t TeamMembershipApprovedDetailsInternal__) Import() TeamMembershipApprovedDetails {
	return TeamMembershipApprovedDetails{
		Dst: (func(x *RoleAndSeqnoInternal__) (ret RoleAndSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Dst),
		KeyComm: (func(x *KeyCommitmentInternal__) (ret KeyCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.KeyComm),
	}
}

func (t TeamMembershipApprovedDetails) Export() *TeamMembershipApprovedDetailsInternal__ {
	return &TeamMembershipApprovedDetailsInternal__{
		Dst:     t.Dst.Export(),
		KeyComm: t.KeyComm.Export(),
	}
}

func (t *TeamMembershipApprovedDetails) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMembershipApprovedDetails) Decode(dec rpc.Decoder) error {
	var tmp TeamMembershipApprovedDetailsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMembershipApprovedDetails) Bytes() []byte { return nil }

type TeamMembershipDetails struct {
	T     TeamMembershipLinkState
	F_1__ *TeamMembershipApprovedDetails `json:"f1,omitempty"`
}

type TeamMembershipDetailsInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        TeamMembershipLinkState
	Switch__ TeamMembershipDetailsInternalSwitch__
}

type TeamMembershipDetailsInternalSwitch__ struct {
	_struct struct{}                                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *TeamMembershipApprovedDetailsInternal__ `codec:"1"`
}

func (t TeamMembershipDetails) GetT() (ret TeamMembershipLinkState, err error) {
	switch t.T {
	case TeamMembershipLinkState_Approved:
		if t.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	default:
		break
	}
	return t.T, nil
}

func (t TeamMembershipDetails) Approved() TeamMembershipApprovedDetails {
	if t.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.T != TeamMembershipLinkState_Approved {
		panic(fmt.Sprintf("unexpected switch value (%v) when Approved is called", t.T))
	}
	return *t.F_1__
}

func NewTeamMembershipDetailsWithApproved(v TeamMembershipApprovedDetails) TeamMembershipDetails {
	return TeamMembershipDetails{
		T:     TeamMembershipLinkState_Approved,
		F_1__: &v,
	}
}

func NewTeamMembershipDetailsDefault(s TeamMembershipLinkState) TeamMembershipDetails {
	return TeamMembershipDetails{
		T: s,
	}
}

func (t TeamMembershipDetailsInternal__) Import() TeamMembershipDetails {
	return TeamMembershipDetails{
		T: t.T,
		F_1__: (func(x *TeamMembershipApprovedDetailsInternal__) *TeamMembershipApprovedDetails {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamMembershipApprovedDetailsInternal__) (ret TeamMembershipApprovedDetails) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_1__),
	}
}

func (t TeamMembershipDetails) Export() *TeamMembershipDetailsInternal__ {
	return &TeamMembershipDetailsInternal__{
		T: t.T,
		Switch__: TeamMembershipDetailsInternalSwitch__{
			F_1__: (func(x *TeamMembershipApprovedDetails) *TeamMembershipApprovedDetailsInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_1__),
		},
	}
}

func (t *TeamMembershipDetails) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMembershipDetails) Decode(dec rpc.Decoder) error {
	var tmp TeamMembershipDetailsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMembershipDetails) Bytes() []byte { return nil }

type TeamMembershipLink struct {
	Team    FQTeam
	SrcRole Role
	State   TeamMembershipDetails
}

type TeamMembershipLinkInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *FQTeamInternal__
	SrcRole *RoleInternal__
	State   *TeamMembershipDetailsInternal__
}

func (t TeamMembershipLinkInternal__) Import() TeamMembershipLink {
	return TeamMembershipLink{
		Team: (func(x *FQTeamInternal__) (ret FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		SrcRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		State: (func(x *TeamMembershipDetailsInternal__) (ret TeamMembershipDetails) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.State),
	}
}

func (t TeamMembershipLink) Export() *TeamMembershipLinkInternal__ {
	return &TeamMembershipLinkInternal__{
		Team:    t.Team.Export(),
		SrcRole: t.SrcRole.Export(),
		State:   t.State.Export(),
	}
}

func (t *TeamMembershipLink) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMembershipLink) Decode(dec rpc.Decoder) error {
	var tmp TeamMembershipLinkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMembershipLink) Bytes() []byte { return nil }

type FQTeam struct {
	Team TeamID
	Host HostID
}

type FQTeamInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *TeamIDInternal__
	Host    *HostIDInternal__
}

func (f FQTeamInternal__) Import() FQTeam {
	return FQTeam{
		Team: (func(x *TeamIDInternal__) (ret TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Team),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
	}
}

func (f FQTeam) Export() *FQTeamInternal__ {
	return &FQTeamInternal__{
		Team: f.Team.Export(),
		Host: f.Host.Export(),
	}
}

func (f *FQTeam) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQTeam) Decode(dec rpc.Decoder) error {
	var tmp FQTeamInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQTeam) Bytes() []byte { return nil }

type TeamRemoteMemberViewTokenBoxPayload struct {
	Tok   PermissionToken
	Party FQParty
	Tm    Time
}

type TeamRemoteMemberViewTokenBoxPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *PermissionTokenInternal__
	Party   *FQPartyInternal__
	Tm      *TimeInternal__
}

func (t TeamRemoteMemberViewTokenBoxPayloadInternal__) Import() TeamRemoteMemberViewTokenBoxPayload {
	return TeamRemoteMemberViewTokenBoxPayload{
		Tok: (func(x *PermissionTokenInternal__) (ret PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Party: (func(x *FQPartyInternal__) (ret FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Party),
		Tm: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tm),
	}
}

func (t TeamRemoteMemberViewTokenBoxPayload) Export() *TeamRemoteMemberViewTokenBoxPayloadInternal__ {
	return &TeamRemoteMemberViewTokenBoxPayloadInternal__{
		Tok:   t.Tok.Export(),
		Party: t.Party.Export(),
		Tm:    t.Tm.Export(),
	}
}

func (t *TeamRemoteMemberViewTokenBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteMemberViewTokenBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteMemberViewTokenBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamRemoteMemberViewTokenBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0xb869945e21b2d379)

func (t *TeamRemoteMemberViewTokenBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamRemoteMemberViewTokenBoxPayloadTypeUniqueID
}

func (t *TeamRemoteMemberViewTokenBoxPayload) Bytes() []byte { return nil }

type TeamRemoteMemberViewToken struct {
	Team  TeamID
	Inner TeamRemoteMemberViewTokenInner
	Jrt   TeamRSVPRemote
}

type TeamRemoteMemberViewTokenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *TeamIDInternal__
	Inner   *TeamRemoteMemberViewTokenInnerInternal__
	Jrt     *TeamRSVPRemoteInternal__
}

func (t TeamRemoteMemberViewTokenInternal__) Import() TeamRemoteMemberViewToken {
	return TeamRemoteMemberViewToken{
		Team: (func(x *TeamIDInternal__) (ret TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Inner: (func(x *TeamRemoteMemberViewTokenInnerInternal__) (ret TeamRemoteMemberViewTokenInner) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Inner),
		Jrt: (func(x *TeamRSVPRemoteInternal__) (ret TeamRSVPRemote) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Jrt),
	}
}

func (t TeamRemoteMemberViewToken) Export() *TeamRemoteMemberViewTokenInternal__ {
	return &TeamRemoteMemberViewTokenInternal__{
		Team:  t.Team.Export(),
		Inner: t.Inner.Export(),
		Jrt:   t.Jrt.Export(),
	}
}

func (t *TeamRemoteMemberViewToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteMemberViewToken) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteMemberViewTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoteMemberViewToken) Bytes() []byte { return nil }

type TeamRemoteMemberViewTokenInner struct {
	Member    FQParty
	PtkGen    Generation
	SecretBox SecretBox
}

type TeamRemoteMemberViewTokenInnerInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Member    *FQPartyInternal__
	PtkGen    *GenerationInternal__
	SecretBox *SecretBoxInternal__
}

func (t TeamRemoteMemberViewTokenInnerInternal__) Import() TeamRemoteMemberViewTokenInner {
	return TeamRemoteMemberViewTokenInner{
		Member: (func(x *FQPartyInternal__) (ret FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Member),
		PtkGen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.PtkGen),
		SecretBox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SecretBox),
	}
}

func (t TeamRemoteMemberViewTokenInner) Export() *TeamRemoteMemberViewTokenInnerInternal__ {
	return &TeamRemoteMemberViewTokenInnerInternal__{
		Member:    t.Member.Export(),
		PtkGen:    t.PtkGen.Export(),
		SecretBox: t.SecretBox.Export(),
	}
}

func (t *TeamRemoteMemberViewTokenInner) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemoteMemberViewTokenInner) Decode(dec rpc.Decoder) error {
	var tmp TeamRemoteMemberViewTokenInnerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemoteMemberViewTokenInner) Bytes() []byte { return nil }

type TeamCertHash StdHash
type TeamCertHashInternal__ StdHashInternal__

func (t TeamCertHash) Export() *TeamCertHashInternal__ {
	tmp := ((StdHash)(t))
	return ((*TeamCertHashInternal__)(tmp.Export()))
}

func (t TeamCertHashInternal__) Import() TeamCertHash {
	tmp := (StdHashInternal__)(t)
	return TeamCertHash((func(x *StdHashInternal__) (ret StdHash) {
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
	return ((StdHash)(t)).Bytes()
}

type TeamInviteVersion int

const (
	TeamInviteVersion_V1 TeamInviteVersion = 1
)

var TeamInviteVersionMap = map[string]TeamInviteVersion{
	"V1": 1,
}

var TeamInviteVersionRevMap = map[TeamInviteVersion]string{
	1: "V1",
}

type TeamInviteVersionInternal__ TeamInviteVersion

func (t TeamInviteVersionInternal__) Import() TeamInviteVersion {
	return TeamInviteVersion(t)
}

func (t TeamInviteVersion) Export() *TeamInviteVersionInternal__ {
	return ((*TeamInviteVersionInternal__)(&t))
}

type TeamInviteV1 struct {
	Hsh  TeamCertHash
	Host HostID
}

type TeamInviteV1Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hsh     *TeamCertHashInternal__
	Host    *HostIDInternal__
}

func (t TeamInviteV1Internal__) Import() TeamInviteV1 {
	return TeamInviteV1{
		Hsh: (func(x *TeamCertHashInternal__) (ret TeamCertHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hsh),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Host),
	}
}

func (t TeamInviteV1) Export() *TeamInviteV1Internal__ {
	return &TeamInviteV1Internal__{
		Hsh:  t.Hsh.Export(),
		Host: t.Host.Export(),
	}
}

func (t *TeamInviteV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInviteV1) Decode(dec rpc.Decoder) error {
	var tmp TeamInviteV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamInviteV1TypeUniqueID = rpc.TypeUniqueID(0x9c91987467d09630)

func (t *TeamInviteV1) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamInviteV1TypeUniqueID
}

func (t *TeamInviteV1) Bytes() []byte { return nil }

type TeamInvite struct {
	V     TeamInviteVersion
	F_0__ *TeamInviteV1 `json:"f0,omitempty"`
}

type TeamInviteInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        TeamInviteVersion
	Switch__ TeamInviteInternalSwitch__
}

type TeamInviteInternalSwitch__ struct {
	_struct struct{}                `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *TeamInviteV1Internal__ `codec:"0"`
}

func (t TeamInvite) GetV() (ret TeamInviteVersion, err error) {
	switch t.V {
	case TeamInviteVersion_V1:
		if t.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return t.V, nil
}

func (t TeamInvite) V1() TeamInviteV1 {
	if t.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.V != TeamInviteVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", t.V))
	}
	return *t.F_0__
}

func NewTeamInviteWithV1(v TeamInviteV1) TeamInvite {
	return TeamInvite{
		V:     TeamInviteVersion_V1,
		F_0__: &v,
	}
}

func (t TeamInviteInternal__) Import() TeamInvite {
	return TeamInvite{
		V: t.V,
		F_0__: (func(x *TeamInviteV1Internal__) *TeamInviteV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamInviteV1Internal__) (ret TeamInviteV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_0__),
	}
}

func (t TeamInvite) Export() *TeamInviteInternal__ {
	return &TeamInviteInternal__{
		V: t.V,
		Switch__: TeamInviteInternalSwitch__{
			F_0__: (func(x *TeamInviteV1) *TeamInviteV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_0__),
		},
	}
}

func (t *TeamInvite) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInvite) Decode(dec rpc.Decoder) error {
	var tmp TeamInviteInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamInvite) Bytes() []byte { return nil }

type TeamIDOrName struct {
	Id    bool
	F_0__ *Name   `json:"f0,omitempty"`
	F_1__ *TeamID `json:"f1,omitempty"`
}

type TeamIDOrNameInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id       bool
	Switch__ TeamIDOrNameInternalSwitch__
}

type TeamIDOrNameInternalSwitch__ struct {
	_struct struct{}          `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *NameInternal__   `codec:"0"`
	F_1__   *TeamIDInternal__ `codec:"1"`
}

func (t TeamIDOrName) GetId() (ret bool, err error) {
	switch t.Id {
	case false:
		if t.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if t.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return t.Id, nil
}

func (t TeamIDOrName) False() Name {
	if t.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if t.Id {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", t.Id))
	}
	return *t.F_0__
}

func (t TeamIDOrName) True() TeamID {
	if t.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if !t.Id {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", t.Id))
	}
	return *t.F_1__
}

func NewTeamIDOrNameWithFalse(v Name) TeamIDOrName {
	return TeamIDOrName{
		Id:    false,
		F_0__: &v,
	}
}

func NewTeamIDOrNameWithTrue(v TeamID) TeamIDOrName {
	return TeamIDOrName{
		Id:    true,
		F_1__: &v,
	}
}

func (t TeamIDOrNameInternal__) Import() TeamIDOrName {
	return TeamIDOrName{
		Id: t.Id,
		F_0__: (func(x *NameInternal__) *Name {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameInternal__) (ret Name) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_0__),
		F_1__: (func(x *TeamIDInternal__) *TeamID {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamIDInternal__) (ret TeamID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Switch__.F_1__),
	}
}

func (t TeamIDOrName) Export() *TeamIDOrNameInternal__ {
	return &TeamIDOrNameInternal__{
		Id: t.Id,
		Switch__: TeamIDOrNameInternalSwitch__{
			F_0__: (func(x *Name) *NameInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_0__),
			F_1__: (func(x *TeamID) *TeamIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(t.F_1__),
		},
	}
}

func (t *TeamIDOrName) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIDOrName) Decode(dec rpc.Decoder) error {
	var tmp TeamIDOrNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIDOrName) Bytes() []byte { return nil }

type FQTeamIDOrName struct {
	Host     HostID
	IdOrName TeamIDOrName
}

type FQTeamIDOrNameInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host     *HostIDInternal__
	IdOrName *TeamIDOrNameInternal__
}

func (f FQTeamIDOrNameInternal__) Import() FQTeamIDOrName {
	return FQTeamIDOrName{
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
		IdOrName: (func(x *TeamIDOrNameInternal__) (ret TeamIDOrName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.IdOrName),
	}
}

func (f FQTeamIDOrName) Export() *FQTeamIDOrNameInternal__ {
	return &FQTeamIDOrNameInternal__{
		Host:     f.Host.Export(),
		IdOrName: f.IdOrName.Export(),
	}
}

func (f *FQTeamIDOrName) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQTeamIDOrName) Decode(dec rpc.Decoder) error {
	var tmp FQTeamIDOrNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQTeamIDOrName) Bytes() []byte { return nil }

type SenderPair struct {
	VerifyKey EntityID
	HepkFp    HEPKFingerprint
}

type SenderPairInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	VerifyKey *EntityIDInternal__
	HepkFp    *HEPKFingerprintInternal__
}

func (s SenderPairInternal__) Import() SenderPair {
	return SenderPair{
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

func (s SenderPair) Export() *SenderPairInternal__ {
	return &SenderPairInternal__{
		VerifyKey: s.VerifyKey.Export(),
		HepkFp:    s.HepkFp.Export(),
	}
}

func (s *SenderPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SenderPair) Decode(dec rpc.Decoder) error {
	var tmp SenderPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SenderPair) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(TeamRemoteMemberViewTokenBoxPayloadTypeUniqueID)
	rpc.AddUnique(TeamInviteV1TypeUniqueID)
}
