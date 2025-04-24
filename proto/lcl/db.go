// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/db.snowp

package lcl

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type DbVal []byte
type DbValInternal__ []byte

func (d DbVal) Export() *DbValInternal__ {
	tmp := (([]byte)(d))
	return ((*DbValInternal__)(&tmp))
}

func (d DbValInternal__) Import() DbVal {
	tmp := ([]byte)(d)
	return DbVal((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DbVal) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DbVal) Decode(dec rpc.Decoder) error {
	var tmp DbValInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DbVal) Bytes() []byte {
	return (d)[:]
}

type DataType int

const (
	DataType_None                 DataType = 0
	DataType_YubiKey              DataType = 1
	DataType_TreeLocation         DataType = 3
	DataType_MerkleRootByHash     DataType = 4
	DataType_MerkleRootHashByEpno DataType = 5
	DataType_MerkleLatestEpno     DataType = 6
	DataType_Hostchain            DataType = 7
	DataType_SharedKeyCacheEntry  DataType = 8
	DataType_UserSigchainState    DataType = 9
	DataType_SubkeyBox            DataType = 10
	DataType_User                 DataType = 11
	DataType_GenericChainState    DataType = 12
	DataType_TeamChainState       DataType = 13
	DataType_UsernameReservation  DataType = 14
	DataType_UsernameLookup       DataType = 15
	DataType_KVRealm              DataType = 65
	DataType_KVNSRoot             DataType = 66
	DataType_KVDir                DataType = 67
	DataType_KVDirent             DataType = 68
	DataType_KVFileHeader         DataType = 69
	DataType_KVFileChunk          DataType = 70
	DataType_KVNSName             DataType = 71
	DataType_KVSymlink            DataType = 72
	DataType_KVGitRefSet          DataType = 73
)

var DataTypeMap = map[string]DataType{
	"None":                 0,
	"YubiKey":              1,
	"TreeLocation":         3,
	"MerkleRootByHash":     4,
	"MerkleRootHashByEpno": 5,
	"MerkleLatestEpno":     6,
	"Hostchain":            7,
	"SharedKeyCacheEntry":  8,
	"UserSigchainState":    9,
	"SubkeyBox":            10,
	"User":                 11,
	"GenericChainState":    12,
	"TeamChainState":       13,
	"UsernameReservation":  14,
	"UsernameLookup":       15,
	"KVRealm":              65,
	"KVNSRoot":             66,
	"KVDir":                67,
	"KVDirent":             68,
	"KVFileHeader":         69,
	"KVFileChunk":          70,
	"KVNSName":             71,
	"KVSymlink":            72,
	"KVGitRefSet":          73,
}

var DataTypeRevMap = map[DataType]string{
	0:  "None",
	1:  "YubiKey",
	3:  "TreeLocation",
	4:  "MerkleRootByHash",
	5:  "MerkleRootHashByEpno",
	6:  "MerkleLatestEpno",
	7:  "Hostchain",
	8:  "SharedKeyCacheEntry",
	9:  "UserSigchainState",
	10: "SubkeyBox",
	11: "User",
	12: "GenericChainState",
	13: "TeamChainState",
	14: "UsernameReservation",
	15: "UsernameLookup",
	65: "KVRealm",
	66: "KVNSRoot",
	67: "KVDir",
	68: "KVDirent",
	69: "KVFileHeader",
	70: "KVFileChunk",
	71: "KVNSName",
	72: "KVSymlink",
	73: "KVGitRefSet",
}

type DataTypeInternal__ DataType

func (d DataTypeInternal__) Import() DataType {
	return DataType(d)
}

func (d DataType) Export() *DataTypeInternal__ {
	return ((*DataTypeInternal__)(&d))
}

type ScopeLabel []byte
type ScopeLabelInternal__ []byte

func (s ScopeLabel) Export() *ScopeLabelInternal__ {
	tmp := (([]byte)(s))
	return ((*ScopeLabelInternal__)(&tmp))
}

func (s ScopeLabelInternal__) Import() ScopeLabel {
	tmp := ([]byte)(s)
	return ScopeLabel((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *ScopeLabel) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ScopeLabel) Decode(dec rpc.Decoder) error {
	var tmp ScopeLabelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s ScopeLabel) Bytes() []byte {
	return (s)[:]
}

type ScopeID uint64
type ScopeIDInternal__ uint64

func (s ScopeID) Export() *ScopeIDInternal__ {
	tmp := ((uint64)(s))
	return ((*ScopeIDInternal__)(&tmp))
}

func (s ScopeIDInternal__) Import() ScopeID {
	tmp := (uint64)(s)
	return ScopeID((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *ScopeID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ScopeID) Decode(dec rpc.Decoder) error {
	var tmp ScopeIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s ScopeID) Bytes() []byte {
	return nil
}

type UserSigchainState struct {
	Tail         lib.HidingChainer
	LastHash     lib.LinkHash
	Username     lib.NameAndSeqnoBundle
	Puks         []lib.SharedKey
	Devices      []lib.DeviceInfo
	PukGens      []lib.SharedKeyGen
	Sctlsc       lib.TreeLocationCommitment
	MerkleLeaves []lib.MerkleLeaf
	Hepks        lib.HEPKSet
	StalePUKs    []lib.Role
}

type UserSigchainStateInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tail         *lib.HidingChainerInternal__
	LastHash     *lib.LinkHashInternal__
	Username     *lib.NameAndSeqnoBundleInternal__
	Puks         *[](*lib.SharedKeyInternal__)
	Devices      *[](*lib.DeviceInfoInternal__)
	PukGens      *[](*lib.SharedKeyGenInternal__)
	Deprecated6  *struct{}
	Sctlsc       *lib.TreeLocationCommitmentInternal__
	MerkleLeaves *[](*lib.MerkleLeafInternal__)
	Hepks        *lib.HEPKSetInternal__
	StalePUKs    *[](*lib.RoleInternal__)
}

func (u UserSigchainStateInternal__) Import() UserSigchainState {
	return UserSigchainState{
		Tail: (func(x *lib.HidingChainerInternal__) (ret lib.HidingChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Tail),
		LastHash: (func(x *lib.LinkHashInternal__) (ret lib.LinkHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.LastHash),
		Username: (func(x *lib.NameAndSeqnoBundleInternal__) (ret lib.NameAndSeqnoBundle) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Username),
		Puks: (func(x *[](*lib.SharedKeyInternal__)) (ret []lib.SharedKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SharedKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SharedKeyInternal__) (ret lib.SharedKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Puks),
		Devices: (func(x *[](*lib.DeviceInfoInternal__)) (ret []lib.DeviceInfo) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.DeviceInfo, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.DeviceInfoInternal__) (ret lib.DeviceInfo) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Devices),
		PukGens: (func(x *[](*lib.SharedKeyGenInternal__)) (ret []lib.SharedKeyGen) {
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
		})(u.PukGens),
		Sctlsc: (func(x *lib.TreeLocationCommitmentInternal__) (ret lib.TreeLocationCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Sctlsc),
		MerkleLeaves: (func(x *[](*lib.MerkleLeafInternal__)) (ret []lib.MerkleLeaf) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleLeaf, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleLeafInternal__) (ret lib.MerkleLeaf) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.MerkleLeaves),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Hepks),
		StalePUKs: (func(x *[](*lib.RoleInternal__)) (ret []lib.Role) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.Role, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.RoleInternal__) (ret lib.Role) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.StalePUKs),
	}
}

func (u UserSigchainState) Export() *UserSigchainStateInternal__ {
	return &UserSigchainStateInternal__{
		Tail:     u.Tail.Export(),
		LastHash: u.LastHash.Export(),
		Username: u.Username.Export(),
		Puks: (func(x []lib.SharedKey) *[](*lib.SharedKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SharedKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Puks),
		Devices: (func(x []lib.DeviceInfo) *[](*lib.DeviceInfoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.DeviceInfoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Devices),
		PukGens: (func(x []lib.SharedKeyGen) *[](*lib.SharedKeyGenInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SharedKeyGenInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.PukGens),
		Sctlsc: u.Sctlsc.Export(),
		MerkleLeaves: (func(x []lib.MerkleLeaf) *[](*lib.MerkleLeafInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleLeafInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.MerkleLeaves),
		Hepks: u.Hepks.Export(),
		StalePUKs: (func(x []lib.Role) *[](*lib.RoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.RoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.StalePUKs),
	}
}

func (u *UserSigchainState) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserSigchainState) Decode(dec rpc.Decoder) error {
	var tmp UserSigchainStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserSigchainState) Bytes() []byte { return nil }

type UserMetadataAndSigchainState struct {
	Fqu      lib.FQUser
	State    UserSigchainState
	Hostname lib.Hostname
}

type UserMetadataAndSigchainStateInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu      *lib.FQUserInternal__
	State    *UserSigchainStateInternal__
	Hostname *lib.HostnameInternal__
}

func (u UserMetadataAndSigchainStateInternal__) Import() UserMetadataAndSigchainState {
	return UserMetadataAndSigchainState{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Fqu),
		State: (func(x *UserSigchainStateInternal__) (ret UserSigchainState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.State),
		Hostname: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Hostname),
	}
}

func (u UserMetadataAndSigchainState) Export() *UserMetadataAndSigchainStateInternal__ {
	return &UserMetadataAndSigchainStateInternal__{
		Fqu:      u.Fqu.Export(),
		State:    u.State.Export(),
		Hostname: u.Hostname.Export(),
	}
}

func (u *UserMetadataAndSigchainState) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserMetadataAndSigchainState) Decode(dec rpc.Decoder) error {
	var tmp UserMetadataAndSigchainStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserMetadataAndSigchainState) Bytes() []byte { return nil }

type RoleAndGenus struct {
	Role  lib.Role
	Genus lib.KeyGenus
}

type RoleAndGenusInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *lib.RoleInternal__
	Genus   *lib.KeyGenusInternal__
}

func (r RoleAndGenusInternal__) Import() RoleAndGenus {
	return RoleAndGenus{
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Role),
		Genus: (func(x *lib.KeyGenusInternal__) (ret lib.KeyGenus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Genus),
	}
}

func (r RoleAndGenus) Export() *RoleAndGenusInternal__ {
	return &RoleAndGenusInternal__{
		Role:  r.Role.Export(),
		Genus: r.Genus.Export(),
	}
}

func (r *RoleAndGenus) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleAndGenus) Decode(dec rpc.Decoder) error {
	var tmp RoleAndGenusInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RoleAndGenusTypeUniqueID = rpc.TypeUniqueID(0xfaeb1f09bcded289)

func (r *RoleAndGenus) GetTypeUniqueID() rpc.TypeUniqueID {
	return RoleAndGenusTypeUniqueID
}

func (r *RoleAndGenus) Bytes() []byte { return nil }

type PUKBoxDBKey struct {
	Rg  RoleAndGenus
	Eid lib.EntityID
}

type PUKBoxDBKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenusInternal__
	Eid     *lib.EntityIDInternal__
}

func (p PUKBoxDBKeyInternal__) Import() PUKBoxDBKey {
	return PUKBoxDBKey{
		Rg: (func(x *RoleAndGenusInternal__) (ret RoleAndGenus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Rg),
		Eid: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Eid),
	}
}

func (p PUKBoxDBKey) Export() *PUKBoxDBKeyInternal__ {
	return &PUKBoxDBKeyInternal__{
		Rg:  p.Rg.Export(),
		Eid: p.Eid.Export(),
	}
}

func (p *PUKBoxDBKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PUKBoxDBKey) Decode(dec rpc.Decoder) error {
	var tmp PUKBoxDBKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var PUKBoxDBKeyTypeUniqueID = rpc.TypeUniqueID(0xf3b0c875bbfcdc03)

func (p *PUKBoxDBKey) GetTypeUniqueID() rpc.TypeUniqueID {
	return PUKBoxDBKeyTypeUniqueID
}

func (p *PUKBoxDBKey) Bytes() []byte { return nil }

type GenericChainState struct {
	Tail     lib.HidingChainer
	LastHash lib.LinkHash
	Payload  GenericChainStatePayload
}

type GenericChainStateInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tail     *lib.HidingChainerInternal__
	LastHash *lib.LinkHashInternal__
	Payload  *GenericChainStatePayloadInternal__
}

func (g GenericChainStateInternal__) Import() GenericChainState {
	return GenericChainState{
		Tail: (func(x *lib.HidingChainerInternal__) (ret lib.HidingChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Tail),
		LastHash: (func(x *lib.LinkHashInternal__) (ret lib.LinkHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.LastHash),
		Payload: (func(x *GenericChainStatePayloadInternal__) (ret GenericChainStatePayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Payload),
	}
}

func (g GenericChainState) Export() *GenericChainStateInternal__ {
	return &GenericChainStateInternal__{
		Tail:     g.Tail.Export(),
		LastHash: g.LastHash.Export(),
		Payload:  g.Payload.Export(),
	}
}

func (g *GenericChainState) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GenericChainState) Decode(dec rpc.Decoder) error {
	var tmp GenericChainStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GenericChainState) Bytes() []byte { return nil }

type UserSettingsChainPayload struct {
	Passphrase *lib.PassphraseInfo
}

type UserSettingsChainPayloadInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Passphrase *lib.PassphraseInfoInternal__
}

func (u UserSettingsChainPayloadInternal__) Import() UserSettingsChainPayload {
	return UserSettingsChainPayload{
		Passphrase: (func(x *lib.PassphraseInfoInternal__) *lib.PassphraseInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PassphraseInfoInternal__) (ret lib.PassphraseInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Passphrase),
	}
}

func (u UserSettingsChainPayload) Export() *UserSettingsChainPayloadInternal__ {
	return &UserSettingsChainPayloadInternal__{
		Passphrase: (func(x *lib.PassphraseInfo) *lib.PassphraseInfoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(u.Passphrase),
	}
}

func (u *UserSettingsChainPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserSettingsChainPayload) Decode(dec rpc.Decoder) error {
	var tmp UserSettingsChainPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserSettingsChainPayload) Bytes() []byte { return nil }

type TeamMembershipChainPayload struct {
	Teams []lib.TeamMembershipLink
}

type TeamMembershipChainPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Teams   *[](*lib.TeamMembershipLinkInternal__)
}

func (t TeamMembershipChainPayloadInternal__) Import() TeamMembershipChainPayload {
	return TeamMembershipChainPayload{
		Teams: (func(x *[](*lib.TeamMembershipLinkInternal__)) (ret []lib.TeamMembershipLink) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TeamMembershipLink, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TeamMembershipLinkInternal__) (ret lib.TeamMembershipLink) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Teams),
	}
}

func (t TeamMembershipChainPayload) Export() *TeamMembershipChainPayloadInternal__ {
	return &TeamMembershipChainPayloadInternal__{
		Teams: (func(x []lib.TeamMembershipLink) *[](*lib.TeamMembershipLinkInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TeamMembershipLinkInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Teams),
	}
}

func (t *TeamMembershipChainPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMembershipChainPayload) Decode(dec rpc.Decoder) error {
	var tmp TeamMembershipChainPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMembershipChainPayload) Bytes() []byte { return nil }

type GenericChainStatePayload struct {
	T     lib.ChainType
	F_2__ *UserSettingsChainPayload   `json:"f2,omitempty"`
	F_4__ *TeamMembershipChainPayload `json:"f4,omitempty"`
}

type GenericChainStatePayloadInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.ChainType
	Switch__ GenericChainStatePayloadInternalSwitch__
}

type GenericChainStatePayloadInternalSwitch__ struct {
	_struct struct{}                              `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_2__   *UserSettingsChainPayloadInternal__   `codec:"2"`
	F_4__   *TeamMembershipChainPayloadInternal__ `codec:"4"`
}

func (g GenericChainStatePayload) GetT() (ret lib.ChainType, err error) {
	switch g.T {
	case lib.ChainType_UserSettings:
		if g.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case lib.ChainType_TeamMembership:
		if g.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	}
	return g.T, nil
}

func (g GenericChainStatePayload) Usersettings() UserSettingsChainPayload {
	if g.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if g.T != lib.ChainType_UserSettings {
		panic(fmt.Sprintf("unexpected switch value (%v) when Usersettings is called", g.T))
	}
	return *g.F_2__
}

func (g GenericChainStatePayload) Teammembership() TeamMembershipChainPayload {
	if g.F_4__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if g.T != lib.ChainType_TeamMembership {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teammembership is called", g.T))
	}
	return *g.F_4__
}

func NewGenericChainStatePayloadWithUsersettings(v UserSettingsChainPayload) GenericChainStatePayload {
	return GenericChainStatePayload{
		T:     lib.ChainType_UserSettings,
		F_2__: &v,
	}
}

func NewGenericChainStatePayloadWithTeammembership(v TeamMembershipChainPayload) GenericChainStatePayload {
	return GenericChainStatePayload{
		T:     lib.ChainType_TeamMembership,
		F_4__: &v,
	}
}

func (g GenericChainStatePayloadInternal__) Import() GenericChainStatePayload {
	return GenericChainStatePayload{
		T: g.T,
		F_2__: (func(x *UserSettingsChainPayloadInternal__) *UserSettingsChainPayload {
			if x == nil {
				return nil
			}
			tmp := (func(x *UserSettingsChainPayloadInternal__) (ret UserSettingsChainPayload) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Switch__.F_2__),
		F_4__: (func(x *TeamMembershipChainPayloadInternal__) *TeamMembershipChainPayload {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamMembershipChainPayloadInternal__) (ret TeamMembershipChainPayload) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Switch__.F_4__),
	}
}

func (g GenericChainStatePayload) Export() *GenericChainStatePayloadInternal__ {
	return &GenericChainStatePayloadInternal__{
		T: g.T,
		Switch__: GenericChainStatePayloadInternalSwitch__{
			F_2__: (func(x *UserSettingsChainPayload) *UserSettingsChainPayloadInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(g.F_2__),
			F_4__: (func(x *TeamMembershipChainPayload) *TeamMembershipChainPayloadInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(g.F_4__),
		},
	}
}

func (g *GenericChainStatePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GenericChainStatePayload) Decode(dec rpc.Decoder) error {
	var tmp GenericChainStatePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GenericChainStatePayload) Bytes() []byte { return nil }

type TeamChainIndex struct {
	Team     lib.FQTeam
	AsLoader lib.FQParty
	SrcRole  lib.Role
	Priv     bool
}

type TeamChainIndexInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team     *lib.FQTeamInternal__
	AsLoader *lib.FQPartyInternal__
	SrcRole  *lib.RoleInternal__
	Priv     *bool
}

func (t TeamChainIndexInternal__) Import() TeamChainIndex {
	return TeamChainIndex{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		AsLoader: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.AsLoader),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Priv: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Priv),
	}
}

func (t TeamChainIndex) Export() *TeamChainIndexInternal__ {
	return &TeamChainIndexInternal__{
		Team:     t.Team.Export(),
		AsLoader: t.AsLoader.Export(),
		SrcRole:  t.SrcRole.Export(),
		Priv:     &t.Priv,
	}
}

func (t *TeamChainIndex) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamChainIndex) Decode(dec rpc.Decoder) error {
	var tmp TeamChainIndexInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TeamChainIndexTypeUniqueID = rpc.TypeUniqueID(0xf84d4b49bf61d869)

func (t *TeamChainIndex) GetTypeUniqueID() rpc.TypeUniqueID {
	return TeamChainIndexTypeUniqueID
}

func (t *TeamChainIndex) Bytes() []byte { return nil }

type SharedKeyWithInfo struct {
	Sk lib.SharedKey
	Pi lib.ProvisionInfo
	Ri *lib.RevokeInfo
}

type SharedKeyWithInfoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sk      *lib.SharedKeyInternal__
	Pi      *lib.ProvisionInfoInternal__
	Ri      *lib.RevokeInfoInternal__
}

func (s SharedKeyWithInfoInternal__) Import() SharedKeyWithInfo {
	return SharedKeyWithInfo{
		Sk: (func(x *lib.SharedKeyInternal__) (ret lib.SharedKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sk),
		Pi: (func(x *lib.ProvisionInfoInternal__) (ret lib.ProvisionInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Pi),
		Ri: (func(x *lib.RevokeInfoInternal__) *lib.RevokeInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RevokeInfoInternal__) (ret lib.RevokeInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Ri),
	}
}

func (s SharedKeyWithInfo) Export() *SharedKeyWithInfoInternal__ {
	return &SharedKeyWithInfoInternal__{
		Sk: s.Sk.Export(),
		Pi: s.Pi.Export(),
		Ri: (func(x *lib.RevokeInfo) *lib.RevokeInfoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Ri),
	}
}

func (s *SharedKeyWithInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyWithInfo) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyWithInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyWithInfo) Bytes() []byte { return nil }

type TeamChainState struct {
	Fqt               lib.FQTeam
	Tail              lib.HidingChainer
	LastHash          lib.LinkHash
	Name              lib.NameAndSeqnoBundle
	Ptks              []SharedKeyWithInfo
	Members           []lib.MemberRoleSeqno
	Sctlsc            lib.TreeLocationCommitment
	MerkleLeaves      []lib.MerkleLeaf
	PrivateKeys       []lib.SharedKeyParcel
	RemovalKey        *lib.TeamRemovalKeyBox
	RemoteViewTokens  []lib.TeamRemoteMemberViewTokenInner
	Hepks             lib.HEPKSet
	Tir               lib.RationalRange
	HistoricalSenders []lib.SenderPair
}

type TeamChainStateInternal__ struct {
	_struct           struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqt               *lib.FQTeamInternal__
	Tail              *lib.HidingChainerInternal__
	LastHash          *lib.LinkHashInternal__
	Name              *lib.NameAndSeqnoBundleInternal__
	Ptks              *[](*SharedKeyWithInfoInternal__)
	Members           *[](*lib.MemberRoleSeqnoInternal__)
	Sctlsc            *lib.TreeLocationCommitmentInternal__
	MerkleLeaves      *[](*lib.MerkleLeafInternal__)
	PrivateKeys       *[](*lib.SharedKeyParcelInternal__)
	RemovalKey        *lib.TeamRemovalKeyBoxInternal__
	RemoteViewTokens  *[](*lib.TeamRemoteMemberViewTokenInnerInternal__)
	Hepks             *lib.HEPKSetInternal__
	Tir               *lib.RationalRangeInternal__
	HistoricalSenders *[](*lib.SenderPairInternal__)
}

func (t TeamChainStateInternal__) Import() TeamChainState {
	return TeamChainState{
		Fqt: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Fqt),
		Tail: (func(x *lib.HidingChainerInternal__) (ret lib.HidingChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tail),
		LastHash: (func(x *lib.LinkHashInternal__) (ret lib.LinkHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.LastHash),
		Name: (func(x *lib.NameAndSeqnoBundleInternal__) (ret lib.NameAndSeqnoBundle) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Name),
		Ptks: (func(x *[](*SharedKeyWithInfoInternal__)) (ret []SharedKeyWithInfo) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SharedKeyWithInfo, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SharedKeyWithInfoInternal__) (ret SharedKeyWithInfo) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Ptks),
		Members: (func(x *[](*lib.MemberRoleSeqnoInternal__)) (ret []lib.MemberRoleSeqno) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MemberRoleSeqno, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MemberRoleSeqnoInternal__) (ret lib.MemberRoleSeqno) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Members),
		Sctlsc: (func(x *lib.TreeLocationCommitmentInternal__) (ret lib.TreeLocationCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Sctlsc),
		MerkleLeaves: (func(x *[](*lib.MerkleLeafInternal__)) (ret []lib.MerkleLeaf) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleLeaf, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleLeafInternal__) (ret lib.MerkleLeaf) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.MerkleLeaves),
		PrivateKeys: (func(x *[](*lib.SharedKeyParcelInternal__)) (ret []lib.SharedKeyParcel) {
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
		})(t.PrivateKeys),
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
		Tir: (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tir),
		HistoricalSenders: (func(x *[](*lib.SenderPairInternal__)) (ret []lib.SenderPair) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SenderPair, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SenderPairInternal__) (ret lib.SenderPair) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.HistoricalSenders),
	}
}

func (t TeamChainState) Export() *TeamChainStateInternal__ {
	return &TeamChainStateInternal__{
		Fqt:      t.Fqt.Export(),
		Tail:     t.Tail.Export(),
		LastHash: t.LastHash.Export(),
		Name:     t.Name.Export(),
		Ptks: (func(x []SharedKeyWithInfo) *[](*SharedKeyWithInfoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SharedKeyWithInfoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Ptks),
		Members: (func(x []lib.MemberRoleSeqno) *[](*lib.MemberRoleSeqnoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MemberRoleSeqnoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Members),
		Sctlsc: t.Sctlsc.Export(),
		MerkleLeaves: (func(x []lib.MerkleLeaf) *[](*lib.MerkleLeafInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleLeafInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.MerkleLeaves),
		PrivateKeys: (func(x []lib.SharedKeyParcel) *[](*lib.SharedKeyParcelInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SharedKeyParcelInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.PrivateKeys),
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
		Tir:   t.Tir.Export(),
		HistoricalSenders: (func(x []lib.SenderPair) *[](*lib.SenderPairInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SenderPairInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.HistoricalSenders),
	}
}

func (t *TeamChainState) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamChainState) Decode(dec rpc.Decoder) error {
	var tmp TeamChainStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamChainState) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(RoleAndGenusTypeUniqueID)
	rpc.AddUnique(PUKBoxDBKeyTypeUniqueID)
	rpc.AddUnique(TeamChainIndexTypeUniqueID)
}
