// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/keys.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type KeyDerivationType int

const (
	KeyDerivationType_Signing        KeyDerivationType = 0
	KeyDerivationType_DH             KeyDerivationType = 1
	KeyDerivationType_SecretBoxKey   KeyDerivationType = 2
	KeyDerivationType_TreeLocationRF KeyDerivationType = 3
	KeyDerivationType_MLKEM          KeyDerivationType = 4
	KeyDerivationType_AppKey         KeyDerivationType = 5
)

var KeyDerivationTypeMap = map[string]KeyDerivationType{
	"Signing":        0,
	"DH":             1,
	"SecretBoxKey":   2,
	"TreeLocationRF": 3,
	"MLKEM":          4,
	"AppKey":         5,
}
var KeyDerivationTypeRevMap = map[KeyDerivationType]string{
	0: "Signing",
	1: "DH",
	2: "SecretBoxKey",
	3: "TreeLocationRF",
	4: "MLKEM",
	5: "AppKey",
}

type KeyDerivationTypeInternal__ KeyDerivationType

func (k KeyDerivationTypeInternal__) Import() KeyDerivationType {
	return KeyDerivationType(k)
}
func (k KeyDerivationType) Export() *KeyDerivationTypeInternal__ {
	return ((*KeyDerivationTypeInternal__)(&k))
}

type AppKeyDerivationType int

const (
	AppKeyDerivationType_Enum   AppKeyDerivationType = 0
	AppKeyDerivationType_String AppKeyDerivationType = 1
)

var AppKeyDerivationTypeMap = map[string]AppKeyDerivationType{
	"Enum":   0,
	"String": 1,
}
var AppKeyDerivationTypeRevMap = map[AppKeyDerivationType]string{
	0: "Enum",
	1: "String",
}

type AppKeyDerivationTypeInternal__ AppKeyDerivationType

func (a AppKeyDerivationTypeInternal__) Import() AppKeyDerivationType {
	return AppKeyDerivationType(a)
}
func (a AppKeyDerivationType) Export() *AppKeyDerivationTypeInternal__ {
	return ((*AppKeyDerivationTypeInternal__)(&a))
}

type AppKeyEnum int

const (
	AppKeyEnum_KVStore AppKeyEnum = 0
)

var AppKeyEnumMap = map[string]AppKeyEnum{
	"KVStore": 0,
}
var AppKeyEnumRevMap = map[AppKeyEnum]string{
	0: "KVStore",
}

type AppKeyEnumInternal__ AppKeyEnum

func (a AppKeyEnumInternal__) Import() AppKeyEnum {
	return AppKeyEnum(a)
}
func (a AppKeyEnum) Export() *AppKeyEnumInternal__ {
	return ((*AppKeyEnumInternal__)(&a))
}

type KeyDerivation struct {
	T     KeyDerivationType
	F_4__ *uint64 `json:"f4,omitempty"`
}
type KeyDerivationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KeyDerivationType
	Switch__ KeyDerivationInternalSwitch__
}
type KeyDerivationInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_4__   *uint64  `codec:"4"`
}

func (k KeyDerivation) GetT() (ret KeyDerivationType, err error) {
	switch k.T {
	case KeyDerivationType_MLKEM:
		if k.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	default:
		break
	}
	return k.T, nil
}
func (k KeyDerivation) Mlkem() uint64 {
	if k.F_4__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != KeyDerivationType_MLKEM {
		panic(fmt.Sprintf("unexpected switch value (%v) when Mlkem is called", k.T))
	}
	return *k.F_4__
}
func NewKeyDerivationWithMlkem(v uint64) KeyDerivation {
	return KeyDerivation{
		T:     KeyDerivationType_MLKEM,
		F_4__: &v,
	}
}
func NewKeyDerivationDefault(s KeyDerivationType) KeyDerivation {
	return KeyDerivation{
		T: s,
	}
}
func (k KeyDerivationInternal__) Import() KeyDerivation {
	return KeyDerivation{
		T:     k.T,
		F_4__: k.Switch__.F_4__,
	}
}
func (k KeyDerivation) Export() *KeyDerivationInternal__ {
	return &KeyDerivationInternal__{
		T: k.T,
		Switch__: KeyDerivationInternalSwitch__{
			F_4__: k.F_4__,
		},
	}
}
func (k *KeyDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyDerivation) Decode(dec rpc.Decoder) error {
	var tmp KeyDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KeyDerivationTypeUniqueID = rpc.TypeUniqueID(0xd35cdcc95caef674)

func (k *KeyDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return KeyDerivationTypeUniqueID
}
func (k *KeyDerivation) Bytes() []byte { return nil }

type ChainLocationDerivation struct {
	T ChainType
}
type ChainLocationDerivationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        ChainType
	Switch__ ChainLocationDerivationInternalSwitch__
}
type ChainLocationDerivationInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
}

func (c ChainLocationDerivation) GetT() (ret ChainType, err error) {
	switch c.T {
	default:
		break
	}
	return c.T, nil
}
func NewChainLocationDerivationDefault(s ChainType) ChainLocationDerivation {
	return ChainLocationDerivation{
		T: s,
	}
}
func (c ChainLocationDerivationInternal__) Import() ChainLocationDerivation {
	return ChainLocationDerivation{
		T: c.T,
	}
}
func (c ChainLocationDerivation) Export() *ChainLocationDerivationInternal__ {
	return &ChainLocationDerivationInternal__{
		T:        c.T,
		Switch__: ChainLocationDerivationInternalSwitch__{},
	}
}
func (c *ChainLocationDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChainLocationDerivation) Decode(dec rpc.Decoder) error {
	var tmp ChainLocationDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChainLocationDerivationTypeUniqueID = rpc.TypeUniqueID(0xe516acf96cf56e58)

func (c *ChainLocationDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChainLocationDerivationTypeUniqueID
}
func (c *ChainLocationDerivation) Bytes() []byte { return nil }

type AppKeyDerivation struct {
	T     AppKeyDerivationType
	F_0__ *AppKeyEnum `json:"f0,omitempty"`
	F_1__ *string     `json:"f1,omitempty"`
}
type AppKeyDerivationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        AppKeyDerivationType
	Switch__ AppKeyDerivationInternalSwitch__
}
type AppKeyDerivationInternalSwitch__ struct {
	_struct struct{}              `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *AppKeyEnumInternal__ `codec:"0"`
	F_1__   *string               `codec:"1"`
}

func (a AppKeyDerivation) GetT() (ret AppKeyDerivationType, err error) {
	switch a.T {
	case AppKeyDerivationType_Enum:
		if a.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case AppKeyDerivationType_String:
		if a.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return a.T, nil
}
func (a AppKeyDerivation) Enum() AppKeyEnum {
	if a.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if a.T != AppKeyDerivationType_Enum {
		panic(fmt.Sprintf("unexpected switch value (%v) when Enum is called", a.T))
	}
	return *a.F_0__
}
func (a AppKeyDerivation) String() string {
	if a.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if a.T != AppKeyDerivationType_String {
		panic(fmt.Sprintf("unexpected switch value (%v) when String is called", a.T))
	}
	return *a.F_1__
}
func NewAppKeyDerivationWithEnum(v AppKeyEnum) AppKeyDerivation {
	return AppKeyDerivation{
		T:     AppKeyDerivationType_Enum,
		F_0__: &v,
	}
}
func NewAppKeyDerivationWithString(v string) AppKeyDerivation {
	return AppKeyDerivation{
		T:     AppKeyDerivationType_String,
		F_1__: &v,
	}
}
func (a AppKeyDerivationInternal__) Import() AppKeyDerivation {
	return AppKeyDerivation{
		T: a.T,
		F_0__: (func(x *AppKeyEnumInternal__) *AppKeyEnum {
			if x == nil {
				return nil
			}
			tmp := (func(x *AppKeyEnumInternal__) (ret AppKeyEnum) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(a.Switch__.F_0__),
		F_1__: a.Switch__.F_1__,
	}
}
func (a AppKeyDerivation) Export() *AppKeyDerivationInternal__ {
	return &AppKeyDerivationInternal__{
		T: a.T,
		Switch__: AppKeyDerivationInternalSwitch__{
			F_0__: (func(x *AppKeyEnum) *AppKeyEnumInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(a.F_0__),
			F_1__: a.F_1__,
		},
	}
}
func (a *AppKeyDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AppKeyDerivation) Decode(dec rpc.Decoder) error {
	var tmp AppKeyDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

var AppKeyDerivationTypeUniqueID = rpc.TypeUniqueID(0x94318317830b409b)

func (a *AppKeyDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return AppKeyDerivationTypeUniqueID
}
func (a *AppKeyDerivation) Bytes() []byte { return nil }

type KVKeyType int

const (
	KVKeyType_MAC        KVKeyType = 1
	KVKeyType_Box        KVKeyType = 2
	KVKeyType_Commitment KVKeyType = 3
)

var KVKeyTypeMap = map[string]KVKeyType{
	"MAC":        1,
	"Box":        2,
	"Commitment": 3,
}
var KVKeyTypeRevMap = map[KVKeyType]string{
	1: "MAC",
	2: "Box",
	3: "Commitment",
}

type KVKeyTypeInternal__ KVKeyType

func (k KVKeyTypeInternal__) Import() KVKeyType {
	return KVKeyType(k)
}
func (k KVKeyType) Export() *KVKeyTypeInternal__ {
	return ((*KVKeyTypeInternal__)(&k))
}

type KVKeyDerivation struct {
	T KVKeyType
}
type KVKeyDerivationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KVKeyType
	Switch__ KVKeyDerivationInternalSwitch__
}
type KVKeyDerivationInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
}

func (k KVKeyDerivation) GetT() (ret KVKeyType, err error) {
	switch k.T {
	default:
		break
	}
	return k.T, nil
}
func NewKVKeyDerivationDefault(s KVKeyType) KVKeyDerivation {
	return KVKeyDerivation{
		T: s,
	}
}
func (k KVKeyDerivationInternal__) Import() KVKeyDerivation {
	return KVKeyDerivation{
		T: k.T,
	}
}
func (k KVKeyDerivation) Export() *KVKeyDerivationInternal__ {
	return &KVKeyDerivationInternal__{
		T:        k.T,
		Switch__: KVKeyDerivationInternalSwitch__{},
	}
}
func (k *KVKeyDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVKeyDerivation) Decode(dec rpc.Decoder) error {
	var tmp KVKeyDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVKeyDerivationTypeUniqueID = rpc.TypeUniqueID(0xdbdf2ba29c0de2cb)

func (k *KVKeyDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVKeyDerivationTypeUniqueID
}
func (k *KVKeyDerivation) Bytes() []byte { return nil }

type KeyGenus int

const (
	KeyGenus_Device   KeyGenus = 0
	KeyGenus_Yubi     KeyGenus = 1
	KeyGenus_Backup   KeyGenus = 2
	KeyGenus_BotToken KeyGenus = 3
)

var KeyGenusMap = map[string]KeyGenus{
	"Device":   0,
	"Yubi":     1,
	"Backup":   2,
	"BotToken": 3,
}
var KeyGenusRevMap = map[KeyGenus]string{
	0: "Device",
	1: "Yubi",
	2: "Backup",
	3: "BotToken",
}

type KeyGenusInternal__ KeyGenus

func (k KeyGenusInternal__) Import() KeyGenus {
	return KeyGenus(k)
}
func (k KeyGenus) Export() *KeyGenusInternal__ {
	return ((*KeyGenusInternal__)(&k))
}

type SharedKeyParcel struct {
	Box             SharedKeyBox
	Sender          EntityID
	BoxId           BoxSetID
	TempDHKeySigned *TempDHKeySigned
	SeedChain       []SeedChainBox
}
type SharedKeyParcelInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Box             *SharedKeyBoxInternal__
	Sender          *EntityIDInternal__
	BoxId           *BoxSetIDInternal__
	TempDHKeySigned *TempDHKeySignedInternal__
	SeedChain       *[](*SeedChainBoxInternal__)
}

func (s SharedKeyParcelInternal__) Import() SharedKeyParcel {
	return SharedKeyParcel{
		Box: (func(x *SharedKeyBoxInternal__) (ret SharedKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Box),
		Sender: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sender),
		BoxId: (func(x *BoxSetIDInternal__) (ret BoxSetID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.BoxId),
		TempDHKeySigned: (func(x *TempDHKeySignedInternal__) *TempDHKeySigned {
			if x == nil {
				return nil
			}
			tmp := (func(x *TempDHKeySignedInternal__) (ret TempDHKeySigned) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.TempDHKeySigned),
		SeedChain: (func(x *[](*SeedChainBoxInternal__)) (ret []SeedChainBox) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SeedChainBox, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SeedChainBoxInternal__) (ret SeedChainBox) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.SeedChain),
	}
}
func (s SharedKeyParcel) Export() *SharedKeyParcelInternal__ {
	return &SharedKeyParcelInternal__{
		Box:    s.Box.Export(),
		Sender: s.Sender.Export(),
		BoxId:  s.BoxId.Export(),
		TempDHKeySigned: (func(x *TempDHKeySigned) *TempDHKeySignedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.TempDHKeySigned),
		SeedChain: (func(x []SeedChainBox) *[](*SeedChainBoxInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SeedChainBoxInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.SeedChain),
	}
}
func (s *SharedKeyParcel) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyParcel) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyParcelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyParcel) Bytes() []byte { return nil }

type SeedChainBox struct {
	Gen  Generation
	Role Role
	Box  SecretBox
}
type SeedChainBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen     *GenerationInternal__
	Role    *RoleInternal__
	Box     *SecretBoxInternal__
}

func (s SeedChainBoxInternal__) Import() SeedChainBox {
	return SeedChainBox{
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
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Box),
	}
}
func (s SeedChainBox) Export() *SeedChainBoxInternal__ {
	return &SeedChainBoxInternal__{
		Gen:  s.Gen.Export(),
		Role: s.Role.Export(),
		Box:  s.Box.Export(),
	}
}
func (s *SeedChainBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SeedChainBox) Decode(dec rpc.Decoder) error {
	var tmp SeedChainBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SeedChainBox) Bytes() []byte { return nil }

type SharedKeyBoxTarget struct {
	Eid  EntityID
	Host *HostID
	Role Role
	Gen  Generation
}
type SharedKeyBoxTargetInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Eid     *EntityIDInternal__
	Host    *HostIDInternal__
	Role    *RoleInternal__
	Gen     *GenerationInternal__
}

func (s SharedKeyBoxTargetInternal__) Import() SharedKeyBoxTarget {
	return SharedKeyBoxTarget{
		Eid: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Eid),
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
		})(s.Host),
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
func (s SharedKeyBoxTarget) Export() *SharedKeyBoxTargetInternal__ {
	return &SharedKeyBoxTargetInternal__{
		Eid: s.Eid.Export(),
		Host: (func(x *HostID) *HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Host),
		Role: s.Role.Export(),
		Gen:  s.Gen.Export(),
	}
}
func (s *SharedKeyBoxTarget) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyBoxTarget) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyBoxTargetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyBoxTarget) Bytes() []byte { return nil }

type SharedKeyBox struct {
	Gen  Generation
	Role Role
	Box  Box
	Targ SharedKeyBoxTarget
}
type SharedKeyBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen     *GenerationInternal__
	Role    *RoleInternal__
	Box     *BoxInternal__
	Targ    *SharedKeyBoxTargetInternal__
}

func (s SharedKeyBoxInternal__) Import() SharedKeyBox {
	return SharedKeyBox{
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
		Box: (func(x *BoxInternal__) (ret Box) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Box),
		Targ: (func(x *SharedKeyBoxTargetInternal__) (ret SharedKeyBoxTarget) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Targ),
	}
}
func (s SharedKeyBox) Export() *SharedKeyBoxInternal__ {
	return &SharedKeyBoxInternal__{
		Gen:  s.Gen.Export(),
		Role: s.Role.Export(),
		Box:  s.Box.Export(),
		Targ: s.Targ.Export(),
	}
}
func (s *SharedKeyBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyBox) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyBox) Bytes() []byte { return nil }

type SharedKeyBoxSet struct {
	Id              BoxSetID
	Boxes           []SharedKeyBox
	TempDHKeySigned *TempDHKeySigned
}
type SharedKeyBoxSetInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id              *BoxSetIDInternal__
	Boxes           *[](*SharedKeyBoxInternal__)
	TempDHKeySigned *TempDHKeySignedInternal__
}

func (s SharedKeyBoxSetInternal__) Import() SharedKeyBoxSet {
	return SharedKeyBoxSet{
		Id: (func(x *BoxSetIDInternal__) (ret BoxSetID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Boxes: (func(x *[](*SharedKeyBoxInternal__)) (ret []SharedKeyBox) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SharedKeyBox, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SharedKeyBoxInternal__) (ret SharedKeyBox) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Boxes),
		TempDHKeySigned: (func(x *TempDHKeySignedInternal__) *TempDHKeySigned {
			if x == nil {
				return nil
			}
			tmp := (func(x *TempDHKeySignedInternal__) (ret TempDHKeySigned) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.TempDHKeySigned),
	}
}
func (s SharedKeyBoxSet) Export() *SharedKeyBoxSetInternal__ {
	return &SharedKeyBoxSetInternal__{
		Id: s.Id.Export(),
		Boxes: (func(x []SharedKeyBox) *[](*SharedKeyBoxInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SharedKeyBoxInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Boxes),
		TempDHKeySigned: (func(x *TempDHKeySigned) *TempDHKeySignedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.TempDHKeySigned),
	}
}
func (s *SharedKeyBoxSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SharedKeyBoxSet) Decode(dec rpc.Decoder) error {
	var tmp SharedKeyBoxSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SharedKeyBoxSet) Bytes() []byte { return nil }

type TeamRemovalKeyBox struct {
	Box    Box
	EncKey RoleAndGen
}
type TeamRemovalKeyBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Box     *BoxInternal__
	EncKey  *RoleAndGenInternal__
}

func (t TeamRemovalKeyBoxInternal__) Import() TeamRemovalKeyBox {
	return TeamRemovalKeyBox{
		Box: (func(x *BoxInternal__) (ret Box) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Box),
		EncKey: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.EncKey),
	}
}
func (t TeamRemovalKeyBox) Export() *TeamRemovalKeyBoxInternal__ {
	return &TeamRemovalKeyBoxInternal__{
		Box:    t.Box.Export(),
		EncKey: t.EncKey.Export(),
	}
}
func (t *TeamRemovalKeyBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRemovalKeyBox) Decode(dec rpc.Decoder) error {
	var tmp TeamRemovalKeyBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRemovalKeyBox) Bytes() []byte { return nil }

type RoleAndGen struct {
	Role Role
	Gen  Generation
}
type RoleAndGenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *RoleInternal__
	Gen     *GenerationInternal__
}

func (r RoleAndGenInternal__) Import() RoleAndGen {
	return RoleAndGen{
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Role),
		Gen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Gen),
	}
}
func (r RoleAndGen) Export() *RoleAndGenInternal__ {
	return &RoleAndGenInternal__{
		Role: r.Role.Export(),
		Gen:  r.Gen.Export(),
	}
}
func (r *RoleAndGen) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleAndGen) Decode(dec rpc.Decoder) error {
	var tmp RoleAndGenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RoleAndGen) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(KeyDerivationTypeUniqueID)
	rpc.AddUnique(ChainLocationDerivationTypeUniqueID)
	rpc.AddUnique(AppKeyDerivationTypeUniqueID)
	rpc.AddUnique(KVKeyDerivationTypeUniqueID)
}
