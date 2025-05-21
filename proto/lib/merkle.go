// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/merkle.snowp

package lib

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

type MerkleNodeType int

const (
	MerkleNodeType_Leaf MerkleNodeType = 0
	MerkleNodeType_Node MerkleNodeType = 1
)

var MerkleNodeTypeMap = map[string]MerkleNodeType{
	"Leaf": 0,
	"Node": 1,
}
var MerkleNodeTypeRevMap = map[MerkleNodeType]string{
	0: "Leaf",
	1: "Node",
}

type MerkleNodeTypeInternal__ MerkleNodeType

func (m MerkleNodeTypeInternal__) Import() MerkleNodeType {
	return MerkleNodeType(m)
}
func (m MerkleNodeType) Export() *MerkleNodeTypeInternal__ {
	return ((*MerkleNodeTypeInternal__)(&m))
}

type MerkleWorkID []byte
type MerkleWorkIDInternal__ []byte

func (m MerkleWorkID) Export() *MerkleWorkIDInternal__ {
	tmp := (([]byte)(m))
	return ((*MerkleWorkIDInternal__)(&tmp))
}
func (m MerkleWorkIDInternal__) Import() MerkleWorkID {
	tmp := ([]byte)(m)
	return MerkleWorkID((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MerkleWorkID) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleWorkID) Decode(dec rpc.Decoder) error {
	var tmp MerkleWorkIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleWorkID) Bytes() []byte {
	return (m)[:]
}

type MerkleEpno uint64
type MerkleEpnoInternal__ uint64

func (m MerkleEpno) Export() *MerkleEpnoInternal__ {
	tmp := ((uint64)(m))
	return ((*MerkleEpnoInternal__)(&tmp))
}
func (m MerkleEpnoInternal__) Import() MerkleEpno {
	tmp := (uint64)(m)
	return MerkleEpno((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MerkleEpno) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleEpno) Decode(dec rpc.Decoder) error {
	var tmp MerkleEpnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleEpno) Bytes() []byte {
	return nil
}

type MerkleTreeRFOutput StdHash
type MerkleTreeRFOutputInternal__ StdHashInternal__

func (m MerkleTreeRFOutput) Export() *MerkleTreeRFOutputInternal__ {
	tmp := ((StdHash)(m))
	return ((*MerkleTreeRFOutputInternal__)(tmp.Export()))
}
func (m MerkleTreeRFOutputInternal__) Import() MerkleTreeRFOutput {
	tmp := (StdHashInternal__)(m)
	return MerkleTreeRFOutput((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (m *MerkleTreeRFOutput) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleTreeRFOutput) Decode(dec rpc.Decoder) error {
	var tmp MerkleTreeRFOutputInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleTreeRFOutput) Bytes() []byte {
	return ((StdHash)(m)).Bytes()
}

type MerkleNodeHash StdHash
type MerkleNodeHashInternal__ StdHashInternal__

func (m MerkleNodeHash) Export() *MerkleNodeHashInternal__ {
	tmp := ((StdHash)(m))
	return ((*MerkleNodeHashInternal__)(tmp.Export()))
}
func (m MerkleNodeHashInternal__) Import() MerkleNodeHash {
	tmp := (StdHashInternal__)(m)
	return MerkleNodeHash((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (m *MerkleNodeHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleNodeHash) Decode(dec rpc.Decoder) error {
	var tmp MerkleNodeHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleNodeHash) Bytes() []byte {
	return ((StdHash)(m)).Bytes()
}

type MerkleBackPointerHash StdHash
type MerkleBackPointerHashInternal__ StdHashInternal__

func (m MerkleBackPointerHash) Export() *MerkleBackPointerHashInternal__ {
	tmp := ((StdHash)(m))
	return ((*MerkleBackPointerHashInternal__)(tmp.Export()))
}
func (m MerkleBackPointerHashInternal__) Import() MerkleBackPointerHash {
	tmp := (StdHashInternal__)(m)
	return MerkleBackPointerHash((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (m *MerkleBackPointerHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBackPointerHash) Decode(dec rpc.Decoder) error {
	var tmp MerkleBackPointerHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleBackPointerHash) Bytes() []byte {
	return ((StdHash)(m)).Bytes()
}

type MerkleRootHash StdHash
type MerkleRootHashInternal__ StdHashInternal__

func (m MerkleRootHash) Export() *MerkleRootHashInternal__ {
	tmp := ((StdHash)(m))
	return ((*MerkleRootHashInternal__)(tmp.Export()))
}
func (m MerkleRootHashInternal__) Import() MerkleRootHash {
	tmp := (StdHashInternal__)(m)
	return MerkleRootHash((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (m *MerkleRootHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleRootHash) Decode(dec rpc.Decoder) error {
	var tmp MerkleRootHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleRootHash) Bytes() []byte {
	return ((StdHash)(m)).Bytes()
}

type ChainType int

const (
	ChainType_User           ChainType = 0
	ChainType_Name           ChainType = 1
	ChainType_UserSettings   ChainType = 2
	ChainType_Team           ChainType = 3
	ChainType_TeamMembership ChainType = 4
)

var ChainTypeMap = map[string]ChainType{
	"User":           0,
	"Name":           1,
	"UserSettings":   2,
	"Team":           3,
	"TeamMembership": 4,
}
var ChainTypeRevMap = map[ChainType]string{
	0: "User",
	1: "Name",
	2: "UserSettings",
	3: "Team",
	4: "TeamMembership",
}

type ChainTypeInternal__ ChainType

func (c ChainTypeInternal__) Import() ChainType {
	return ChainType(c)
}
func (c ChainType) Export() *ChainTypeInternal__ {
	return ((*ChainTypeInternal__)(&c))
}

type MerkleTreeRFInput struct {
	Ct       ChainType
	Entity   EntityID
	Seqno    Seqno
	Location *TreeLocation
}
type MerkleTreeRFInputInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ct       *ChainTypeInternal__
	Entity   *EntityIDInternal__
	Seqno    *SeqnoInternal__
	Location *TreeLocationInternal__
}

func (m MerkleTreeRFInputInternal__) Import() MerkleTreeRFInput {
	return MerkleTreeRFInput{
		Ct: (func(x *ChainTypeInternal__) (ret ChainType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Ct),
		Entity: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Entity),
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Seqno),
		Location: (func(x *TreeLocationInternal__) *TreeLocation {
			if x == nil {
				return nil
			}
			tmp := (func(x *TreeLocationInternal__) (ret TreeLocation) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Location),
	}
}
func (m MerkleTreeRFInput) Export() *MerkleTreeRFInputInternal__ {
	return &MerkleTreeRFInputInternal__{
		Ct:     m.Ct.Export(),
		Entity: m.Entity.Export(),
		Seqno:  m.Seqno.Export(),
		Location: (func(x *TreeLocation) *TreeLocationInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.Location),
	}
}
func (m *MerkleTreeRFInput) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleTreeRFInput) Decode(dec rpc.Decoder) error {
	var tmp MerkleTreeRFInputInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleTreeRFInputTypeUniqueID = rpc.TypeUniqueID(0xb0e268f388acc97a)

func (m *MerkleTreeRFInput) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleTreeRFInputTypeUniqueID
}
func (m *MerkleTreeRFInput) Bytes() []byte { return nil }

type MerkleNameInput struct {
	Name Name
}
type MerkleNameInputInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *NameInternal__
}

func (m MerkleNameInputInternal__) Import() MerkleNameInput {
	return MerkleNameInput{
		Name: (func(x *NameInternal__) (ret Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Name),
	}
}
func (m MerkleNameInput) Export() *MerkleNameInputInternal__ {
	return &MerkleNameInputInternal__{
		Name: m.Name.Export(),
	}
}
func (m *MerkleNameInput) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleNameInput) Decode(dec rpc.Decoder) error {
	var tmp MerkleNameInputInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleNameInputTypeUniqueID = rpc.TypeUniqueID(0x80ca15f6452ea908)

func (m *MerkleNameInput) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleNameInputTypeUniqueID
}
func (m *MerkleNameInput) Bytes() []byte { return nil }

type MerkleLeafUID struct {
	Uid UID
}
type MerkleLeafUIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *UIDInternal__
}

func (m MerkleLeafUIDInternal__) Import() MerkleLeafUID {
	return MerkleLeafUID{
		Uid: (func(x *UIDInternal__) (ret UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Uid),
	}
}
func (m MerkleLeafUID) Export() *MerkleLeafUIDInternal__ {
	return &MerkleLeafUIDInternal__{
		Uid: m.Uid.Export(),
	}
}
func (m *MerkleLeafUID) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleLeafUID) Decode(dec rpc.Decoder) error {
	var tmp MerkleLeafUIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleLeafUIDTypeUniqueID = rpc.TypeUniqueID(0xa7d24a9f4fcadd6f)

func (m *MerkleLeafUID) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleLeafUIDTypeUniqueID
}
func (m *MerkleLeafUID) Bytes() []byte { return nil }

type MerkleInteriorNode struct {
	PrefixBitStart uint64
	PrefixBitCount uint64
	Prefix         []byte
	Left           MerkleNodeHash
	Right          MerkleNodeHash
}
type MerkleInteriorNodeInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PrefixBitStart *uint64
	PrefixBitCount *uint64
	Prefix         *[]byte
	Left           *MerkleNodeHashInternal__
	Right          *MerkleNodeHashInternal__
}

func (m MerkleInteriorNodeInternal__) Import() MerkleInteriorNode {
	return MerkleInteriorNode{
		PrefixBitStart: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(m.PrefixBitStart),
		PrefixBitCount: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(m.PrefixBitCount),
		Prefix: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Prefix),
		Left: (func(x *MerkleNodeHashInternal__) (ret MerkleNodeHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Left),
		Right: (func(x *MerkleNodeHashInternal__) (ret MerkleNodeHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Right),
	}
}
func (m MerkleInteriorNode) Export() *MerkleInteriorNodeInternal__ {
	return &MerkleInteriorNodeInternal__{
		PrefixBitStart: &m.PrefixBitStart,
		PrefixBitCount: &m.PrefixBitCount,
		Prefix:         &m.Prefix,
		Left:           m.Left.Export(),
		Right:          m.Right.Export(),
	}
}
func (m *MerkleInteriorNode) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleInteriorNode) Decode(dec rpc.Decoder) error {
	var tmp MerkleInteriorNodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleInteriorNode) Bytes() []byte { return nil }

type MerkleLeaf struct {
	Key   MerkleTreeRFOutput
	Value StdHash
}
type MerkleLeafInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *MerkleTreeRFOutputInternal__
	Value   *StdHashInternal__
}

func (m MerkleLeafInternal__) Import() MerkleLeaf {
	return MerkleLeaf{
		Key: (func(x *MerkleTreeRFOutputInternal__) (ret MerkleTreeRFOutput) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Key),
		Value: (func(x *StdHashInternal__) (ret StdHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Value),
	}
}
func (m MerkleLeaf) Export() *MerkleLeafInternal__ {
	return &MerkleLeafInternal__{
		Key:   m.Key.Export(),
		Value: m.Value.Export(),
	}
}
func (m *MerkleLeaf) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleLeaf) Decode(dec rpc.Decoder) error {
	var tmp MerkleLeafInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleLeaf) Bytes() []byte { return nil }

type MerkleNode struct {
	T     MerkleNodeType
	F_0__ *MerkleInteriorNode `json:"f0,omitempty"`
	F_1__ *MerkleLeaf         `json:"f1,omitempty"`
}
type MerkleNodeInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        MerkleNodeType
	Switch__ MerkleNodeInternalSwitch__
}
type MerkleNodeInternalSwitch__ struct {
	_struct struct{}                      `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *MerkleInteriorNodeInternal__ `codec:"0"`
	F_1__   *MerkleLeafInternal__         `codec:"1"`
}

func (m MerkleNode) GetT() (ret MerkleNodeType, err error) {
	switch m.T {
	case MerkleNodeType_Node:
		if m.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case MerkleNodeType_Leaf:
		if m.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return m.T, nil
}
func (m MerkleNode) Node() MerkleInteriorNode {
	if m.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.T != MerkleNodeType_Node {
		panic(fmt.Sprintf("unexpected switch value (%v) when Node is called", m.T))
	}
	return *m.F_0__
}
func (m MerkleNode) Leaf() MerkleLeaf {
	if m.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.T != MerkleNodeType_Leaf {
		panic(fmt.Sprintf("unexpected switch value (%v) when Leaf is called", m.T))
	}
	return *m.F_1__
}
func NewMerkleNodeWithNode(v MerkleInteriorNode) MerkleNode {
	return MerkleNode{
		T:     MerkleNodeType_Node,
		F_0__: &v,
	}
}
func NewMerkleNodeWithLeaf(v MerkleLeaf) MerkleNode {
	return MerkleNode{
		T:     MerkleNodeType_Leaf,
		F_1__: &v,
	}
}
func (m MerkleNodeInternal__) Import() MerkleNode {
	return MerkleNode{
		T: m.T,
		F_0__: (func(x *MerkleInteriorNodeInternal__) *MerkleInteriorNode {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerkleInteriorNodeInternal__) (ret MerkleInteriorNode) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_0__),
		F_1__: (func(x *MerkleLeafInternal__) *MerkleLeaf {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerkleLeafInternal__) (ret MerkleLeaf) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_1__),
	}
}
func (m MerkleNode) Export() *MerkleNodeInternal__ {
	return &MerkleNodeInternal__{
		T: m.T,
		Switch__: MerkleNodeInternalSwitch__{
			F_0__: (func(x *MerkleInteriorNode) *MerkleInteriorNodeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_0__),
			F_1__: (func(x *MerkleLeaf) *MerkleLeafInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_1__),
		},
	}
}
func (m *MerkleNode) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleNode) Decode(dec rpc.Decoder) error {
	var tmp MerkleNodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleNodeTypeUniqueID = rpc.TypeUniqueID(0xe941750dc5b96783)

func (m *MerkleNode) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleNodeTypeUniqueID
}
func (m *MerkleNode) Bytes() []byte { return nil }

type MerkleRootVersion int

const (
	MerkleRootVersion_V1 MerkleRootVersion = 1
)

var MerkleRootVersionMap = map[string]MerkleRootVersion{
	"V1": 1,
}
var MerkleRootVersionRevMap = map[MerkleRootVersion]string{
	1: "V1",
}

type MerkleRootVersionInternal__ MerkleRootVersion

func (m MerkleRootVersionInternal__) Import() MerkleRootVersion {
	return MerkleRootVersion(m)
}
func (m MerkleRootVersion) Export() *MerkleRootVersionInternal__ {
	return ((*MerkleRootVersionInternal__)(&m))
}

type MerkleBackPointer struct {
	Epno MerkleEpno
	Hash MerkleRootHash
}
type MerkleBackPointerInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Epno    *MerkleEpnoInternal__
	Hash    *MerkleRootHashInternal__
}

func (m MerkleBackPointerInternal__) Import() MerkleBackPointer {
	return MerkleBackPointer{
		Epno: (func(x *MerkleEpnoInternal__) (ret MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Epno),
		Hash: (func(x *MerkleRootHashInternal__) (ret MerkleRootHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Hash),
	}
}
func (m MerkleBackPointer) Export() *MerkleBackPointerInternal__ {
	return &MerkleBackPointerInternal__{
		Epno: m.Epno.Export(),
		Hash: m.Hash.Export(),
	}
}
func (m *MerkleBackPointer) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBackPointer) Decode(dec rpc.Decoder) error {
	var tmp MerkleBackPointerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleBackPointer) Bytes() []byte { return nil }

type MerkleBackPointers []MerkleBackPointer
type MerkleBackPointersInternal__ [](*MerkleBackPointerInternal__)

func (m MerkleBackPointers) Export() *MerkleBackPointersInternal__ {
	tmp := (([]MerkleBackPointer)(m))
	return ((*MerkleBackPointersInternal__)((func(x []MerkleBackPointer) *[](*MerkleBackPointerInternal__) {
		if len(x) == 0 {
			return nil
		}
		ret := make([](*MerkleBackPointerInternal__), len(x))
		for k, v := range x {
			ret[k] = v.Export()
		}
		return &ret
	})(tmp)))
}
func (m MerkleBackPointersInternal__) Import() MerkleBackPointers {
	tmp := ([](*MerkleBackPointerInternal__))(m)
	return MerkleBackPointers((func(x *[](*MerkleBackPointerInternal__)) (ret []MerkleBackPointer) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]MerkleBackPointer, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *MerkleBackPointerInternal__) (ret MerkleBackPointer) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp))
}

func (m *MerkleBackPointers) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBackPointers) Decode(dec rpc.Decoder) error {
	var tmp MerkleBackPointersInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleBackPointersTypeUniqueID = rpc.TypeUniqueID(0x8c7c4b855fba9000)

func (m *MerkleBackPointers) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleBackPointersTypeUniqueID
}
func (m MerkleBackPointers) Bytes() []byte {
	return nil
}

type MerkleRootV1 struct {
	Epno         MerkleEpno
	Time         Time
	BackPointers MerkleBackPointerHash
	RootNode     MerkleNodeHash
	Hostchain    HostchainTail
}
type MerkleRootV1Internal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Epno         *MerkleEpnoInternal__
	Time         *TimeInternal__
	BackPointers *MerkleBackPointerHashInternal__
	RootNode     *MerkleNodeHashInternal__
	Hostchain    *HostchainTailInternal__
}

func (m MerkleRootV1Internal__) Import() MerkleRootV1 {
	return MerkleRootV1{
		Epno: (func(x *MerkleEpnoInternal__) (ret MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Epno),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Time),
		BackPointers: (func(x *MerkleBackPointerHashInternal__) (ret MerkleBackPointerHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.BackPointers),
		RootNode: (func(x *MerkleNodeHashInternal__) (ret MerkleNodeHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.RootNode),
		Hostchain: (func(x *HostchainTailInternal__) (ret HostchainTail) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Hostchain),
	}
}
func (m MerkleRootV1) Export() *MerkleRootV1Internal__ {
	return &MerkleRootV1Internal__{
		Epno:         m.Epno.Export(),
		Time:         m.Time.Export(),
		BackPointers: m.BackPointers.Export(),
		RootNode:     m.RootNode.Export(),
		Hostchain:    m.Hostchain.Export(),
	}
}
func (m *MerkleRootV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleRootV1) Decode(dec rpc.Decoder) error {
	var tmp MerkleRootV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleRootV1) Bytes() []byte { return nil }

type MerkleRoot struct {
	V     MerkleRootVersion
	F_1__ *MerkleRootV1 `json:"f1,omitempty"`
}
type MerkleRootInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        MerkleRootVersion
	Switch__ MerkleRootInternalSwitch__
}
type MerkleRootInternalSwitch__ struct {
	_struct struct{}                `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *MerkleRootV1Internal__ `codec:"1"`
}

func (m MerkleRoot) GetV() (ret MerkleRootVersion, err error) {
	switch m.V {
	case MerkleRootVersion_V1:
		if m.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return m.V, nil
}
func (m MerkleRoot) V1() MerkleRootV1 {
	if m.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.V != MerkleRootVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", m.V))
	}
	return *m.F_1__
}
func NewMerkleRootWithV1(v MerkleRootV1) MerkleRoot {
	return MerkleRoot{
		V:     MerkleRootVersion_V1,
		F_1__: &v,
	}
}
func (m MerkleRootInternal__) Import() MerkleRoot {
	return MerkleRoot{
		V: m.V,
		F_1__: (func(x *MerkleRootV1Internal__) *MerkleRootV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerkleRootV1Internal__) (ret MerkleRootV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_1__),
	}
}
func (m MerkleRoot) Export() *MerkleRootInternal__ {
	return &MerkleRootInternal__{
		V: m.V,
		Switch__: MerkleRootInternalSwitch__{
			F_1__: (func(x *MerkleRootV1) *MerkleRootV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_1__),
		},
	}
}
func (m *MerkleRoot) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleRoot) Decode(dec rpc.Decoder) error {
	var tmp MerkleRootInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleRootTypeUniqueID = rpc.TypeUniqueID(0xa88fc49b6df3a111)

func (m *MerkleRoot) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleRootTypeUniqueID
}
func (m *MerkleRoot) Bytes() []byte { return nil }

type MerkleRootBlob []byte
type MerkleRootBlobInternal__ []byte

func (m MerkleRootBlob) Export() *MerkleRootBlobInternal__ {
	tmp := (([]byte)(m))
	return ((*MerkleRootBlobInternal__)(&tmp))
}
func (m MerkleRootBlobInternal__) Import() MerkleRootBlob {
	tmp := ([]byte)(m)
	return MerkleRootBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MerkleRootBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleRootBlob) Decode(dec rpc.Decoder) error {
	var tmp MerkleRootBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

var MerkleRootBlobTypeUniqueID = rpc.TypeUniqueID(0xa22f0c0921d4e651)

func (m *MerkleRootBlob) GetTypeUniqueID() rpc.TypeUniqueID {
	return MerkleRootBlobTypeUniqueID
}
func (m MerkleRootBlob) Bytes() []byte {
	return (m)[:]
}
func (m *MerkleRootBlob) AllocAndDecode(f rpc.DecoderFactory) (*MerkleRoot, error) {
	var ret MerkleRoot
	src := f.NewDecoderBytes(&ret, m.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}
func (m *MerkleRootBlob) AssertNormalized() error { return nil }
func (m *MerkleRoot) EncodeTyped(f rpc.EncoderFactory) (*MerkleRootBlob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := m.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := MerkleRootBlob(tmp)
	return &ret, nil
}
func (m *MerkleRoot) ChildBlob(__b []byte) MerkleRootBlob {
	return MerkleRootBlob(__b)
}

type SignedMerkleRoot struct {
	Inner MerkleRootBlob
	Sig   Signature
}
type SignedMerkleRootInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner   *MerkleRootBlobInternal__
	Sig     *SignatureInternal__
}

func (s SignedMerkleRootInternal__) Import() SignedMerkleRoot {
	return SignedMerkleRoot{
		Inner: (func(x *MerkleRootBlobInternal__) (ret MerkleRootBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Inner),
		Sig: (func(x *SignatureInternal__) (ret Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sig),
	}
}
func (s SignedMerkleRoot) Export() *SignedMerkleRootInternal__ {
	return &SignedMerkleRootInternal__{
		Inner: s.Inner.Export(),
		Sig:   s.Sig.Export(),
	}
}
func (s *SignedMerkleRoot) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignedMerkleRoot) Decode(dec rpc.Decoder) error {
	var tmp SignedMerkleRootInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignedMerkleRoot) Bytes() []byte { return nil }

type MerkleSegment struct {
	PrefixBitCount uint64
	Prefix         []byte
}
type MerkleSegmentInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PrefixBitCount *uint64
	Prefix         *[]byte
}

func (m MerkleSegmentInternal__) Import() MerkleSegment {
	return MerkleSegment{
		PrefixBitCount: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(m.PrefixBitCount),
		Prefix: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Prefix),
	}
}
func (m MerkleSegment) Export() *MerkleSegmentInternal__ {
	return &MerkleSegmentInternal__{
		PrefixBitCount: &m.PrefixBitCount,
		Prefix:         &m.Prefix,
	}
}
func (m *MerkleSegment) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleSegment) Decode(dec rpc.Decoder) error {
	var tmp MerkleSegmentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleSegment) Bytes() []byte { return nil }

type MerklePathToLeaf struct {
	Leaf     StdHash
	FoundKey *MerkleTreeRFOutput
}
type MerklePathToLeafInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Leaf     *StdHashInternal__
	FoundKey *MerkleTreeRFOutputInternal__
}

func (m MerklePathToLeafInternal__) Import() MerklePathToLeaf {
	return MerklePathToLeaf{
		Leaf: (func(x *StdHashInternal__) (ret StdHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Leaf),
		FoundKey: (func(x *MerkleTreeRFOutputInternal__) *MerkleTreeRFOutput {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerkleTreeRFOutputInternal__) (ret MerkleTreeRFOutput) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.FoundKey),
	}
}
func (m MerklePathToLeaf) Export() *MerklePathToLeafInternal__ {
	return &MerklePathToLeafInternal__{
		Leaf: m.Leaf.Export(),
		FoundKey: (func(x *MerkleTreeRFOutput) *MerkleTreeRFOutputInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.FoundKey),
	}
}
func (m *MerklePathToLeaf) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathToLeaf) Decode(dec rpc.Decoder) error {
	var tmp MerklePathToLeafInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathToLeaf) Bytes() []byte { return nil }

type MerklePathIncomplete struct {
	NodeAtPrefixMiss MerkleInteriorNode
}
type MerklePathIncompleteInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	NodeAtPrefixMiss *MerkleInteriorNodeInternal__
}

func (m MerklePathIncompleteInternal__) Import() MerklePathIncomplete {
	return MerklePathIncomplete{
		NodeAtPrefixMiss: (func(x *MerkleInteriorNodeInternal__) (ret MerkleInteriorNode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.NodeAtPrefixMiss),
	}
}
func (m MerklePathIncomplete) Export() *MerklePathIncompleteInternal__ {
	return &MerklePathIncompleteInternal__{
		NodeAtPrefixMiss: m.NodeAtPrefixMiss.Export(),
	}
}
func (m *MerklePathIncomplete) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathIncomplete) Decode(dec rpc.Decoder) error {
	var tmp MerklePathIncompleteInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathIncomplete) Bytes() []byte { return nil }

type MerklePathTerminal struct {
	Leaf  bool
	F_0__ *MerklePathIncomplete `json:"f0,omitempty"`
	F_1__ *MerklePathToLeaf     `json:"f1,omitempty"`
}
type MerklePathTerminalInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Leaf     bool
	Switch__ MerklePathTerminalInternalSwitch__
}
type MerklePathTerminalInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *MerklePathIncompleteInternal__ `codec:"0"`
	F_1__   *MerklePathToLeafInternal__     `codec:"1"`
}

func (m MerklePathTerminal) GetLeaf() (ret bool, err error) {
	switch m.Leaf {
	case false:
		if m.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if m.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return m.Leaf, nil
}
func (m MerklePathTerminal) False() MerklePathIncomplete {
	if m.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if m.Leaf {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", m.Leaf))
	}
	return *m.F_0__
}
func (m MerklePathTerminal) True() MerklePathToLeaf {
	if m.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if !m.Leaf {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", m.Leaf))
	}
	return *m.F_1__
}
func NewMerklePathTerminalWithFalse(v MerklePathIncomplete) MerklePathTerminal {
	return MerklePathTerminal{
		Leaf:  false,
		F_0__: &v,
	}
}
func NewMerklePathTerminalWithTrue(v MerklePathToLeaf) MerklePathTerminal {
	return MerklePathTerminal{
		Leaf:  true,
		F_1__: &v,
	}
}
func (m MerklePathTerminalInternal__) Import() MerklePathTerminal {
	return MerklePathTerminal{
		Leaf: m.Leaf,
		F_0__: (func(x *MerklePathIncompleteInternal__) *MerklePathIncomplete {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerklePathIncompleteInternal__) (ret MerklePathIncomplete) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_0__),
		F_1__: (func(x *MerklePathToLeafInternal__) *MerklePathToLeaf {
			if x == nil {
				return nil
			}
			tmp := (func(x *MerklePathToLeafInternal__) (ret MerklePathToLeaf) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Switch__.F_1__),
	}
}
func (m MerklePathTerminal) Export() *MerklePathTerminalInternal__ {
	return &MerklePathTerminalInternal__{
		Leaf: m.Leaf,
		Switch__: MerklePathTerminalInternalSwitch__{
			F_0__: (func(x *MerklePathIncomplete) *MerklePathIncompleteInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_0__),
			F_1__: (func(x *MerklePathToLeaf) *MerklePathToLeafInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(m.F_1__),
		},
	}
}
func (m *MerklePathTerminal) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathTerminal) Decode(dec rpc.Decoder) error {
	var tmp MerklePathTerminalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathTerminal) Bytes() []byte { return nil }

type MerklePathCompressedBlob []byte
type MerklePathCompressedBlobInternal__ []byte

func (m MerklePathCompressedBlob) Export() *MerklePathCompressedBlobInternal__ {
	tmp := (([]byte)(m))
	return ((*MerklePathCompressedBlobInternal__)(&tmp))
}
func (m MerklePathCompressedBlobInternal__) Import() MerklePathCompressedBlob {
	tmp := ([]byte)(m)
	return MerklePathCompressedBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MerklePathCompressedBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathCompressedBlob) Decode(dec rpc.Decoder) error {
	var tmp MerklePathCompressedBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerklePathCompressedBlob) Bytes() []byte {
	return (m)[:]
}

type MerklePathCompressedPair struct {
	Path     MerklePathCompressedBlob
	Terminal MerklePathTerminal
}
type MerklePathCompressedPairInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Path     *MerklePathCompressedBlobInternal__
	Terminal *MerklePathTerminalInternal__
}

func (m MerklePathCompressedPairInternal__) Import() MerklePathCompressedPair {
	return MerklePathCompressedPair{
		Path: (func(x *MerklePathCompressedBlobInternal__) (ret MerklePathCompressedBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Path),
		Terminal: (func(x *MerklePathTerminalInternal__) (ret MerklePathTerminal) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Terminal),
	}
}
func (m MerklePathCompressedPair) Export() *MerklePathCompressedPairInternal__ {
	return &MerklePathCompressedPairInternal__{
		Path:     m.Path.Export(),
		Terminal: m.Terminal.Export(),
	}
}
func (m *MerklePathCompressedPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathCompressedPair) Decode(dec rpc.Decoder) error {
	var tmp MerklePathCompressedPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathCompressedPair) Bytes() []byte { return nil }

type MerklePathCompressed struct {
	Root     MerkleRoot
	Path     MerklePathCompressedBlob
	Terminal MerklePathTerminal
}
type MerklePathCompressedInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Root     *MerkleRootInternal__
	Path     *MerklePathCompressedBlobInternal__
	Terminal *MerklePathTerminalInternal__
}

func (m MerklePathCompressedInternal__) Import() MerklePathCompressed {
	return MerklePathCompressed{
		Root: (func(x *MerkleRootInternal__) (ret MerkleRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Root),
		Path: (func(x *MerklePathCompressedBlobInternal__) (ret MerklePathCompressedBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Path),
		Terminal: (func(x *MerklePathTerminalInternal__) (ret MerklePathTerminal) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Terminal),
	}
}
func (m MerklePathCompressed) Export() *MerklePathCompressedInternal__ {
	return &MerklePathCompressedInternal__{
		Root:     m.Root.Export(),
		Path:     m.Path.Export(),
		Terminal: m.Terminal.Export(),
	}
}
func (m *MerklePathCompressed) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathCompressed) Decode(dec rpc.Decoder) error {
	var tmp MerklePathCompressedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathCompressed) Bytes() []byte { return nil }

type MerklePathsCompressed struct {
	Root  MerkleRoot
	Paths []MerklePathCompressedPair
}
type MerklePathsCompressedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Root    *MerkleRootInternal__
	Paths   *[](*MerklePathCompressedPairInternal__)
}

func (m MerklePathsCompressedInternal__) Import() MerklePathsCompressed {
	return MerklePathsCompressed{
		Root: (func(x *MerkleRootInternal__) (ret MerkleRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Root),
		Paths: (func(x *[](*MerklePathCompressedPairInternal__)) (ret []MerklePathCompressedPair) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]MerklePathCompressedPair, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *MerklePathCompressedPairInternal__) (ret MerklePathCompressedPair) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(m.Paths),
	}
}
func (m MerklePathsCompressed) Export() *MerklePathsCompressedInternal__ {
	return &MerklePathsCompressedInternal__{
		Root: m.Root.Export(),
		Paths: (func(x []MerklePathCompressedPair) *[](*MerklePathCompressedPairInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*MerklePathCompressedPairInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(m.Paths),
	}
}
func (m *MerklePathsCompressed) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerklePathsCompressed) Decode(dec rpc.Decoder) error {
	var tmp MerklePathsCompressedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerklePathsCompressed) Bytes() []byte { return nil }

type MerkleUpdateBatch struct {
	Epno   MerkleEpno
	Leaves []MerkleLeaf
}
type MerkleUpdateBatchInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Epno    *MerkleEpnoInternal__
	Leaves  *[](*MerkleLeafInternal__)
}

func (m MerkleUpdateBatchInternal__) Import() MerkleUpdateBatch {
	return MerkleUpdateBatch{
		Epno: (func(x *MerkleEpnoInternal__) (ret MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Epno),
		Leaves: (func(x *[](*MerkleLeafInternal__)) (ret []MerkleLeaf) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]MerkleLeaf, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *MerkleLeafInternal__) (ret MerkleLeaf) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(m.Leaves),
	}
}
func (m MerkleUpdateBatch) Export() *MerkleUpdateBatchInternal__ {
	return &MerkleUpdateBatchInternal__{
		Epno: m.Epno.Export(),
		Leaves: (func(x []MerkleLeaf) *[](*MerkleLeafInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*MerkleLeafInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(m.Leaves),
	}
}
func (m *MerkleUpdateBatch) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleUpdateBatch) Decode(dec rpc.Decoder) error {
	var tmp MerkleUpdateBatchInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleUpdateBatch) Bytes() []byte { return nil }

var MerkleBuilderProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x9a712168)

type MerkleBuilderPokeArg struct {
}
type MerkleBuilderPokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (m MerkleBuilderPokeArgInternal__) Import() MerkleBuilderPokeArg {
	return MerkleBuilderPokeArg{}
}
func (m MerkleBuilderPokeArg) Export() *MerkleBuilderPokeArgInternal__ {
	return &MerkleBuilderPokeArgInternal__{}
}
func (m *MerkleBuilderPokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBuilderPokeArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleBuilderPokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleBuilderPokeArg) Bytes() []byte { return nil }

type MerkleBuilderInterface interface {
	Poke(context.Context) error
	ErrorWrapper() func(error) Status
}

func MerkleBuilderMakeGenericErrorWrapper(f MerkleBuilderErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type MerkleBuilderErrorUnwrapper func(Status) error
type MerkleBuilderErrorWrapper func(error) Status

type merkleBuilderErrorUnwrapperAdapter struct {
	h MerkleBuilderErrorUnwrapper
}

func (m merkleBuilderErrorUnwrapperAdapter) MakeArg() interface{} {
	return &StatusInternal__{}
}

func (m merkleBuilderErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return m.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = merkleBuilderErrorUnwrapperAdapter{}

type MerkleBuilderClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper MerkleBuilderErrorUnwrapper
}

func (c MerkleBuilderClient) Poke(ctx context.Context) (err error) {
	var arg MerkleBuilderPokeArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleBuilderProtocolID, 0, "MerkleBuilder.poke"), warg, nil, 0*time.Millisecond, merkleBuilderErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func MerkleBuilderProtocol(i MerkleBuilderInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "MerkleBuilder",
		ID:   MerkleBuilderProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret MerkleBuilderPokeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*MerkleBuilderPokeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*MerkleBuilderPokeArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Poke(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "poke",
			},
		},
		WrapError: MerkleBuilderMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var MerkleBatcherProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xdc826c84)

type MerkleBatcherPokeArg struct {
}
type MerkleBatcherPokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (m MerkleBatcherPokeArgInternal__) Import() MerkleBatcherPokeArg {
	return MerkleBatcherPokeArg{}
}
func (m MerkleBatcherPokeArg) Export() *MerkleBatcherPokeArgInternal__ {
	return &MerkleBatcherPokeArgInternal__{}
}
func (m *MerkleBatcherPokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBatcherPokeArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleBatcherPokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleBatcherPokeArg) Bytes() []byte { return nil }

type MerkleBatcherInterface interface {
	Poke(context.Context) error
	ErrorWrapper() func(error) Status
}

func MerkleBatcherMakeGenericErrorWrapper(f MerkleBatcherErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type MerkleBatcherErrorUnwrapper func(Status) error
type MerkleBatcherErrorWrapper func(error) Status

type merkleBatcherErrorUnwrapperAdapter struct {
	h MerkleBatcherErrorUnwrapper
}

func (m merkleBatcherErrorUnwrapperAdapter) MakeArg() interface{} {
	return &StatusInternal__{}
}

func (m merkleBatcherErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return m.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = merkleBatcherErrorUnwrapperAdapter{}

type MerkleBatcherClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper MerkleBatcherErrorUnwrapper
}

func (c MerkleBatcherClient) Poke(ctx context.Context) (err error) {
	var arg MerkleBatcherPokeArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleBatcherProtocolID, 0, "MerkleBatcher.poke"), warg, nil, 0*time.Millisecond, merkleBatcherErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func MerkleBatcherProtocol(i MerkleBatcherInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "MerkleBatcher",
		ID:   MerkleBatcherProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret MerkleBatcherPokeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*MerkleBatcherPokeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*MerkleBatcherPokeArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Poke(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "poke",
			},
		},
		WrapError: MerkleBatcherMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var MerkleSignerProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x8630fe8e)

type MerkleSignerPokeArg struct {
}
type MerkleSignerPokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (m MerkleSignerPokeArgInternal__) Import() MerkleSignerPokeArg {
	return MerkleSignerPokeArg{}
}
func (m MerkleSignerPokeArg) Export() *MerkleSignerPokeArgInternal__ {
	return &MerkleSignerPokeArgInternal__{}
}
func (m *MerkleSignerPokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleSignerPokeArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleSignerPokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleSignerPokeArg) Bytes() []byte { return nil }

type MerkleSignerInterface interface {
	Poke(context.Context) error
	ErrorWrapper() func(error) Status
}

func MerkleSignerMakeGenericErrorWrapper(f MerkleSignerErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type MerkleSignerErrorUnwrapper func(Status) error
type MerkleSignerErrorWrapper func(error) Status

type merkleSignerErrorUnwrapperAdapter struct {
	h MerkleSignerErrorUnwrapper
}

func (m merkleSignerErrorUnwrapperAdapter) MakeArg() interface{} {
	return &StatusInternal__{}
}

func (m merkleSignerErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return m.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = merkleSignerErrorUnwrapperAdapter{}

type MerkleSignerClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper MerkleSignerErrorUnwrapper
}

func (c MerkleSignerClient) Poke(ctx context.Context) (err error) {
	var arg MerkleSignerPokeArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleSignerProtocolID, 0, "MerkleSigner.poke"), warg, nil, 0*time.Millisecond, merkleSignerErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func MerkleSignerProtocol(i MerkleSignerInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "MerkleSigner",
		ID:   MerkleSignerProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret MerkleSignerPokeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*MerkleSignerPokeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*MerkleSignerPokeArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Poke(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "poke",
			},
		},
		WrapError: MerkleSignerMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

type MerkleBatchNo uint64
type MerkleBatchNoInternal__ uint64

func (m MerkleBatchNo) Export() *MerkleBatchNoInternal__ {
	tmp := ((uint64)(m))
	return ((*MerkleBatchNoInternal__)(&tmp))
}
func (m MerkleBatchNoInternal__) Import() MerkleBatchNo {
	tmp := (uint64)(m)
	return MerkleBatchNo((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MerkleBatchNo) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBatchNo) Decode(dec rpc.Decoder) error {
	var tmp MerkleBatchNoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MerkleBatchNo) Bytes() []byte {
	return nil
}

type MerkleBatch struct {
	Batchno   MerkleBatchNo
	Time      Time
	Leaves    []MerkleLeaf
	Hostchain *HostchainTail
}
type MerkleBatchInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Batchno   *MerkleBatchNoInternal__
	Time      *TimeInternal__
	Leaves    *[](*MerkleLeafInternal__)
	Hostchain *HostchainTailInternal__
}

func (m MerkleBatchInternal__) Import() MerkleBatch {
	return MerkleBatch{
		Batchno: (func(x *MerkleBatchNoInternal__) (ret MerkleBatchNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Batchno),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Time),
		Leaves: (func(x *[](*MerkleLeafInternal__)) (ret []MerkleLeaf) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]MerkleLeaf, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *MerkleLeafInternal__) (ret MerkleLeaf) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(m.Leaves),
		Hostchain: (func(x *HostchainTailInternal__) *HostchainTail {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostchainTailInternal__) (ret HostchainTail) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Hostchain),
	}
}
func (m MerkleBatch) Export() *MerkleBatchInternal__ {
	return &MerkleBatchInternal__{
		Batchno: m.Batchno.Export(),
		Time:    m.Time.Export(),
		Leaves: (func(x []MerkleLeaf) *[](*MerkleLeafInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*MerkleLeafInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(m.Leaves),
		Hostchain: (func(x *HostchainTail) *HostchainTailInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.Hostchain),
	}
}
func (m *MerkleBatch) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBatch) Decode(dec rpc.Decoder) error {
	var tmp MerkleBatchInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleBatch) Bytes() []byte { return nil }

type MerkleBatcherState struct {
	Next MerkleBatchNo
}
type MerkleBatcherStateInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Next    *MerkleBatchNoInternal__
}

func (m MerkleBatcherStateInternal__) Import() MerkleBatcherState {
	return MerkleBatcherState{
		Next: (func(x *MerkleBatchNoInternal__) (ret MerkleBatchNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Next),
	}
}
func (m MerkleBatcherState) Export() *MerkleBatcherStateInternal__ {
	return &MerkleBatcherStateInternal__{
		Next: m.Next.Export(),
	}
}
func (m *MerkleBatcherState) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleBatcherState) Decode(dec rpc.Decoder) error {
	var tmp MerkleBatcherStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleBatcherState) Bytes() []byte { return nil }

type UpdateTriggerType int

const (
	UpdateTriggerType_None       UpdateTriggerType = 0
	UpdateTriggerType_Revoke     UpdateTriggerType = 1
	UpdateTriggerType_Provision  UpdateTriggerType = 2
	UpdateTriggerType_TeamChange UpdateTriggerType = 3
)

var UpdateTriggerTypeMap = map[string]UpdateTriggerType{
	"None":       0,
	"Revoke":     1,
	"Provision":  2,
	"TeamChange": 3,
}
var UpdateTriggerTypeRevMap = map[UpdateTriggerType]string{
	0: "None",
	1: "Revoke",
	2: "Provision",
	3: "TeamChange",
}

type UpdateTriggerTypeInternal__ UpdateTriggerType

func (u UpdateTriggerTypeInternal__) Import() UpdateTriggerType {
	return UpdateTriggerType(u)
}
func (u UpdateTriggerType) Export() *UpdateTriggerTypeInternal__ {
	return ((*UpdateTriggerTypeInternal__)(&u))
}

type UpdateTriggerRevoke struct {
	PartyID     PartyID
	VerifyKeyID EntityID
	Epno        MerkleEpno
}
type UpdateTriggerRevokeInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PartyID     *PartyIDInternal__
	VerifyKeyID *EntityIDInternal__
	Epno        *MerkleEpnoInternal__
}

func (u UpdateTriggerRevokeInternal__) Import() UpdateTriggerRevoke {
	return UpdateTriggerRevoke{
		PartyID: (func(x *PartyIDInternal__) (ret PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.PartyID),
		VerifyKeyID: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.VerifyKeyID),
		Epno: (func(x *MerkleEpnoInternal__) (ret MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Epno),
	}
}
func (u UpdateTriggerRevoke) Export() *UpdateTriggerRevokeInternal__ {
	return &UpdateTriggerRevokeInternal__{
		PartyID:     u.PartyID.Export(),
		VerifyKeyID: u.VerifyKeyID.Export(),
		Epno:        u.Epno.Export(),
	}
}
func (u *UpdateTriggerRevoke) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UpdateTriggerRevoke) Decode(dec rpc.Decoder) error {
	var tmp UpdateTriggerRevokeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UpdateTriggerRevoke) Bytes() []byte { return nil }

type UpdateTriggerTeamChange struct {
	Team    TeamID
	Seqno   Seqno
	Changes []MemberRole
	NewKeys []SharedKey
}
type UpdateTriggerTeamChangeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *TeamIDInternal__
	Seqno   *SeqnoInternal__
	Changes *[](*MemberRoleInternal__)
	NewKeys *[](*SharedKeyInternal__)
}

func (u UpdateTriggerTeamChangeInternal__) Import() UpdateTriggerTeamChange {
	return UpdateTriggerTeamChange{
		Team: (func(x *TeamIDInternal__) (ret TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Team),
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Seqno),
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
		})(u.Changes),
		NewKeys: (func(x *[](*SharedKeyInternal__)) (ret []SharedKey) {
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
		})(u.NewKeys),
	}
}
func (u UpdateTriggerTeamChange) Export() *UpdateTriggerTeamChangeInternal__ {
	return &UpdateTriggerTeamChangeInternal__{
		Team:  u.Team.Export(),
		Seqno: u.Seqno.Export(),
		Changes: (func(x []MemberRole) *[](*MemberRoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*MemberRoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Changes),
		NewKeys: (func(x []SharedKey) *[](*SharedKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SharedKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.NewKeys),
	}
}
func (u *UpdateTriggerTeamChange) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UpdateTriggerTeamChange) Decode(dec rpc.Decoder) error {
	var tmp UpdateTriggerTeamChangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UpdateTriggerTeamChange) Bytes() []byte { return nil }

type UpdateTriggerProvision struct {
	Eid EntityID
}
type UpdateTriggerProvisionInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Eid     *EntityIDInternal__
}

func (u UpdateTriggerProvisionInternal__) Import() UpdateTriggerProvision {
	return UpdateTriggerProvision{
		Eid: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Eid),
	}
}
func (u UpdateTriggerProvision) Export() *UpdateTriggerProvisionInternal__ {
	return &UpdateTriggerProvisionInternal__{
		Eid: u.Eid.Export(),
	}
}
func (u *UpdateTriggerProvision) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UpdateTriggerProvision) Decode(dec rpc.Decoder) error {
	var tmp UpdateTriggerProvisionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UpdateTriggerProvision) Bytes() []byte { return nil }

type UpdateTrigger struct {
	T     UpdateTriggerType
	F_1__ *UpdateTriggerRevoke     `json:"f1,omitempty"`
	F_2__ *UpdateTriggerProvision  `json:"f2,omitempty"`
	F_3__ *UpdateTriggerTeamChange `json:"f3,omitempty"`
}
type UpdateTriggerInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        UpdateTriggerType
	Switch__ UpdateTriggerInternalSwitch__
}
type UpdateTriggerInternalSwitch__ struct {
	_struct struct{}                           `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *UpdateTriggerRevokeInternal__     `codec:"1"`
	F_2__   *UpdateTriggerProvisionInternal__  `codec:"2"`
	F_3__   *UpdateTriggerTeamChangeInternal__ `codec:"3"`
}

func (u UpdateTrigger) GetT() (ret UpdateTriggerType, err error) {
	switch u.T {
	case UpdateTriggerType_Revoke:
		if u.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case UpdateTriggerType_Provision:
		if u.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case UpdateTriggerType_TeamChange:
		if u.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	default:
		break
	}
	return u.T, nil
}
func (u UpdateTrigger) Revoke() UpdateTriggerRevoke {
	if u.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != UpdateTriggerType_Revoke {
		panic(fmt.Sprintf("unexpected switch value (%v) when Revoke is called", u.T))
	}
	return *u.F_1__
}
func (u UpdateTrigger) Provision() UpdateTriggerProvision {
	if u.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != UpdateTriggerType_Provision {
		panic(fmt.Sprintf("unexpected switch value (%v) when Provision is called", u.T))
	}
	return *u.F_2__
}
func (u UpdateTrigger) Teamchange() UpdateTriggerTeamChange {
	if u.F_3__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != UpdateTriggerType_TeamChange {
		panic(fmt.Sprintf("unexpected switch value (%v) when Teamchange is called", u.T))
	}
	return *u.F_3__
}
func NewUpdateTriggerWithRevoke(v UpdateTriggerRevoke) UpdateTrigger {
	return UpdateTrigger{
		T:     UpdateTriggerType_Revoke,
		F_1__: &v,
	}
}
func NewUpdateTriggerWithProvision(v UpdateTriggerProvision) UpdateTrigger {
	return UpdateTrigger{
		T:     UpdateTriggerType_Provision,
		F_2__: &v,
	}
}
func NewUpdateTriggerWithTeamchange(v UpdateTriggerTeamChange) UpdateTrigger {
	return UpdateTrigger{
		T:     UpdateTriggerType_TeamChange,
		F_3__: &v,
	}
}
func NewUpdateTriggerDefault(s UpdateTriggerType) UpdateTrigger {
	return UpdateTrigger{
		T: s,
	}
}
func (u UpdateTriggerInternal__) Import() UpdateTrigger {
	return UpdateTrigger{
		T: u.T,
		F_1__: (func(x *UpdateTriggerRevokeInternal__) *UpdateTriggerRevoke {
			if x == nil {
				return nil
			}
			tmp := (func(x *UpdateTriggerRevokeInternal__) (ret UpdateTriggerRevoke) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_1__),
		F_2__: (func(x *UpdateTriggerProvisionInternal__) *UpdateTriggerProvision {
			if x == nil {
				return nil
			}
			tmp := (func(x *UpdateTriggerProvisionInternal__) (ret UpdateTriggerProvision) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_2__),
		F_3__: (func(x *UpdateTriggerTeamChangeInternal__) *UpdateTriggerTeamChange {
			if x == nil {
				return nil
			}
			tmp := (func(x *UpdateTriggerTeamChangeInternal__) (ret UpdateTriggerTeamChange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_3__),
	}
}
func (u UpdateTrigger) Export() *UpdateTriggerInternal__ {
	return &UpdateTriggerInternal__{
		T: u.T,
		Switch__: UpdateTriggerInternalSwitch__{
			F_1__: (func(x *UpdateTriggerRevoke) *UpdateTriggerRevokeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_1__),
			F_2__: (func(x *UpdateTriggerProvision) *UpdateTriggerProvisionInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_2__),
			F_3__: (func(x *UpdateTriggerTeamChange) *UpdateTriggerTeamChangeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_3__),
		},
	}
}
func (u *UpdateTrigger) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UpdateTrigger) Decode(dec rpc.Decoder) error {
	var tmp UpdateTriggerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UpdateTrigger) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(MerkleTreeRFInputTypeUniqueID)
	rpc.AddUnique(MerkleNameInputTypeUniqueID)
	rpc.AddUnique(MerkleLeafUIDTypeUniqueID)
	rpc.AddUnique(MerkleNodeTypeUniqueID)
	rpc.AddUnique(MerkleBackPointersTypeUniqueID)
	rpc.AddUnique(MerkleRootTypeUniqueID)
	rpc.AddUnique(MerkleRootBlobTypeUniqueID)
	rpc.AddUnique(MerkleBuilderProtocolID)
	rpc.AddUnique(MerkleBatcherProtocolID)
	rpc.AddUnique(MerkleSignerProtocolID)
}
