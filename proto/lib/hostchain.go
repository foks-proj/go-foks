// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/hostchain.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type HostchainChangeType int

const (
	HostchainChangeType_None   HostchainChangeType = 0
	HostchainChangeType_Revoke HostchainChangeType = 1
	HostchainChangeType_Key    HostchainChangeType = 2
	HostchainChangeType_TLSCA  HostchainChangeType = 3
)

var HostchainChangeTypeMap = map[string]HostchainChangeType{
	"None":   0,
	"Revoke": 1,
	"Key":    2,
	"TLSCA":  3,
}

var HostchainChangeTypeRevMap = map[HostchainChangeType]string{
	0: "None",
	1: "Revoke",
	2: "Key",
	3: "TLSCA",
}

type HostchainChangeTypeInternal__ HostchainChangeType

func (h HostchainChangeTypeInternal__) Import() HostchainChangeType {
	return HostchainChangeType(h)
}

func (h HostchainChangeType) Export() *HostchainChangeTypeInternal__ {
	return ((*HostchainChangeTypeInternal__)(&h))
}

type HostTLSCA struct {
	Id   HostTLSCAID
	Cert []byte
}

type HostTLSCAInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *HostTLSCAIDInternal__
	Cert    *[]byte
}

func (h HostTLSCAInternal__) Import() HostTLSCA {
	return HostTLSCA{
		Id: (func(x *HostTLSCAIDInternal__) (ret HostTLSCAID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Id),
		Cert: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(h.Cert),
	}
}

func (h HostTLSCA) Export() *HostTLSCAInternal__ {
	return &HostTLSCAInternal__{
		Id:   h.Id.Export(),
		Cert: &h.Cert,
	}
}

func (h *HostTLSCA) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostTLSCA) Decode(dec rpc.Decoder) error {
	var tmp HostTLSCAInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostTLSCA) Bytes() []byte { return nil }

type HostchainChangeItem struct {
	T     HostchainChangeType
	F_1__ *EntityID  `json:"f1,omitempty"`
	F_2__ *EntityID  `json:"f2,omitempty"`
	F_3__ *HostTLSCA `json:"f3,omitempty"`
}

type HostchainChangeItemInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        HostchainChangeType
	Switch__ HostchainChangeItemInternalSwitch__
}

type HostchainChangeItemInternalSwitch__ struct {
	_struct struct{}             `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *EntityIDInternal__  `codec:"1"`
	F_2__   *EntityIDInternal__  `codec:"2"`
	F_3__   *HostTLSCAInternal__ `codec:"3"`
}

func (h HostchainChangeItem) GetT() (ret HostchainChangeType, err error) {
	switch h.T {
	case HostchainChangeType_Revoke:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case HostchainChangeType_Key:
		if h.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case HostchainChangeType_TLSCA:
		if h.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	}
	return h.T, nil
}

func (h HostchainChangeItem) Revoke() EntityID {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.T != HostchainChangeType_Revoke {
		panic(fmt.Sprintf("unexpected switch value (%v) when Revoke is called", h.T))
	}
	return *h.F_1__
}

func (h HostchainChangeItem) Key() EntityID {
	if h.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.T != HostchainChangeType_Key {
		panic(fmt.Sprintf("unexpected switch value (%v) when Key is called", h.T))
	}
	return *h.F_2__
}

func (h HostchainChangeItem) Tlsca() HostTLSCA {
	if h.F_3__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.T != HostchainChangeType_TLSCA {
		panic(fmt.Sprintf("unexpected switch value (%v) when Tlsca is called", h.T))
	}
	return *h.F_3__
}

func NewHostchainChangeItemWithRevoke(v EntityID) HostchainChangeItem {
	return HostchainChangeItem{
		T:     HostchainChangeType_Revoke,
		F_1__: &v,
	}
}

func NewHostchainChangeItemWithKey(v EntityID) HostchainChangeItem {
	return HostchainChangeItem{
		T:     HostchainChangeType_Key,
		F_2__: &v,
	}
}

func NewHostchainChangeItemWithTlsca(v HostTLSCA) HostchainChangeItem {
	return HostchainChangeItem{
		T:     HostchainChangeType_TLSCA,
		F_3__: &v,
	}
}

func (h HostchainChangeItemInternal__) Import() HostchainChangeItem {
	return HostchainChangeItem{
		T: h.T,
		F_1__: (func(x *EntityIDInternal__) *EntityID {
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
		})(h.Switch__.F_1__),
		F_2__: (func(x *EntityIDInternal__) *EntityID {
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
		})(h.Switch__.F_2__),
		F_3__: (func(x *HostTLSCAInternal__) *HostTLSCA {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostTLSCAInternal__) (ret HostTLSCA) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_3__),
	}
}

func (h HostchainChangeItem) Export() *HostchainChangeItemInternal__ {
	return &HostchainChangeItemInternal__{
		T: h.T,
		Switch__: HostchainChangeItemInternalSwitch__{
			F_1__: (func(x *EntityID) *EntityIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
			F_2__: (func(x *EntityID) *EntityIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_2__),
			F_3__: (func(x *HostTLSCA) *HostTLSCAInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_3__),
		},
	}
}

func (h *HostchainChangeItem) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainChangeItem) Decode(dec rpc.Decoder) error {
	var tmp HostchainChangeItemInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostchainChangeItemTypeUniqueID = rpc.TypeUniqueID(0xf653d2ca359b0624)

func (h *HostchainChangeItem) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostchainChangeItemTypeUniqueID
}

func (h *HostchainChangeItem) Bytes() []byte { return nil }

type HostchainChange struct {
	Chainer BaseChainer
	Host    HostID
	Signer  HostID
	Changes []HostchainChangeItem
}

type HostchainChangeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chainer *BaseChainerInternal__
	Host    *HostIDInternal__
	Signer  *HostIDInternal__
	Changes *[](*HostchainChangeItemInternal__)
}

func (h HostchainChangeInternal__) Import() HostchainChange {
	return HostchainChange{
		Chainer: (func(x *BaseChainerInternal__) (ret BaseChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Chainer),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Host),
		Signer: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Signer),
		Changes: (func(x *[](*HostchainChangeItemInternal__)) (ret []HostchainChangeItem) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]HostchainChangeItem, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *HostchainChangeItemInternal__) (ret HostchainChangeItem) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(h.Changes),
	}
}

func (h HostchainChange) Export() *HostchainChangeInternal__ {
	return &HostchainChangeInternal__{
		Chainer: h.Chainer.Export(),
		Host:    h.Host.Export(),
		Signer:  h.Signer.Export(),
		Changes: (func(x []HostchainChangeItem) *[](*HostchainChangeItemInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*HostchainChangeItemInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(h.Changes),
	}
}

func (h *HostchainChange) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainChange) Decode(dec rpc.Decoder) error {
	var tmp HostchainChangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostchainChangeTypeUniqueID = rpc.TypeUniqueID(0xfac18a7a1f30f887)

func (h *HostchainChange) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostchainChangeTypeUniqueID
}

func (h *HostchainChange) Bytes() []byte { return nil }

type HostchainLinkType int

const (
	HostchainLinkType_Change    HostchainLinkType = 1
	HostchainLinkType_Discovery HostchainLinkType = 2
)

var HostchainLinkTypeMap = map[string]HostchainLinkType{
	"Change":    1,
	"Discovery": 2,
}

var HostchainLinkTypeRevMap = map[HostchainLinkType]string{
	1: "Change",
	2: "Discovery",
}

type HostchainLinkTypeInternal__ HostchainLinkType

func (h HostchainLinkTypeInternal__) Import() HostchainLinkType {
	return HostchainLinkType(h)
}

func (h HostchainLinkType) Export() *HostchainLinkTypeInternal__ {
	return ((*HostchainLinkTypeInternal__)(&h))
}

type HostchainLinkInner struct {
	T     HostchainLinkType
	F_1__ *HostchainChange `json:"f1,omitempty"`
}

type HostchainLinkInnerInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        HostchainLinkType
	Switch__ HostchainLinkInnerInternalSwitch__
}

type HostchainLinkInnerInternalSwitch__ struct {
	_struct struct{}                   `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HostchainChangeInternal__ `codec:"1"`
}

func (h HostchainLinkInner) GetT() (ret HostchainLinkType, err error) {
	switch h.T {
	case HostchainLinkType_Change:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return h.T, nil
}

func (h HostchainLinkInner) Change() HostchainChange {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.T != HostchainLinkType_Change {
		panic(fmt.Sprintf("unexpected switch value (%v) when Change is called", h.T))
	}
	return *h.F_1__
}

func NewHostchainLinkInnerWithChange(v HostchainChange) HostchainLinkInner {
	return HostchainLinkInner{
		T:     HostchainLinkType_Change,
		F_1__: &v,
	}
}

func (h HostchainLinkInnerInternal__) Import() HostchainLinkInner {
	return HostchainLinkInner{
		T: h.T,
		F_1__: (func(x *HostchainChangeInternal__) *HostchainChange {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostchainChangeInternal__) (ret HostchainChange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_1__),
	}
}

func (h HostchainLinkInner) Export() *HostchainLinkInnerInternal__ {
	return &HostchainLinkInnerInternal__{
		T: h.T,
		Switch__: HostchainLinkInnerInternalSwitch__{
			F_1__: (func(x *HostchainChange) *HostchainChangeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
		},
	}
}

func (h *HostchainLinkInner) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainLinkInner) Decode(dec rpc.Decoder) error {
	var tmp HostchainLinkInnerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostchainLinkInnerTypeUniqueID = rpc.TypeUniqueID(0xc2fc3a01ef13daa8)

func (h *HostchainLinkInner) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostchainLinkInnerTypeUniqueID
}

func (h *HostchainLinkInner) Bytes() []byte { return nil }

type HostchainLinkVersion int

const (
	HostchainLinkVersion_V1 HostchainLinkVersion = 1
)

var HostchainLinkVersionMap = map[string]HostchainLinkVersion{
	"V1": 1,
}

var HostchainLinkVersionRevMap = map[HostchainLinkVersion]string{
	1: "V1",
}

type HostchainLinkVersionInternal__ HostchainLinkVersion

func (h HostchainLinkVersionInternal__) Import() HostchainLinkVersion {
	return HostchainLinkVersion(h)
}

func (h HostchainLinkVersion) Export() *HostchainLinkVersionInternal__ {
	return ((*HostchainLinkVersionInternal__)(&h))
}

type HostchainLinkOuterV1 struct {
	Inner      []byte
	Signatures []Signature
}

type HostchainLinkOuterV1Internal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner      *[]byte
	Signatures *[](*SignatureInternal__)
}

func (h HostchainLinkOuterV1Internal__) Import() HostchainLinkOuterV1 {
	return HostchainLinkOuterV1{
		Inner: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(h.Inner),
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
		})(h.Signatures),
	}
}

func (h HostchainLinkOuterV1) Export() *HostchainLinkOuterV1Internal__ {
	return &HostchainLinkOuterV1Internal__{
		Inner: &h.Inner,
		Signatures: (func(x []Signature) *[](*SignatureInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SignatureInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(h.Signatures),
	}
}

func (h *HostchainLinkOuterV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainLinkOuterV1) Decode(dec rpc.Decoder) error {
	var tmp HostchainLinkOuterV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostchainLinkOuterV1TypeUniqueID = rpc.TypeUniqueID(0xa23ba3620d758f7a)

func (h *HostchainLinkOuterV1) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostchainLinkOuterV1TypeUniqueID
}

func (h *HostchainLinkOuterV1) Bytes() []byte { return nil }

type HostchainLinkOuter struct {
	V     HostchainLinkVersion
	F_1__ *HostchainLinkOuterV1 `json:"f1,omitempty"`
}

type HostchainLinkOuterInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        HostchainLinkVersion
	Switch__ HostchainLinkOuterInternalSwitch__
}

type HostchainLinkOuterInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HostchainLinkOuterV1Internal__ `codec:"1"`
}

func (h HostchainLinkOuter) GetV() (ret HostchainLinkVersion, err error) {
	switch h.V {
	case HostchainLinkVersion_V1:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return h.V, nil
}

func (h HostchainLinkOuter) V1() HostchainLinkOuterV1 {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.V != HostchainLinkVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", h.V))
	}
	return *h.F_1__
}

func NewHostchainLinkOuterWithV1(v HostchainLinkOuterV1) HostchainLinkOuter {
	return HostchainLinkOuter{
		V:     HostchainLinkVersion_V1,
		F_1__: &v,
	}
}

func (h HostchainLinkOuterInternal__) Import() HostchainLinkOuter {
	return HostchainLinkOuter{
		V: h.V,
		F_1__: (func(x *HostchainLinkOuterV1Internal__) *HostchainLinkOuterV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostchainLinkOuterV1Internal__) (ret HostchainLinkOuterV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_1__),
	}
}

func (h HostchainLinkOuter) Export() *HostchainLinkOuterInternal__ {
	return &HostchainLinkOuterInternal__{
		V: h.V,
		Switch__: HostchainLinkOuterInternalSwitch__{
			F_1__: (func(x *HostchainLinkOuterV1) *HostchainLinkOuterV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
		},
	}
}

func (h *HostchainLinkOuter) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainLinkOuter) Decode(dec rpc.Decoder) error {
	var tmp HostchainLinkOuterInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostchainLinkOuterTypeUniqueID = rpc.TypeUniqueID(0x8d87ac224920355c)

func (h *HostchainLinkOuter) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostchainLinkOuterTypeUniqueID
}

func (h *HostchainLinkOuter) Bytes() []byte { return nil }

type HostKeyPrivateStorageV1 struct {
	Type EntityType
	Time Time
	Seed Ed25519SecretKey
}

type HostKeyPrivateStorageV1Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Type    *EntityTypeInternal__
	Time    *TimeInternal__
	Seed    *Ed25519SecretKeyInternal__
}

func (h HostKeyPrivateStorageV1Internal__) Import() HostKeyPrivateStorageV1 {
	return HostKeyPrivateStorageV1{
		Type: (func(x *EntityTypeInternal__) (ret EntityType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Type),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Time),
		Seed: (func(x *Ed25519SecretKeyInternal__) (ret Ed25519SecretKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Seed),
	}
}

func (h HostKeyPrivateStorageV1) Export() *HostKeyPrivateStorageV1Internal__ {
	return &HostKeyPrivateStorageV1Internal__{
		Type: h.Type.Export(),
		Time: h.Time.Export(),
		Seed: h.Seed.Export(),
	}
}

func (h *HostKeyPrivateStorageV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostKeyPrivateStorageV1) Decode(dec rpc.Decoder) error {
	var tmp HostKeyPrivateStorageV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostKeyPrivateStorageV1) Bytes() []byte { return nil }

type HostKeyPrivateStorageVersion int

const (
	HostKeyPrivateStorageVersion_V1 HostKeyPrivateStorageVersion = 1
)

var HostKeyPrivateStorageVersionMap = map[string]HostKeyPrivateStorageVersion{
	"V1": 1,
}

var HostKeyPrivateStorageVersionRevMap = map[HostKeyPrivateStorageVersion]string{
	1: "V1",
}

type HostKeyPrivateStorageVersionInternal__ HostKeyPrivateStorageVersion

func (h HostKeyPrivateStorageVersionInternal__) Import() HostKeyPrivateStorageVersion {
	return HostKeyPrivateStorageVersion(h)
}

func (h HostKeyPrivateStorageVersion) Export() *HostKeyPrivateStorageVersionInternal__ {
	return ((*HostKeyPrivateStorageVersionInternal__)(&h))
}

type HostKeyPrivateStorage struct {
	V     HostKeyPrivateStorageVersion
	F_1__ *HostKeyPrivateStorageV1 `json:"f1,omitempty"`
}

type HostKeyPrivateStorageInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        HostKeyPrivateStorageVersion
	Switch__ HostKeyPrivateStorageInternalSwitch__
}

type HostKeyPrivateStorageInternalSwitch__ struct {
	_struct struct{}                           `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HostKeyPrivateStorageV1Internal__ `codec:"1"`
}

func (h HostKeyPrivateStorage) GetV() (ret HostKeyPrivateStorageVersion, err error) {
	switch h.V {
	case HostKeyPrivateStorageVersion_V1:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return h.V, nil
}

func (h HostKeyPrivateStorage) V1() HostKeyPrivateStorageV1 {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.V != HostKeyPrivateStorageVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", h.V))
	}
	return *h.F_1__
}

func NewHostKeyPrivateStorageWithV1(v HostKeyPrivateStorageV1) HostKeyPrivateStorage {
	return HostKeyPrivateStorage{
		V:     HostKeyPrivateStorageVersion_V1,
		F_1__: &v,
	}
}

func (h HostKeyPrivateStorageInternal__) Import() HostKeyPrivateStorage {
	return HostKeyPrivateStorage{
		V: h.V,
		F_1__: (func(x *HostKeyPrivateStorageV1Internal__) *HostKeyPrivateStorageV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostKeyPrivateStorageV1Internal__) (ret HostKeyPrivateStorageV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_1__),
	}
}

func (h HostKeyPrivateStorage) Export() *HostKeyPrivateStorageInternal__ {
	return &HostKeyPrivateStorageInternal__{
		V: h.V,
		Switch__: HostKeyPrivateStorageInternalSwitch__{
			F_1__: (func(x *HostKeyPrivateStorageV1) *HostKeyPrivateStorageV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
		},
	}
}

func (h *HostKeyPrivateStorage) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostKeyPrivateStorage) Decode(dec rpc.Decoder) error {
	var tmp HostKeyPrivateStorageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostKeyPrivateStorage) Bytes() []byte { return nil }

type KeyAtSeqno struct {
	Seqno Seqno
	Eid   EntityID
}

type KeyAtSeqnoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *SeqnoInternal__
	Eid     *EntityIDInternal__
}

func (k KeyAtSeqnoInternal__) Import() KeyAtSeqno {
	return KeyAtSeqno{
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Seqno),
		Eid: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Eid),
	}
}

func (k KeyAtSeqno) Export() *KeyAtSeqnoInternal__ {
	return &KeyAtSeqnoInternal__{
		Seqno: k.Seqno.Export(),
		Eid:   k.Eid.Export(),
	}
}

func (k *KeyAtSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyAtSeqno) Decode(dec rpc.Decoder) error {
	var tmp KeyAtSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeyAtSeqno) Bytes() []byte { return nil }

type HostTLSCAAtSeqno struct {
	Seqno Seqno
	Ca    HostTLSCA
}

type HostTLSCAAtSeqnoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *SeqnoInternal__
	Ca      *HostTLSCAInternal__
}

func (h HostTLSCAAtSeqnoInternal__) Import() HostTLSCAAtSeqno {
	return HostTLSCAAtSeqno{
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Seqno),
		Ca: (func(x *HostTLSCAInternal__) (ret HostTLSCA) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Ca),
	}
}

func (h HostTLSCAAtSeqno) Export() *HostTLSCAAtSeqnoInternal__ {
	return &HostTLSCAAtSeqnoInternal__{
		Seqno: h.Seqno.Export(),
		Ca:    h.Ca.Export(),
	}
}

func (h *HostTLSCAAtSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostTLSCAAtSeqno) Decode(dec rpc.Decoder) error {
	var tmp HostTLSCAAtSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostTLSCAAtSeqno) Bytes() []byte { return nil }

type HostchainState struct {
	Seqno Seqno
	Host  HostID
	Time  Time
	Tail  LinkHash
	Keys  []KeyAtSeqno
	Cas   []HostTLSCAAtSeqno
	Addr  TCPAddr
}

type HostchainStateInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *SeqnoInternal__
	Host    *HostIDInternal__
	Time    *TimeInternal__
	Tail    *LinkHashInternal__
	Keys    *[](*KeyAtSeqnoInternal__)
	Cas     *[](*HostTLSCAAtSeqnoInternal__)
	Addr    *TCPAddrInternal__
}

func (h HostchainStateInternal__) Import() HostchainState {
	return HostchainState{
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Seqno),
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Host),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Time),
		Tail: (func(x *LinkHashInternal__) (ret LinkHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Tail),
		Keys: (func(x *[](*KeyAtSeqnoInternal__)) (ret []KeyAtSeqno) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]KeyAtSeqno, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *KeyAtSeqnoInternal__) (ret KeyAtSeqno) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(h.Keys),
		Cas: (func(x *[](*HostTLSCAAtSeqnoInternal__)) (ret []HostTLSCAAtSeqno) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]HostTLSCAAtSeqno, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *HostTLSCAAtSeqnoInternal__) (ret HostTLSCAAtSeqno) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(h.Cas),
		Addr: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Addr),
	}
}

func (h HostchainState) Export() *HostchainStateInternal__ {
	return &HostchainStateInternal__{
		Seqno: h.Seqno.Export(),
		Host:  h.Host.Export(),
		Time:  h.Time.Export(),
		Tail:  h.Tail.Export(),
		Keys: (func(x []KeyAtSeqno) *[](*KeyAtSeqnoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*KeyAtSeqnoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(h.Keys),
		Cas: (func(x []HostTLSCAAtSeqno) *[](*HostTLSCAAtSeqnoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*HostTLSCAAtSeqnoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(h.Cas),
		Addr: h.Addr.Export(),
	}
}

func (h *HostchainState) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainState) Decode(dec rpc.Decoder) error {
	var tmp HostchainStateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostchainState) Bytes() []byte { return nil }

type HostchainTail struct {
	Seqno Seqno
	Hash  LinkHash
}

type HostchainTailInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *SeqnoInternal__
	Hash    *LinkHashInternal__
}

func (h HostchainTailInternal__) Import() HostchainTail {
	return HostchainTail{
		Seqno: (func(x *SeqnoInternal__) (ret Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Seqno),
		Hash: (func(x *LinkHashInternal__) (ret LinkHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Hash),
	}
}

func (h HostchainTail) Export() *HostchainTailInternal__ {
	return &HostchainTailInternal__{
		Seqno: h.Seqno.Export(),
		Hash:  h.Hash.Export(),
	}
}

func (h *HostchainTail) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostchainTail) Decode(dec rpc.Decoder) error {
	var tmp HostchainTailInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostchainTail) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(HostchainChangeItemTypeUniqueID)
	rpc.AddUnique(HostchainChangeTypeUniqueID)
	rpc.AddUnique(HostchainLinkInnerTypeUniqueID)
	rpc.AddUnique(HostchainLinkOuterV1TypeUniqueID)
	rpc.AddUnique(HostchainLinkOuterTypeUniqueID)
}
