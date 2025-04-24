// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/yubi.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type YubiCardName string
type YubiCardNameInternal__ string

func (y YubiCardName) Export() *YubiCardNameInternal__ {
	tmp := ((string)(y))
	return ((*YubiCardNameInternal__)(&tmp))
}

func (y YubiCardNameInternal__) Import() YubiCardName {
	tmp := (string)(y)
	return YubiCardName((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiCardName) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiCardName) Decode(dec rpc.Decoder) error {
	var tmp YubiCardNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiCardName) Bytes() []byte {
	return nil
}

type YubiSerial uint64
type YubiSerialInternal__ uint64

func (y YubiSerial) Export() *YubiSerialInternal__ {
	tmp := ((uint64)(y))
	return ((*YubiSerialInternal__)(&tmp))
}

func (y YubiSerialInternal__) Import() YubiSerial {
	tmp := (uint64)(y)
	return YubiSerial((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiSerial) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSerial) Decode(dec rpc.Decoder) error {
	var tmp YubiSerialInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiSerial) Bytes() []byte {
	return nil
}

type YubiSlot uint64
type YubiSlotInternal__ uint64

func (y YubiSlot) Export() *YubiSlotInternal__ {
	tmp := ((uint64)(y))
	return ((*YubiSlotInternal__)(&tmp))
}

func (y YubiSlotInternal__) Import() YubiSlot {
	tmp := (uint64)(y)
	return YubiSlot((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiSlot) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSlot) Decode(dec rpc.Decoder) error {
	var tmp YubiSlotInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiSlot) Bytes() []byte {
	return nil
}

type YubiPIN string
type YubiPINInternal__ string

func (y YubiPIN) Export() *YubiPINInternal__ {
	tmp := ((string)(y))
	return ((*YubiPINInternal__)(&tmp))
}

func (y YubiPINInternal__) Import() YubiPIN {
	tmp := (string)(y)
	return YubiPIN((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiPIN) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiPIN) Decode(dec rpc.Decoder) error {
	var tmp YubiPINInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiPIN) Bytes() []byte {
	return nil
}

type YubiPUK string
type YubiPUKInternal__ string

func (y YubiPUK) Export() *YubiPUKInternal__ {
	tmp := ((string)(y))
	return ((*YubiPUKInternal__)(&tmp))
}

func (y YubiPUKInternal__) Import() YubiPUK {
	tmp := (string)(y)
	return YubiPUK((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiPUK) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiPUK) Decode(dec rpc.Decoder) error {
	var tmp YubiPUKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiPUK) Bytes() []byte {
	return nil
}

type YubiManagementKey [24]byte
type YubiManagementKeyInternal__ [24]byte

func (y YubiManagementKey) Export() *YubiManagementKeyInternal__ {
	tmp := (([24]byte)(y))
	return ((*YubiManagementKeyInternal__)(&tmp))
}

func (y YubiManagementKeyInternal__) Import() YubiManagementKey {
	tmp := ([24]byte)(y)
	return YubiManagementKey((func(x *[24]byte) (ret [24]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiManagementKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiManagementKey) Decode(dec rpc.Decoder) error {
	var tmp YubiManagementKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiManagementKey) Bytes() []byte {
	return (y)[:]
}

type ManagementKeyState int

const (
	ManagementKeyState_None         ManagementKeyState = 0
	ManagementKeyState_Default      ManagementKeyState = 1
	ManagementKeyState_PINRetrieved ManagementKeyState = 2
	ManagementKeyState_ShouldTryPIN ManagementKeyState = 3
	ManagementKeyState_Unknown      ManagementKeyState = 4
)

var ManagementKeyStateMap = map[string]ManagementKeyState{
	"None":         0,
	"Default":      1,
	"PINRetrieved": 2,
	"ShouldTryPIN": 3,
	"Unknown":      4,
}

var ManagementKeyStateRevMap = map[ManagementKeyState]string{
	0: "None",
	1: "Default",
	2: "PINRetrieved",
	3: "ShouldTryPIN",
	4: "Unknown",
}

type ManagementKeyStateInternal__ ManagementKeyState

func (m ManagementKeyStateInternal__) Import() ManagementKeyState {
	return ManagementKeyState(m)
}

func (m ManagementKeyState) Export() *ManagementKeyStateInternal__ {
	return ((*ManagementKeyStateInternal__)(&m))
}

type YubiCardID struct {
	Name   YubiCardName
	Serial YubiSerial
}

type YubiCardIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *YubiCardNameInternal__
	Serial  *YubiSerialInternal__
}

func (y YubiCardIDInternal__) Import() YubiCardID {
	return YubiCardID{
		Name: (func(x *YubiCardNameInternal__) (ret YubiCardName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Name),
		Serial: (func(x *YubiSerialInternal__) (ret YubiSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Serial),
	}
}

func (y YubiCardID) Export() *YubiCardIDInternal__ {
	return &YubiCardIDInternal__{
		Name:   y.Name.Export(),
		Serial: y.Serial.Export(),
	}
}

func (y *YubiCardID) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiCardID) Decode(dec rpc.Decoder) error {
	var tmp YubiCardIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiCardID) Bytes() []byte { return nil }

type YubiCardInfo struct {
	Id         YubiCardID
	Keys       []YubiSlotAndKeyID
	EmptySlots []YubiSlot
	Selected   []YubiSlotAndKeyID
	Mks        ManagementKeyState
}

type YubiCardInfoInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id         *YubiCardIDInternal__
	Keys       *[](*YubiSlotAndKeyIDInternal__)
	EmptySlots *[](*YubiSlotInternal__)
	Selected   *[](*YubiSlotAndKeyIDInternal__)
	Mks        *ManagementKeyStateInternal__
}

func (y YubiCardInfoInternal__) Import() YubiCardInfo {
	return YubiCardInfo{
		Id: (func(x *YubiCardIDInternal__) (ret YubiCardID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Id),
		Keys: (func(x *[](*YubiSlotAndKeyIDInternal__)) (ret []YubiSlotAndKeyID) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]YubiSlotAndKeyID, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *YubiSlotAndKeyIDInternal__) (ret YubiSlotAndKeyID) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(y.Keys),
		EmptySlots: (func(x *[](*YubiSlotInternal__)) (ret []YubiSlot) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]YubiSlot, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *YubiSlotInternal__) (ret YubiSlot) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(y.EmptySlots),
		Selected: (func(x *[](*YubiSlotAndKeyIDInternal__)) (ret []YubiSlotAndKeyID) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]YubiSlotAndKeyID, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *YubiSlotAndKeyIDInternal__) (ret YubiSlotAndKeyID) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(y.Selected),
		Mks: (func(x *ManagementKeyStateInternal__) (ret ManagementKeyState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Mks),
	}
}

func (y YubiCardInfo) Export() *YubiCardInfoInternal__ {
	return &YubiCardInfoInternal__{
		Id: y.Id.Export(),
		Keys: (func(x []YubiSlotAndKeyID) *[](*YubiSlotAndKeyIDInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*YubiSlotAndKeyIDInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(y.Keys),
		EmptySlots: (func(x []YubiSlot) *[](*YubiSlotInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*YubiSlotInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(y.EmptySlots),
		Selected: (func(x []YubiSlotAndKeyID) *[](*YubiSlotAndKeyIDInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*YubiSlotAndKeyIDInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(y.Selected),
		Mks: y.Mks.Export(),
	}
}

func (y *YubiCardInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiCardInfo) Decode(dec rpc.Decoder) error {
	var tmp YubiCardInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiCardInfo) Bytes() []byte { return nil }

type YubiSlotAndKeyID struct {
	Slot YubiSlot
	Id   YubiID
}

type YubiSlotAndKeyIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Slot    *YubiSlotInternal__
	Id      *YubiIDInternal__
}

func (y YubiSlotAndKeyIDInternal__) Import() YubiSlotAndKeyID {
	return YubiSlotAndKeyID{
		Slot: (func(x *YubiSlotInternal__) (ret YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Slot),
		Id: (func(x *YubiIDInternal__) (ret YubiID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Id),
	}
}

func (y YubiSlotAndKeyID) Export() *YubiSlotAndKeyIDInternal__ {
	return &YubiSlotAndKeyIDInternal__{
		Slot: y.Slot.Export(),
		Id:   y.Id.Export(),
	}
}

func (y *YubiSlotAndKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSlotAndKeyID) Decode(dec rpc.Decoder) error {
	var tmp YubiSlotAndKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiSlotAndKeyID) Bytes() []byte { return nil }

type YubiKeyInfo struct {
	Card YubiCardID
	Key  YubiSlotAndKeyID
}

type YubiKeyInfoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Card    *YubiCardIDInternal__
	Key     *YubiSlotAndKeyIDInternal__
}

func (y YubiKeyInfoInternal__) Import() YubiKeyInfo {
	return YubiKeyInfo{
		Card: (func(x *YubiCardIDInternal__) (ret YubiCardID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Card),
		Key: (func(x *YubiSlotAndKeyIDInternal__) (ret YubiSlotAndKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Key),
	}
}

func (y YubiKeyInfo) Export() *YubiKeyInfoInternal__ {
	return &YubiKeyInfoInternal__{
		Card: y.Card.Export(),
		Key:  y.Key.Export(),
	}
}

func (y *YubiKeyInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiKeyInfo) Decode(dec rpc.Decoder) error {
	var tmp YubiKeyInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiKeyInfo) Bytes() []byte { return nil }

type YubiSlotAndPQKeyID struct {
	Slot YubiSlot
	Id   YubiPQKeyID
}

type YubiSlotAndPQKeyIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Slot    *YubiSlotInternal__
	Id      *YubiPQKeyIDInternal__
}

func (y YubiSlotAndPQKeyIDInternal__) Import() YubiSlotAndPQKeyID {
	return YubiSlotAndPQKeyID{
		Slot: (func(x *YubiSlotInternal__) (ret YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Slot),
		Id: (func(x *YubiPQKeyIDInternal__) (ret YubiPQKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Id),
	}
}

func (y YubiSlotAndPQKeyID) Export() *YubiSlotAndPQKeyIDInternal__ {
	return &YubiSlotAndPQKeyIDInternal__{
		Slot: y.Slot.Export(),
		Id:   y.Id.Export(),
	}
}

func (y *YubiSlotAndPQKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSlotAndPQKeyID) Decode(dec rpc.Decoder) error {
	var tmp YubiSlotAndPQKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiSlotAndPQKeyID) Bytes() []byte { return nil }

type YubiKeyInfoPQ struct {
	Card YubiCardID
	Key  YubiSlotAndPQKeyID
}

type YubiKeyInfoPQInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Card    *YubiCardIDInternal__
	Key     *YubiSlotAndPQKeyIDInternal__
}

func (y YubiKeyInfoPQInternal__) Import() YubiKeyInfoPQ {
	return YubiKeyInfoPQ{
		Card: (func(x *YubiCardIDInternal__) (ret YubiCardID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Card),
		Key: (func(x *YubiSlotAndPQKeyIDInternal__) (ret YubiSlotAndPQKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Key),
	}
}

func (y YubiKeyInfoPQ) Export() *YubiKeyInfoPQInternal__ {
	return &YubiKeyInfoPQInternal__{
		Card: y.Card.Export(),
		Key:  y.Key.Export(),
	}
}

func (y *YubiKeyInfoPQ) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiKeyInfoPQ) Decode(dec rpc.Decoder) error {
	var tmp YubiKeyInfoPQInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiKeyInfoPQ) Bytes() []byte { return nil }

type YubiKeyInfoHybrid struct {
	Card  YubiCardID
	Key   YubiSlotAndKeyID
	PqKey YubiSlotAndPQKeyID
}

type YubiKeyInfoHybridInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Card    *YubiCardIDInternal__
	Key     *YubiSlotAndKeyIDInternal__
	PqKey   *YubiSlotAndPQKeyIDInternal__
}

func (y YubiKeyInfoHybridInternal__) Import() YubiKeyInfoHybrid {
	return YubiKeyInfoHybrid{
		Card: (func(x *YubiCardIDInternal__) (ret YubiCardID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Card),
		Key: (func(x *YubiSlotAndKeyIDInternal__) (ret YubiSlotAndKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Key),
		PqKey: (func(x *YubiSlotAndPQKeyIDInternal__) (ret YubiSlotAndPQKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.PqKey),
	}
}

func (y YubiKeyInfoHybrid) Export() *YubiKeyInfoHybridInternal__ {
	return &YubiKeyInfoHybridInternal__{
		Card:  y.Card.Export(),
		Key:   y.Key.Export(),
		PqKey: y.PqKey.Export(),
	}
}

func (y *YubiKeyInfoHybrid) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiKeyInfoHybrid) Decode(dec rpc.Decoder) error {
	var tmp YubiKeyInfoHybridInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiKeyInfoHybrid) Bytes() []byte { return nil }

type YubiIndexType int

const (
	YubiIndexType_None  YubiIndexType = 0
	YubiIndexType_Empty YubiIndexType = 1
	YubiIndexType_Reuse YubiIndexType = 2
)

var YubiIndexTypeMap = map[string]YubiIndexType{
	"None":  0,
	"Empty": 1,
	"Reuse": 2,
}

var YubiIndexTypeRevMap = map[YubiIndexType]string{
	0: "None",
	1: "Empty",
	2: "Reuse",
}

type YubiIndexTypeInternal__ YubiIndexType

func (y YubiIndexTypeInternal__) Import() YubiIndexType {
	return YubiIndexType(y)
}

func (y YubiIndexType) Export() *YubiIndexTypeInternal__ {
	return ((*YubiIndexTypeInternal__)(&y))
}

type YubiIndex struct {
	T     YubiIndexType
	F_1__ *uint64 `json:"f1,omitempty"`
	F_2__ *uint64 `json:"f2,omitempty"`
}

type YubiIndexInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        YubiIndexType
	Switch__ YubiIndexInternalSwitch__
}

type YubiIndexInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *uint64  `codec:"1"`
	F_2__   *uint64  `codec:"2"`
}

func (y YubiIndex) GetT() (ret YubiIndexType, err error) {
	switch y.T {
	case YubiIndexType_Empty:
		if y.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case YubiIndexType_Reuse:
		if y.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	default:
		break
	}
	return y.T, nil
}

func (y YubiIndex) Empty() uint64 {
	if y.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if y.T != YubiIndexType_Empty {
		panic(fmt.Sprintf("unexpected switch value (%v) when Empty is called", y.T))
	}
	return *y.F_1__
}

func (y YubiIndex) Reuse() uint64 {
	if y.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if y.T != YubiIndexType_Reuse {
		panic(fmt.Sprintf("unexpected switch value (%v) when Reuse is called", y.T))
	}
	return *y.F_2__
}

func NewYubiIndexWithEmpty(v uint64) YubiIndex {
	return YubiIndex{
		T:     YubiIndexType_Empty,
		F_1__: &v,
	}
}

func NewYubiIndexWithReuse(v uint64) YubiIndex {
	return YubiIndex{
		T:     YubiIndexType_Reuse,
		F_2__: &v,
	}
}

func NewYubiIndexDefault(s YubiIndexType) YubiIndex {
	return YubiIndex{
		T: s,
	}
}

func (y YubiIndexInternal__) Import() YubiIndex {
	return YubiIndex{
		T:     y.T,
		F_1__: y.Switch__.F_1__,
		F_2__: y.Switch__.F_2__,
	}
}

func (y YubiIndex) Export() *YubiIndexInternal__ {
	return &YubiIndexInternal__{
		T: y.T,
		Switch__: YubiIndexInternalSwitch__{
			F_1__: y.F_1__,
			F_2__: y.F_2__,
		},
	}
}

func (y *YubiIndex) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiIndex) Decode(dec rpc.Decoder) error {
	var tmp YubiIndexInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiIndex) Bytes() []byte { return nil }

type YubiSerialSlotHost struct {
	Serial YubiSerial
	Slot   YubiSlot
	Host   TCPAddr
}

type YubiSerialSlotHostInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Serial  *YubiSerialInternal__
	Slot    *YubiSlotInternal__
	Host    *TCPAddrInternal__
}

func (y YubiSerialSlotHostInternal__) Import() YubiSerialSlotHost {
	return YubiSerialSlotHost{
		Serial: (func(x *YubiSerialInternal__) (ret YubiSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Serial),
		Slot: (func(x *YubiSlotInternal__) (ret YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Slot),
		Host: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Host),
	}
}

func (y YubiSerialSlotHost) Export() *YubiSerialSlotHostInternal__ {
	return &YubiSerialSlotHostInternal__{
		Serial: y.Serial.Export(),
		Slot:   y.Slot.Export(),
		Host:   y.Host.Export(),
	}
}

func (y *YubiSerialSlotHost) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSerialSlotHost) Decode(dec rpc.Decoder) error {
	var tmp YubiSerialSlotHostInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiSerialSlotHost) Bytes() []byte { return nil }

type YubiSerialSlot struct {
	Serial YubiSerial
	Slot   YubiSlot
}

type YubiSerialSlotInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Serial  *YubiSerialInternal__
	Slot    *YubiSlotInternal__
}

func (y YubiSerialSlotInternal__) Import() YubiSerialSlot {
	return YubiSerialSlot{
		Serial: (func(x *YubiSerialInternal__) (ret YubiSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Serial),
		Slot: (func(x *YubiSlotInternal__) (ret YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Slot),
	}
}

func (y YubiSerialSlot) Export() *YubiSerialSlotInternal__ {
	return &YubiSerialSlotInternal__{
		Serial: y.Serial.Export(),
		Slot:   y.Slot.Export(),
	}
}

func (y *YubiSerialSlot) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiSerialSlot) Decode(dec rpc.Decoder) error {
	var tmp YubiSerialSlotInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiSerialSlot) Bytes() []byte { return nil }

type YubiPQKeyID [32]byte
type YubiPQKeyIDInternal__ [32]byte

func (y YubiPQKeyID) Export() *YubiPQKeyIDInternal__ {
	tmp := (([32]byte)(y))
	return ((*YubiPQKeyIDInternal__)(&tmp))
}

func (y YubiPQKeyIDInternal__) Import() YubiPQKeyID {
	tmp := ([32]byte)(y)
	return YubiPQKeyID((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (y *YubiPQKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiPQKeyID) Decode(dec rpc.Decoder) error {
	var tmp YubiPQKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiPQKeyID) Bytes() []byte {
	return (y)[:]
}

type YubiManagementKeyBoxPayload struct {
	Mk   YubiManagementKey
	Card YubiCardID
	Slot YubiSlot
	Yk   YubiID
}

type YubiManagementKeyBoxPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Mk      *YubiManagementKeyInternal__
	Card    *YubiCardIDInternal__
	Slot    *YubiSlotInternal__
	Yk      *YubiIDInternal__
}

func (y YubiManagementKeyBoxPayloadInternal__) Import() YubiManagementKeyBoxPayload {
	return YubiManagementKeyBoxPayload{
		Mk: (func(x *YubiManagementKeyInternal__) (ret YubiManagementKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Mk),
		Card: (func(x *YubiCardIDInternal__) (ret YubiCardID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Card),
		Slot: (func(x *YubiSlotInternal__) (ret YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Slot),
		Yk: (func(x *YubiIDInternal__) (ret YubiID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Yk),
	}
}

func (y YubiManagementKeyBoxPayload) Export() *YubiManagementKeyBoxPayloadInternal__ {
	return &YubiManagementKeyBoxPayloadInternal__{
		Mk:   y.Mk.Export(),
		Card: y.Card.Export(),
		Slot: y.Slot.Export(),
		Yk:   y.Yk.Export(),
	}
}

func (y *YubiManagementKeyBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiManagementKeyBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp YubiManagementKeyBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

var YubiManagementKeyBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0xc939af74e0147c7a)

func (y *YubiManagementKeyBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return YubiManagementKeyBoxPayloadTypeUniqueID
}

func (y *YubiManagementKeyBoxPayload) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(YubiManagementKeyBoxPayloadTypeUniqueID)
}
