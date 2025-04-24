// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/yubi.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SetOrGetManagementKeyRes struct {
	WasMade bool
	Key     lib.YubiManagementKey
}

type SetOrGetManagementKeyResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	WasMade *bool
	Key     *lib.YubiManagementKeyInternal__
}

func (s SetOrGetManagementKeyResInternal__) Import() SetOrGetManagementKeyRes {
	return SetOrGetManagementKeyRes{
		WasMade: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(s.WasMade),
		Key: (func(x *lib.YubiManagementKeyInternal__) (ret lib.YubiManagementKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Key),
	}
}

func (s SetOrGetManagementKeyRes) Export() *SetOrGetManagementKeyResInternal__ {
	return &SetOrGetManagementKeyResInternal__{
		WasMade: &s.WasMade,
		Key:     s.Key.Export(),
	}
}

func (s *SetOrGetManagementKeyRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetOrGetManagementKeyRes) Decode(dec rpc.Decoder) error {
	var tmp SetOrGetManagementKeyResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetOrGetManagementKeyRes) Bytes() []byte { return nil }

var YubiProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xd6c6ce5e)

type YubiUnlockArg struct {
}

type YubiUnlockArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (y YubiUnlockArgInternal__) Import() YubiUnlockArg {
	return YubiUnlockArg{}
}

func (y YubiUnlockArg) Export() *YubiUnlockArgInternal__ {
	return &YubiUnlockArgInternal__{}
}

func (y *YubiUnlockArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiUnlockArg) Decode(dec rpc.Decoder) error {
	var tmp YubiUnlockArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiUnlockArg) Bytes() []byte { return nil }

type YubiListAllCardsArg struct {
}

type YubiListAllCardsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (y YubiListAllCardsArgInternal__) Import() YubiListAllCardsArg {
	return YubiListAllCardsArg{}
}

func (y YubiListAllCardsArg) Export() *YubiListAllCardsArgInternal__ {
	return &YubiListAllCardsArgInternal__{}
}

func (y *YubiListAllCardsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiListAllCardsArg) Decode(dec rpc.Decoder) error {
	var tmp YubiListAllCardsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiListAllCardsArg) Bytes() []byte { return nil }

type YubiListAllSlotsArg struct {
	Serial lib.YubiSerial
}

type YubiListAllSlotsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Serial  *lib.YubiSerialInternal__
}

func (y YubiListAllSlotsArgInternal__) Import() YubiListAllSlotsArg {
	return YubiListAllSlotsArg{
		Serial: (func(x *lib.YubiSerialInternal__) (ret lib.YubiSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Serial),
	}
}

func (y YubiListAllSlotsArg) Export() *YubiListAllSlotsArgInternal__ {
	return &YubiListAllSlotsArgInternal__{
		Serial: y.Serial.Export(),
	}
}

func (y *YubiListAllSlotsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiListAllSlotsArg) Decode(dec rpc.Decoder) error {
	var tmp YubiListAllSlotsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiListAllSlotsArg) Bytes() []byte { return nil }

type YubiMapSlotToUserArg struct {
	Ssh lib.YubiSerialSlotHost
}

type YubiMapSlotToUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ssh     *lib.YubiSerialSlotHostInternal__
}

func (y YubiMapSlotToUserArgInternal__) Import() YubiMapSlotToUserArg {
	return YubiMapSlotToUserArg{
		Ssh: (func(x *lib.YubiSerialSlotHostInternal__) (ret lib.YubiSerialSlotHost) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Ssh),
	}
}

func (y YubiMapSlotToUserArg) Export() *YubiMapSlotToUserArgInternal__ {
	return &YubiMapSlotToUserArgInternal__{
		Ssh: y.Ssh.Export(),
	}
}

func (y *YubiMapSlotToUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiMapSlotToUserArg) Decode(dec rpc.Decoder) error {
	var tmp YubiMapSlotToUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiMapSlotToUserArg) Bytes() []byte { return nil }

type YubiProvisionArg struct {
	Ssh lib.YubiSerialSlotHost
}

type YubiProvisionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ssh     *lib.YubiSerialSlotHostInternal__
}

func (y YubiProvisionArgInternal__) Import() YubiProvisionArg {
	return YubiProvisionArg{
		Ssh: (func(x *lib.YubiSerialSlotHostInternal__) (ret lib.YubiSerialSlotHost) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Ssh),
	}
}

func (y YubiProvisionArg) Export() *YubiProvisionArgInternal__ {
	return &YubiProvisionArgInternal__{
		Ssh: y.Ssh.Export(),
	}
}

func (y *YubiProvisionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiProvisionArg) Decode(dec rpc.Decoder) error {
	var tmp YubiProvisionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiProvisionArg) Bytes() []byte { return nil }

type YubiNewArg struct {
	Ss          lib.YubiSerialSlot
	Role        lib.Role
	Dln         lib.DeviceLabelAndName
	PqSlot      lib.YubiSlot
	Pin         lib.YubiPIN
	LockWithPin bool
}

type YubiNewArgInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ss          *lib.YubiSerialSlotInternal__
	Role        *lib.RoleInternal__
	Dln         *lib.DeviceLabelAndNameInternal__
	PqSlot      *lib.YubiSlotInternal__
	Pin         *lib.YubiPINInternal__
	LockWithPin *bool
}

func (y YubiNewArgInternal__) Import() YubiNewArg {
	return YubiNewArg{
		Ss: (func(x *lib.YubiSerialSlotInternal__) (ret lib.YubiSerialSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Ss),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Role),
		Dln: (func(x *lib.DeviceLabelAndNameInternal__) (ret lib.DeviceLabelAndName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Dln),
		PqSlot: (func(x *lib.YubiSlotInternal__) (ret lib.YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.PqSlot),
		Pin: (func(x *lib.YubiPINInternal__) (ret lib.YubiPIN) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Pin),
		LockWithPin: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(y.LockWithPin),
	}
}

func (y YubiNewArg) Export() *YubiNewArgInternal__ {
	return &YubiNewArgInternal__{
		Ss:          y.Ss.Export(),
		Role:        y.Role.Export(),
		Dln:         y.Dln.Export(),
		PqSlot:      y.PqSlot.Export(),
		Pin:         y.Pin.Export(),
		LockWithPin: &y.LockWithPin,
	}
}

func (y *YubiNewArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiNewArg) Decode(dec rpc.Decoder) error {
	var tmp YubiNewArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiNewArg) Bytes() []byte { return nil }

type ListAllLocalYubiDevicesArg struct {
	SessionId lib.UISessionID
}

type ListAllLocalYubiDevicesArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (l ListAllLocalYubiDevicesArgInternal__) Import() ListAllLocalYubiDevicesArg {
	return ListAllLocalYubiDevicesArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
	}
}

func (l ListAllLocalYubiDevicesArg) Export() *ListAllLocalYubiDevicesArgInternal__ {
	return &ListAllLocalYubiDevicesArgInternal__{
		SessionId: l.SessionId.Export(),
	}
}

func (l *ListAllLocalYubiDevicesArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *ListAllLocalYubiDevicesArg) Decode(dec rpc.Decoder) error {
	var tmp ListAllLocalYubiDevicesArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *ListAllLocalYubiDevicesArg) Bytes() []byte { return nil }

type UseYubiArg struct {
	SessionId lib.UISessionID
	Idx       uint64
}

type UseYubiArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Idx       *uint64
}

func (u UseYubiArgInternal__) Import() UseYubiArg {
	return UseYubiArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.SessionId),
		Idx: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(u.Idx),
	}
}

func (u UseYubiArg) Export() *UseYubiArgInternal__ {
	return &UseYubiArgInternal__{
		SessionId: u.SessionId.Export(),
		Idx:       &u.Idx,
	}
}

func (u *UseYubiArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UseYubiArg) Decode(dec rpc.Decoder) error {
	var tmp UseYubiArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UseYubiArg) Bytes() []byte { return nil }

type ValidateCurrentPINArg struct {
	SessionId lib.UISessionID
	Pin       lib.YubiPIN
	DoUnlock  bool
}

type ValidateCurrentPINArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Pin       *lib.YubiPINInternal__
	DoUnlock  *bool
}

func (v ValidateCurrentPINArgInternal__) Import() ValidateCurrentPINArg {
	return ValidateCurrentPINArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.SessionId),
		Pin: (func(x *lib.YubiPINInternal__) (ret lib.YubiPIN) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.Pin),
		DoUnlock: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(v.DoUnlock),
	}
}

func (v ValidateCurrentPINArg) Export() *ValidateCurrentPINArgInternal__ {
	return &ValidateCurrentPINArgInternal__{
		SessionId: v.SessionId.Export(),
		Pin:       v.Pin.Export(),
		DoUnlock:  &v.DoUnlock,
	}
}

func (v *ValidateCurrentPINArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *ValidateCurrentPINArg) Decode(dec rpc.Decoder) error {
	var tmp ValidateCurrentPINArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v *ValidateCurrentPINArg) Bytes() []byte { return nil }

type SetPINArg struct {
	SessionId lib.UISessionID
	Pin       lib.YubiPIN
}

type SetPINArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Pin       *lib.YubiPINInternal__
}

func (s SetPINArgInternal__) Import() SetPINArg {
	return SetPINArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
		Pin: (func(x *lib.YubiPINInternal__) (ret lib.YubiPIN) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Pin),
	}
}

func (s SetPINArg) Export() *SetPINArgInternal__ {
	return &SetPINArgInternal__{
		SessionId: s.SessionId.Export(),
		Pin:       s.Pin.Export(),
	}
}

func (s *SetPINArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetPINArg) Decode(dec rpc.Decoder) error {
	var tmp SetPINArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetPINArg) Bytes() []byte { return nil }

type ValidateCurrentPUKArg struct {
	SessionId lib.UISessionID
	Puk       lib.YubiPUK
}

type ValidateCurrentPUKArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Puk       *lib.YubiPUKInternal__
}

func (v ValidateCurrentPUKArgInternal__) Import() ValidateCurrentPUKArg {
	return ValidateCurrentPUKArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.SessionId),
		Puk: (func(x *lib.YubiPUKInternal__) (ret lib.YubiPUK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.Puk),
	}
}

func (v ValidateCurrentPUKArg) Export() *ValidateCurrentPUKArgInternal__ {
	return &ValidateCurrentPUKArgInternal__{
		SessionId: v.SessionId.Export(),
		Puk:       v.Puk.Export(),
	}
}

func (v *ValidateCurrentPUKArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *ValidateCurrentPUKArg) Decode(dec rpc.Decoder) error {
	var tmp ValidateCurrentPUKArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v *ValidateCurrentPUKArg) Bytes() []byte { return nil }

type SetPUKArg struct {
	SessionId lib.UISessionID
	New       lib.YubiPUK
}

type SetPUKArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	New       *lib.YubiPUKInternal__
}

func (s SetPUKArgInternal__) Import() SetPUKArg {
	return SetPUKArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
		New: (func(x *lib.YubiPUKInternal__) (ret lib.YubiPUK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.New),
	}
}

func (s SetPUKArg) Export() *SetPUKArgInternal__ {
	return &SetPUKArgInternal__{
		SessionId: s.SessionId.Export(),
		New:       s.New.Export(),
	}
}

func (s *SetPUKArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetPUKArg) Decode(dec rpc.Decoder) error {
	var tmp SetPUKArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetPUKArg) Bytes() []byte { return nil }

type SetOrGetManagementKeyArg struct {
	SessionId lib.UISessionID
}

type SetOrGetManagementKeyArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (s SetOrGetManagementKeyArgInternal__) Import() SetOrGetManagementKeyArg {
	return SetOrGetManagementKeyArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
	}
}

func (s SetOrGetManagementKeyArg) Export() *SetOrGetManagementKeyArgInternal__ {
	return &SetOrGetManagementKeyArgInternal__{
		SessionId: s.SessionId.Export(),
	}
}

func (s *SetOrGetManagementKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetOrGetManagementKeyArg) Decode(dec rpc.Decoder) error {
	var tmp SetOrGetManagementKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetOrGetManagementKeyArg) Bytes() []byte { return nil }

type InputPINArg struct {
	SessionId lib.UISessionID
	Pin       lib.YubiPIN
}

type InputPINArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Pin       *lib.YubiPINInternal__
}

func (i InputPINArgInternal__) Import() InputPINArg {
	return InputPINArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.SessionId),
		Pin: (func(x *lib.YubiPINInternal__) (ret lib.YubiPIN) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.Pin),
	}
}

func (i InputPINArg) Export() *InputPINArgInternal__ {
	return &InputPINArgInternal__{
		SessionId: i.SessionId.Export(),
		Pin:       i.Pin.Export(),
	}
}

func (i *InputPINArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *InputPINArg) Decode(dec rpc.Decoder) error {
	var tmp InputPINArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i *InputPINArg) Bytes() []byte { return nil }

type ManagementKeyStateArg struct {
	SessionId lib.UISessionID
}

type ManagementKeyStateArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (m ManagementKeyStateArgInternal__) Import() ManagementKeyStateArg {
	return ManagementKeyStateArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.SessionId),
	}
}

func (m ManagementKeyStateArg) Export() *ManagementKeyStateArgInternal__ {
	return &ManagementKeyStateArgInternal__{
		SessionId: m.SessionId.Export(),
	}
}

func (m *ManagementKeyStateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *ManagementKeyStateArg) Decode(dec rpc.Decoder) error {
	var tmp ManagementKeyStateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *ManagementKeyStateArg) Bytes() []byte { return nil }

type ProtectKeyWithPINArg struct {
	SessionId lib.UISessionID
}

type ProtectKeyWithPINArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (p ProtectKeyWithPINArgInternal__) Import() ProtectKeyWithPINArg {
	return ProtectKeyWithPINArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
	}
}

func (p ProtectKeyWithPINArg) Export() *ProtectKeyWithPINArgInternal__ {
	return &ProtectKeyWithPINArgInternal__{
		SessionId: p.SessionId.Export(),
	}
}

func (p *ProtectKeyWithPINArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProtectKeyWithPINArg) Decode(dec rpc.Decoder) error {
	var tmp ProtectKeyWithPINArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ProtectKeyWithPINArg) Bytes() []byte { return nil }

type RecoverManagementKeyArg struct {
	Serial lib.YubiSerial
	Pin    lib.YubiPIN
	Puk    lib.YubiPUK
	Mk     *lib.YubiManagementKey
}

type RecoverManagementKeyArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Serial  *lib.YubiSerialInternal__
	Pin     *lib.YubiPINInternal__
	Puk     *lib.YubiPUKInternal__
	Mk      *lib.YubiManagementKeyInternal__
}

func (r RecoverManagementKeyArgInternal__) Import() RecoverManagementKeyArg {
	return RecoverManagementKeyArg{
		Serial: (func(x *lib.YubiSerialInternal__) (ret lib.YubiSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Serial),
		Pin: (func(x *lib.YubiPINInternal__) (ret lib.YubiPIN) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Pin),
		Puk: (func(x *lib.YubiPUKInternal__) (ret lib.YubiPUK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Puk),
		Mk: (func(x *lib.YubiManagementKeyInternal__) *lib.YubiManagementKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.YubiManagementKeyInternal__) (ret lib.YubiManagementKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Mk),
	}
}

func (r RecoverManagementKeyArg) Export() *RecoverManagementKeyArgInternal__ {
	return &RecoverManagementKeyArgInternal__{
		Serial: r.Serial.Export(),
		Pin:    r.Pin.Export(),
		Puk:    r.Puk.Export(),
		Mk: (func(x *lib.YubiManagementKey) *lib.YubiManagementKeyInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Mk),
	}
}

func (r *RecoverManagementKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RecoverManagementKeyArg) Decode(dec rpc.Decoder) error {
	var tmp RecoverManagementKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RecoverManagementKeyArg) Bytes() []byte { return nil }

type YubiInterface interface {
	YubiUnlock(context.Context) error
	YubiListAllCards(context.Context) ([]lib.YubiCardID, error)
	YubiListAllSlots(context.Context, lib.YubiSerial) (ListYubiSlotsRes, error)
	YubiMapSlotToUser(context.Context, lib.YubiSerialSlotHost) (lib.LookupUserRes, error)
	YubiProvision(context.Context, lib.YubiSerialSlotHost) error
	YubiNew(context.Context, YubiNewArg) error
	ListAllLocalYubiDevices(context.Context, lib.UISessionID) ([]lib.YubiCardID, error)
	UseYubi(context.Context, UseYubiArg) error
	ValidateCurrentPIN(context.Context, ValidateCurrentPINArg) error
	SetPIN(context.Context, SetPINArg) error
	ValidateCurrentPUK(context.Context, ValidateCurrentPUKArg) error
	SetPUK(context.Context, SetPUKArg) error
	SetOrGetManagementKey(context.Context, lib.UISessionID) (SetOrGetManagementKeyRes, error)
	InputPIN(context.Context, InputPINArg) (lib.ManagementKeyState, error)
	ManagementKeyState(context.Context, lib.UISessionID) (lib.ManagementKeyState, error)
	ProtectKeyWithPIN(context.Context, lib.UISessionID) error
	RecoverManagementKey(context.Context, RecoverManagementKeyArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func YubiMakeGenericErrorWrapper(f YubiErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type YubiErrorUnwrapper func(lib.Status) error
type YubiErrorWrapper func(error) lib.Status

type yubiErrorUnwrapperAdapter struct {
	h YubiErrorUnwrapper
}

func (y yubiErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (y yubiErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return y.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = yubiErrorUnwrapperAdapter{}

type YubiClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper YubiErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c YubiClient) YubiUnlock(ctx context.Context) (err error) {
	var arg YubiUnlockArg
	warg := &rpc.DataWrap[Header, *YubiUnlockArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 0, "Yubi.yubiUnlock"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) YubiListAllCards(ctx context.Context) (res []lib.YubiCardID, err error) {
	var arg YubiListAllCardsArg
	warg := &rpc.DataWrap[Header, *YubiListAllCardsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, [](*lib.YubiCardIDInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 1, "Yubi.yubiListAllCards"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*lib.YubiCardIDInternal__)) (ret []lib.YubiCardID) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]lib.YubiCardID, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *lib.YubiCardIDInternal__) (ret lib.YubiCardID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp.Data)
	return
}

func (c YubiClient) YubiListAllSlots(ctx context.Context, serial lib.YubiSerial) (res ListYubiSlotsRes, err error) {
	arg := YubiListAllSlotsArg{
		Serial: serial,
	}
	warg := &rpc.DataWrap[Header, *YubiListAllSlotsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, ListYubiSlotsResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 2, "Yubi.yubiListAllSlots"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) YubiMapSlotToUser(ctx context.Context, ssh lib.YubiSerialSlotHost) (res lib.LookupUserRes, err error) {
	arg := YubiMapSlotToUserArg{
		Ssh: ssh,
	}
	warg := &rpc.DataWrap[Header, *YubiMapSlotToUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.LookupUserResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 3, "Yubi.yubiMapSlotToUser"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) YubiProvision(ctx context.Context, ssh lib.YubiSerialSlotHost) (err error) {
	arg := YubiProvisionArg{
		Ssh: ssh,
	}
	warg := &rpc.DataWrap[Header, *YubiProvisionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 4, "Yubi.yubiProvision"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) YubiNew(ctx context.Context, arg YubiNewArg) (err error) {
	warg := &rpc.DataWrap[Header, *YubiNewArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 5, "Yubi.yubiNew"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) ListAllLocalYubiDevices(ctx context.Context, sessionId lib.UISessionID) (res []lib.YubiCardID, err error) {
	arg := ListAllLocalYubiDevicesArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *ListAllLocalYubiDevicesArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, [](*lib.YubiCardIDInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 6, "Yubi.listAllLocalYubiDevices"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*lib.YubiCardIDInternal__)) (ret []lib.YubiCardID) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]lib.YubiCardID, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *lib.YubiCardIDInternal__) (ret lib.YubiCardID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp.Data)
	return
}

func (c YubiClient) UseYubi(ctx context.Context, arg UseYubiArg) (err error) {
	warg := &rpc.DataWrap[Header, *UseYubiArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 7, "Yubi.useYubi"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) ValidateCurrentPIN(ctx context.Context, arg ValidateCurrentPINArg) (err error) {
	warg := &rpc.DataWrap[Header, *ValidateCurrentPINArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 8, "Yubi.validateCurrentPIN"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) SetPIN(ctx context.Context, arg SetPINArg) (err error) {
	warg := &rpc.DataWrap[Header, *SetPINArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 9, "Yubi.setPIN"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) ValidateCurrentPUK(ctx context.Context, arg ValidateCurrentPUKArg) (err error) {
	warg := &rpc.DataWrap[Header, *ValidateCurrentPUKArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 10, "Yubi.validateCurrentPUK"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) SetPUK(ctx context.Context, arg SetPUKArg) (err error) {
	warg := &rpc.DataWrap[Header, *SetPUKArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 11, "Yubi.setPUK"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) SetOrGetManagementKey(ctx context.Context, sessionId lib.UISessionID) (res SetOrGetManagementKeyRes, err error) {
	arg := SetOrGetManagementKeyArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *SetOrGetManagementKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SetOrGetManagementKeyResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 12, "Yubi.setOrGetManagementKey"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) InputPIN(ctx context.Context, arg InputPINArg) (res lib.ManagementKeyState, err error) {
	warg := &rpc.DataWrap[Header, *InputPINArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.ManagementKeyStateInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 13, "Yubi.inputPIN"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) ManagementKeyState(ctx context.Context, sessionId lib.UISessionID) (res lib.ManagementKeyState, err error) {
	arg := ManagementKeyStateArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *ManagementKeyStateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.ManagementKeyStateInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 14, "Yubi.managementKeyState"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) ProtectKeyWithPIN(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := ProtectKeyWithPINArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *ProtectKeyWithPINArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 15, "Yubi.protectKeyWithPIN"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c YubiClient) RecoverManagementKey(ctx context.Context, arg RecoverManagementKeyArg) (err error) {
	warg := &rpc.DataWrap[Header, *RecoverManagementKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(YubiProtocolID, 16, "Yubi.recoverManagementKey"), warg, &tmp, 0*time.Millisecond, yubiErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func YubiProtocol(i YubiInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Yubi",
		ID:   YubiProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiUnlockArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiUnlockArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiUnlockArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.YubiUnlock(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "yubiUnlock",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiListAllCardsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiListAllCardsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiListAllCardsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.YubiListAllCards(ctx)
						if err != nil {
							return nil, err
						}
						lst := (func(x []lib.YubiCardID) *[](*lib.YubiCardIDInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*lib.YubiCardIDInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[Header, [](*lib.YubiCardIDInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "yubiListAllCards",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiListAllSlotsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiListAllSlotsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiListAllSlotsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.YubiListAllSlots(ctx, (typedArg.Import()).Serial)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *ListYubiSlotsResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "yubiListAllSlots",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiMapSlotToUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiMapSlotToUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiMapSlotToUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.YubiMapSlotToUser(ctx, (typedArg.Import()).Ssh)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.LookupUserResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "yubiMapSlotToUser",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiProvisionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiProvisionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiProvisionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.YubiProvision(ctx, (typedArg.Import()).Ssh)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "yubiProvision",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *YubiNewArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *YubiNewArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *YubiNewArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.YubiNew(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "yubiNew",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ListAllLocalYubiDevicesArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ListAllLocalYubiDevicesArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ListAllLocalYubiDevicesArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ListAllLocalYubiDevices(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						lst := (func(x []lib.YubiCardID) *[](*lib.YubiCardIDInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*lib.YubiCardIDInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[Header, [](*lib.YubiCardIDInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "listAllLocalYubiDevices",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *UseYubiArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *UseYubiArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *UseYubiArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.UseYubi(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "useYubi",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ValidateCurrentPINArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ValidateCurrentPINArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ValidateCurrentPINArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ValidateCurrentPIN(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "validateCurrentPIN",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetPINArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetPINArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetPINArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetPIN(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setPIN",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ValidateCurrentPUKArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ValidateCurrentPUKArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ValidateCurrentPUKArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ValidateCurrentPUK(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "validateCurrentPUK",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetPUKArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetPUKArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetPUKArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetPUK(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setPUK",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetOrGetManagementKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetOrGetManagementKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetOrGetManagementKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.SetOrGetManagementKey(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SetOrGetManagementKeyResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setOrGetManagementKey",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *InputPINArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *InputPINArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *InputPINArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.InputPIN(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.ManagementKeyStateInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "inputPIN",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ManagementKeyStateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ManagementKeyStateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ManagementKeyStateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ManagementKeyState(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.ManagementKeyStateInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "managementKeyState",
			},
			15: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ProtectKeyWithPINArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ProtectKeyWithPINArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ProtectKeyWithPINArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ProtectKeyWithPIN(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "protectKeyWithPIN",
			},
			16: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *RecoverManagementKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *RecoverManagementKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *RecoverManagementKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.RecoverManagementKey(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "recoverManagementKey",
			},
		},
		WrapError: YubiMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(YubiProtocolID)
}
