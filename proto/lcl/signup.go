// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/signup.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type InviteCodeString string
type InviteCodeStringInternal__ string

func (i InviteCodeString) Export() *InviteCodeStringInternal__ {
	tmp := ((string)(i))
	return ((*InviteCodeStringInternal__)(&tmp))
}
func (i InviteCodeStringInternal__) Import() InviteCodeString {
	tmp := (string)(i)
	return InviteCodeString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (i *InviteCodeString) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *InviteCodeString) Decode(dec rpc.Decoder) error {
	var tmp InviteCodeStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i InviteCodeString) Bytes() []byte {
	return nil
}

type ViewToken struct {
	IsSelf bool
	Token  lib.PermissionToken
}
type ViewTokenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	IsSelf  *bool
	Token   *lib.PermissionTokenInternal__
}

func (v ViewTokenInternal__) Import() ViewToken {
	return ViewToken{
		IsSelf: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(v.IsSelf),
		Token: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.Token),
	}
}
func (v ViewToken) Export() *ViewTokenInternal__ {
	return &ViewTokenInternal__{
		IsSelf: &v.IsSelf,
		Token:  v.Token.Export(),
	}
}
func (v *ViewToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *ViewToken) Decode(dec rpc.Decoder) error {
	var tmp ViewTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v *ViewToken) Bytes() []byte { return nil }

type PutYubiSlotRes struct {
	Username   *lib.Name
	Device     lib.YubiCardInfo
	ChosenSlot lib.YubiSlot
	IdxType    lib.YubiIndexType
}
type PutYubiSlotResInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Username   *lib.NameInternal__
	Device     *lib.YubiCardInfoInternal__
	ChosenSlot *lib.YubiSlotInternal__
	IdxType    *lib.YubiIndexTypeInternal__
}

func (p PutYubiSlotResInternal__) Import() PutYubiSlotRes {
	return PutYubiSlotRes{
		Username: (func(x *lib.NameInternal__) *lib.Name {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.NameInternal__) (ret lib.Name) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Username),
		Device: (func(x *lib.YubiCardInfoInternal__) (ret lib.YubiCardInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Device),
		ChosenSlot: (func(x *lib.YubiSlotInternal__) (ret lib.YubiSlot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.ChosenSlot),
		IdxType: (func(x *lib.YubiIndexTypeInternal__) (ret lib.YubiIndexType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.IdxType),
	}
}
func (p PutYubiSlotRes) Export() *PutYubiSlotResInternal__ {
	return &PutYubiSlotResInternal__{
		Username: (func(x *lib.Name) *lib.NameInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.Username),
		Device:     p.Device.Export(),
		ChosenSlot: p.ChosenSlot.Export(),
		IdxType:    p.IdxType.Export(),
	}
}
func (p *PutYubiSlotRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutYubiSlotRes) Decode(dec rpc.Decoder) error {
	var tmp PutYubiSlotResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutYubiSlotRes) Bytes() []byte { return nil }

type SsoLoginFlow struct {
	Url lib.URLString
}
type SsoLoginFlowInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Url     *lib.URLStringInternal__
}

func (s SsoLoginFlowInternal__) Import() SsoLoginFlow {
	return SsoLoginFlow{
		Url: (func(x *lib.URLStringInternal__) (ret lib.URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Url),
	}
}
func (s SsoLoginFlow) Export() *SsoLoginFlowInternal__ {
	return &SsoLoginFlowInternal__{
		Url: s.Url.Export(),
	}
}
func (s *SsoLoginFlow) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SsoLoginFlow) Decode(dec rpc.Decoder) error {
	var tmp SsoLoginFlowInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SsoLoginFlow) Bytes() []byte { return nil }

type ListYubiSlotsRes struct {
	Device *lib.YubiCardInfo
}
type ListYubiSlotsResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Device  *lib.YubiCardInfoInternal__
}

func (l ListYubiSlotsResInternal__) Import() ListYubiSlotsRes {
	return ListYubiSlotsRes{
		Device: (func(x *lib.YubiCardInfoInternal__) *lib.YubiCardInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.YubiCardInfoInternal__) (ret lib.YubiCardInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Device),
	}
}
func (l ListYubiSlotsRes) Export() *ListYubiSlotsResInternal__ {
	return &ListYubiSlotsResInternal__{
		Device: (func(x *lib.YubiCardInfo) *lib.YubiCardInfoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.Device),
	}
}
func (l *ListYubiSlotsRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *ListYubiSlotsRes) Decode(dec rpc.Decoder) error {
	var tmp ListYubiSlotsResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *ListYubiSlotsRes) Bytes() []byte { return nil }

type FinishRes struct {
	RegServerType RegServerType
	HostType      lib.HostType
}
type FinishResInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	RegServerType *RegServerTypeInternal__
	HostType      *lib.HostTypeInternal__
}

func (f FinishResInternal__) Import() FinishRes {
	return FinishRes{
		RegServerType: (func(x *RegServerTypeInternal__) (ret RegServerType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.RegServerType),
		HostType: (func(x *lib.HostTypeInternal__) (ret lib.HostType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.HostType),
	}
}
func (f FinishRes) Export() *FinishResInternal__ {
	return &FinishResInternal__{
		RegServerType: f.RegServerType.Export(),
		HostType:      f.HostType.Export(),
	}
}
func (f *FinishRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishRes) Decode(dec rpc.Decoder) error {
	var tmp FinishResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishRes) Bytes() []byte { return nil }

var SignupProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xe7053af6)

type LoginAsArg struct {
	SessionId lib.UISessionID
	User      lib.UserInfo
}
type LoginAsArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	User      *lib.UserInfoInternal__
}

func (l LoginAsArgInternal__) Import() LoginAsArg {
	return LoginAsArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
		User: (func(x *lib.UserInfoInternal__) (ret lib.UserInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.User),
	}
}
func (l LoginAsArg) Export() *LoginAsArgInternal__ {
	return &LoginAsArgInternal__{
		SessionId: l.SessionId.Export(),
		User:      l.User.Export(),
	}
}
func (l *LoginAsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoginAsArg) Decode(dec rpc.Decoder) error {
	var tmp LoginAsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoginAsArg) Bytes() []byte { return nil }

type PutInviteCodeArg struct {
	SessionId  lib.UISessionID
	InviteCode InviteCodeString
}
type PutInviteCodeArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId  *lib.UISessionIDInternal__
	InviteCode *InviteCodeStringInternal__
}

func (p PutInviteCodeArgInternal__) Import() PutInviteCodeArg {
	return PutInviteCodeArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		InviteCode: (func(x *InviteCodeStringInternal__) (ret InviteCodeString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.InviteCode),
	}
}
func (p PutInviteCodeArg) Export() *PutInviteCodeArgInternal__ {
	return &PutInviteCodeArgInternal__{
		SessionId:  p.SessionId.Export(),
		InviteCode: p.InviteCode.Export(),
	}
}
func (p *PutInviteCodeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutInviteCodeArg) Decode(dec rpc.Decoder) error {
	var tmp PutInviteCodeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutInviteCodeArg) Bytes() []byte { return nil }

type PutUsernameArg struct {
	SessionId lib.UISessionID
	Username  lib.NameUtf8
}
type PutUsernameArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Username  *lib.NameUtf8Internal__
}

func (p PutUsernameArgInternal__) Import() PutUsernameArg {
	return PutUsernameArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		Username: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Username),
	}
}
func (p PutUsernameArg) Export() *PutUsernameArgInternal__ {
	return &PutUsernameArgInternal__{
		SessionId: p.SessionId.Export(),
		Username:  p.Username.Export(),
	}
}
func (p *PutUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp PutUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutUsernameArg) Bytes() []byte { return nil }

type ListYubiSlotsArg struct {
	SessionId lib.UISessionID
}
type ListYubiSlotsArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (l ListYubiSlotsArgInternal__) Import() ListYubiSlotsArg {
	return ListYubiSlotsArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
	}
}
func (l ListYubiSlotsArg) Export() *ListYubiSlotsArgInternal__ {
	return &ListYubiSlotsArgInternal__{
		SessionId: l.SessionId.Export(),
	}
}
func (l *ListYubiSlotsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *ListYubiSlotsArg) Decode(dec rpc.Decoder) error {
	var tmp ListYubiSlotsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *ListYubiSlotsArg) Bytes() []byte { return nil }

type CliJoinWaitListArg struct {
	SessionId lib.UISessionID
}
type CliJoinWaitListArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (c CliJoinWaitListArgInternal__) Import() CliJoinWaitListArg {
	return CliJoinWaitListArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SessionId),
	}
}
func (c CliJoinWaitListArg) Export() *CliJoinWaitListArgInternal__ {
	return &CliJoinWaitListArgInternal__{
		SessionId: c.SessionId.Export(),
	}
}
func (c *CliJoinWaitListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CliJoinWaitListArg) Decode(dec rpc.Decoder) error {
	var tmp CliJoinWaitListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CliJoinWaitListArg) Bytes() []byte { return nil }

type PutDeviceNameArg struct {
	SessionId  lib.UISessionID
	DeviceName lib.DeviceName
}
type PutDeviceNameArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId  *lib.UISessionIDInternal__
	DeviceName *lib.DeviceNameInternal__
}

func (p PutDeviceNameArgInternal__) Import() PutDeviceNameArg {
	return PutDeviceNameArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		DeviceName: (func(x *lib.DeviceNameInternal__) (ret lib.DeviceName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.DeviceName),
	}
}
func (p PutDeviceNameArg) Export() *PutDeviceNameArgInternal__ {
	return &PutDeviceNameArgInternal__{
		SessionId:  p.SessionId.Export(),
		DeviceName: p.DeviceName.Export(),
	}
}
func (p *PutDeviceNameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutDeviceNameArg) Decode(dec rpc.Decoder) error {
	var tmp PutDeviceNameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutDeviceNameArg) Bytes() []byte { return nil }

type PutEmailArg struct {
	SessionId lib.UISessionID
	Email     lib.Email
}
type PutEmailArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Email     *lib.EmailInternal__
}

func (p PutEmailArgInternal__) Import() PutEmailArg {
	return PutEmailArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		Email: (func(x *lib.EmailInternal__) (ret lib.Email) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Email),
	}
}
func (p PutEmailArg) Export() *PutEmailArgInternal__ {
	return &PutEmailArgInternal__{
		SessionId: p.SessionId.Export(),
		Email:     p.Email.Export(),
	}
}
func (p *PutEmailArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutEmailArg) Decode(dec rpc.Decoder) error {
	var tmp PutEmailArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutEmailArg) Bytes() []byte { return nil }

type FinishArg struct {
	SessionId lib.UISessionID
}
type FinishArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishArgInternal__) Import() FinishArg {
	return FinishArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishArg) Export() *FinishArgInternal__ {
	return &FinishArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishArg) Decode(dec rpc.Decoder) error {
	var tmp FinishArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishArg) Bytes() []byte { return nil }

type PutYubiSlotArg struct {
	SessionId lib.UISessionID
	Index     lib.YubiIndex
	Typ       lib.CryptosystemType
}
type PutYubiSlotArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Index     *lib.YubiIndexInternal__
	Typ       *lib.CryptosystemTypeInternal__
}

func (p PutYubiSlotArgInternal__) Import() PutYubiSlotArg {
	return PutYubiSlotArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		Index: (func(x *lib.YubiIndexInternal__) (ret lib.YubiIndex) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Index),
		Typ: (func(x *lib.CryptosystemTypeInternal__) (ret lib.CryptosystemType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Typ),
	}
}
func (p PutYubiSlotArg) Export() *PutYubiSlotArgInternal__ {
	return &PutYubiSlotArgInternal__{
		SessionId: p.SessionId.Export(),
		Index:     p.Index.Export(),
		Typ:       p.Typ.Export(),
	}
}
func (p *PutYubiSlotArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutYubiSlotArg) Decode(dec rpc.Decoder) error {
	var tmp PutYubiSlotArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutYubiSlotArg) Bytes() []byte { return nil }

type IsUsernameServerAssignedArg struct {
	SessionId lib.UISessionID
}
type IsUsernameServerAssignedArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (i IsUsernameServerAssignedArgInternal__) Import() IsUsernameServerAssignedArg {
	return IsUsernameServerAssignedArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(i.SessionId),
	}
}
func (i IsUsernameServerAssignedArg) Export() *IsUsernameServerAssignedArgInternal__ {
	return &IsUsernameServerAssignedArgInternal__{
		SessionId: i.SessionId.Export(),
	}
}
func (i *IsUsernameServerAssignedArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *IsUsernameServerAssignedArg) Decode(dec rpc.Decoder) error {
	var tmp IsUsernameServerAssignedArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i *IsUsernameServerAssignedArg) Bytes() []byte { return nil }

type StartKexArg struct {
	SessionId lib.UISessionID
}
type StartKexArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (s StartKexArgInternal__) Import() StartKexArg {
	return StartKexArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
	}
}
func (s StartKexArg) Export() *StartKexArgInternal__ {
	return &StartKexArgInternal__{
		SessionId: s.SessionId.Export(),
	}
}
func (s *StartKexArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StartKexArg) Decode(dec rpc.Decoder) error {
	var tmp StartKexArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *StartKexArg) Bytes() []byte { return nil }

type GotKexInputArg struct {
	K KexSessionAndHESP
}
type GotKexInputArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	K       *KexSessionAndHESPInternal__
}

func (g GotKexInputArgInternal__) Import() GotKexInputArg {
	return GotKexInputArg{
		K: (func(x *KexSessionAndHESPInternal__) (ret KexSessionAndHESP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.K),
	}
}
func (g GotKexInputArg) Export() *GotKexInputArgInternal__ {
	return &GotKexInputArgInternal__{
		K: g.K.Export(),
	}
}
func (g *GotKexInputArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GotKexInputArg) Decode(dec rpc.Decoder) error {
	var tmp GotKexInputArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GotKexInputArg) Bytes() []byte { return nil }

type KexCancelInputArg struct {
	SessionId lib.UISessionID
}
type KexCancelInputArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (k KexCancelInputArgInternal__) Import() KexCancelInputArg {
	return KexCancelInputArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SessionId),
	}
}
func (k KexCancelInputArg) Export() *KexCancelInputArgInternal__ {
	return &KexCancelInputArgInternal__{
		SessionId: k.SessionId.Export(),
	}
}
func (k *KexCancelInputArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexCancelInputArg) Decode(dec rpc.Decoder) error {
	var tmp KexCancelInputArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KexCancelInputArg) Bytes() []byte { return nil }

type WaitForKexCompleteArg struct {
	SessionId lib.UISessionID
}
type WaitForKexCompleteArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (w WaitForKexCompleteArgInternal__) Import() WaitForKexCompleteArg {
	return WaitForKexCompleteArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(w.SessionId),
	}
}
func (w WaitForKexCompleteArg) Export() *WaitForKexCompleteArgInternal__ {
	return &WaitForKexCompleteArgInternal__{
		SessionId: w.SessionId.Export(),
	}
}
func (w *WaitForKexCompleteArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(w.Export())
}

func (w *WaitForKexCompleteArg) Decode(dec rpc.Decoder) error {
	var tmp WaitForKexCompleteArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*w = tmp.Import()
	return nil
}

func (w *WaitForKexCompleteArg) Bytes() []byte { return nil }

type FinishYubiProvisionArg struct {
	SessionId lib.UISessionID
}
type FinishYubiProvisionArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishYubiProvisionArgInternal__) Import() FinishYubiProvisionArg {
	return FinishYubiProvisionArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishYubiProvisionArg) Export() *FinishYubiProvisionArgInternal__ {
	return &FinishYubiProvisionArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishYubiProvisionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishYubiProvisionArg) Decode(dec rpc.Decoder) error {
	var tmp FinishYubiProvisionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishYubiProvisionArg) Bytes() []byte { return nil }

type GetDeviceTypeArg struct {
	SessionId lib.UISessionID
}
type GetDeviceTypeArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (g GetDeviceTypeArgInternal__) Import() GetDeviceTypeArg {
	return GetDeviceTypeArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
	}
}
func (g GetDeviceTypeArg) Export() *GetDeviceTypeArgInternal__ {
	return &GetDeviceTypeArgInternal__{
		SessionId: g.SessionId.Export(),
	}
}
func (g *GetDeviceTypeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetDeviceTypeArg) Decode(dec rpc.Decoder) error {
	var tmp GetDeviceTypeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetDeviceTypeArg) Bytes() []byte { return nil }

type GetActiveUserForProvisionArg struct {
	SessionId lib.UISessionID
}
type GetActiveUserForProvisionArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (g GetActiveUserForProvisionArgInternal__) Import() GetActiveUserForProvisionArg {
	return GetActiveUserForProvisionArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
	}
}
func (g GetActiveUserForProvisionArg) Export() *GetActiveUserForProvisionArgInternal__ {
	return &GetActiveUserForProvisionArgInternal__{
		SessionId: g.SessionId.Export(),
	}
}
func (g *GetActiveUserForProvisionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetActiveUserForProvisionArg) Decode(dec rpc.Decoder) error {
	var tmp GetActiveUserForProvisionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetActiveUserForProvisionArg) Bytes() []byte { return nil }

type PromptForPassphraseArg struct {
	SessionId lib.UISessionID
}
type PromptForPassphraseArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (p PromptForPassphraseArgInternal__) Import() PromptForPassphraseArg {
	return PromptForPassphraseArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
	}
}
func (p PromptForPassphraseArg) Export() *PromptForPassphraseArgInternal__ {
	return &PromptForPassphraseArgInternal__{
		SessionId: p.SessionId.Export(),
	}
}
func (p *PromptForPassphraseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PromptForPassphraseArg) Decode(dec rpc.Decoder) error {
	var tmp PromptForPassphraseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PromptForPassphraseArg) Bytes() []byte { return nil }

type PutPassphraseArg struct {
	SessionID  lib.UISessionID
	Passphrase lib.Passphrase
}
type PutPassphraseArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionID  *lib.UISessionIDInternal__
	Passphrase *lib.PassphraseInternal__
}

func (p PutPassphraseArgInternal__) Import() PutPassphraseArg {
	return PutPassphraseArg{
		SessionID: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionID),
		Passphrase: (func(x *lib.PassphraseInternal__) (ret lib.Passphrase) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Passphrase),
	}
}
func (p PutPassphraseArg) Export() *PutPassphraseArgInternal__ {
	return &PutPassphraseArgInternal__{
		SessionID:  p.SessionID.Export(),
		Passphrase: p.Passphrase.Export(),
	}
}
func (p *PutPassphraseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutPassphraseArg) Decode(dec rpc.Decoder) error {
	var tmp PutPassphraseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutPassphraseArg) Bytes() []byte { return nil }

type LoadStateFromActiveUserArg struct {
	SessionId lib.UISessionID
}
type LoadStateFromActiveUserArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (l LoadStateFromActiveUserArgInternal__) Import() LoadStateFromActiveUserArg {
	return LoadStateFromActiveUserArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
	}
}
func (l LoadStateFromActiveUserArg) Export() *LoadStateFromActiveUserArgInternal__ {
	return &LoadStateFromActiveUserArgInternal__{
		SessionId: l.SessionId.Export(),
	}
}
func (l *LoadStateFromActiveUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadStateFromActiveUserArg) Decode(dec rpc.Decoder) error {
	var tmp LoadStateFromActiveUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadStateFromActiveUserArg) Bytes() []byte { return nil }

type FinishYubiNewArg struct {
	SessionId lib.UISessionID
}
type FinishYubiNewArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishYubiNewArgInternal__) Import() FinishYubiNewArg {
	return FinishYubiNewArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishYubiNewArg) Export() *FinishYubiNewArgInternal__ {
	return &FinishYubiNewArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishYubiNewArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishYubiNewArg) Decode(dec rpc.Decoder) error {
	var tmp FinishYubiNewArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishYubiNewArg) Bytes() []byte { return nil }

type SignupStartSsoLoginFlowArg struct {
	SessionId lib.UISessionID
}
type SignupStartSsoLoginFlowArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (s SignupStartSsoLoginFlowArgInternal__) Import() SignupStartSsoLoginFlowArg {
	return SignupStartSsoLoginFlowArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
	}
}
func (s SignupStartSsoLoginFlowArg) Export() *SignupStartSsoLoginFlowArgInternal__ {
	return &SignupStartSsoLoginFlowArgInternal__{
		SessionId: s.SessionId.Export(),
	}
}
func (s *SignupStartSsoLoginFlowArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignupStartSsoLoginFlowArg) Decode(dec rpc.Decoder) error {
	var tmp SignupStartSsoLoginFlowArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignupStartSsoLoginFlowArg) Bytes() []byte { return nil }

type SignupWaitForSsoLoginArg struct {
	SessionId lib.UISessionID
}
type SignupWaitForSsoLoginArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (s SignupWaitForSsoLoginArgInternal__) Import() SignupWaitForSsoLoginArg {
	return SignupWaitForSsoLoginArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SessionId),
	}
}
func (s SignupWaitForSsoLoginArg) Export() *SignupWaitForSsoLoginArgInternal__ {
	return &SignupWaitForSsoLoginArgInternal__{
		SessionId: s.SessionId.Export(),
	}
}
func (s *SignupWaitForSsoLoginArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignupWaitForSsoLoginArg) Decode(dec rpc.Decoder) error {
	var tmp SignupWaitForSsoLoginArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignupWaitForSsoLoginArg) Bytes() []byte { return nil }

type GetUsernameSSOArg struct {
	SessionId lib.UISessionID
}
type GetUsernameSSOArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (g GetUsernameSSOArgInternal__) Import() GetUsernameSSOArg {
	return GetUsernameSSOArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
	}
}
func (g GetUsernameSSOArg) Export() *GetUsernameSSOArgInternal__ {
	return &GetUsernameSSOArgInternal__{
		SessionId: g.SessionId.Export(),
	}
}
func (g *GetUsernameSSOArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetUsernameSSOArg) Decode(dec rpc.Decoder) error {
	var tmp GetUsernameSSOArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetUsernameSSOArg) Bytes() []byte { return nil }

type GetEmailSSOArg struct {
	SessionId lib.UISessionID
}
type GetEmailSSOArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (g GetEmailSSOArgInternal__) Import() GetEmailSSOArg {
	return GetEmailSSOArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
	}
}
func (g GetEmailSSOArg) Export() *GetEmailSSOArgInternal__ {
	return &GetEmailSSOArgInternal__{
		SessionId: g.SessionId.Export(),
	}
}
func (g *GetEmailSSOArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetEmailSSOArg) Decode(dec rpc.Decoder) error {
	var tmp GetEmailSSOArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetEmailSSOArg) Bytes() []byte { return nil }

type GetSkipInviteCodeSSOArg struct {
	SessionId lib.UISessionID
}
type GetSkipInviteCodeSSOArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (g GetSkipInviteCodeSSOArgInternal__) Import() GetSkipInviteCodeSSOArg {
	return GetSkipInviteCodeSSOArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
	}
}
func (g GetSkipInviteCodeSSOArg) Export() *GetSkipInviteCodeSSOArgInternal__ {
	return &GetSkipInviteCodeSSOArgInternal__{
		SessionId: g.SessionId.Export(),
	}
}
func (g *GetSkipInviteCodeSSOArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetSkipInviteCodeSSOArg) Decode(dec rpc.Decoder) error {
	var tmp GetSkipInviteCodeSSOArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetSkipInviteCodeSSOArg) Bytes() []byte { return nil }

type FinishNKWNewDeviceKeyArg struct {
	SessionId lib.UISessionID
}
type FinishNKWNewDeviceKeyArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishNKWNewDeviceKeyArgInternal__) Import() FinishNKWNewDeviceKeyArg {
	return FinishNKWNewDeviceKeyArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishNKWNewDeviceKeyArg) Export() *FinishNKWNewDeviceKeyArgInternal__ {
	return &FinishNKWNewDeviceKeyArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishNKWNewDeviceKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishNKWNewDeviceKeyArg) Decode(dec rpc.Decoder) error {
	var tmp FinishNKWNewDeviceKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishNKWNewDeviceKeyArg) Bytes() []byte { return nil }

type FinishNKWNewBackupKeyArg struct {
	SessionId lib.UISessionID
}
type FinishNKWNewBackupKeyArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishNKWNewBackupKeyArgInternal__) Import() FinishNKWNewBackupKeyArg {
	return FinishNKWNewBackupKeyArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishNKWNewBackupKeyArg) Export() *FinishNKWNewBackupKeyArgInternal__ {
	return &FinishNKWNewBackupKeyArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishNKWNewBackupKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishNKWNewBackupKeyArg) Decode(dec rpc.Decoder) error {
	var tmp FinishNKWNewBackupKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishNKWNewBackupKeyArg) Bytes() []byte { return nil }

type SignupInterface interface {
	LoginAs(context.Context, LoginAsArg) error
	PutInviteCode(context.Context, PutInviteCodeArg) error
	PutUsername(context.Context, PutUsernameArg) error
	ListYubiSlots(context.Context, lib.UISessionID) (ListYubiSlotsRes, error)
	JoinWaitList(context.Context, lib.UISessionID) (lib.WaitListID, error)
	PutDeviceName(context.Context, PutDeviceNameArg) error
	PutEmail(context.Context, PutEmailArg) error
	Finish(context.Context, lib.UISessionID) (FinishRes, error)
	PutYubiSlot(context.Context, PutYubiSlotArg) (PutYubiSlotRes, error)
	IsUsernameServerAssigned(context.Context, lib.UISessionID) (bool, error)
	StartKex(context.Context, lib.UISessionID) (lib.KexHESP, error)
	GotKexInput(context.Context, KexSessionAndHESP) error
	KexCancelInput(context.Context, lib.UISessionID) error
	WaitForKexComplete(context.Context, lib.UISessionID) error
	FinishYubiProvision(context.Context, lib.UISessionID) error
	GetDeviceType(context.Context, lib.UISessionID) (lib.DeviceType, error)
	GetActiveUserForProvision(context.Context, lib.UISessionID) (lib.UserContext, error)
	PromptForPassphrase(context.Context, lib.UISessionID) (bool, error)
	PutPassphrase(context.Context, PutPassphraseArg) error
	LoadStateFromActiveUser(context.Context, lib.UISessionID) (lib.UserInfo, error)
	FinishYubiNew(context.Context, lib.UISessionID) error
	SignupStartSsoLoginFlow(context.Context, lib.UISessionID) (SsoLoginFlow, error)
	SignupWaitForSsoLogin(context.Context, lib.UISessionID) (lib.SSOLoginRes, error)
	GetUsernameSSO(context.Context, lib.UISessionID) (lib.NameUtf8, error)
	GetEmailSSO(context.Context, lib.UISessionID) (lib.Email, error)
	GetSkipInviteCodeSSO(context.Context, lib.UISessionID) (bool, error)
	FinishNKWNewDeviceKey(context.Context, lib.UISessionID) error
	FinishNKWNewBackupKey(context.Context, lib.UISessionID) (BackupHESP, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func SignupMakeGenericErrorWrapper(f SignupErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type SignupErrorUnwrapper func(lib.Status) error
type SignupErrorWrapper func(error) lib.Status

type signupErrorUnwrapperAdapter struct {
	h SignupErrorUnwrapper
}

func (s signupErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (s signupErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return s.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = signupErrorUnwrapperAdapter{}

type SignupClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper SignupErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c SignupClient) LoginAs(ctx context.Context, arg LoginAsArg) (err error) {
	warg := &rpc.DataWrap[Header, *LoginAsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 4, "Signup.loginAs"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PutInviteCode(ctx context.Context, arg PutInviteCodeArg) (err error) {
	warg := &rpc.DataWrap[Header, *PutInviteCodeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 6, "Signup.putInviteCode"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PutUsername(ctx context.Context, arg PutUsernameArg) (err error) {
	warg := &rpc.DataWrap[Header, *PutUsernameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 7, "Signup.putUsername"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) ListYubiSlots(ctx context.Context, sessionId lib.UISessionID) (res ListYubiSlotsRes, err error) {
	arg := ListYubiSlotsArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *ListYubiSlotsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, ListYubiSlotsResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 8, "Signup.listYubiSlots"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) JoinWaitList(ctx context.Context, sessionId lib.UISessionID) (res lib.WaitListID, err error) {
	arg := CliJoinWaitListArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *CliJoinWaitListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.WaitListIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 9, "Signup.joinWaitList"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PutDeviceName(ctx context.Context, arg PutDeviceNameArg) (err error) {
	warg := &rpc.DataWrap[Header, *PutDeviceNameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 10, "Signup.putDeviceName"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PutEmail(ctx context.Context, arg PutEmailArg) (err error) {
	warg := &rpc.DataWrap[Header, *PutEmailArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 11, "Signup.putEmail"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) Finish(ctx context.Context, sessionId lib.UISessionID) (res FinishRes, err error) {
	arg := FinishArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, FinishResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 12, "Signup.finish"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PutYubiSlot(ctx context.Context, arg PutYubiSlotArg) (res PutYubiSlotRes, err error) {
	warg := &rpc.DataWrap[Header, *PutYubiSlotArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, PutYubiSlotResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 14, "Signup.putYubiSlot"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) IsUsernameServerAssigned(ctx context.Context, sessionId lib.UISessionID) (res bool, err error) {
	arg := IsUsernameServerAssignedArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *IsUsernameServerAssignedArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, bool]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 15, "Signup.isUsernameServerAssigned"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data
	return
}
func (c SignupClient) StartKex(ctx context.Context, sessionId lib.UISessionID) (res lib.KexHESP, err error) {
	arg := StartKexArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *StartKexArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KexHESPInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 17, "Signup.startKex"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GotKexInput(ctx context.Context, k KexSessionAndHESP) (err error) {
	arg := GotKexInputArg{
		K: k,
	}
	warg := &rpc.DataWrap[Header, *GotKexInputArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 18, "Signup.gotKexInput"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) KexCancelInput(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := KexCancelInputArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *KexCancelInputArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 19, "Signup.kexCancelInput"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) WaitForKexComplete(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := WaitForKexCompleteArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *WaitForKexCompleteArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 20, "Signup.waitForKexComplete"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) FinishYubiProvision(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := FinishYubiProvisionArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishYubiProvisionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 21, "Signup.finishYubiProvision"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GetDeviceType(ctx context.Context, sessionId lib.UISessionID) (res lib.DeviceType, err error) {
	arg := GetDeviceTypeArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *GetDeviceTypeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.DeviceTypeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 22, "Signup.getDeviceType"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GetActiveUserForProvision(ctx context.Context, sessionId lib.UISessionID) (res lib.UserContext, err error) {
	arg := GetActiveUserForProvisionArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *GetActiveUserForProvisionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UserContextInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 23, "Signup.getActiveUserForProvision"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) PromptForPassphrase(ctx context.Context, sessionId lib.UISessionID) (res bool, err error) {
	arg := PromptForPassphraseArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *PromptForPassphraseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, bool]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 24, "Signup.promptForPassphrase"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data
	return
}
func (c SignupClient) PutPassphrase(ctx context.Context, arg PutPassphraseArg) (err error) {
	warg := &rpc.DataWrap[Header, *PutPassphraseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 25, "Signup.putPassphrase"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) LoadStateFromActiveUser(ctx context.Context, sessionId lib.UISessionID) (res lib.UserInfo, err error) {
	arg := LoadStateFromActiveUserArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *LoadStateFromActiveUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UserInfoInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 26, "Signup.loadStateFromActiveUser"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) FinishYubiNew(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := FinishYubiNewArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishYubiNewArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 27, "Signup.finishYubiNew"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) SignupStartSsoLoginFlow(ctx context.Context, sessionId lib.UISessionID) (res SsoLoginFlow, err error) {
	arg := SignupStartSsoLoginFlowArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *SignupStartSsoLoginFlowArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SsoLoginFlowInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 28, "Signup.signupStartSsoLoginFlow"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) SignupWaitForSsoLogin(ctx context.Context, sessionId lib.UISessionID) (res lib.SSOLoginRes, err error) {
	arg := SignupWaitForSsoLoginArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *SignupWaitForSsoLoginArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.SSOLoginResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 29, "Signup.signupWaitForSsoLogin"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GetUsernameSSO(ctx context.Context, sessionId lib.UISessionID) (res lib.NameUtf8, err error) {
	arg := GetUsernameSSOArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *GetUsernameSSOArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.NameUtf8Internal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 30, "Signup.getUsernameSSO"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GetEmailSSO(ctx context.Context, sessionId lib.UISessionID) (res lib.Email, err error) {
	arg := GetEmailSSOArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *GetEmailSSOArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.EmailInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 31, "Signup.getEmailSSO"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) GetSkipInviteCodeSSO(ctx context.Context, sessionId lib.UISessionID) (res bool, err error) {
	arg := GetSkipInviteCodeSSOArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *GetSkipInviteCodeSSOArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, bool]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 32, "Signup.getSkipInviteCodeSSO"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data
	return
}
func (c SignupClient) FinishNKWNewDeviceKey(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := FinishNKWNewDeviceKeyArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishNKWNewDeviceKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 33, "Signup.finishNKWNewDeviceKey"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SignupClient) FinishNKWNewBackupKey(ctx context.Context, sessionId lib.UISessionID) (res BackupHESP, err error) {
	arg := FinishNKWNewBackupKeyArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishNKWNewBackupKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, BackupHESPInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SignupProtocolID, 34, "Signup.finishNKWNewBackupKey"), warg, &tmp, 0*time.Millisecond, signupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func SignupProtocol(i SignupInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Signup",
		ID:   SignupProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoginAsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoginAsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoginAsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.LoginAs(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loginAs",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutInviteCodeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutInviteCodeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutInviteCodeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutInviteCode(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putInviteCode",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutUsernameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutUsernameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutUsernameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutUsername(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putUsername",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ListYubiSlotsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ListYubiSlotsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ListYubiSlotsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ListYubiSlots(ctx, (typedArg.Import()).SessionId)
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
				Name: "listYubiSlots",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *CliJoinWaitListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *CliJoinWaitListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *CliJoinWaitListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.JoinWaitList(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.WaitListIDInternal__]{
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
						var ret rpc.DataWrap[Header, *PutDeviceNameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutDeviceNameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutDeviceNameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutDeviceName(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putDeviceName",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutEmailArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutEmailArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutEmailArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutEmail(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putEmail",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Finish(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *FinishResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finish",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutYubiSlotArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutYubiSlotArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutYubiSlotArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.PutYubiSlot(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *PutYubiSlotResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putYubiSlot",
			},
			15: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *IsUsernameServerAssignedArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *IsUsernameServerAssignedArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *IsUsernameServerAssignedArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.IsUsernameServerAssigned(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, bool]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "isUsernameServerAssigned",
			},
			17: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *StartKexArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *StartKexArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *StartKexArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.StartKex(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.KexHESPInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "startKex",
			},
			18: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GotKexInputArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GotKexInputArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GotKexInputArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.GotKexInput(ctx, (typedArg.Import()).K)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "gotKexInput",
			},
			19: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *KexCancelInputArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *KexCancelInputArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *KexCancelInputArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KexCancelInput(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kexCancelInput",
			},
			20: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *WaitForKexCompleteArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *WaitForKexCompleteArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *WaitForKexCompleteArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.WaitForKexComplete(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "waitForKexComplete",
			},
			21: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishYubiProvisionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishYubiProvisionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishYubiProvisionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.FinishYubiProvision(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finishYubiProvision",
			},
			22: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetDeviceTypeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetDeviceTypeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetDeviceTypeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetDeviceType(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.DeviceTypeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getDeviceType",
			},
			23: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetActiveUserForProvisionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetActiveUserForProvisionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetActiveUserForProvisionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetActiveUserForProvision(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.UserContextInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getActiveUserForProvision",
			},
			24: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PromptForPassphraseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PromptForPassphraseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PromptForPassphraseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.PromptForPassphrase(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, bool]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "promptForPassphrase",
			},
			25: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutPassphraseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutPassphraseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutPassphraseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutPassphrase(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putPassphrase",
			},
			26: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoadStateFromActiveUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoadStateFromActiveUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoadStateFromActiveUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoadStateFromActiveUser(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.UserInfoInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadStateFromActiveUser",
			},
			27: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishYubiNewArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishYubiNewArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishYubiNewArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.FinishYubiNew(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finishYubiNew",
			},
			28: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SignupStartSsoLoginFlowArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SignupStartSsoLoginFlowArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SignupStartSsoLoginFlowArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.SignupStartSsoLoginFlow(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SsoLoginFlowInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "signupStartSsoLoginFlow",
			},
			29: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SignupWaitForSsoLoginArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SignupWaitForSsoLoginArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SignupWaitForSsoLoginArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.SignupWaitForSsoLogin(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.SSOLoginResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "signupWaitForSsoLogin",
			},
			30: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetUsernameSSOArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetUsernameSSOArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetUsernameSSOArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetUsernameSSO(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.NameUtf8Internal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getUsernameSSO",
			},
			31: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetEmailSSOArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetEmailSSOArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetEmailSSOArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetEmailSSO(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.EmailInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getEmailSSO",
			},
			32: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetSkipInviteCodeSSOArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetSkipInviteCodeSSOArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetSkipInviteCodeSSOArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetSkipInviteCodeSSO(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, bool]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getSkipInviteCodeSSO",
			},
			33: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishNKWNewDeviceKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishNKWNewDeviceKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishNKWNewDeviceKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.FinishNKWNewDeviceKey(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finishNKWNewDeviceKey",
			},
			34: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishNKWNewBackupKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishNKWNewBackupKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishNKWNewBackupKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.FinishNKWNewBackupKey(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *BackupHESPInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finishNKWNewBackupKey",
			},
		},
		WrapError: SignupMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(SignupProtocolID)
}
