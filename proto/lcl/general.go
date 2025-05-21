// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/general.snowp

package lcl

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type HostStatusPair struct {
	Host   lib.TCPAddr
	Status lib.Status
}
type HostStatusPairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.TCPAddrInternal__
	Status  *lib.StatusInternal__
}

func (h HostStatusPairInternal__) Import() HostStatusPair {
	return HostStatusPair{
		Host: (func(x *lib.TCPAddrInternal__) (ret lib.TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Host),
		Status: (func(x *lib.StatusInternal__) (ret lib.Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Status),
	}
}
func (h HostStatusPair) Export() *HostStatusPairInternal__ {
	return &HostStatusPairInternal__{
		Host:   h.Host.Export(),
		Status: h.Status.Export(),
	}
}
func (h *HostStatusPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostStatusPair) Decode(dec rpc.Decoder) error {
	var tmp HostStatusPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostStatusPair) Bytes() []byte { return nil }

type GetDefaultServerRes struct {
	BigTop HostStatusPair
	Mgmt   *HostStatusPair
}
type GetDefaultServerResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	BigTop  *HostStatusPairInternal__
	Mgmt    *HostStatusPairInternal__
}

func (g GetDefaultServerResInternal__) Import() GetDefaultServerRes {
	return GetDefaultServerRes{
		BigTop: (func(x *HostStatusPairInternal__) (ret HostStatusPair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.BigTop),
		Mgmt: (func(x *HostStatusPairInternal__) *HostStatusPair {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostStatusPairInternal__) (ret HostStatusPair) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Mgmt),
	}
}
func (g GetDefaultServerRes) Export() *GetDefaultServerResInternal__ {
	return &GetDefaultServerResInternal__{
		BigTop: g.BigTop.Export(),
		Mgmt: (func(x *HostStatusPair) *HostStatusPairInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.Mgmt),
	}
}
func (g *GetDefaultServerRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetDefaultServerRes) Decode(dec rpc.Decoder) error {
	var tmp GetDefaultServerResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetDefaultServerRes) Bytes() []byte { return nil }

type DeviceNagInfo struct {
	DoNag      bool
	NumDevices uint64
}
type DeviceNagInfoInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	DoNag      *bool
	NumDevices *uint64
}

func (d DeviceNagInfoInternal__) Import() DeviceNagInfo {
	return DeviceNagInfo{
		DoNag: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(d.DoNag),
		NumDevices: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(d.NumDevices),
	}
}
func (d DeviceNagInfo) Export() *DeviceNagInfoInternal__ {
	return &DeviceNagInfoInternal__{
		DoNag:      &d.DoNag,
		NumDevices: &d.NumDevices,
	}
}
func (d *DeviceNagInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceNagInfo) Decode(dec rpc.Decoder) error {
	var tmp DeviceNagInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceNagInfo) Bytes() []byte { return nil }

type CliVersionPair struct {
	Cli   lib.SemVer
	Agent lib.SemVer
}
type CliVersionPairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cli     *lib.SemVerInternal__
	Agent   *lib.SemVerInternal__
}

func (c CliVersionPairInternal__) Import() CliVersionPair {
	return CliVersionPair{
		Cli: (func(x *lib.SemVerInternal__) (ret lib.SemVer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cli),
		Agent: (func(x *lib.SemVerInternal__) (ret lib.SemVer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Agent),
	}
}
func (c CliVersionPair) Export() *CliVersionPairInternal__ {
	return &CliVersionPairInternal__{
		Cli:   c.Cli.Export(),
		Agent: c.Agent.Export(),
	}
}
func (c *CliVersionPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CliVersionPair) Decode(dec rpc.Decoder) error {
	var tmp CliVersionPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CliVersionPair) Bytes() []byte { return nil }

type UpgradeNagInfo struct {
	Agent  lib.SemVer
	Server lib.ServerClientVersionInfo
}
type UpgradeNagInfoInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Deprecated0 *struct{}
	Agent       *lib.SemVerInternal__
	Server      *lib.ServerClientVersionInfoInternal__
}

func (u UpgradeNagInfoInternal__) Import() UpgradeNagInfo {
	return UpgradeNagInfo{
		Agent: (func(x *lib.SemVerInternal__) (ret lib.SemVer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Agent),
		Server: (func(x *lib.ServerClientVersionInfoInternal__) (ret lib.ServerClientVersionInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Server),
	}
}
func (u UpgradeNagInfo) Export() *UpgradeNagInfoInternal__ {
	return &UpgradeNagInfoInternal__{
		Agent:  u.Agent.Export(),
		Server: u.Server.Export(),
	}
}
func (u *UpgradeNagInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UpgradeNagInfo) Decode(dec rpc.Decoder) error {
	var tmp UpgradeNagInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UpgradeNagInfo) Bytes() []byte { return nil }

type NagType int

const (
	NagType_None                          NagType = 0
	NagType_TooFewDevices                 NagType = 1
	NagType_ClientVersionCritical         NagType = 2
	NagType_ClientVersionUpgradeAvailable NagType = 3
	NagType_ClientVersionClash            NagType = 4
)

var NagTypeMap = map[string]NagType{
	"None":                          0,
	"TooFewDevices":                 1,
	"ClientVersionCritical":         2,
	"ClientVersionUpgradeAvailable": 3,
	"ClientVersionClash":            4,
}
var NagTypeRevMap = map[NagType]string{
	0: "None",
	1: "TooFewDevices",
	2: "ClientVersionCritical",
	3: "ClientVersionUpgradeAvailable",
	4: "ClientVersionClash",
}

type NagTypeInternal__ NagType

func (n NagTypeInternal__) Import() NagType {
	return NagType(n)
}
func (n NagType) Export() *NagTypeInternal__ {
	return ((*NagTypeInternal__)(&n))
}

type UnifiedNag struct {
	T     NagType
	F_1__ *DeviceNagInfo  `json:"f1,omitempty"`
	F_2__ *UpgradeNagInfo `json:"f2,omitempty"`
	F_3__ *CliVersionPair `json:"f3,omitempty"`
}
type UnifiedNagInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        NagType
	Switch__ UnifiedNagInternalSwitch__
}
type UnifiedNagInternalSwitch__ struct {
	_struct struct{}                  `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *DeviceNagInfoInternal__  `codec:"1"`
	F_2__   *UpgradeNagInfoInternal__ `codec:"2"`
	F_3__   *CliVersionPairInternal__ `codec:"3"`
}

func (u UnifiedNag) GetT() (ret NagType, err error) {
	switch u.T {
	case NagType_TooFewDevices:
		if u.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case NagType_ClientVersionCritical, NagType_ClientVersionUpgradeAvailable:
		if u.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case NagType_ClientVersionClash:
		if u.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	}
	return u.T, nil
}
func (u UnifiedNag) Toofewdevices() DeviceNagInfo {
	if u.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != NagType_TooFewDevices {
		panic(fmt.Sprintf("unexpected switch value (%v) when Toofewdevices is called", u.T))
	}
	return *u.F_1__
}
func (u UnifiedNag) Clientversioncritical() UpgradeNagInfo {
	if u.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != NagType_ClientVersionCritical {
		panic(fmt.Sprintf("unexpected switch value (%v) when Clientversioncritical is called", u.T))
	}
	return *u.F_2__
}
func (u UnifiedNag) Clientversionupgradeavailable() UpgradeNagInfo {
	if u.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != NagType_ClientVersionUpgradeAvailable {
		panic(fmt.Sprintf("unexpected switch value (%v) when Clientversionupgradeavailable is called", u.T))
	}
	return *u.F_2__
}
func (u UnifiedNag) Clientversionclash() CliVersionPair {
	if u.F_3__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if u.T != NagType_ClientVersionClash {
		panic(fmt.Sprintf("unexpected switch value (%v) when Clientversionclash is called", u.T))
	}
	return *u.F_3__
}
func NewUnifiedNagWithToofewdevices(v DeviceNagInfo) UnifiedNag {
	return UnifiedNag{
		T:     NagType_TooFewDevices,
		F_1__: &v,
	}
}
func NewUnifiedNagWithClientversioncritical(v UpgradeNagInfo) UnifiedNag {
	return UnifiedNag{
		T:     NagType_ClientVersionCritical,
		F_2__: &v,
	}
}
func NewUnifiedNagWithClientversionupgradeavailable(v UpgradeNagInfo) UnifiedNag {
	return UnifiedNag{
		T:     NagType_ClientVersionUpgradeAvailable,
		F_2__: &v,
	}
}
func NewUnifiedNagWithClientversionclash(v CliVersionPair) UnifiedNag {
	return UnifiedNag{
		T:     NagType_ClientVersionClash,
		F_3__: &v,
	}
}
func (u UnifiedNagInternal__) Import() UnifiedNag {
	return UnifiedNag{
		T: u.T,
		F_1__: (func(x *DeviceNagInfoInternal__) *DeviceNagInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *DeviceNagInfoInternal__) (ret DeviceNagInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_1__),
		F_2__: (func(x *UpgradeNagInfoInternal__) *UpgradeNagInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *UpgradeNagInfoInternal__) (ret UpgradeNagInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_2__),
		F_3__: (func(x *CliVersionPairInternal__) *CliVersionPair {
			if x == nil {
				return nil
			}
			tmp := (func(x *CliVersionPairInternal__) (ret CliVersionPair) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Switch__.F_3__),
	}
}
func (u UnifiedNag) Export() *UnifiedNagInternal__ {
	return &UnifiedNagInternal__{
		T: u.T,
		Switch__: UnifiedNagInternalSwitch__{
			F_1__: (func(x *DeviceNagInfo) *DeviceNagInfoInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_1__),
			F_2__: (func(x *UpgradeNagInfo) *UpgradeNagInfoInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_2__),
			F_3__: (func(x *CliVersionPair) *CliVersionPairInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(u.F_3__),
		},
	}
}
func (u *UnifiedNag) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UnifiedNag) Decode(dec rpc.Decoder) error {
	var tmp UnifiedNagInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UnifiedNag) Bytes() []byte { return nil }

type UnifiedNagRes struct {
	Nags []UnifiedNag
}
type UnifiedNagResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Nags    *[](*UnifiedNagInternal__)
}

func (u UnifiedNagResInternal__) Import() UnifiedNagRes {
	return UnifiedNagRes{
		Nags: (func(x *[](*UnifiedNagInternal__)) (ret []UnifiedNag) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]UnifiedNag, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *UnifiedNagInternal__) (ret UnifiedNag) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Nags),
	}
}
func (u UnifiedNagRes) Export() *UnifiedNagResInternal__ {
	return &UnifiedNagResInternal__{
		Nags: (func(x []UnifiedNag) *[](*UnifiedNagInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*UnifiedNagInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Nags),
	}
}
func (u *UnifiedNagRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UnifiedNagRes) Decode(dec rpc.Decoder) error {
	var tmp UnifiedNagResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UnifiedNagRes) Bytes() []byte { return nil }

type RegServerType int

const (
	RegServerType_None    RegServerType = 0
	RegServerType_Default RegServerType = 1
	RegServerType_Mgmt    RegServerType = 2
	RegServerType_Custom  RegServerType = 3
)

var RegServerTypeMap = map[string]RegServerType{
	"None":    0,
	"Default": 1,
	"Mgmt":    2,
	"Custom":  3,
}
var RegServerTypeRevMap = map[RegServerType]string{
	0: "None",
	1: "Default",
	2: "Mgmt",
	3: "Custom",
}

type RegServerTypeInternal__ RegServerType

func (r RegServerTypeInternal__) Import() RegServerType {
	return RegServerType(r)
}
func (r RegServerType) Export() *RegServerTypeInternal__ {
	return ((*RegServerTypeInternal__)(&r))
}

var GeneralProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf6cc941b)

type ClientProbeArg struct {
	Addr lib.TCPAddr
}
type ClientProbeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Addr    *lib.TCPAddrInternal__
}

func (c ClientProbeArgInternal__) Import() ClientProbeArg {
	return ClientProbeArg{
		Addr: (func(x *lib.TCPAddrInternal__) (ret lib.TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Addr),
	}
}
func (c ClientProbeArg) Export() *ClientProbeArgInternal__ {
	return &ClientProbeArgInternal__{
		Addr: c.Addr.Export(),
	}
}
func (c *ClientProbeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientProbeArg) Decode(dec rpc.Decoder) error {
	var tmp ClientProbeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientProbeArg) Bytes() []byte { return nil }

type NewSessionArg struct {
	SessionType lib.UISessionType
}
type NewSessionArgInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionType *lib.UISessionTypeInternal__
}

func (n NewSessionArgInternal__) Import() NewSessionArg {
	return NewSessionArg{
		SessionType: (func(x *lib.UISessionTypeInternal__) (ret lib.UISessionType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.SessionType),
	}
}
func (n NewSessionArg) Export() *NewSessionArgInternal__ {
	return &NewSessionArgInternal__{
		SessionType: n.SessionType.Export(),
	}
}
func (n *NewSessionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NewSessionArg) Decode(dec rpc.Decoder) error {
	var tmp NewSessionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NewSessionArg) Bytes() []byte { return nil }

type FinishSessionArg struct {
	SessionId lib.UISessionID
}
type FinishSessionArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (f FinishSessionArgInternal__) Import() FinishSessionArg {
	return FinishSessionArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.SessionId),
	}
}
func (f FinishSessionArg) Export() *FinishSessionArgInternal__ {
	return &FinishSessionArgInternal__{
		SessionId: f.SessionId.Export(),
	}
}
func (f *FinishSessionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FinishSessionArg) Decode(dec rpc.Decoder) error {
	var tmp FinishSessionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FinishSessionArg) Bytes() []byte { return nil }

type GetDefaultServerArg struct {
	SessionId lib.UISessionID
	Timeout   lib.DurationMilli
}
type GetDefaultServerArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Timeout   *lib.DurationMilliInternal__
}

func (g GetDefaultServerArgInternal__) Import() GetDefaultServerArg {
	return GetDefaultServerArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.SessionId),
		Timeout: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Timeout),
	}
}
func (g GetDefaultServerArg) Export() *GetDefaultServerArgInternal__ {
	return &GetDefaultServerArgInternal__{
		SessionId: g.SessionId.Export(),
		Timeout:   g.Timeout.Export(),
	}
}
func (g *GetDefaultServerArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetDefaultServerArg) Decode(dec rpc.Decoder) error {
	var tmp GetDefaultServerArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetDefaultServerArg) Bytes() []byte { return nil }

type PutServerArg struct {
	SessionId lib.UISessionID
	Server    *lib.TCPAddr
	Timeout   lib.DurationMilli
	Typ       RegServerType
}
type PutServerArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Server    *lib.TCPAddrInternal__
	Timeout   *lib.DurationMilliInternal__
	Typ       *RegServerTypeInternal__
}

func (p PutServerArgInternal__) Import() PutServerArg {
	return PutServerArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SessionId),
		Server: (func(x *lib.TCPAddrInternal__) *lib.TCPAddr {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.TCPAddrInternal__) (ret lib.TCPAddr) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Server),
		Timeout: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Timeout),
		Typ: (func(x *RegServerTypeInternal__) (ret RegServerType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Typ),
	}
}
func (p PutServerArg) Export() *PutServerArgInternal__ {
	return &PutServerArgInternal__{
		SessionId: p.SessionId.Export(),
		Server: (func(x *lib.TCPAddr) *lib.TCPAddrInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.Server),
		Timeout: p.Timeout.Export(),
		Typ:     p.Typ.Export(),
	}
}
func (p *PutServerArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutServerArg) Decode(dec rpc.Decoder) error {
	var tmp PutServerArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutServerArg) Bytes() []byte { return nil }

type GetActiveUserArg struct {
}
type GetActiveUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetActiveUserArgInternal__) Import() GetActiveUserArg {
	return GetActiveUserArg{}
}
func (g GetActiveUserArg) Export() *GetActiveUserArgInternal__ {
	return &GetActiveUserArgInternal__{}
}
func (g *GetActiveUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetActiveUserArg) Decode(dec rpc.Decoder) error {
	var tmp GetActiveUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetActiveUserArg) Bytes() []byte { return nil }

type ClearDeviceNagArg struct {
	Val bool
}
type ClearDeviceNagArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Val     *bool
}

func (c ClearDeviceNagArgInternal__) Import() ClearDeviceNagArg {
	return ClearDeviceNagArg{
		Val: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Val),
	}
}
func (c ClearDeviceNagArg) Export() *ClearDeviceNagArgInternal__ {
	return &ClearDeviceNagArgInternal__{
		Val: &c.Val,
	}
}
func (c *ClearDeviceNagArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClearDeviceNagArg) Decode(dec rpc.Decoder) error {
	var tmp ClearDeviceNagArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClearDeviceNagArg) Bytes() []byte { return nil }

type GetUnifiedNagsArg struct {
	WithRateLimit bool
	Cv            lib.ClientVersionExt
}
type GetUnifiedNagsArgInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	WithRateLimit *bool
	Cv            *lib.ClientVersionExtInternal__
}

func (g GetUnifiedNagsArgInternal__) Import() GetUnifiedNagsArg {
	return GetUnifiedNagsArg{
		WithRateLimit: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(g.WithRateLimit),
		Cv: (func(x *lib.ClientVersionExtInternal__) (ret lib.ClientVersionExt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Cv),
	}
}
func (g GetUnifiedNagsArg) Export() *GetUnifiedNagsArgInternal__ {
	return &GetUnifiedNagsArgInternal__{
		WithRateLimit: &g.WithRateLimit,
		Cv:            g.Cv.Export(),
	}
}
func (g *GetUnifiedNagsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetUnifiedNagsArg) Decode(dec rpc.Decoder) error {
	var tmp GetUnifiedNagsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetUnifiedNagsArg) Bytes() []byte { return nil }

type SnoozeUpgradeNagArg struct {
	Val bool
	Dur lib.DurationSecs
}
type SnoozeUpgradeNagArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Val     *bool
	Dur     *lib.DurationSecsInternal__
}

func (s SnoozeUpgradeNagArgInternal__) Import() SnoozeUpgradeNagArg {
	return SnoozeUpgradeNagArg{
		Val: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Val),
		Dur: (func(x *lib.DurationSecsInternal__) (ret lib.DurationSecs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Dur),
	}
}
func (s SnoozeUpgradeNagArg) Export() *SnoozeUpgradeNagArgInternal__ {
	return &SnoozeUpgradeNagArgInternal__{
		Val: &s.Val,
		Dur: s.Dur.Export(),
	}
}
func (s *SnoozeUpgradeNagArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SnoozeUpgradeNagArg) Decode(dec rpc.Decoder) error {
	var tmp SnoozeUpgradeNagArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SnoozeUpgradeNagArg) Bytes() []byte { return nil }

type GeneralInterface interface {
	Probe(context.Context, lib.TCPAddr) (lib.PublicZone, error)
	NewSession(context.Context, lib.UISessionType) (lib.UISessionID, error)
	FinishSession(context.Context, lib.UISessionID) error
	GetDefaultServer(context.Context, GetDefaultServerArg) (GetDefaultServerRes, error)
	PutServer(context.Context, PutServerArg) (lib.RegServerConfig, error)
	GetActiveUser(context.Context) (lib.UserContext, error)
	ClearDeviceNag(context.Context, bool) error
	GetUnifiedNags(context.Context, GetUnifiedNagsArg) (UnifiedNagRes, error)
	SnoozeUpgradeNag(context.Context, SnoozeUpgradeNagArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func GeneralMakeGenericErrorWrapper(f GeneralErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type GeneralErrorUnwrapper func(lib.Status) error
type GeneralErrorWrapper func(error) lib.Status

type generalErrorUnwrapperAdapter struct {
	h GeneralErrorUnwrapper
}

func (g generalErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (g generalErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return g.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = generalErrorUnwrapperAdapter{}

type GeneralClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper GeneralErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c GeneralClient) Probe(ctx context.Context, addr lib.TCPAddr) (res lib.PublicZone, err error) {
	arg := ClientProbeArg{
		Addr: addr,
	}
	warg := &rpc.DataWrap[Header, *ClientProbeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.PublicZoneInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 0, "General.probe"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) NewSession(ctx context.Context, sessionType lib.UISessionType) (res lib.UISessionID, err error) {
	arg := NewSessionArg{
		SessionType: sessionType,
	}
	warg := &rpc.DataWrap[Header, *NewSessionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UISessionIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 1, "General.newSession"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) FinishSession(ctx context.Context, sessionId lib.UISessionID) (err error) {
	arg := FinishSessionArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *FinishSessionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 2, "General.finishSession"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) GetDefaultServer(ctx context.Context, arg GetDefaultServerArg) (res GetDefaultServerRes, err error) {
	warg := &rpc.DataWrap[Header, *GetDefaultServerArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, GetDefaultServerResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 3, "General.getDefaultServer"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) PutServer(ctx context.Context, arg PutServerArg) (res lib.RegServerConfig, err error) {
	warg := &rpc.DataWrap[Header, *PutServerArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RegServerConfigInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 4, "General.putServer"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) GetActiveUser(ctx context.Context) (res lib.UserContext, err error) {
	var arg GetActiveUserArg
	warg := &rpc.DataWrap[Header, *GetActiveUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UserContextInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 5, "General.getActiveUser"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) ClearDeviceNag(ctx context.Context, val bool) (err error) {
	arg := ClearDeviceNagArg{
		Val: val,
	}
	warg := &rpc.DataWrap[Header, *ClearDeviceNagArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 7, "General.clearDeviceNag"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) GetUnifiedNags(ctx context.Context, arg GetUnifiedNagsArg) (res UnifiedNagRes, err error) {
	warg := &rpc.DataWrap[Header, *GetUnifiedNagsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, UnifiedNagResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 8, "General.getUnifiedNags"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c GeneralClient) SnoozeUpgradeNag(ctx context.Context, arg SnoozeUpgradeNagArg) (err error) {
	warg := &rpc.DataWrap[Header, *SnoozeUpgradeNagArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 9, "General.snoozeUpgradeNag"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func GeneralProtocol(i GeneralInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "General",
		ID:   GeneralProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientProbeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientProbeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientProbeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Probe(ctx, (typedArg.Import()).Addr)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.PublicZoneInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "probe",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *NewSessionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *NewSessionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *NewSessionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.NewSession(ctx, (typedArg.Import()).SessionType)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.UISessionIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "newSession",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *FinishSessionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *FinishSessionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *FinishSessionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.FinishSession(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "finishSession",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetDefaultServerArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetDefaultServerArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetDefaultServerArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetDefaultServer(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *GetDefaultServerResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getDefaultServer",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PutServerArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PutServerArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PutServerArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.PutServer(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RegServerConfigInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putServer",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetActiveUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetActiveUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetActiveUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetActiveUser(ctx)
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
				Name: "getActiveUser",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClearDeviceNagArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClearDeviceNagArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClearDeviceNagArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClearDeviceNag(ctx, (typedArg.Import()).Val)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clearDeviceNag",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetUnifiedNagsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetUnifiedNagsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetUnifiedNagsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetUnifiedNags(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *UnifiedNagResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getUnifiedNags",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SnoozeUpgradeNagArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SnoozeUpgradeNagArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SnoozeUpgradeNagArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SnoozeUpgradeNag(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "snoozeUpgradeNag",
			},
		},
		WrapError: GeneralMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(GeneralProtocolID)
}
