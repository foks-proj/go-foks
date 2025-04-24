// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/general.snowp

package lcl

import (
	"context"
	"errors"
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

type GetDeviceNagArg struct {
	WithRateLimit bool
}

type GetDeviceNagArgInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	WithRateLimit *bool
}

func (g GetDeviceNagArgInternal__) Import() GetDeviceNagArg {
	return GetDeviceNagArg{
		WithRateLimit: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(g.WithRateLimit),
	}
}

func (g GetDeviceNagArg) Export() *GetDeviceNagArgInternal__ {
	return &GetDeviceNagArgInternal__{
		WithRateLimit: &g.WithRateLimit,
	}
}

func (g *GetDeviceNagArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetDeviceNagArg) Decode(dec rpc.Decoder) error {
	var tmp GetDeviceNagArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetDeviceNagArg) Bytes() []byte { return nil }

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

type GeneralInterface interface {
	Probe(context.Context, lib.TCPAddr) (lib.PublicZone, error)
	NewSession(context.Context, lib.UISessionType) (lib.UISessionID, error)
	FinishSession(context.Context, lib.UISessionID) error
	GetDefaultServer(context.Context, GetDefaultServerArg) (GetDefaultServerRes, error)
	PutServer(context.Context, PutServerArg) (lib.RegServerConfig, error)
	GetActiveUser(context.Context) (lib.UserContext, error)
	GetDeviceNag(context.Context, bool) (DeviceNagInfo, error)
	ClearDeviceNag(context.Context, bool) error
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
		return nil, errors.New("Error converting to internal type in UnwrapError")
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

func (c GeneralClient) GetDeviceNag(ctx context.Context, withRateLimit bool) (res DeviceNagInfo, err error) {
	arg := GetDeviceNagArg{
		WithRateLimit: withRateLimit,
	}
	warg := &rpc.DataWrap[Header, *GetDeviceNagArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, DeviceNagInfoInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GeneralProtocolID, 6, "General.getDeviceNag"), warg, &tmp, 0*time.Millisecond, generalErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetDeviceNagArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetDeviceNagArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetDeviceNagArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetDeviceNag(ctx, (typedArg.Import()).WithRateLimit)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *DeviceNagInfoInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getDeviceNag",
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
		},
		WrapError: GeneralMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(GeneralProtocolID)
}
