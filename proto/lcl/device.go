// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/device.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type KexSessionAndHESP struct {
	SessionId lib.UISessionID
	Hesp      lib.KexHESP
}
type KexSessionAndHESPInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Hesp      *lib.KexHESPInternal__
}

func (k KexSessionAndHESPInternal__) Import() KexSessionAndHESP {
	return KexSessionAndHESP{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SessionId),
		Hesp: (func(x *lib.KexHESPInternal__) (ret lib.KexHESP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Hesp),
	}
}
func (k KexSessionAndHESP) Export() *KexSessionAndHESPInternal__ {
	return &KexSessionAndHESPInternal__{
		SessionId: k.SessionId.Export(),
		Hesp:      k.Hesp.Export(),
	}
}
func (k *KexSessionAndHESP) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexSessionAndHESP) Decode(dec rpc.Decoder) error {
	var tmp KexSessionAndHESPInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KexSessionAndHESP) Bytes() []byte { return nil }

var DeviceAssistProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xbd6aaf3b)

type AssistInitArg struct {
	Id lib.UISessionID
}
type AssistInitArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.UISessionIDInternal__
}

func (a AssistInitArgInternal__) Import() AssistInitArg {
	return AssistInitArg{
		Id: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
	}
}
func (a AssistInitArg) Export() *AssistInitArgInternal__ {
	return &AssistInitArgInternal__{
		Id: a.Id.Export(),
	}
}
func (a *AssistInitArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssistInitArg) Decode(dec rpc.Decoder) error {
	var tmp AssistInitArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssistInitArg) Bytes() []byte { return nil }

type AssistStartKexArg struct {
	Id lib.UISessionID
}
type AssistStartKexArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.UISessionIDInternal__
}

func (a AssistStartKexArgInternal__) Import() AssistStartKexArg {
	return AssistStartKexArg{
		Id: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
	}
}
func (a AssistStartKexArg) Export() *AssistStartKexArgInternal__ {
	return &AssistStartKexArgInternal__{
		Id: a.Id.Export(),
	}
}
func (a *AssistStartKexArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssistStartKexArg) Decode(dec rpc.Decoder) error {
	var tmp AssistStartKexArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssistStartKexArg) Bytes() []byte { return nil }

type AssistGotKexInputArg struct {
	K KexSessionAndHESP
}
type AssistGotKexInputArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	K       *KexSessionAndHESPInternal__
}

func (a AssistGotKexInputArgInternal__) Import() AssistGotKexInputArg {
	return AssistGotKexInputArg{
		K: (func(x *KexSessionAndHESPInternal__) (ret KexSessionAndHESP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.K),
	}
}
func (a AssistGotKexInputArg) Export() *AssistGotKexInputArgInternal__ {
	return &AssistGotKexInputArgInternal__{
		K: a.K.Export(),
	}
}
func (a *AssistGotKexInputArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssistGotKexInputArg) Decode(dec rpc.Decoder) error {
	var tmp AssistGotKexInputArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssistGotKexInputArg) Bytes() []byte { return nil }

type AssistKexCancelInputArg struct {
	Id lib.UISessionID
}
type AssistKexCancelInputArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.UISessionIDInternal__
}

func (a AssistKexCancelInputArgInternal__) Import() AssistKexCancelInputArg {
	return AssistKexCancelInputArg{
		Id: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
	}
}
func (a AssistKexCancelInputArg) Export() *AssistKexCancelInputArgInternal__ {
	return &AssistKexCancelInputArgInternal__{
		Id: a.Id.Export(),
	}
}
func (a *AssistKexCancelInputArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssistKexCancelInputArg) Decode(dec rpc.Decoder) error {
	var tmp AssistKexCancelInputArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssistKexCancelInputArg) Bytes() []byte { return nil }

type AssistWaitForKexCompleteArg struct {
	Id lib.UISessionID
}
type AssistWaitForKexCompleteArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.UISessionIDInternal__
}

func (a AssistWaitForKexCompleteArgInternal__) Import() AssistWaitForKexCompleteArg {
	return AssistWaitForKexCompleteArg{
		Id: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
	}
}
func (a AssistWaitForKexCompleteArg) Export() *AssistWaitForKexCompleteArgInternal__ {
	return &AssistWaitForKexCompleteArgInternal__{
		Id: a.Id.Export(),
	}
}
func (a *AssistWaitForKexCompleteArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssistWaitForKexCompleteArg) Decode(dec rpc.Decoder) error {
	var tmp AssistWaitForKexCompleteArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssistWaitForKexCompleteArg) Bytes() []byte { return nil }

type DeviceAssistInterface interface {
	AssistInit(context.Context, lib.UISessionID) (lib.UserInfo, error)
	AssistStartKex(context.Context, lib.UISessionID) (lib.KexHESP, error)
	AssistGotKexInput(context.Context, KexSessionAndHESP) error
	AssistKexCancelInput(context.Context, lib.UISessionID) error
	AssistWaitForKexComplete(context.Context, lib.UISessionID) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func DeviceAssistMakeGenericErrorWrapper(f DeviceAssistErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type DeviceAssistErrorUnwrapper func(lib.Status) error
type DeviceAssistErrorWrapper func(error) lib.Status

type deviceAssistErrorUnwrapperAdapter struct {
	h DeviceAssistErrorUnwrapper
}

func (d deviceAssistErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (d deviceAssistErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return d.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = deviceAssistErrorUnwrapperAdapter{}

type DeviceAssistClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper DeviceAssistErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c DeviceAssistClient) AssistInit(ctx context.Context, id lib.UISessionID) (res lib.UserInfo, err error) {
	arg := AssistInitArg{
		Id: id,
	}
	warg := &rpc.DataWrap[Header, *AssistInitArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UserInfoInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceAssistProtocolID, 0, "DeviceAssist.assistInit"), warg, &tmp, 0*time.Millisecond, deviceAssistErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c DeviceAssistClient) AssistStartKex(ctx context.Context, id lib.UISessionID) (res lib.KexHESP, err error) {
	arg := AssistStartKexArg{
		Id: id,
	}
	warg := &rpc.DataWrap[Header, *AssistStartKexArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KexHESPInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceAssistProtocolID, 1, "DeviceAssist.assistStartKex"), warg, &tmp, 0*time.Millisecond, deviceAssistErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c DeviceAssistClient) AssistGotKexInput(ctx context.Context, k KexSessionAndHESP) (err error) {
	arg := AssistGotKexInputArg{
		K: k,
	}
	warg := &rpc.DataWrap[Header, *AssistGotKexInputArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceAssistProtocolID, 2, "DeviceAssist.assistGotKexInput"), warg, &tmp, 0*time.Millisecond, deviceAssistErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c DeviceAssistClient) AssistKexCancelInput(ctx context.Context, id lib.UISessionID) (err error) {
	arg := AssistKexCancelInputArg{
		Id: id,
	}
	warg := &rpc.DataWrap[Header, *AssistKexCancelInputArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceAssistProtocolID, 3, "DeviceAssist.assistKexCancelInput"), warg, &tmp, 0*time.Millisecond, deviceAssistErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c DeviceAssistClient) AssistWaitForKexComplete(ctx context.Context, id lib.UISessionID) (err error) {
	arg := AssistWaitForKexCompleteArg{
		Id: id,
	}
	warg := &rpc.DataWrap[Header, *AssistWaitForKexCompleteArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceAssistProtocolID, 4, "DeviceAssist.assistWaitForKexComplete"), warg, &tmp, 0*time.Millisecond, deviceAssistErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func DeviceAssistProtocol(i DeviceAssistInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "DeviceAssist",
		ID:   DeviceAssistProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AssistInitArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AssistInitArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AssistInitArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.AssistInit(ctx, (typedArg.Import()).Id)
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
				Name: "assistInit",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AssistStartKexArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AssistStartKexArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AssistStartKexArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.AssistStartKex(ctx, (typedArg.Import()).Id)
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
				Name: "assistStartKex",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AssistGotKexInputArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AssistGotKexInputArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AssistGotKexInputArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.AssistGotKexInput(ctx, (typedArg.Import()).K)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "assistGotKexInput",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AssistKexCancelInputArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AssistKexCancelInputArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AssistKexCancelInputArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.AssistKexCancelInput(ctx, (typedArg.Import()).Id)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "assistKexCancelInput",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AssistWaitForKexCompleteArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AssistWaitForKexCompleteArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AssistWaitForKexCompleteArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.AssistWaitForKexComplete(ctx, (typedArg.Import()).Id)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "assistWaitForKexComplete",
			},
		},
		WrapError: DeviceAssistMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

type ActiveDeviceInfo struct {
	Di       lib.DeviceInfo
	Active   bool
	Unlocked bool
}
type ActiveDeviceInfoInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Di       *lib.DeviceInfoInternal__
	Active   *bool
	Unlocked *bool
}

func (a ActiveDeviceInfoInternal__) Import() ActiveDeviceInfo {
	return ActiveDeviceInfo{
		Di: (func(x *lib.DeviceInfoInternal__) (ret lib.DeviceInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Di),
		Active: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(a.Active),
		Unlocked: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(a.Unlocked),
	}
}
func (a ActiveDeviceInfo) Export() *ActiveDeviceInfoInternal__ {
	return &ActiveDeviceInfoInternal__{
		Di:       a.Di.Export(),
		Active:   &a.Active,
		Unlocked: &a.Unlocked,
	}
}
func (a *ActiveDeviceInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActiveDeviceInfo) Decode(dec rpc.Decoder) error {
	var tmp ActiveDeviceInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActiveDeviceInfo) Bytes() []byte { return nil }

var DeviceProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xc35b771b)

type SelfProvisionArg struct {
	Role lib.Role
	Dln  lib.DeviceLabelAndName
}
type SelfProvisionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *lib.RoleInternal__
	Dln     *lib.DeviceLabelAndNameInternal__
}

func (s SelfProvisionArgInternal__) Import() SelfProvisionArg {
	return SelfProvisionArg{
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Role),
		Dln: (func(x *lib.DeviceLabelAndNameInternal__) (ret lib.DeviceLabelAndName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Dln),
	}
}
func (s SelfProvisionArg) Export() *SelfProvisionArgInternal__ {
	return &SelfProvisionArgInternal__{
		Role: s.Role.Export(),
		Dln:  s.Dln.Export(),
	}
}
func (s *SelfProvisionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SelfProvisionArg) Decode(dec rpc.Decoder) error {
	var tmp SelfProvisionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SelfProvisionArg) Bytes() []byte { return nil }

type DeviceInterface interface {
	SelfProvision(context.Context, SelfProvisionArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func DeviceMakeGenericErrorWrapper(f DeviceErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type DeviceErrorUnwrapper func(lib.Status) error
type DeviceErrorWrapper func(error) lib.Status

type deviceErrorUnwrapperAdapter struct {
	h DeviceErrorUnwrapper
}

func (d deviceErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (d deviceErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return d.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = deviceErrorUnwrapperAdapter{}

type DeviceClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper DeviceErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c DeviceClient) SelfProvision(ctx context.Context, arg SelfProvisionArg) (err error) {
	warg := &rpc.DataWrap[Header, *SelfProvisionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(DeviceProtocolID, 1, "Device.selfProvision"), warg, &tmp, 0*time.Millisecond, deviceErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func DeviceProtocol(i DeviceInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Device",
		ID:   DeviceProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SelfProvisionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SelfProvisionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SelfProvisionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SelfProvision(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "selfProvision",
			},
		},
		WrapError: DeviceMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(DeviceAssistProtocolID)
	rpc.AddUnique(DeviceProtocolID)
}
