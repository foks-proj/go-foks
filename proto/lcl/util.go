// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/util.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var UtilProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x8ce48129)

type TriggerBgClkrArg struct {
}

type TriggerBgClkrArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (t TriggerBgClkrArgInternal__) Import() TriggerBgClkrArg {
	return TriggerBgClkrArg{}
}

func (t TriggerBgClkrArg) Export() *TriggerBgClkrArgInternal__ {
	return &TriggerBgClkrArgInternal__{}
}

func (t *TriggerBgClkrArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TriggerBgClkrArg) Decode(dec rpc.Decoder) error {
	var tmp TriggerBgClkrArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TriggerBgClkrArg) Bytes() []byte { return nil }

type TriggerBgUserRefreshArg struct {
}

type TriggerBgUserRefreshArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (t TriggerBgUserRefreshArgInternal__) Import() TriggerBgUserRefreshArg {
	return TriggerBgUserRefreshArg{}
}

func (t TriggerBgUserRefreshArg) Export() *TriggerBgUserRefreshArgInternal__ {
	return &TriggerBgUserRefreshArgInternal__{}
}

func (t *TriggerBgUserRefreshArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TriggerBgUserRefreshArg) Decode(dec rpc.Decoder) error {
	var tmp TriggerBgUserRefreshArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TriggerBgUserRefreshArg) Bytes() []byte { return nil }

type UtilInterface interface {
	TriggerBgClkr(context.Context) error
	TriggerBgUserRefresh(context.Context) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func UtilMakeGenericErrorWrapper(f UtilErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type UtilErrorUnwrapper func(lib.Status) error
type UtilErrorWrapper func(error) lib.Status

type utilErrorUnwrapperAdapter struct {
	h UtilErrorUnwrapper
}

func (u utilErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (u utilErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return u.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = utilErrorUnwrapperAdapter{}

type UtilClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper UtilErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c UtilClient) TriggerBgClkr(ctx context.Context) (err error) {
	var arg TriggerBgClkrArg
	warg := &rpc.DataWrap[Header, *TriggerBgClkrArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UtilProtocolID, 1, "Util.triggerBgClkr"), warg, &tmp, 0*time.Millisecond, utilErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UtilClient) TriggerBgUserRefresh(ctx context.Context) (err error) {
	var arg TriggerBgUserRefreshArg
	warg := &rpc.DataWrap[Header, *TriggerBgUserRefreshArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UtilProtocolID, 2, "Util.triggerBgUserRefresh"), warg, &tmp, 0*time.Millisecond, utilErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func UtilProtocol(i UtilInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Util",
		ID:   UtilProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TriggerBgClkrArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TriggerBgClkrArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TriggerBgClkrArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.TriggerBgClkr(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "triggerBgClkr",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TriggerBgUserRefreshArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TriggerBgUserRefreshArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TriggerBgUserRefreshArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.TriggerBgUserRefresh(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "triggerBgUserRefresh",
			},
		},
		WrapError: UtilMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(UtilProtocolID)
}
