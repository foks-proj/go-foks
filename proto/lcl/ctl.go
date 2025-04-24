// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/ctl.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var CtlProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xb9b6958c)

type ShutdownArg struct {
}

type ShutdownArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (s ShutdownArgInternal__) Import() ShutdownArg {
	return ShutdownArg{}
}

func (s ShutdownArg) Export() *ShutdownArgInternal__ {
	return &ShutdownArgInternal__{}
}

func (s *ShutdownArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ShutdownArg) Decode(dec rpc.Decoder) error {
	var tmp ShutdownArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *ShutdownArg) Bytes() []byte { return nil }

type PingAgentArg struct {
}

type PingAgentArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (p PingAgentArgInternal__) Import() PingAgentArg {
	return PingAgentArg{}
}

func (p PingAgentArg) Export() *PingAgentArgInternal__ {
	return &PingAgentArgInternal__{}
}

func (p *PingAgentArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PingAgentArg) Decode(dec rpc.Decoder) error {
	var tmp PingAgentArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PingAgentArg) Bytes() []byte { return nil }

type CtlInterface interface {
	Shutdown(context.Context) (uint64, error)
	PingAgent(context.Context) (uint64, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func CtlMakeGenericErrorWrapper(f CtlErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type CtlErrorUnwrapper func(lib.Status) error
type CtlErrorWrapper func(error) lib.Status

type ctlErrorUnwrapperAdapter struct {
	h CtlErrorUnwrapper
}

func (c ctlErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (c ctlErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return c.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = ctlErrorUnwrapperAdapter{}

type CtlClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper CtlErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c CtlClient) Shutdown(ctx context.Context) (res uint64, err error) {
	var arg ShutdownArg
	warg := &rpc.DataWrap[Header, *ShutdownArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, uint64]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(CtlProtocolID, 0, "Ctl.shutdown"), warg, &tmp, 0*time.Millisecond, ctlErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c CtlClient) PingAgent(ctx context.Context) (res uint64, err error) {
	var arg PingAgentArg
	warg := &rpc.DataWrap[Header, *PingAgentArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, uint64]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(CtlProtocolID, 1, "Ctl.pingAgent"), warg, &tmp, 0*time.Millisecond, ctlErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func CtlProtocol(i CtlInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Ctl",
		ID:   CtlProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ShutdownArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ShutdownArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ShutdownArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.Shutdown(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, uint64]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "shutdown",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *PingAgentArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *PingAgentArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *PingAgentArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.PingAgent(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, uint64]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "pingAgent",
			},
		},
		WrapError: CtlMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(CtlProtocolID)
}
