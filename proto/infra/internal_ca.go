// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/infra/internal_ca.snowp

package infra

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var InternalCAProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xdf57a947)

type GetClientCertChainForServiceArg struct {
	Service lib.UID
	Key     lib.DeviceID
}

type GetClientCertChainForServiceArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Service *lib.UIDInternal__
	Key     *lib.DeviceIDInternal__
}

func (g GetClientCertChainForServiceArgInternal__) Import() GetClientCertChainForServiceArg {
	return GetClientCertChainForServiceArg{
		Service: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Service),
		Key: (func(x *lib.DeviceIDInternal__) (ret lib.DeviceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Key),
	}
}

func (g GetClientCertChainForServiceArg) Export() *GetClientCertChainForServiceArgInternal__ {
	return &GetClientCertChainForServiceArgInternal__{
		Service: g.Service.Export(),
		Key:     g.Key.Export(),
	}
}

func (g *GetClientCertChainForServiceArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetClientCertChainForServiceArg) Decode(dec rpc.Decoder) error {
	var tmp GetClientCertChainForServiceArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetClientCertChainForServiceArg) Bytes() []byte { return nil }

type InternalCAInterface interface {
	GetClientCertChainForService(context.Context, GetClientCertChainForServiceArg) ([][]byte, error)
	ErrorWrapper() func(error) lib.Status
}

func InternalCAMakeGenericErrorWrapper(f InternalCAErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type InternalCAErrorUnwrapper func(lib.Status) error
type InternalCAErrorWrapper func(error) lib.Status

type internalCAErrorUnwrapperAdapter struct {
	h InternalCAErrorUnwrapper
}

func (i internalCAErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (i internalCAErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return i.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = internalCAErrorUnwrapperAdapter{}

type InternalCAClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper InternalCAErrorUnwrapper
}

func (c InternalCAClient) GetClientCertChainForService(ctx context.Context, arg GetClientCertChainForServiceArg) (res [][]byte, err error) {
	warg := arg.Export()
	var tmp []([]byte)
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(InternalCAProtocolID, 0, "InternalCA.getClientCertChainForService"), warg, &tmp, 0*time.Millisecond, internalCAErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = (func(x *[]([]byte)) (ret [][]byte) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([][]byte, len(*x))
		for k, v := range *x {
			ret[k] = (func(x *[]byte) (ret []byte) {
				if x == nil {
					return ret
				}
				return *x
			})(&v)
		}
		return ret
	})(&tmp)
	return
}

func InternalCAProtocol(i InternalCAInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "InternalCA",
		ID:   InternalCAProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GetClientCertChainForServiceArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GetClientCertChainForServiceArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GetClientCertChainForServiceArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.GetClientCertChainForService(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						lst := (func(x [][]byte) *[]([]byte) {
							if len(x) == 0 {
								return nil
							}
							ret := make([]([]byte), len(x))
							copy(ret, x)
							return &ret
						})(tmp)
						return lst, nil
					},
				},
				Name: "getClientCertChainForService",
			},
		},
		WrapError: InternalCAMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(InternalCAProtocolID)
}
