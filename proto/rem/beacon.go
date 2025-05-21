// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/rem/beacon.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var BeaconProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xbe314f3c)

type BeaconRegisterArg struct {
	Host   lib.Hostname
	Port   lib.Port
	HostID lib.HostID
}
type BeaconRegisterArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostnameInternal__
	Port    *lib.PortInternal__
	HostID  *lib.HostIDInternal__
}

func (b BeaconRegisterArgInternal__) Import() BeaconRegisterArg {
	return BeaconRegisterArg{
		Host: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Host),
		Port: (func(x *lib.PortInternal__) (ret lib.Port) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Port),
		HostID: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.HostID),
	}
}
func (b BeaconRegisterArg) Export() *BeaconRegisterArgInternal__ {
	return &BeaconRegisterArgInternal__{
		Host:   b.Host.Export(),
		Port:   b.Port.Export(),
		HostID: b.HostID.Export(),
	}
}
func (b *BeaconRegisterArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BeaconRegisterArg) Decode(dec rpc.Decoder) error {
	var tmp BeaconRegisterArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BeaconRegisterArg) Bytes() []byte { return nil }

type BeaconLookupArg struct {
	HostID lib.HostID
}
type BeaconLookupArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
}

func (b BeaconLookupArgInternal__) Import() BeaconLookupArg {
	return BeaconLookupArg{
		HostID: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.HostID),
	}
}
func (b BeaconLookupArg) Export() *BeaconLookupArgInternal__ {
	return &BeaconLookupArgInternal__{
		HostID: b.HostID.Export(),
	}
}
func (b *BeaconLookupArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BeaconLookupArg) Decode(dec rpc.Decoder) error {
	var tmp BeaconLookupArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BeaconLookupArg) Bytes() []byte { return nil }

type BeaconInterface interface {
	BeaconRegister(context.Context, BeaconRegisterArg) error
	BeaconLookup(context.Context, lib.HostID) (lib.TCPAddr, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error
	MakeResHeader() lib.Header
}

func BeaconMakeGenericErrorWrapper(f BeaconErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type BeaconErrorUnwrapper func(lib.Status) error
type BeaconErrorWrapper func(error) lib.Status

type beaconErrorUnwrapperAdapter struct {
	h BeaconErrorUnwrapper
}

func (b beaconErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (b beaconErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return b.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = beaconErrorUnwrapperAdapter{}

type BeaconClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper BeaconErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c BeaconClient) BeaconRegister(ctx context.Context, arg BeaconRegisterArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *BeaconRegisterArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BeaconProtocolID, 1, "Beacon.beaconRegister"), warg, &tmp, 0*time.Millisecond, beaconErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c BeaconClient) BeaconLookup(ctx context.Context, hostID lib.HostID) (res lib.TCPAddr, err error) {
	arg := BeaconLookupArg{
		HostID: hostID,
	}
	warg := &rpc.DataWrap[lib.Header, *BeaconLookupArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.TCPAddrInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BeaconProtocolID, 2, "Beacon.beaconLookup"), warg, &tmp, 0*time.Millisecond, beaconErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func BeaconProtocol(i BeaconInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Beacon",
		ID:   BeaconProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *BeaconRegisterArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *BeaconRegisterArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *BeaconRegisterArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.BeaconRegister(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "beaconRegister",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *BeaconLookupArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *BeaconLookupArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *BeaconLookupArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.BeaconLookup(ctx, (typedArg.Import()).HostID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.TCPAddrInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "beaconLookup",
			},
		},
		WrapError: BeaconMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(BeaconProtocolID)
}
