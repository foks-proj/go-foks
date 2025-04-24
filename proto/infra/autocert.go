// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/infra/autocert.snowp

package infra

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type KVShardID uint64
type KVShardIDInternal__ uint64

func (k KVShardID) Export() *KVShardIDInternal__ {
	tmp := ((uint64)(k))
	return ((*KVShardIDInternal__)(&tmp))
}

func (k KVShardIDInternal__) Import() KVShardID {
	tmp := (uint64)(k)
	return KVShardID((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVShardID) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVShardID) Decode(dec rpc.Decoder) error {
	var tmp KVShardIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVShardID) Bytes() []byte {
	return nil
}

type AutocertPackage struct {
	Hostname lib.Hostname
	Hostid   lib.HostID
	Styp     lib.ServerType
	IsVanity bool
}

type AutocertPackageInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hostname *lib.HostnameInternal__
	Hostid   *lib.HostIDInternal__
	Styp     *lib.ServerTypeInternal__
	IsVanity *bool
}

func (a AutocertPackageInternal__) Import() AutocertPackage {
	return AutocertPackage{
		Hostname: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Hostname),
		Hostid: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Hostid),
		Styp: (func(x *lib.ServerTypeInternal__) (ret lib.ServerType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Styp),
		IsVanity: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(a.IsVanity),
	}
}

func (a AutocertPackage) Export() *AutocertPackageInternal__ {
	return &AutocertPackageInternal__{
		Hostname: a.Hostname.Export(),
		Hostid:   a.Hostid.Export(),
		Styp:     a.Styp.Export(),
		IsVanity: &a.IsVanity,
	}
}

func (a *AutocertPackage) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AutocertPackage) Decode(dec rpc.Decoder) error {
	var tmp AutocertPackageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AutocertPackage) Bytes() []byte { return nil }

var AutocertProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xb9515d98)

type DoAutocertArg struct {
	Pkg     AutocertPackage
	WaitFor lib.DurationMilli
}

type DoAutocertArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Pkg     *AutocertPackageInternal__
	WaitFor *lib.DurationMilliInternal__
}

func (d DoAutocertArgInternal__) Import() DoAutocertArg {
	return DoAutocertArg{
		Pkg: (func(x *AutocertPackageInternal__) (ret AutocertPackage) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Pkg),
		WaitFor: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.WaitFor),
	}
}

func (d DoAutocertArg) Export() *DoAutocertArgInternal__ {
	return &DoAutocertArgInternal__{
		Pkg:     d.Pkg.Export(),
		WaitFor: d.WaitFor.Export(),
	}
}

func (d *DoAutocertArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DoAutocertArg) Decode(dec rpc.Decoder) error {
	var tmp DoAutocertArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DoAutocertArg) Bytes() []byte { return nil }

type AutocertPokeArg struct {
}

type AutocertPokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (a AutocertPokeArgInternal__) Import() AutocertPokeArg {
	return AutocertPokeArg{}
}

func (a AutocertPokeArg) Export() *AutocertPokeArgInternal__ {
	return &AutocertPokeArgInternal__{}
}

func (a *AutocertPokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AutocertPokeArg) Decode(dec rpc.Decoder) error {
	var tmp AutocertPokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AutocertPokeArg) Bytes() []byte { return nil }

type AutocertInterface interface {
	DoAutocert(context.Context, DoAutocertArg) error
	Poke(context.Context) error
	ErrorWrapper() func(error) lib.Status
}

func AutocertMakeGenericErrorWrapper(f AutocertErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type AutocertErrorUnwrapper func(lib.Status) error
type AutocertErrorWrapper func(error) lib.Status

type autocertErrorUnwrapperAdapter struct {
	h AutocertErrorUnwrapper
}

func (a autocertErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (a autocertErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return a.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = autocertErrorUnwrapperAdapter{}

type AutocertClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper AutocertErrorUnwrapper
}

func (c AutocertClient) DoAutocert(ctx context.Context, arg DoAutocertArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(AutocertProtocolID, 0, "Autocert.doAutocert"), warg, nil, 0*time.Millisecond, autocertErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func (c AutocertClient) Poke(ctx context.Context) (err error) {
	var arg AutocertPokeArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(AutocertProtocolID, 1, "Autocert.poke"), warg, nil, 0*time.Millisecond, autocertErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func AutocertProtocol(i AutocertInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Autocert",
		ID:   AutocertProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret DoAutocertArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*DoAutocertArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*DoAutocertArgInternal__)(nil), args)
							return nil, err
						}
						err := i.DoAutocert(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "doAutocert",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret AutocertPokeArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*AutocertPokeArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*AutocertPokeArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Poke(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "poke",
			},
		},
		WrapError: AutocertMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(AutocertProtocolID)
}
