// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/passphrase.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var PassphraseProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf099577a)

type PassphraseUnlockArg struct {
	Passphrase lib.Passphrase
}
type PassphraseUnlockArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Passphrase *lib.PassphraseInternal__
}

func (p PassphraseUnlockArgInternal__) Import() PassphraseUnlockArg {
	return PassphraseUnlockArg{
		Passphrase: (func(x *lib.PassphraseInternal__) (ret lib.Passphrase) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Passphrase),
	}
}
func (p PassphraseUnlockArg) Export() *PassphraseUnlockArgInternal__ {
	return &PassphraseUnlockArgInternal__{
		Passphrase: p.Passphrase.Export(),
	}
}
func (p *PassphraseUnlockArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseUnlockArg) Decode(dec rpc.Decoder) error {
	var tmp PassphraseUnlockArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PassphraseUnlockArg) Bytes() []byte { return nil }

type PassphraseSetArg struct {
	Passphrase lib.Passphrase
	First      bool
}
type PassphraseSetArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Passphrase *lib.PassphraseInternal__
	First      *bool
}

func (p PassphraseSetArgInternal__) Import() PassphraseSetArg {
	return PassphraseSetArg{
		Passphrase: (func(x *lib.PassphraseInternal__) (ret lib.Passphrase) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Passphrase),
		First: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.First),
	}
}
func (p PassphraseSetArg) Export() *PassphraseSetArgInternal__ {
	return &PassphraseSetArgInternal__{
		Passphrase: p.Passphrase.Export(),
		First:      &p.First,
	}
}
func (p *PassphraseSetArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseSetArg) Decode(dec rpc.Decoder) error {
	var tmp PassphraseSetArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PassphraseSetArg) Bytes() []byte { return nil }

type PassphraseInterface interface {
	PassphraseUnlock(context.Context, lib.Passphrase) error
	PassphraseSet(context.Context, PassphraseSetArg) error
	ErrorWrapper() func(error) lib.Status
}

func PassphraseMakeGenericErrorWrapper(f PassphraseErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type PassphraseErrorUnwrapper func(lib.Status) error
type PassphraseErrorWrapper func(error) lib.Status

type passphraseErrorUnwrapperAdapter struct {
	h PassphraseErrorUnwrapper
}

func (p passphraseErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (p passphraseErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return p.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = passphraseErrorUnwrapperAdapter{}

type PassphraseClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper PassphraseErrorUnwrapper
}

func (c PassphraseClient) PassphraseUnlock(ctx context.Context, passphrase lib.Passphrase) (err error) {
	arg := PassphraseUnlockArg{
		Passphrase: passphrase,
	}
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(PassphraseProtocolID, 0, "Passphrase.passphraseUnlock"), warg, nil, 0*time.Millisecond, passphraseErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func (c PassphraseClient) PassphraseSet(ctx context.Context, arg PassphraseSetArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(PassphraseProtocolID, 1, "Passphrase.passphraseSet"), warg, nil, 0*time.Millisecond, passphraseErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func PassphraseProtocol(i PassphraseInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Passphrase",
		ID:   PassphraseProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret PassphraseUnlockArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*PassphraseUnlockArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*PassphraseUnlockArgInternal__)(nil), args)
							return nil, err
						}
						err := i.PassphraseUnlock(ctx, (typedArg.Import()).Passphrase)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "passphraseUnlock",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret PassphraseSetArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*PassphraseSetArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*PassphraseSetArgInternal__)(nil), args)
							return nil, err
						}
						err := i.PassphraseSet(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "passphraseSet",
			},
		},
		WrapError: PassphraseMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(PassphraseProtocolID)
}
