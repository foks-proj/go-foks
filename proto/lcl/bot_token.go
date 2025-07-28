// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/bot_token.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type BotTokenString string
type BotTokenStringInternal__ string

func (b BotTokenString) Export() *BotTokenStringInternal__ {
	tmp := ((string)(b))
	return ((*BotTokenStringInternal__)(&tmp))
}
func (b BotTokenStringInternal__) Import() BotTokenString {
	tmp := (string)(b)
	return BotTokenString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (b *BotTokenString) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BotTokenString) Decode(dec rpc.Decoder) error {
	var tmp BotTokenStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BotTokenString) Bytes() []byte {
	return nil
}

var BotTokenProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xe289e233)

type BotTokenNewArg struct {
	Role lib.Role
}
type BotTokenNewArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *lib.RoleInternal__
}

func (b BotTokenNewArgInternal__) Import() BotTokenNewArg {
	return BotTokenNewArg{
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Role),
	}
}
func (b BotTokenNewArg) Export() *BotTokenNewArgInternal__ {
	return &BotTokenNewArgInternal__{
		Role: b.Role.Export(),
	}
}
func (b *BotTokenNewArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BotTokenNewArg) Decode(dec rpc.Decoder) error {
	var tmp BotTokenNewArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BotTokenNewArg) Bytes() []byte { return nil }

type BotTokenLoadArg struct {
	Host lib.TCPAddr
	Tok  BotTokenString
}
type BotTokenLoadArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.TCPAddrInternal__
	Tok     *BotTokenStringInternal__
}

func (b BotTokenLoadArgInternal__) Import() BotTokenLoadArg {
	return BotTokenLoadArg{
		Host: (func(x *lib.TCPAddrInternal__) (ret lib.TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Host),
		Tok: (func(x *BotTokenStringInternal__) (ret BotTokenString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Tok),
	}
}
func (b BotTokenLoadArg) Export() *BotTokenLoadArgInternal__ {
	return &BotTokenLoadArgInternal__{
		Host: b.Host.Export(),
		Tok:  b.Tok.Export(),
	}
}
func (b *BotTokenLoadArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BotTokenLoadArg) Decode(dec rpc.Decoder) error {
	var tmp BotTokenLoadArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BotTokenLoadArg) Bytes() []byte { return nil }

type BotTokenInterface interface {
	BotTokenNew(context.Context, lib.Role) (BotTokenString, error)
	BotTokenLoad(context.Context, BotTokenLoadArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func BotTokenMakeGenericErrorWrapper(f BotTokenErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type BotTokenErrorUnwrapper func(lib.Status) error
type BotTokenErrorWrapper func(error) lib.Status

type botTokenErrorUnwrapperAdapter struct {
	h BotTokenErrorUnwrapper
}

func (b botTokenErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (b botTokenErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return b.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = botTokenErrorUnwrapperAdapter{}

type BotTokenClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper BotTokenErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c BotTokenClient) BotTokenNew(ctx context.Context, role lib.Role) (res BotTokenString, err error) {
	arg := BotTokenNewArg{
		Role: role,
	}
	warg := &rpc.DataWrap[Header, *BotTokenNewArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, BotTokenStringInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BotTokenProtocolID, 0, "BotToken.botTokenNew"), warg, &tmp, 0*time.Millisecond, botTokenErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c BotTokenClient) BotTokenLoad(ctx context.Context, arg BotTokenLoadArg) (err error) {
	warg := &rpc.DataWrap[Header, *BotTokenLoadArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BotTokenProtocolID, 1, "BotToken.botTokenLoad"), warg, &tmp, 0*time.Millisecond, botTokenErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func BotTokenProtocol(i BotTokenInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "BotToken",
		ID:   BotTokenProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *BotTokenNewArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *BotTokenNewArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *BotTokenNewArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.BotTokenNew(ctx, (typedArg.Import()).Role)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *BotTokenStringInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "botTokenNew",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *BotTokenLoadArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *BotTokenLoadArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *BotTokenLoadArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.BotTokenLoad(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "botTokenLoad",
			},
		},
		WrapError: BotTokenMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(BotTokenProtocolID)
}
