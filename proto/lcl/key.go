// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/key.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type KeyListRes struct {
	CurrUser        *lib.UserContext
	CurrUserAllKeys []ActiveDeviceInfo
	AllUsers        []lib.UserInfoAndStatus
}
type KeyListResInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	CurrUser        *lib.UserContextInternal__
	CurrUserAllKeys *[](*ActiveDeviceInfoInternal__)
	AllUsers        *[](*lib.UserInfoAndStatusInternal__)
}

func (k KeyListResInternal__) Import() KeyListRes {
	return KeyListRes{
		CurrUser: (func(x *lib.UserContextInternal__) *lib.UserContext {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.UserContextInternal__) (ret lib.UserContext) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.CurrUser),
		CurrUserAllKeys: (func(x *[](*ActiveDeviceInfoInternal__)) (ret []ActiveDeviceInfo) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]ActiveDeviceInfo, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *ActiveDeviceInfoInternal__) (ret ActiveDeviceInfo) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.CurrUserAllKeys),
		AllUsers: (func(x *[](*lib.UserInfoAndStatusInternal__)) (ret []lib.UserInfoAndStatus) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.UserInfoAndStatus, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.UserInfoAndStatusInternal__) (ret lib.UserInfoAndStatus) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.AllUsers),
	}
}
func (k KeyListRes) Export() *KeyListResInternal__ {
	return &KeyListResInternal__{
		CurrUser: (func(x *lib.UserContext) *lib.UserContextInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.CurrUser),
		CurrUserAllKeys: (func(x []ActiveDeviceInfo) *[](*ActiveDeviceInfoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*ActiveDeviceInfoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.CurrUserAllKeys),
		AllUsers: (func(x []lib.UserInfoAndStatus) *[](*lib.UserInfoAndStatusInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.UserInfoAndStatusInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.AllUsers),
	}
}
func (k *KeyListRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyListRes) Decode(dec rpc.Decoder) error {
	var tmp KeyListResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeyListRes) Bytes() []byte { return nil }

var KeyProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xbaa02ef2)

type KeyListArg struct {
}
type KeyListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (k KeyListArgInternal__) Import() KeyListArg {
	return KeyListArg{}
}
func (k KeyListArg) Export() *KeyListArgInternal__ {
	return &KeyListArgInternal__{}
}
func (k *KeyListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyListArg) Decode(dec rpc.Decoder) error {
	var tmp KeyListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeyListArg) Bytes() []byte { return nil }

type KeyRevokeArg struct {
	Eid lib.EntityID
}
type KeyRevokeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Eid     *lib.EntityIDInternal__
}

func (k KeyRevokeArgInternal__) Import() KeyRevokeArg {
	return KeyRevokeArg{
		Eid: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Eid),
	}
}
func (k KeyRevokeArg) Export() *KeyRevokeArgInternal__ {
	return &KeyRevokeArgInternal__{
		Eid: k.Eid.Export(),
	}
}
func (k *KeyRevokeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeyRevokeArg) Decode(dec rpc.Decoder) error {
	var tmp KeyRevokeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeyRevokeArg) Bytes() []byte { return nil }

type KeyInterface interface {
	KeyList(context.Context) (KeyListRes, error)
	KeyRevoke(context.Context, lib.EntityID) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func KeyMakeGenericErrorWrapper(f KeyErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type KeyErrorUnwrapper func(lib.Status) error
type KeyErrorWrapper func(error) lib.Status

type keyErrorUnwrapperAdapter struct {
	h KeyErrorUnwrapper
}

func (k keyErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (k keyErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return k.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = keyErrorUnwrapperAdapter{}

type KeyClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper KeyErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c KeyClient) KeyList(ctx context.Context) (res KeyListRes, err error) {
	var arg KeyListArg
	warg := &rpc.DataWrap[Header, *KeyListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, KeyListResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KeyProtocolID, 0, "Key.keyList"), warg, &tmp, 0*time.Millisecond, keyErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KeyClient) KeyRevoke(ctx context.Context, eid lib.EntityID) (err error) {
	arg := KeyRevokeArg{
		Eid: eid,
	}
	warg := &rpc.DataWrap[Header, *KeyRevokeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KeyProtocolID, 1, "Key.keyRevoke"), warg, &tmp, 0*time.Millisecond, keyErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func KeyProtocol(i KeyInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Key",
		ID:   KeyProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *KeyListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *KeyListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *KeyListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.KeyList(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *KeyListResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "keyList",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *KeyRevokeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *KeyRevokeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *KeyRevokeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KeyRevoke(ctx, (typedArg.Import()).Eid)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "keyRevoke",
			},
		},
		WrapError: KeyMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(KeyProtocolID)
}
