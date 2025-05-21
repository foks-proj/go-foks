// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/backup.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type BackupHESP []string
type BackupHESPInternal__ [](string)

func (b BackupHESP) Export() *BackupHESPInternal__ {
	tmp := (([]string)(b))
	return ((*BackupHESPInternal__)((func(x []string) *[](string) {
		if len(x) == 0 {
			return nil
		}
		ret := make([](string), len(x))
		copy(ret, x)
		return &ret
	})(tmp)))
}
func (b BackupHESPInternal__) Import() BackupHESP {
	tmp := ([](string))(b)
	return BackupHESP((func(x *[](string)) (ret []string) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]string, len(*x))
		for k, v := range *x {
			ret[k] = (func(x *string) (ret string) {
				if x == nil {
					return ret
				}
				return *x
			})(&v)
		}
		return ret
	})(&tmp))
}

func (b *BackupHESP) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupHESP) Decode(dec rpc.Decoder) error {
	var tmp BackupHESPInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BackupHESP) Bytes() []byte {
	return nil
}

type BackupHESPString string
type BackupHESPStringInternal__ string

func (b BackupHESPString) Export() *BackupHESPStringInternal__ {
	tmp := ((string)(b))
	return ((*BackupHESPStringInternal__)(&tmp))
}
func (b BackupHESPStringInternal__) Import() BackupHESPString {
	tmp := (string)(b)
	return BackupHESPString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (b *BackupHESPString) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupHESPString) Decode(dec rpc.Decoder) error {
	var tmp BackupHESPStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BackupHESPString) Bytes() []byte {
	return nil
}

var BackupProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf01cb7eb)

type BackupNewArg struct {
	Role lib.Role
}
type BackupNewArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role    *lib.RoleInternal__
}

func (b BackupNewArgInternal__) Import() BackupNewArg {
	return BackupNewArg{
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Role),
	}
}
func (b BackupNewArg) Export() *BackupNewArgInternal__ {
	return &BackupNewArgInternal__{
		Role: b.Role.Export(),
	}
}
func (b *BackupNewArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupNewArg) Decode(dec rpc.Decoder) error {
	var tmp BackupNewArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BackupNewArg) Bytes() []byte { return nil }

type BackupLoadPutHESPArg struct {
	SessionId lib.UISessionID
	Hesp      BackupHESP
}
type BackupLoadPutHESPArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
	Hesp      *BackupHESPInternal__
}

func (b BackupLoadPutHESPArgInternal__) Import() BackupLoadPutHESPArg {
	return BackupLoadPutHESPArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.SessionId),
		Hesp: (func(x *BackupHESPInternal__) (ret BackupHESP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Hesp),
	}
}
func (b BackupLoadPutHESPArg) Export() *BackupLoadPutHESPArgInternal__ {
	return &BackupLoadPutHESPArgInternal__{
		SessionId: b.SessionId.Export(),
		Hesp:      b.Hesp.Export(),
	}
}
func (b *BackupLoadPutHESPArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupLoadPutHESPArg) Decode(dec rpc.Decoder) error {
	var tmp BackupLoadPutHESPArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BackupLoadPutHESPArg) Bytes() []byte { return nil }

type BackupInterface interface {
	BackupNew(context.Context, lib.Role) (BackupHESP, error)
	BackupLoadPutHESP(context.Context, BackupLoadPutHESPArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func BackupMakeGenericErrorWrapper(f BackupErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type BackupErrorUnwrapper func(lib.Status) error
type BackupErrorWrapper func(error) lib.Status

type backupErrorUnwrapperAdapter struct {
	h BackupErrorUnwrapper
}

func (b backupErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (b backupErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return b.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = backupErrorUnwrapperAdapter{}

type BackupClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper BackupErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c BackupClient) BackupNew(ctx context.Context, role lib.Role) (res BackupHESP, err error) {
	arg := BackupNewArg{
		Role: role,
	}
	warg := &rpc.DataWrap[Header, *BackupNewArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, BackupHESPInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BackupProtocolID, 0, "Backup.backupNew"), warg, &tmp, 0*time.Millisecond, backupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c BackupClient) BackupLoadPutHESP(ctx context.Context, arg BackupLoadPutHESPArg) (err error) {
	warg := &rpc.DataWrap[Header, *BackupLoadPutHESPArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(BackupProtocolID, 1, "Backup.backupLoadPutHESP"), warg, &tmp, 0*time.Millisecond, backupErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func BackupProtocol(i BackupInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Backup",
		ID:   BackupProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *BackupNewArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *BackupNewArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *BackupNewArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.BackupNew(ctx, (typedArg.Import()).Role)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *BackupHESPInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "backupNew",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *BackupLoadPutHESPArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *BackupLoadPutHESPArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *BackupLoadPutHESPArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.BackupLoadPutHESP(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "backupLoadPutHESP",
			},
		},
		WrapError: BackupMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(BackupProtocolID)
}
