// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/admin.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var AdminProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xa0a81e0b)

type WebAdminPanelLinkArg struct {
}

type WebAdminPanelLinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (w WebAdminPanelLinkArgInternal__) Import() WebAdminPanelLinkArg {
	return WebAdminPanelLinkArg{}
}

func (w WebAdminPanelLinkArg) Export() *WebAdminPanelLinkArgInternal__ {
	return &WebAdminPanelLinkArgInternal__{}
}

func (w *WebAdminPanelLinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(w.Export())
}

func (w *WebAdminPanelLinkArg) Decode(dec rpc.Decoder) error {
	var tmp WebAdminPanelLinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*w = tmp.Import()
	return nil
}

func (w *WebAdminPanelLinkArg) Bytes() []byte { return nil }

type CheckLinkArg struct {
	Url lib.URLString
}

type CheckLinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Url     *lib.URLStringInternal__
}

func (c CheckLinkArgInternal__) Import() CheckLinkArg {
	return CheckLinkArg{
		Url: (func(x *lib.URLStringInternal__) (ret lib.URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Url),
	}
}

func (c CheckLinkArg) Export() *CheckLinkArgInternal__ {
	return &CheckLinkArgInternal__{
		Url: c.Url.Export(),
	}
}

func (c *CheckLinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckLinkArg) Decode(dec rpc.Decoder) error {
	var tmp CheckLinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckLinkArg) Bytes() []byte { return nil }

type AdminInterface interface {
	WebAdminPanelLink(context.Context) (lib.URLString, error)
	CheckLink(context.Context, lib.URLString) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func AdminMakeGenericErrorWrapper(f AdminErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type AdminErrorUnwrapper func(lib.Status) error
type AdminErrorWrapper func(error) lib.Status

type adminErrorUnwrapperAdapter struct {
	h AdminErrorUnwrapper
}

func (a adminErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (a adminErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return a.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = adminErrorUnwrapperAdapter{}

type AdminClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper AdminErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c AdminClient) WebAdminPanelLink(ctx context.Context) (res lib.URLString, err error) {
	var arg WebAdminPanelLinkArg
	warg := &rpc.DataWrap[Header, *WebAdminPanelLinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.URLStringInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(AdminProtocolID, 0, "Admin.webAdminPanelLink"), warg, &tmp, 0*time.Millisecond, adminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c AdminClient) CheckLink(ctx context.Context, url lib.URLString) (err error) {
	arg := CheckLinkArg{
		Url: url,
	}
	warg := &rpc.DataWrap[Header, *CheckLinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(AdminProtocolID, 1, "Admin.checkLink"), warg, &tmp, 0*time.Millisecond, adminErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func AdminProtocol(i AdminInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Admin",
		ID:   AdminProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *WebAdminPanelLinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *WebAdminPanelLinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *WebAdminPanelLinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.WebAdminPanelLink(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.URLStringInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "webAdminPanelLink",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *CheckLinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *CheckLinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *CheckLinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.CheckLink(ctx, (typedArg.Import()).Url)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "checkLink",
			},
		},
		WrapError: AdminMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(AdminProtocolID)
}
