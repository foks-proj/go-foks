// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/realtime.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type RTConfig struct {
	Team    *lib.FQTeamParsed
	Roles   lib.RolePairOpt
	Channel lib.RTChannelName
}
type RTConfigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Roles   *lib.RolePairOptInternal__
	Channel *lib.RTChannelNameInternal__
}

func (r RTConfigInternal__) Import() RTConfig {
	return RTConfig{
		Team: (func(x *lib.FQTeamParsedInternal__) *lib.FQTeamParsed {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Team),
		Roles: (func(x *lib.RolePairOptInternal__) (ret lib.RolePairOpt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		Channel: (func(x *lib.RTChannelNameInternal__) (ret lib.RTChannelName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Channel),
	}
}
func (r RTConfig) Export() *RTConfigInternal__ {
	return &RTConfigInternal__{
		Team: (func(x *lib.FQTeamParsed) *lib.FQTeamParsedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Team),
		Roles:   r.Roles.Export(),
		Channel: r.Channel.Export(),
	}
}
func (r *RTConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTConfig) Decode(dec rpc.Decoder) error {
	var tmp RTConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTConfig) Bytes() []byte { return nil }

var RealTimeProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xaaf0cd97)

type ClientRTMakeChannelArg struct {
	Cfg  RTConfig
	Desc lib.RTChannelDesc
}
type ClientRTMakeChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
	Desc    *lib.RTChannelDescInternal__
}

func (c ClientRTMakeChannelArgInternal__) Import() ClientRTMakeChannelArg {
	return ClientRTMakeChannelArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Desc: (func(x *lib.RTChannelDescInternal__) (ret lib.RTChannelDesc) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Desc),
	}
}
func (c ClientRTMakeChannelArg) Export() *ClientRTMakeChannelArgInternal__ {
	return &ClientRTMakeChannelArgInternal__{
		Cfg:  c.Cfg.Export(),
		Desc: c.Desc.Export(),
	}
}
func (c *ClientRTMakeChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTMakeChannelArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTMakeChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTMakeChannelArg) Bytes() []byte { return nil }

type RealTimeInterface interface {
	ClientRTMakeChannel(context.Context, ClientRTMakeChannelArg) (lib.RTChannelID, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func RealTimeMakeGenericErrorWrapper(f RealTimeErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type RealTimeErrorUnwrapper func(lib.Status) error
type RealTimeErrorWrapper func(error) lib.Status

type realTimeErrorUnwrapperAdapter struct {
	h RealTimeErrorUnwrapper
}

func (r realTimeErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (r realTimeErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return r.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = realTimeErrorUnwrapperAdapter{}

type RealTimeClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper RealTimeErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c RealTimeClient) ClientRTMakeChannel(ctx context.Context, arg ClientRTMakeChannelArg) (res lib.RTChannelID, err error) {
	warg := &rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RTChannelIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 0, "RealTime.clientRTMakeChannel"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func RealTimeProtocol(i RealTimeInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "RealTime",
		ID:   RealTimeProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTMakeChannel(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RTChannelIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTMakeChannel",
			},
		},
		WrapError: RealTimeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(RealTimeProtocolID)
}
