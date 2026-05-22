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
	AppID   lib.RTAppID
	Roles   lib.RolePairOpt
	Channel lib.RTChannelName
}
type RTConfigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	AppID   *lib.RTAppIDInternal__
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
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
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
		AppID:   r.AppID.Export(),
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

type RTChannelMetadataPlaintext struct {
	Id         lib.RTChannelID
	ParentTeam lib.TeamID
	AppID      lib.RTAppID
	Name       lib.RTChannelName
	Desc       *lib.RTChannelDesc
	Roles      lib.RolePair
	Klass      lib.RTChannelClass
	UpdatedAt  lib.RTChannelSetVersion
}
type RTChannelMetadataPlaintextInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id         *lib.RTChannelIDInternal__
	ParentTeam *lib.TeamIDInternal__
	AppID      *lib.RTAppIDInternal__
	Name       *lib.RTChannelNameInternal__
	Desc       *lib.RTChannelDescInternal__
	Roles      *lib.RolePairInternal__
	Klass      *lib.RTChannelClassInternal__
	UpdatedAt  *lib.RTChannelSetVersionInternal__
}

func (r RTChannelMetadataPlaintextInternal__) Import() RTChannelMetadataPlaintext {
	return RTChannelMetadataPlaintext{
		Id: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Id),
		ParentTeam: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ParentTeam),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Name: (func(x *lib.RTChannelNameInternal__) (ret lib.RTChannelName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Name),
		Desc: (func(x *lib.RTChannelDescInternal__) *lib.RTChannelDesc {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTChannelDescInternal__) (ret lib.RTChannelDesc) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Desc),
		Roles: (func(x *lib.RolePairInternal__) (ret lib.RolePair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		Klass: (func(x *lib.RTChannelClassInternal__) (ret lib.RTChannelClass) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Klass),
		UpdatedAt: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.UpdatedAt),
	}
}
func (r RTChannelMetadataPlaintext) Export() *RTChannelMetadataPlaintextInternal__ {
	return &RTChannelMetadataPlaintextInternal__{
		Id:         r.Id.Export(),
		ParentTeam: r.ParentTeam.Export(),
		AppID:      r.AppID.Export(),
		Name:       r.Name.Export(),
		Desc: (func(x *lib.RTChannelDesc) *lib.RTChannelDescInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Desc),
		Roles:     r.Roles.Export(),
		Klass:     r.Klass.Export(),
		UpdatedAt: r.UpdatedAt.Export(),
	}
}
func (r *RTChannelMetadataPlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelMetadataPlaintext) Decode(dec rpc.Decoder) error {
	var tmp RTChannelMetadataPlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelMetadataPlaintext) Bytes() []byte { return nil }

type RTChannelSetForTeam struct {
	Channels []RTChannelMetadataPlaintext
	Vers     lib.RTChannelSetVersion
	AppID    lib.RTAppID
	Team     lib.TeamID
}
type RTChannelSetForTeamInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Channels *[](*RTChannelMetadataPlaintextInternal__)
	Vers     *lib.RTChannelSetVersionInternal__
	AppID    *lib.RTAppIDInternal__
	Team     *lib.TeamIDInternal__
}

func (r RTChannelSetForTeamInternal__) Import() RTChannelSetForTeam {
	return RTChannelSetForTeam{
		Channels: (func(x *[](*RTChannelMetadataPlaintextInternal__)) (ret []RTChannelMetadataPlaintext) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTChannelMetadataPlaintext, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTChannelMetadataPlaintextInternal__) (ret RTChannelMetadataPlaintext) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Channels),
		Vers: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Vers),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Team),
	}
}
func (r RTChannelSetForTeam) Export() *RTChannelSetForTeamInternal__ {
	return &RTChannelSetForTeamInternal__{
		Channels: (func(x []RTChannelMetadataPlaintext) *[](*RTChannelMetadataPlaintextInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTChannelMetadataPlaintextInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Channels),
		Vers:  r.Vers.Export(),
		AppID: r.AppID.Export(),
		Team:  r.Team.Export(),
	}
}
func (r *RTChannelSetForTeam) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSetForTeam) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetForTeamInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelSetForTeam) Bytes() []byte { return nil }

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

type ClientRTListChannelsForTeamArg struct {
	Cfg RTConfig
}
type ClientRTListChannelsForTeamArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
}

func (c ClientRTListChannelsForTeamArgInternal__) Import() ClientRTListChannelsForTeamArg {
	return ClientRTListChannelsForTeamArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
	}
}
func (c ClientRTListChannelsForTeamArg) Export() *ClientRTListChannelsForTeamArgInternal__ {
	return &ClientRTListChannelsForTeamArgInternal__{
		Cfg: c.Cfg.Export(),
	}
}
func (c *ClientRTListChannelsForTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTListChannelsForTeamArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTListChannelsForTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTListChannelsForTeamArg) Bytes() []byte { return nil }

type RealTimeInterface interface {
	ClientRTMakeChannel(context.Context, ClientRTMakeChannelArg) (lib.RTChannelID, error)
	ClientRTListChannelsForTeam(context.Context, RTConfig) (RTChannelSetForTeam, error)
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
func (c RealTimeClient) ClientRTListChannelsForTeam(ctx context.Context, cfg RTConfig) (res RTChannelSetForTeam, err error) {
	arg := ClientRTListChannelsForTeamArg{
		Cfg: cfg,
	}
	warg := &rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, RTChannelSetForTeamInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 1, "RealTime.clientRTListChannelsForTeam"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTListChannelsForTeam(ctx, (typedArg.Import()).Cfg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *RTChannelSetForTeamInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTListChannelsForTeam",
			},
		},
		WrapError: RealTimeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(RealTimeProtocolID)
}
