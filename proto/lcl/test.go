// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/test.snowp

package lcl

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type NetworkConditionsType int

const (
	NetworkConditionsType_Clear        NetworkConditionsType = 0
	NetworkConditionsType_Catastrophic NetworkConditionsType = 1
	NetworkConditionsType_Cloudy       NetworkConditionsType = 2
)

var NetworkConditionsTypeMap = map[string]NetworkConditionsType{
	"Clear":        0,
	"Catastrophic": 1,
	"Cloudy":       2,
}
var NetworkConditionsTypeRevMap = map[NetworkConditionsType]string{
	0: "Clear",
	1: "Catastrophic",
	2: "Cloudy",
}

type NetworkConditionsTypeInternal__ NetworkConditionsType

func (n NetworkConditionsTypeInternal__) Import() NetworkConditionsType {
	return NetworkConditionsType(n)
}
func (n NetworkConditionsType) Export() *NetworkConditionsTypeInternal__ {
	return ((*NetworkConditionsTypeInternal__)(&n))
}

type NetworkConditions struct {
	T     NetworkConditionsType
	F_2__ *uint64 `json:"f2,omitempty"`
}
type NetworkConditionsInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        NetworkConditionsType
	Switch__ NetworkConditionsInternalSwitch__
}
type NetworkConditionsInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_2__   *uint64  `codec:"2"`
}

func (n NetworkConditions) GetT() (ret NetworkConditionsType, err error) {
	switch n.T {
	default:
		break
	case NetworkConditionsType_Cloudy:
		if n.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return n.T, nil
}
func (n NetworkConditions) Cloudy() uint64 {
	if n.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if n.T != NetworkConditionsType_Cloudy {
		panic(fmt.Sprintf("unexpected switch value (%v) when Cloudy is called", n.T))
	}
	return *n.F_2__
}
func NewNetworkConditionsDefault(s NetworkConditionsType) NetworkConditions {
	return NetworkConditions{
		T: s,
	}
}
func NewNetworkConditionsWithCloudy(v uint64) NetworkConditions {
	return NetworkConditions{
		T:     NetworkConditionsType_Cloudy,
		F_2__: &v,
	}
}
func (n NetworkConditionsInternal__) Import() NetworkConditions {
	return NetworkConditions{
		T:     n.T,
		F_2__: n.Switch__.F_2__,
	}
}
func (n NetworkConditions) Export() *NetworkConditionsInternal__ {
	return &NetworkConditionsInternal__{
		T: n.T,
		Switch__: NetworkConditionsInternalSwitch__{
			F_2__: n.F_2__,
		},
	}
}
func (n *NetworkConditions) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NetworkConditions) Decode(dec rpc.Decoder) error {
	var tmp NetworkConditionsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NetworkConditions) Bytes() []byte { return nil }

var TestProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x8a326fcf)

type DeleteMacOSKeychainItemArg struct {
}
type DeleteMacOSKeychainItemArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (d DeleteMacOSKeychainItemArgInternal__) Import() DeleteMacOSKeychainItemArg {
	return DeleteMacOSKeychainItemArg{}
}
func (d DeleteMacOSKeychainItemArg) Export() *DeleteMacOSKeychainItemArgInternal__ {
	return &DeleteMacOSKeychainItemArgInternal__{}
}
func (d *DeleteMacOSKeychainItemArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeleteMacOSKeychainItemArg) Decode(dec rpc.Decoder) error {
	var tmp DeleteMacOSKeychainItemArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeleteMacOSKeychainItemArg) Bytes() []byte { return nil }

type GetNoiseFileArg struct {
}
type GetNoiseFileArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetNoiseFileArgInternal__) Import() GetNoiseFileArg {
	return GetNoiseFileArg{}
}
func (g GetNoiseFileArg) Export() *GetNoiseFileArgInternal__ {
	return &GetNoiseFileArgInternal__{}
}
func (g *GetNoiseFileArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetNoiseFileArg) Decode(dec rpc.Decoder) error {
	var tmp GetNoiseFileArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetNoiseFileArg) Bytes() []byte { return nil }

type ClearUserStateArg struct {
}
type ClearUserStateArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (c ClearUserStateArgInternal__) Import() ClearUserStateArg {
	return ClearUserStateArg{}
}
func (c ClearUserStateArg) Export() *ClearUserStateArgInternal__ {
	return &ClearUserStateArgInternal__{}
}
func (c *ClearUserStateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClearUserStateArg) Decode(dec rpc.Decoder) error {
	var tmp ClearUserStateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClearUserStateArg) Bytes() []byte { return nil }

type TestTriggerBgUserJobArg struct {
}
type TestTriggerBgUserJobArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (t TestTriggerBgUserJobArgInternal__) Import() TestTriggerBgUserJobArg {
	return TestTriggerBgUserJobArg{}
}
func (t TestTriggerBgUserJobArg) Export() *TestTriggerBgUserJobArgInternal__ {
	return &TestTriggerBgUserJobArgInternal__{}
}
func (t *TestTriggerBgUserJobArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestTriggerBgUserJobArg) Decode(dec rpc.Decoder) error {
	var tmp TestTriggerBgUserJobArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TestTriggerBgUserJobArg) Bytes() []byte { return nil }

type LoadSecretStoreArg struct {
}
type LoadSecretStoreArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (l LoadSecretStoreArgInternal__) Import() LoadSecretStoreArg {
	return LoadSecretStoreArg{}
}
func (l LoadSecretStoreArg) Export() *LoadSecretStoreArgInternal__ {
	return &LoadSecretStoreArgInternal__{}
}
func (l *LoadSecretStoreArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadSecretStoreArg) Decode(dec rpc.Decoder) error {
	var tmp LoadSecretStoreArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadSecretStoreArg) Bytes() []byte { return nil }

type SetFakeTeamIndexRangeArg struct {
	Team lib.FQTeam
	Tir  lib.RationalRange
}
type SetFakeTeamIndexRangeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamInternal__
	Tir     *lib.RationalRangeInternal__
}

func (s SetFakeTeamIndexRangeArgInternal__) Import() SetFakeTeamIndexRangeArg {
	return SetFakeTeamIndexRangeArg{
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Team),
		Tir: (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Tir),
	}
}
func (s SetFakeTeamIndexRangeArg) Export() *SetFakeTeamIndexRangeArgInternal__ {
	return &SetFakeTeamIndexRangeArgInternal__{
		Team: s.Team.Export(),
		Tir:  s.Tir.Export(),
	}
}
func (s *SetFakeTeamIndexRangeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetFakeTeamIndexRangeArg) Decode(dec rpc.Decoder) error {
	var tmp SetFakeTeamIndexRangeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetFakeTeamIndexRangeArg) Bytes() []byte { return nil }

type SetNetworkConditionsArg struct {
	Nc NetworkConditions
}
type SetNetworkConditionsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Nc      *NetworkConditionsInternal__
}

func (s SetNetworkConditionsArgInternal__) Import() SetNetworkConditionsArg {
	return SetNetworkConditionsArg{
		Nc: (func(x *NetworkConditionsInternal__) (ret NetworkConditions) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Nc),
	}
}
func (s SetNetworkConditionsArg) Export() *SetNetworkConditionsArgInternal__ {
	return &SetNetworkConditionsArgInternal__{
		Nc: s.Nc.Export(),
	}
}
func (s *SetNetworkConditionsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetNetworkConditionsArg) Decode(dec rpc.Decoder) error {
	var tmp SetNetworkConditionsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetNetworkConditionsArg) Bytes() []byte { return nil }

type GetUnlockedSKMWKArg struct {
}
type GetUnlockedSKMWKArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetUnlockedSKMWKArgInternal__) Import() GetUnlockedSKMWKArg {
	return GetUnlockedSKMWKArg{}
}
func (g GetUnlockedSKMWKArg) Export() *GetUnlockedSKMWKArgInternal__ {
	return &GetUnlockedSKMWKArgInternal__{}
}
func (g *GetUnlockedSKMWKArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetUnlockedSKMWKArg) Decode(dec rpc.Decoder) error {
	var tmp GetUnlockedSKMWKArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetUnlockedSKMWKArg) Bytes() []byte { return nil }

type TestInterface interface {
	DeleteMacOSKeychainItem(context.Context) error
	GetNoiseFile(context.Context) (string, error)
	ClearUserState(context.Context) error
	TestTriggerBgUserJob(context.Context) error
	LoadSecretStore(context.Context) (SecretStore, error)
	SetFakeTeamIndexRange(context.Context, SetFakeTeamIndexRangeArg) error
	SetNetworkConditions(context.Context, NetworkConditions) error
	GetUnlockedSKMWK(context.Context) (UnlockedSKMWK, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func TestMakeGenericErrorWrapper(f TestErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TestErrorUnwrapper func(lib.Status) error
type TestErrorWrapper func(error) lib.Status

type testErrorUnwrapperAdapter struct {
	h TestErrorUnwrapper
}

func (t testErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t testErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = testErrorUnwrapperAdapter{}

type TestClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TestErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c TestClient) DeleteMacOSKeychainItem(ctx context.Context) (err error) {
	var arg DeleteMacOSKeychainItemArg
	warg := &rpc.DataWrap[Header, *DeleteMacOSKeychainItemArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 0, "Test.deleteMacOSKeychainItem"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) GetNoiseFile(ctx context.Context) (res string, err error) {
	var arg GetNoiseFileArg
	warg := &rpc.DataWrap[Header, *GetNoiseFileArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, string]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 1, "Test.getNoiseFile"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data
	return
}
func (c TestClient) ClearUserState(ctx context.Context) (err error) {
	var arg ClearUserStateArg
	warg := &rpc.DataWrap[Header, *ClearUserStateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 2, "Test.clearUserState"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) TestTriggerBgUserJob(ctx context.Context) (err error) {
	var arg TestTriggerBgUserJobArg
	warg := &rpc.DataWrap[Header, *TestTriggerBgUserJobArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 3, "Test.testTriggerBgUserJob"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) LoadSecretStore(ctx context.Context) (res SecretStore, err error) {
	var arg LoadSecretStoreArg
	warg := &rpc.DataWrap[Header, *LoadSecretStoreArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SecretStoreInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 4, "Test.loadSecretStore"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) SetFakeTeamIndexRange(ctx context.Context, arg SetFakeTeamIndexRangeArg) (err error) {
	warg := &rpc.DataWrap[Header, *SetFakeTeamIndexRangeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 5, "Test.setFakeTeamIndexRange"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) SetNetworkConditions(ctx context.Context, nc NetworkConditions) (err error) {
	arg := SetNetworkConditionsArg{
		Nc: nc,
	}
	warg := &rpc.DataWrap[Header, *SetNetworkConditionsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 6, "Test.setNetworkConditions"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TestClient) GetUnlockedSKMWK(ctx context.Context) (res UnlockedSKMWK, err error) {
	var arg GetUnlockedSKMWKArg
	warg := &rpc.DataWrap[Header, *GetUnlockedSKMWKArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, UnlockedSKMWKInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestProtocolID, 7, "Test.getUnlockedSKMWK"), warg, &tmp, 0*time.Millisecond, testErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func TestProtocol(i TestInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Test",
		ID:   TestProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *DeleteMacOSKeychainItemArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *DeleteMacOSKeychainItemArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *DeleteMacOSKeychainItemArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.DeleteMacOSKeychainItem(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "deleteMacOSKeychainItem",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetNoiseFileArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetNoiseFileArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetNoiseFileArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetNoiseFile(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, string]{
							Data:   tmp,
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getNoiseFile",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClearUserStateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClearUserStateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClearUserStateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.ClearUserState(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clearUserState",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TestTriggerBgUserJobArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TestTriggerBgUserJobArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TestTriggerBgUserJobArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.TestTriggerBgUserJob(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "testTriggerBgUserJob",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoadSecretStoreArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoadSecretStoreArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoadSecretStoreArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.LoadSecretStore(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SecretStoreInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadSecretStore",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetFakeTeamIndexRangeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetFakeTeamIndexRangeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetFakeTeamIndexRangeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetFakeTeamIndexRange(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setFakeTeamIndexRange",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetNetworkConditionsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetNetworkConditionsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetNetworkConditionsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetNetworkConditions(ctx, (typedArg.Import()).Nc)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setNetworkConditions",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetUnlockedSKMWKArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetUnlockedSKMWKArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetUnlockedSKMWKArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetUnlockedSKMWK(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *UnlockedSKMWKInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getUnlockedSKMWK",
			},
		},
		WrapError: TestMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var TestLibsProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xb9330a29)

type FastArg struct {
	X int64
}
type FastArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	X       *int64
}

func (f FastArgInternal__) Import() FastArg {
	return FastArg{
		X: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(f.X),
	}
}
func (f FastArg) Export() *FastArgInternal__ {
	return &FastArgInternal__{
		X: &f.X,
	}
}
func (f *FastArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FastArg) Decode(dec rpc.Decoder) error {
	var tmp FastArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FastArg) Bytes() []byte { return nil }

type SlowArg struct {
	X    int64
	Wait lib.DurationMilli
}
type SlowArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	X       *int64
	Wait    *lib.DurationMilliInternal__
}

func (s SlowArgInternal__) Import() SlowArg {
	return SlowArg{
		X: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.X),
		Wait: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Wait),
	}
}
func (s SlowArg) Export() *SlowArgInternal__ {
	return &SlowArgInternal__{
		X:    &s.X,
		Wait: s.Wait.Export(),
	}
}
func (s *SlowArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SlowArg) Decode(dec rpc.Decoder) error {
	var tmp SlowArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SlowArg) Bytes() []byte { return nil }

type DisconnectArg struct {
}
type DisconnectArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (d DisconnectArgInternal__) Import() DisconnectArg {
	return DisconnectArg{}
}
func (d DisconnectArg) Export() *DisconnectArgInternal__ {
	return &DisconnectArgInternal__{}
}
func (d *DisconnectArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DisconnectArg) Decode(dec rpc.Decoder) error {
	var tmp DisconnectArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DisconnectArg) Bytes() []byte { return nil }

type TestLibsInterface interface {
	Fast(context.Context, int64) (int64, error)
	Slow(context.Context, SlowArg) (int64, error)
	Disconnect(context.Context) error
	ErrorWrapper() func(error) lib.Status
}

func TestLibsMakeGenericErrorWrapper(f TestLibsErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TestLibsErrorUnwrapper func(lib.Status) error
type TestLibsErrorWrapper func(error) lib.Status

type testLibsErrorUnwrapperAdapter struct {
	h TestLibsErrorUnwrapper
}

func (t testLibsErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t testLibsErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = testLibsErrorUnwrapperAdapter{}

type TestLibsClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TestLibsErrorUnwrapper
}

func (c TestLibsClient) Fast(ctx context.Context, x int64) (res int64, err error) {
	arg := FastArg{
		X: x,
	}
	warg := arg.Export()
	var tmp int64
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestLibsProtocolID, 0, "TestLibs.fast"), warg, &tmp, 0*time.Millisecond, testLibsErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp
	return
}
func (c TestLibsClient) Slow(ctx context.Context, arg SlowArg) (res int64, err error) {
	warg := arg.Export()
	var tmp int64
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestLibsProtocolID, 1, "TestLibs.slow"), warg, &tmp, 0*time.Millisecond, testLibsErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp
	return
}
func (c TestLibsClient) Disconnect(ctx context.Context) (err error) {
	var arg DisconnectArg
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestLibsProtocolID, 2, "TestLibs.disconnect"), warg, nil, 0*time.Millisecond, testLibsErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func TestLibsProtocol(i TestLibsInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TestLibs",
		ID:   TestLibsProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret FastArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*FastArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*FastArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.Fast(ctx, (typedArg.Import()).X)
						if err != nil {
							return nil, err
						}
						return tmp, nil
					},
				},
				Name: "fast",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret SlowArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*SlowArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*SlowArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.Slow(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp, nil
					},
				},
				Name: "slow",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret DisconnectArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						_, ok := args.(*DisconnectArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*DisconnectArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Disconnect(ctx)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "disconnect",
			},
		},
		WrapError: TestLibsMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(TestProtocolID)
	rpc.AddUnique(TestLibsProtocolID)
}
