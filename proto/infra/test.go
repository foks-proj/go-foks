// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/infra/test.snowp

package infra

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

var TestServicesProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xf79ac642)

type TestQueueServiceArg struct {
	QueueId QueueID
	LaneId  QueueLaneID
	Msg     []byte
}

type TestQueueServiceArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	QueueId *QueueIDInternal__
	LaneId  *QueueLaneIDInternal__
	Msg     *[]byte
}

func (t TestQueueServiceArgInternal__) Import() TestQueueServiceArg {
	return TestQueueServiceArg{
		QueueId: (func(x *QueueIDInternal__) (ret QueueID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.QueueId),
		LaneId: (func(x *QueueLaneIDInternal__) (ret QueueLaneID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.LaneId),
		Msg: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Msg),
	}
}

func (t TestQueueServiceArg) Export() *TestQueueServiceArgInternal__ {
	return &TestQueueServiceArgInternal__{
		QueueId: t.QueueId.Export(),
		LaneId:  t.LaneId.Export(),
		Msg:     &t.Msg,
	}
}

func (t *TestQueueServiceArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestQueueServiceArg) Decode(dec rpc.Decoder) error {
	var tmp TestQueueServiceArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TestQueueServiceArg) Bytes() []byte { return nil }

type TestServicesInterface interface {
	TestQueueService(context.Context, TestQueueServiceArg) ([]byte, error)
	ErrorWrapper() func(error) lib.Status
}

func TestServicesMakeGenericErrorWrapper(f TestServicesErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TestServicesErrorUnwrapper func(lib.Status) error
type TestServicesErrorWrapper func(error) lib.Status

type testServicesErrorUnwrapperAdapter struct {
	h TestServicesErrorUnwrapper
}

func (t testServicesErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t testServicesErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = testServicesErrorUnwrapperAdapter{}

type TestServicesClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TestServicesErrorUnwrapper
}

func (c TestServicesClient) TestQueueService(ctx context.Context, arg TestQueueServiceArg) (res []byte, err error) {
	warg := arg.Export()
	var tmp []byte
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TestServicesProtocolID, 0, "TestServices.testQueueService"), warg, &tmp, 0*time.Millisecond, testServicesErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp
	return
}

func TestServicesProtocol(i TestServicesInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "TestServices",
		ID:   TestServicesProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret TestQueueServiceArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*TestQueueServiceArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*TestQueueServiceArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.TestQueueService(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp, nil
					},
				},
				Name: "testQueueService",
			},
		},
		WrapError: TestServicesMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(TestServicesProtocolID)
}
