// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/infra/queue.snowp

package infra

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type QueueID int

const (
	QueueID_Kex    QueueID = 1
	QueueID_OAuth2 QueueID = 2
)

var QueueIDMap = map[string]QueueID{
	"Kex":    1,
	"OAuth2": 2,
}
var QueueIDRevMap = map[QueueID]string{
	1: "Kex",
	2: "OAuth2",
}

type QueueIDInternal__ QueueID

func (q QueueIDInternal__) Import() QueueID {
	return QueueID(q)
}
func (q QueueID) Export() *QueueIDInternal__ {
	return ((*QueueIDInternal__)(&q))
}

type QueueLaneID [18]byte
type QueueLaneIDInternal__ [18]byte

func (q QueueLaneID) Export() *QueueLaneIDInternal__ {
	tmp := (([18]byte)(q))
	return ((*QueueLaneIDInternal__)(&tmp))
}
func (q QueueLaneIDInternal__) Import() QueueLaneID {
	tmp := ([18]byte)(q)
	return QueueLaneID((func(x *[18]byte) (ret [18]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (q *QueueLaneID) Encode(enc rpc.Encoder) error {
	return enc.Encode(q.Export())
}

func (q *QueueLaneID) Decode(dec rpc.Decoder) error {
	var tmp QueueLaneIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*q = tmp.Import()
	return nil
}

func (q QueueLaneID) Bytes() []byte {
	return (q)[:]
}

var QueueProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x931b5f1a)

type EnqueueArg struct {
	QueueId QueueID
	LaneId  QueueLaneID
	Msg     []byte
}
type EnqueueArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	QueueId *QueueIDInternal__
	LaneId  *QueueLaneIDInternal__
	Msg     *[]byte
}

func (e EnqueueArgInternal__) Import() EnqueueArg {
	return EnqueueArg{
		QueueId: (func(x *QueueIDInternal__) (ret QueueID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.QueueId),
		LaneId: (func(x *QueueLaneIDInternal__) (ret QueueLaneID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(e.LaneId),
		Msg: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(e.Msg),
	}
}
func (e EnqueueArg) Export() *EnqueueArgInternal__ {
	return &EnqueueArgInternal__{
		QueueId: e.QueueId.Export(),
		LaneId:  e.LaneId.Export(),
		Msg:     &e.Msg,
	}
}
func (e *EnqueueArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EnqueueArg) Decode(dec rpc.Decoder) error {
	var tmp EnqueueArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e *EnqueueArg) Bytes() []byte { return nil }

type DequeueArg struct {
	QueueId QueueID
	LaneId  QueueLaneID
	Wait    lib.DurationMilli
}
type DequeueArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	QueueId *QueueIDInternal__
	LaneId  *QueueLaneIDInternal__
	Wait    *lib.DurationMilliInternal__
}

func (d DequeueArgInternal__) Import() DequeueArg {
	return DequeueArg{
		QueueId: (func(x *QueueIDInternal__) (ret QueueID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.QueueId),
		LaneId: (func(x *QueueLaneIDInternal__) (ret QueueLaneID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.LaneId),
		Wait: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Wait),
	}
}
func (d DequeueArg) Export() *DequeueArgInternal__ {
	return &DequeueArgInternal__{
		QueueId: d.QueueId.Export(),
		LaneId:  d.LaneId.Export(),
		Wait:    d.Wait.Export(),
	}
}
func (d *DequeueArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DequeueArg) Decode(dec rpc.Decoder) error {
	var tmp DequeueArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DequeueArg) Bytes() []byte { return nil }

type QueueInterface interface {
	Enqueue(context.Context, EnqueueArg) error
	Dequeue(context.Context, DequeueArg) ([]byte, error)
	ErrorWrapper() func(error) lib.Status
}

func QueueMakeGenericErrorWrapper(f QueueErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type QueueErrorUnwrapper func(lib.Status) error
type QueueErrorWrapper func(error) lib.Status

type queueErrorUnwrapperAdapter struct {
	h QueueErrorUnwrapper
}

func (q queueErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (q queueErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return q.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = queueErrorUnwrapperAdapter{}

type QueueClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper QueueErrorUnwrapper
}

func (c QueueClient) Enqueue(ctx context.Context, arg EnqueueArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QueueProtocolID, 0, "queue.enqueue"), warg, nil, 0*time.Millisecond, queueErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func (c QueueClient) Dequeue(ctx context.Context, arg DequeueArg) (res []byte, err error) {
	warg := arg.Export()
	var tmp []byte
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(QueueProtocolID, 1, "queue.dequeue"), warg, &tmp, 0*time.Millisecond, queueErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp
	return
}
func QueueProtocol(i QueueInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "queue",
		ID:   QueueProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret EnqueueArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*EnqueueArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*EnqueueArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Enqueue(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "enqueue",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret DequeueArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*DequeueArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*DequeueArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.Dequeue(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp, nil
					},
				},
				Name: "dequeue",
			},
		},
		WrapError: QueueMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(QueueProtocolID)
}
