// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/rem/kex.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type QueueMsg struct {
	Seneder lib.EntityID
	Seqno   lib.KexSeqNo
}
type QueueMsgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seneder *lib.EntityIDInternal__
	Seqno   *lib.KexSeqNoInternal__
}

func (q QueueMsgInternal__) Import() QueueMsg {
	return QueueMsg{
		Seneder: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(q.Seneder),
		Seqno: (func(x *lib.KexSeqNoInternal__) (ret lib.KexSeqNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(q.Seqno),
	}
}
func (q QueueMsg) Export() *QueueMsgInternal__ {
	return &QueueMsgInternal__{
		Seneder: q.Seneder.Export(),
		Seqno:   q.Seqno.Export(),
	}
}
func (q *QueueMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(q.Export())
}

func (q *QueueMsg) Decode(dec rpc.Decoder) error {
	var tmp QueueMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*q = tmp.Import()
	return nil
}

func (q *QueueMsg) Bytes() []byte { return nil }

type KexActorType int

const (
	KexActorType_Provisioner KexActorType = 1
	KexActorType_Provisionee KexActorType = 2
)

var KexActorTypeMap = map[string]KexActorType{
	"Provisioner": 1,
	"Provisionee": 2,
}
var KexActorTypeRevMap = map[KexActorType]string{
	1: "Provisioner",
	2: "Provisionee",
}

type KexActorTypeInternal__ KexActorType

func (k KexActorTypeInternal__) Import() KexActorType {
	return KexActorType(k)
}
func (k KexActorType) Export() *KexActorTypeInternal__ {
	return ((*KexActorTypeInternal__)(&k))
}

type KexWrapperMsg struct {
	SessionID lib.KexSessionID
	Sender    lib.EntityID
	Seq       lib.KexSeqNo
	Payload   lib.SecretBox
}
type KexWrapperMsgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionID *lib.KexSessionIDInternal__
	Sender    *lib.EntityIDInternal__
	Seq       *lib.KexSeqNoInternal__
	Payload   *lib.SecretBoxInternal__
}

func (k KexWrapperMsgInternal__) Import() KexWrapperMsg {
	return KexWrapperMsg{
		SessionID: (func(x *lib.KexSessionIDInternal__) (ret lib.KexSessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SessionID),
		Sender: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sender),
		Seq: (func(x *lib.KexSeqNoInternal__) (ret lib.KexSeqNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Seq),
		Payload: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Payload),
	}
}
func (k KexWrapperMsg) Export() *KexWrapperMsgInternal__ {
	return &KexWrapperMsgInternal__{
		SessionID: k.SessionID.Export(),
		Sender:    k.Sender.Export(),
		Seq:       k.Seq.Export(),
		Payload:   k.Payload.Export(),
	}
}
func (k *KexWrapperMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexWrapperMsg) Decode(dec rpc.Decoder) error {
	var tmp KexWrapperMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KexWrapperMsgTypeUniqueID = rpc.TypeUniqueID(0xc59be470ee7ecc62)

func (k *KexWrapperMsg) GetTypeUniqueID() rpc.TypeUniqueID {
	return KexWrapperMsgTypeUniqueID
}
func (k *KexWrapperMsg) Bytes() []byte { return nil }

var KexProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xae4df828)

type SendArg struct {
	Msg   KexWrapperMsg
	Sig   lib.Signature
	Actor KexActorType
}
type SendArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Msg     *KexWrapperMsgInternal__
	Sig     *lib.SignatureInternal__
	Actor   *KexActorTypeInternal__
}

func (s SendArgInternal__) Import() SendArg {
	return SendArg{
		Msg: (func(x *KexWrapperMsgInternal__) (ret KexWrapperMsg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Msg),
		Sig: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sig),
		Actor: (func(x *KexActorTypeInternal__) (ret KexActorType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Actor),
	}
}
func (s SendArg) Export() *SendArgInternal__ {
	return &SendArgInternal__{
		Msg:   s.Msg.Export(),
		Sig:   s.Sig.Export(),
		Actor: s.Actor.Export(),
	}
}
func (s *SendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SendArg) Decode(dec rpc.Decoder) error {
	var tmp SendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SendArg) Bytes() []byte { return nil }

type ReceiveArg struct {
	SessionID lib.KexSessionID
	Receiver  lib.EntityID
	Seq       lib.KexSeqNo
	PollWait  lib.DurationMilli
	Actor     KexActorType
}
type ReceiveArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionID *lib.KexSessionIDInternal__
	Receiver  *lib.EntityIDInternal__
	Seq       *lib.KexSeqNoInternal__
	PollWait  *lib.DurationMilliInternal__
	Actor     *KexActorTypeInternal__
}

func (r ReceiveArgInternal__) Import() ReceiveArg {
	return ReceiveArg{
		SessionID: (func(x *lib.KexSessionIDInternal__) (ret lib.KexSessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SessionID),
		Receiver: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Receiver),
		Seq: (func(x *lib.KexSeqNoInternal__) (ret lib.KexSeqNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		PollWait: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PollWait),
		Actor: (func(x *KexActorTypeInternal__) (ret KexActorType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Actor),
	}
}
func (r ReceiveArg) Export() *ReceiveArgInternal__ {
	return &ReceiveArgInternal__{
		SessionID: r.SessionID.Export(),
		Receiver:  r.Receiver.Export(),
		Seq:       r.Seq.Export(),
		PollWait:  r.PollWait.Export(),
		Actor:     r.Actor.Export(),
	}
}
func (r *ReceiveArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReceiveArg) Decode(dec rpc.Decoder) error {
	var tmp ReceiveArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReceiveArg) Bytes() []byte { return nil }

type KexInterface interface {
	Send(context.Context, SendArg) error
	Receive(context.Context, ReceiveArg) (KexWrapperMsg, error)
	ErrorWrapper() func(error) lib.Status
}

func KexMakeGenericErrorWrapper(f KexErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type KexErrorUnwrapper func(lib.Status) error
type KexErrorWrapper func(error) lib.Status

type kexErrorUnwrapperAdapter struct {
	h KexErrorUnwrapper
}

func (k kexErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (k kexErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return k.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = kexErrorUnwrapperAdapter{}

type KexClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper KexErrorUnwrapper
}

func (c KexClient) Send(ctx context.Context, arg SendArg) (err error) {
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KexProtocolID, 0, "kex.send"), warg, nil, 0*time.Millisecond, kexErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}
func (c KexClient) Receive(ctx context.Context, arg ReceiveArg) (res KexWrapperMsg, err error) {
	warg := arg.Export()
	var tmp KexWrapperMsgInternal__
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KexProtocolID, 1, "kex.receive"), warg, &tmp, 0*time.Millisecond, kexErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	res = tmp.Import()
	return
}
func KexProtocol(i KexInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "kex",
		ID:   KexProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret SendArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*SendArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*SendArgInternal__)(nil), args)
							return nil, err
						}
						err := i.Send(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "send",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret ReceiveArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*ReceiveArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*ReceiveArgInternal__)(nil), args)
							return nil, err
						}
						tmp, err := i.Receive(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						return tmp.Export(), nil
					},
				},
				Name: "receive",
			},
		},
		WrapError: KexMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(KexWrapperMsgTypeUniqueID)
	rpc.AddUnique(KexProtocolID)
}
