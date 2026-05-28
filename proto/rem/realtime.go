// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/rem/realtime.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type RTInboxKey struct {
	AppID lib.RTAppID
}
type RTInboxKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.RTAppIDInternal__
}

func (r RTInboxKeyInternal__) Import() RTInboxKey {
	return RTInboxKey{
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
	}
}
func (r RTInboxKey) Export() *RTInboxKeyInternal__ {
	return &RTInboxKeyInternal__{
		AppID: r.AppID.Export(),
	}
}
func (r *RTInboxKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTInboxKey) Decode(dec rpc.Decoder) error {
	var tmp RTInboxKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTInboxKey) Bytes() []byte { return nil }

type RTSendArg struct {
	ChannelID       lib.RTChannelID
	Typ             lib.RTMsgType
	Body            lib.RTMsgBody
	SentAtTime      lib.Time
	ExpectedPrevSeq *lib.RTMsgSeq
}
type RTSendArgInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID       *lib.RTChannelIDInternal__
	Typ             *lib.RTMsgTypeInternal__
	Body            *lib.RTMsgBodyInternal__
	SentAtTime      *lib.TimeInternal__
	ExpectedPrevSeq *lib.RTMsgSeqInternal__
}

func (r RTSendArgInternal__) Import() RTSendArg {
	return RTSendArg{
		ChannelID: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
		Typ: (func(x *lib.RTMsgTypeInternal__) (ret lib.RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
		Body: (func(x *lib.RTMsgBodyInternal__) (ret lib.RTMsgBody) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Body),
		SentAtTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SentAtTime),
		ExpectedPrevSeq: (func(x *lib.RTMsgSeqInternal__) *lib.RTMsgSeq {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.ExpectedPrevSeq),
	}
}
func (r RTSendArg) Export() *RTSendArgInternal__ {
	return &RTSendArgInternal__{
		ChannelID:  r.ChannelID.Export(),
		Typ:        r.Typ.Export(),
		Body:       r.Body.Export(),
		SentAtTime: r.SentAtTime.Export(),
		ExpectedPrevSeq: (func(x *lib.RTMsgSeq) *lib.RTMsgSeqInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.ExpectedPrevSeq),
	}
}
func (r *RTSendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTSendArg) Decode(dec rpc.Decoder) error {
	var tmp RTSendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTSendArg) Bytes() []byte { return nil }

type RTSendRes struct {
	Seq        lib.RTMsgSeq
	InsertTime lib.Time
}
type RTSendResInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq        *lib.RTMsgSeqInternal__
	InsertTime *lib.TimeInternal__
}

func (r RTSendResInternal__) Import() RTSendRes {
	return RTSendRes{
		Seq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		InsertTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InsertTime),
	}
}
func (r RTSendRes) Export() *RTSendResInternal__ {
	return &RTSendResInternal__{
		Seq:        r.Seq.Export(),
		InsertTime: r.InsertTime.Export(),
	}
}
func (r *RTSendRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTSendRes) Decode(dec rpc.Decoder) error {
	var tmp RTSendResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTSendRes) Bytes() []byte { return nil }

type RTGetChangedThreadsArg struct {
	AppID lib.RTAppID
	Since lib.RTInboxVersion
	Max   uint64
}
type RTGetChangedThreadsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.RTAppIDInternal__
	Since   *lib.RTInboxVersionInternal__
	Max     *uint64
}

func (r RTGetChangedThreadsArgInternal__) Import() RTGetChangedThreadsArg {
	return RTGetChangedThreadsArg{
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Since: (func(x *lib.RTInboxVersionInternal__) (ret lib.RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Since),
		Max: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Max),
	}
}
func (r RTGetChangedThreadsArg) Export() *RTGetChangedThreadsArgInternal__ {
	return &RTGetChangedThreadsArgInternal__{
		AppID: r.AppID.Export(),
		Since: r.Since.Export(),
		Max:   &r.Max,
	}
}
func (r *RTGetChangedThreadsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTGetChangedThreadsArg) Decode(dec rpc.Decoder) error {
	var tmp RTGetChangedThreadsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTGetChangedThreadsArg) Bytes() []byte { return nil }

type RTReadThroughArg struct {
	ChannelID lib.RTChannelID
	Seq       lib.RTMsgSeq
}
type RTReadThroughArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *lib.RTChannelIDInternal__
	Seq       *lib.RTMsgSeqInternal__
}

func (r RTReadThroughArgInternal__) Import() RTReadThroughArg {
	return RTReadThroughArg{
		ChannelID: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
		Seq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
	}
}
func (r RTReadThroughArg) Export() *RTReadThroughArgInternal__ {
	return &RTReadThroughArgInternal__{
		ChannelID: r.ChannelID.Export(),
		Seq:       r.Seq.Export(),
	}
}
func (r *RTReadThroughArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTReadThroughArg) Decode(dec rpc.Decoder) error {
	var tmp RTReadThroughArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTReadThroughArg) Bytes() []byte { return nil }

type RTPollInboxArg struct {
	AppID   lib.RTAppID
	Since   lib.RTInboxVersion
	Timeout lib.DurationMilli
}
type RTPollInboxArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.RTAppIDInternal__
	Since   *lib.RTInboxVersionInternal__
	Timeout *lib.DurationMilliInternal__
}

func (r RTPollInboxArgInternal__) Import() RTPollInboxArg {
	return RTPollInboxArg{
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Since: (func(x *lib.RTInboxVersionInternal__) (ret lib.RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Since),
		Timeout: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Timeout),
	}
}
func (r RTPollInboxArg) Export() *RTPollInboxArgInternal__ {
	return &RTPollInboxArgInternal__{
		AppID:   r.AppID.Export(),
		Since:   r.Since.Export(),
		Timeout: r.Timeout.Export(),
	}
}
func (r *RTPollInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTPollInboxArg) Decode(dec rpc.Decoder) error {
	var tmp RTPollInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTPollInboxArg) Bytes() []byte { return nil }

var RealTimeProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x4f58e7d4)

type RtNewChannelArg struct {
	Md      lib.RTChannelMetadata
	SetVers lib.RTChannelSetVersion
}
type RtNewChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *lib.RTChannelMetadataInternal__
	SetVers *lib.RTChannelSetVersionInternal__
}

func (r RtNewChannelArgInternal__) Import() RtNewChannelArg {
	return RtNewChannelArg{
		Md: (func(x *lib.RTChannelMetadataInternal__) (ret lib.RTChannelMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		SetVers: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SetVers),
	}
}
func (r RtNewChannelArg) Export() *RtNewChannelArgInternal__ {
	return &RtNewChannelArgInternal__{
		Md:      r.Md.Export(),
		SetVers: r.SetVers.Export(),
	}
}
func (r *RtNewChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtNewChannelArg) Decode(dec rpc.Decoder) error {
	var tmp RtNewChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtNewChannelArg) Bytes() []byte { return nil }

type RtGetChannelArg struct {
	ChannelID lib.RTChannelID
}
type RtGetChannelArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *lib.RTChannelIDInternal__
}

func (r RtGetChannelArgInternal__) Import() RtGetChannelArg {
	return RtGetChannelArg{
		ChannelID: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
	}
}
func (r RtGetChannelArg) Export() *RtGetChannelArgInternal__ {
	return &RtGetChannelArgInternal__{
		ChannelID: r.ChannelID.Export(),
	}
}
func (r *RtGetChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtGetChannelArg) Decode(dec rpc.Decoder) error {
	var tmp RtGetChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtGetChannelArg) Bytes() []byte { return nil }

type RtListAllChannelsArg struct {
	Team  lib.TeamID
	AppID lib.RTAppID
}
type RtListAllChannelsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.TeamIDInternal__
	AppID   *lib.RTAppIDInternal__
}

func (r RtListAllChannelsArgInternal__) Import() RtListAllChannelsArg {
	return RtListAllChannelsArg{
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Team),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
	}
}
func (r RtListAllChannelsArg) Export() *RtListAllChannelsArgInternal__ {
	return &RtListAllChannelsArgInternal__{
		Team:  r.Team.Export(),
		AppID: r.AppID.Export(),
	}
}
func (r *RtListAllChannelsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtListAllChannelsArg) Decode(dec rpc.Decoder) error {
	var tmp RtListAllChannelsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtListAllChannelsArg) Bytes() []byte { return nil }

type RtSendArg struct {
	Rtarg RTSendArg
}
type RtSendArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rtarg   *RTSendArgInternal__
}

func (r RtSendArgInternal__) Import() RtSendArg {
	return RtSendArg{
		Rtarg: (func(x *RTSendArgInternal__) (ret RTSendArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rtarg),
	}
}
func (r RtSendArg) Export() *RtSendArgInternal__ {
	return &RtSendArgInternal__{
		Rtarg: r.Rtarg.Export(),
	}
}
func (r *RtSendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtSendArg) Decode(dec rpc.Decoder) error {
	var tmp RtSendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtSendArg) Bytes() []byte { return nil }

type RtGetThreadArg struct {
	Q lib.RTThreadQuery
}
type RtGetThreadArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Q       *lib.RTThreadQueryInternal__
}

func (r RtGetThreadArgInternal__) Import() RtGetThreadArg {
	return RtGetThreadArg{
		Q: (func(x *lib.RTThreadQueryInternal__) (ret lib.RTThreadQuery) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Q),
	}
}
func (r RtGetThreadArg) Export() *RtGetThreadArgInternal__ {
	return &RtGetThreadArgInternal__{
		Q: r.Q.Export(),
	}
}
func (r *RtGetThreadArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtGetThreadArg) Decode(dec rpc.Decoder) error {
	var tmp RtGetThreadArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtGetThreadArg) Bytes() []byte { return nil }

type RtGetInboxVersionArg struct {
	Key RTInboxKey
}
type RtGetInboxVersionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *RTInboxKeyInternal__
}

func (r RtGetInboxVersionArgInternal__) Import() RtGetInboxVersionArg {
	return RtGetInboxVersionArg{
		Key: (func(x *RTInboxKeyInternal__) (ret RTInboxKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Key),
	}
}
func (r RtGetInboxVersionArg) Export() *RtGetInboxVersionArgInternal__ {
	return &RtGetInboxVersionArgInternal__{
		Key: r.Key.Export(),
	}
}
func (r *RtGetInboxVersionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtGetInboxVersionArg) Decode(dec rpc.Decoder) error {
	var tmp RtGetInboxVersionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtGetInboxVersionArg) Bytes() []byte { return nil }

type RtGetChangedThreadsArg struct {
	Rtarg RTGetChangedThreadsArg
}
type RtGetChangedThreadsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rtarg   *RTGetChangedThreadsArgInternal__
}

func (r RtGetChangedThreadsArgInternal__) Import() RtGetChangedThreadsArg {
	return RtGetChangedThreadsArg{
		Rtarg: (func(x *RTGetChangedThreadsArgInternal__) (ret RTGetChangedThreadsArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rtarg),
	}
}
func (r RtGetChangedThreadsArg) Export() *RtGetChangedThreadsArgInternal__ {
	return &RtGetChangedThreadsArgInternal__{
		Rtarg: r.Rtarg.Export(),
	}
}
func (r *RtGetChangedThreadsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtGetChangedThreadsArg) Decode(dec rpc.Decoder) error {
	var tmp RtGetChangedThreadsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtGetChangedThreadsArg) Bytes() []byte { return nil }

type RtReadThroughArg struct {
	Rtarg RTReadThroughArg
}
type RtReadThroughArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rtarg   *RTReadThroughArgInternal__
}

func (r RtReadThroughArgInternal__) Import() RtReadThroughArg {
	return RtReadThroughArg{
		Rtarg: (func(x *RTReadThroughArgInternal__) (ret RTReadThroughArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rtarg),
	}
}
func (r RtReadThroughArg) Export() *RtReadThroughArgInternal__ {
	return &RtReadThroughArgInternal__{
		Rtarg: r.Rtarg.Export(),
	}
}
func (r *RtReadThroughArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtReadThroughArg) Decode(dec rpc.Decoder) error {
	var tmp RtReadThroughArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtReadThroughArg) Bytes() []byte { return nil }

type RtPollInboxArg struct {
	Rtarg RTPollInboxArg
}
type RtPollInboxArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rtarg   *RTPollInboxArgInternal__
}

func (r RtPollInboxArgInternal__) Import() RtPollInboxArg {
	return RtPollInboxArg{
		Rtarg: (func(x *RTPollInboxArgInternal__) (ret RTPollInboxArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rtarg),
	}
}
func (r RtPollInboxArg) Export() *RtPollInboxArgInternal__ {
	return &RtPollInboxArgInternal__{
		Rtarg: r.Rtarg.Export(),
	}
}
func (r *RtPollInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtPollInboxArg) Decode(dec rpc.Decoder) error {
	var tmp RtPollInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtPollInboxArg) Bytes() []byte { return nil }

type RTSelectVhost struct {
	Host lib.HostID
}
type RTSelectVhostInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostIDInternal__
}

func (r RTSelectVhostInternal__) Import() RTSelectVhost {
	return RTSelectVhost{
		Host: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Host),
	}
}
func (r RTSelectVhost) Export() *RTSelectVhostInternal__ {
	return &RTSelectVhostInternal__{
		Host: r.Host.Export(),
	}
}
func (r *RTSelectVhost) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTSelectVhost) Decode(dec rpc.Decoder) error {
	var tmp RTSelectVhostInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTSelectVhost) Bytes() []byte { return nil }

type RealTimeInterface interface {
	RtNewChannel(context.Context, RtNewChannelArg) (lib.RTChannelMetadata, error)
	RtGetChannel(context.Context, lib.RTChannelID) (lib.RTChannelMetadata, error)
	RtListAllChannels(context.Context, RtListAllChannelsArg) (lib.RTChannelSet, error)
	RtSend(context.Context, RTSendArg) (RTSendRes, error)
	RtGetThread(context.Context, lib.RTThreadQuery) (lib.RTThreadPage, error)
	RtGetInboxVersion(context.Context, RTInboxKey) (lib.RTInboxVersion, error)
	RtGetChangedThreads(context.Context, RTGetChangedThreadsArg) (lib.RTInboxDelta, error)
	RtReadThrough(context.Context, RTReadThroughArg) error
	RtPollInbox(context.Context, RTPollInboxArg) (lib.RTInboxPollRes, error)
	RtSelectVHost(context.Context, lib.HostID) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error
	MakeResHeader() lib.Header
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
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c RealTimeClient) RtNewChannel(ctx context.Context, arg RtNewChannelArg) (res lib.RTChannelMetadata, err error) {
	warg := &rpc.DataWrap[lib.Header, *RtNewChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTChannelMetadataInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 0, "RealTime.rtNewChannel"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtGetChannel(ctx context.Context, channelID lib.RTChannelID) (res lib.RTChannelMetadata, err error) {
	arg := RtGetChannelArg{
		ChannelID: channelID,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTChannelMetadataInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 1, "RealTime.rtGetChannel"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtListAllChannels(ctx context.Context, arg RtListAllChannelsArg) (res lib.RTChannelSet, err error) {
	warg := &rpc.DataWrap[lib.Header, *RtListAllChannelsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTChannelSetInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 2, "RealTime.rtListAllChannels"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtSend(ctx context.Context, rtarg RTSendArg) (res RTSendRes, err error) {
	arg := RtSendArg{
		Rtarg: rtarg,
	}
	warg := &rpc.DataWrap[lib.Header, *RtSendArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTSendResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 3, "RealTime.rtSend"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtGetThread(ctx context.Context, q lib.RTThreadQuery) (res lib.RTThreadPage, err error) {
	arg := RtGetThreadArg{
		Q: q,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetThreadArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTThreadPageInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 4, "RealTime.rtGetThread"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtGetInboxVersion(ctx context.Context, key RTInboxKey) (res lib.RTInboxVersion, err error) {
	arg := RtGetInboxVersionArg{
		Key: key,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetInboxVersionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTInboxVersionInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 5, "RealTime.rtGetInboxVersion"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtGetChangedThreads(ctx context.Context, rtarg RTGetChangedThreadsArg) (res lib.RTInboxDelta, err error) {
	arg := RtGetChangedThreadsArg{
		Rtarg: rtarg,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetChangedThreadsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTInboxDeltaInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 6, "RealTime.rtGetChangedThreads"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtReadThrough(ctx context.Context, rtarg RTReadThroughArg) (err error) {
	arg := RtReadThroughArg{
		Rtarg: rtarg,
	}
	warg := &rpc.DataWrap[lib.Header, *RtReadThroughArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 7, "RealTime.rtReadThrough"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtPollInbox(ctx context.Context, rtarg RTPollInboxArg) (res lib.RTInboxPollRes, err error) {
	arg := RtPollInboxArg{
		Rtarg: rtarg,
	}
	warg := &rpc.DataWrap[lib.Header, *RtPollInboxArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.RTInboxPollResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 8, "RealTime.rtPollInbox"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtSelectVHost(ctx context.Context, host lib.HostID) (err error) {
	arg := RTSelectVhost{
		Host: host,
	}
	warg := &rpc.DataWrap[lib.Header, *RTSelectVhostInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 9, "RealTime.rtSelectVHost"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func RealTimeProtocol(i RealTimeInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "RealTime",
		ID:   RealTimeProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtNewChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtNewChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtNewChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtNewChannel(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTChannelMetadataInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtNewChannel",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtGetChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtGetChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtGetChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtGetChannel(ctx, (typedArg.Import()).ChannelID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTChannelMetadataInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtGetChannel",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtListAllChannelsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtListAllChannelsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtListAllChannelsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtListAllChannels(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTChannelSetInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtListAllChannels",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtSendArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtSendArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtSendArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtSend(ctx, (typedArg.Import()).Rtarg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *RTSendResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtSend",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtGetThreadArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtGetThreadArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtGetThreadArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtGetThread(ctx, (typedArg.Import()).Q)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTThreadPageInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtGetThread",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtGetInboxVersionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtGetInboxVersionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtGetInboxVersionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtGetInboxVersion(ctx, (typedArg.Import()).Key)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTInboxVersionInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtGetInboxVersion",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtGetChangedThreadsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtGetChangedThreadsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtGetChangedThreadsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtGetChangedThreads(ctx, (typedArg.Import()).Rtarg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTInboxDeltaInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtGetChangedThreads",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtReadThroughArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtReadThroughArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtReadThroughArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.RtReadThrough(ctx, (typedArg.Import()).Rtarg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtReadThrough",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtPollInboxArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtPollInboxArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtPollInboxArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtPollInbox(ctx, (typedArg.Import()).Rtarg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.RTInboxPollResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtPollInbox",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RTSelectVhostInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RTSelectVhostInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RTSelectVhostInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.RtSelectVHost(ctx, (typedArg.Import()).Host)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtSelectVHost",
			},
		},
		WrapError: RealTimeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(RealTimeProtocolID)
}
