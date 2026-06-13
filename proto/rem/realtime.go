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
	Md              lib.RTMsgMetadata
	Chid            lib.RTChannelIDShort
	Mw              lib.RTMsgWrapper
	ExpectedPrevSeq lib.RTMsgSeq
}
type RTSendArgInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md              *lib.RTMsgMetadataInternal__
	Chid            *lib.RTChannelIDShortInternal__
	Mw              *lib.RTMsgWrapperInternal__
	ExpectedPrevSeq *lib.RTMsgSeqInternal__
}

func (r RTSendArgInternal__) Import() RTSendArg {
	return RTSendArg{
		Md: (func(x *lib.RTMsgMetadataInternal__) (ret lib.RTMsgMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		Chid: (func(x *lib.RTChannelIDShortInternal__) (ret lib.RTChannelIDShort) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Chid),
		Mw: (func(x *lib.RTMsgWrapperInternal__) (ret lib.RTMsgWrapper) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mw),
		ExpectedPrevSeq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ExpectedPrevSeq),
	}
}
func (r RTSendArg) Export() *RTSendArgInternal__ {
	return &RTSendArgInternal__{
		Md:              r.Md.Export(),
		Chid:            r.Chid.Export(),
		Mw:              r.Mw.Export(),
		ExpectedPrevSeq: r.ExpectedPrevSeq.Export(),
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

type RTLastMsg struct {
	Seq                    lib.RTMsgSeq
	Typ                    lib.RTMsgType
	InsertTime             lib.Time
	Sender                 *lib.PartyID
	FurtherUserAttribution *lib.UID
}
type RTLastMsgInternal__ struct {
	_struct                struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq                    *lib.RTMsgSeqInternal__
	Typ                    *lib.RTMsgTypeInternal__
	InsertTime             *lib.TimeInternal__
	Sender                 *lib.PartyIDInternal__
	FurtherUserAttribution *lib.UIDInternal__
}

func (r RTLastMsgInternal__) Import() RTLastMsg {
	return RTLastMsg{
		Seq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		Typ: (func(x *lib.RTMsgTypeInternal__) (ret lib.RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
		InsertTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InsertTime),
		Sender: (func(x *lib.PartyIDInternal__) *lib.PartyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Sender),
		FurtherUserAttribution: (func(x *lib.UIDInternal__) *lib.UID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.UIDInternal__) (ret lib.UID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.FurtherUserAttribution),
	}
}
func (r RTLastMsg) Export() *RTLastMsgInternal__ {
	return &RTLastMsgInternal__{
		Seq:        r.Seq.Export(),
		Typ:        r.Typ.Export(),
		InsertTime: r.InsertTime.Export(),
		Sender: (func(x *lib.PartyID) *lib.PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Sender),
		FurtherUserAttribution: (func(x *lib.UID) *lib.UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.FurtherUserAttribution),
	}
}
func (r *RTLastMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTLastMsg) Decode(dec rpc.Decoder) error {
	var tmp RTLastMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTLastMsg) Bytes() []byte { return nil }

type RTChannelMetadata struct {
	Id         lib.RTChannelID
	ParentTeam lib.TeamID
	AppID      lib.RTAppID
	Seqno      lib.RTChannelSeqno
	NameBox    lib.RTBoxRG
	DescBox    *lib.RTBoxRG
	Roles      lib.RolePair
	LastMsg    *RTLastMsg
	Ctime      lib.Time
	Mtime      lib.Time
	UpdatedAt  lib.RTChannelSetVersion
	Klass      lib.RTChannelClass
	Unreadable bool
}
type RTChannelMetadataInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id         *lib.RTChannelIDInternal__
	ParentTeam *lib.TeamIDInternal__
	AppID      *lib.RTAppIDInternal__
	Seqno      *lib.RTChannelSeqnoInternal__
	NameBox    *lib.RTBoxRGInternal__
	DescBox    *lib.RTBoxRGInternal__
	Roles      *lib.RolePairInternal__
	LastMsg    *RTLastMsgInternal__
	Ctime      *lib.TimeInternal__
	Mtime      *lib.TimeInternal__
	UpdatedAt  *lib.RTChannelSetVersionInternal__
	Klass      *lib.RTChannelClassInternal__
	Unreadable *bool
}

func (r RTChannelMetadataInternal__) Import() RTChannelMetadata {
	return RTChannelMetadata{
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
		Seqno: (func(x *lib.RTChannelSeqnoInternal__) (ret lib.RTChannelSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seqno),
		NameBox: (func(x *lib.RTBoxRGInternal__) (ret lib.RTBoxRG) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.NameBox),
		DescBox: (func(x *lib.RTBoxRGInternal__) *lib.RTBoxRG {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTBoxRGInternal__) (ret lib.RTBoxRG) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.DescBox),
		Roles: (func(x *lib.RolePairInternal__) (ret lib.RolePair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		LastMsg: (func(x *RTLastMsgInternal__) *RTLastMsg {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTLastMsgInternal__) (ret RTLastMsg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.LastMsg),
		Ctime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Ctime),
		Mtime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mtime),
		UpdatedAt: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.UpdatedAt),
		Klass: (func(x *lib.RTChannelClassInternal__) (ret lib.RTChannelClass) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Klass),
		Unreadable: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Unreadable),
	}
}
func (r RTChannelMetadata) Export() *RTChannelMetadataInternal__ {
	return &RTChannelMetadataInternal__{
		Id:         r.Id.Export(),
		ParentTeam: r.ParentTeam.Export(),
		AppID:      r.AppID.Export(),
		Seqno:      r.Seqno.Export(),
		NameBox:    r.NameBox.Export(),
		DescBox: (func(x *lib.RTBoxRG) *lib.RTBoxRGInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.DescBox),
		Roles: r.Roles.Export(),
		LastMsg: (func(x *RTLastMsg) *RTLastMsgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.LastMsg),
		Ctime:      r.Ctime.Export(),
		Mtime:      r.Mtime.Export(),
		UpdatedAt:  r.UpdatedAt.Export(),
		Klass:      r.Klass.Export(),
		Unreadable: &r.Unreadable,
	}
}
func (r *RTChannelMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelMetadata) Decode(dec rpc.Decoder) error {
	var tmp RTChannelMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTChannelMetadataTypeUniqueID = rpc.TypeUniqueID(0xddf6b26b2ace1535)

func (r *RTChannelMetadata) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTChannelMetadataTypeUniqueID
}
func (r *RTChannelMetadata) Bytes() []byte { return nil }

type RTChannelSet struct {
	Vers  lib.RTChannelSetVersion
	Lst   []RTChannelMetadata
	Mtime lib.Time
}
type RTChannelSetInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Vers    *lib.RTChannelSetVersionInternal__
	Lst     *[](*RTChannelMetadataInternal__)
	Mtime   *lib.TimeInternal__
}

func (r RTChannelSetInternal__) Import() RTChannelSet {
	return RTChannelSet{
		Vers: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Vers),
		Lst: (func(x *[](*RTChannelMetadataInternal__)) (ret []RTChannelMetadata) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTChannelMetadata, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTChannelMetadataInternal__) (ret RTChannelMetadata) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Lst),
		Mtime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mtime),
	}
}
func (r RTChannelSet) Export() *RTChannelSetInternal__ {
	return &RTChannelSetInternal__{
		Vers: r.Vers.Export(),
		Lst: (func(x []RTChannelMetadata) *[](*RTChannelMetadataInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTChannelMetadataInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Lst),
		Mtime: r.Mtime.Export(),
	}
}
func (r *RTChannelSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSet) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelSet) Bytes() []byte { return nil }

type RTMsg struct {
	Md         lib.RTMsgMetadata
	Mw         lib.RTMsgWrapper
	Seq        lib.RTMsgSeq
	Sender     *lib.PartyID
	InsertTime lib.Time
}
type RTMsgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md         *lib.RTMsgMetadataInternal__
	Mw         *lib.RTMsgWrapperInternal__
	Seq        *lib.RTMsgSeqInternal__
	Sender     *lib.PartyIDInternal__
	InsertTime *lib.TimeInternal__
}

func (r RTMsgInternal__) Import() RTMsg {
	return RTMsg{
		Md: (func(x *lib.RTMsgMetadataInternal__) (ret lib.RTMsgMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		Mw: (func(x *lib.RTMsgWrapperInternal__) (ret lib.RTMsgWrapper) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mw),
		Seq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		Sender: (func(x *lib.PartyIDInternal__) *lib.PartyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Sender),
		InsertTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InsertTime),
	}
}
func (r RTMsg) Export() *RTMsgInternal__ {
	return &RTMsgInternal__{
		Md:  r.Md.Export(),
		Mw:  r.Mw.Export(),
		Seq: r.Seq.Export(),
		Sender: (func(x *lib.PartyID) *lib.PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Sender),
		InsertTime: r.InsertTime.Export(),
	}
}
func (r *RTMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsg) Decode(dec rpc.Decoder) error {
	var tmp RTMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTMsgTypeUniqueID = rpc.TypeUniqueID(0x7bcd22765c8cd757)

func (r *RTMsg) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMsgTypeUniqueID
}
func (r *RTMsg) Bytes() []byte { return nil }

type RTInboxChannel struct {
	Md           RTChannelMetadata
	InboxVersion lib.RTInboxVersion
	ReadThrough  lib.RTMsgSeq
	Hidden       bool
	Muted        bool
}
type RTInboxChannelInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md           *RTChannelMetadataInternal__
	InboxVersion *lib.RTInboxVersionInternal__
	ReadThrough  *lib.RTMsgSeqInternal__
	Hidden       *bool
	Muted        *bool
}

func (r RTInboxChannelInternal__) Import() RTInboxChannel {
	return RTInboxChannel{
		Md: (func(x *RTChannelMetadataInternal__) (ret RTChannelMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		InboxVersion: (func(x *lib.RTInboxVersionInternal__) (ret lib.RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InboxVersion),
		ReadThrough: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ReadThrough),
		Hidden: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Hidden),
		Muted: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Muted),
	}
}
func (r RTInboxChannel) Export() *RTInboxChannelInternal__ {
	return &RTInboxChannelInternal__{
		Md:           r.Md.Export(),
		InboxVersion: r.InboxVersion.Export(),
		ReadThrough:  r.ReadThrough.Export(),
		Hidden:       &r.Hidden,
		Muted:        &r.Muted,
	}
}
func (r *RTInboxChannel) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTInboxChannel) Decode(dec rpc.Decoder) error {
	var tmp RTInboxChannelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTInboxChannel) Bytes() []byte { return nil }

type RTInboxDelta struct {
	InboxVersion lib.RTInboxVersion
	AppID        lib.RTAppID
	Channels     []RTInboxChannel
}
type RTInboxDeltaInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	InboxVersion *lib.RTInboxVersionInternal__
	AppID        *lib.RTAppIDInternal__
	Channels     *[](*RTInboxChannelInternal__)
}

func (r RTInboxDeltaInternal__) Import() RTInboxDelta {
	return RTInboxDelta{
		InboxVersion: (func(x *lib.RTInboxVersionInternal__) (ret lib.RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InboxVersion),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Channels: (func(x *[](*RTInboxChannelInternal__)) (ret []RTInboxChannel) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTInboxChannel, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTInboxChannelInternal__) (ret RTInboxChannel) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Channels),
	}
}
func (r RTInboxDelta) Export() *RTInboxDeltaInternal__ {
	return &RTInboxDeltaInternal__{
		InboxVersion: r.InboxVersion.Export(),
		AppID:        r.AppID.Export(),
		Channels: (func(x []RTInboxChannel) *[](*RTInboxChannelInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTInboxChannelInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Channels),
	}
}
func (r *RTInboxDelta) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTInboxDelta) Decode(dec rpc.Decoder) error {
	var tmp RTInboxDeltaInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTInboxDelta) Bytes() []byte { return nil }

type RTThreadRangeBookends struct {
	Start lib.RTMsgSeq
	End   lib.RTMsgSeq
}
type RTThreadRangeBookendsInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Start   *lib.RTMsgSeqInternal__
	End     *lib.RTMsgSeqInternal__
}

func (r RTThreadRangeBookendsInternal__) Import() RTThreadRangeBookends {
	return RTThreadRangeBookends{
		Start: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Start),
		End: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.End),
	}
}
func (r RTThreadRangeBookends) Export() *RTThreadRangeBookendsInternal__ {
	return &RTThreadRangeBookendsInternal__{
		Start: r.Start.Export(),
		End:   r.End.Export(),
	}
}
func (r *RTThreadRangeBookends) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTThreadRangeBookends) Decode(dec rpc.Decoder) error {
	var tmp RTThreadRangeBookendsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTThreadRangeBookends) Bytes() []byte { return nil }

type RTThreadQuery struct {
	ChannelID lib.RTChannelID
	Bookends  []RTThreadRangeBookends
	Seqs      []lib.RTMsgSeq
}
type RTThreadQueryInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *lib.RTChannelIDInternal__
	Bookends  *[](*RTThreadRangeBookendsInternal__)
	Seqs      *[](*lib.RTMsgSeqInternal__)
}

func (r RTThreadQueryInternal__) Import() RTThreadQuery {
	return RTThreadQuery{
		ChannelID: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
		Bookends: (func(x *[](*RTThreadRangeBookendsInternal__)) (ret []RTThreadRangeBookends) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTThreadRangeBookends, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTThreadRangeBookendsInternal__) (ret RTThreadRangeBookends) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Bookends),
		Seqs: (func(x *[](*lib.RTMsgSeqInternal__)) (ret []lib.RTMsgSeq) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.RTMsgSeq, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Seqs),
	}
}
func (r RTThreadQuery) Export() *RTThreadQueryInternal__ {
	return &RTThreadQueryInternal__{
		ChannelID: r.ChannelID.Export(),
		Bookends: (func(x []RTThreadRangeBookends) *[](*RTThreadRangeBookendsInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTThreadRangeBookendsInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Bookends),
		Seqs: (func(x []lib.RTMsgSeq) *[](*lib.RTMsgSeqInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.RTMsgSeqInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Seqs),
	}
}
func (r *RTThreadQuery) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTThreadQuery) Decode(dec rpc.Decoder) error {
	var tmp RTThreadQueryInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTThreadQuery) Bytes() []byte { return nil }

type RTMsgList struct {
	Lst []RTMsg
}
type RTMsgListInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Lst     *[](*RTMsgInternal__)
}

func (r RTMsgListInternal__) Import() RTMsgList {
	return RTMsgList{
		Lst: (func(x *[](*RTMsgInternal__)) (ret []RTMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMsgInternal__) (ret RTMsg) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Lst),
	}
}
func (r RTMsgList) Export() *RTMsgListInternal__ {
	return &RTMsgListInternal__{
		Lst: (func(x []RTMsg) *[](*RTMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Lst),
	}
}
func (r *RTMsgList) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgList) Decode(dec rpc.Decoder) error {
	var tmp RTMsgListInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgList) Bytes() []byte { return nil }

type RTThreadPage struct {
	RangeMsgs []RTMsgList
	SeqMsgs   []RTMsg
}
type RTThreadPageInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	RangeMsgs *[](*RTMsgListInternal__)
	SeqMsgs   *[](*RTMsgInternal__)
}

func (r RTThreadPageInternal__) Import() RTThreadPage {
	return RTThreadPage{
		RangeMsgs: (func(x *[](*RTMsgListInternal__)) (ret []RTMsgList) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMsgList, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMsgListInternal__) (ret RTMsgList) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.RangeMsgs),
		SeqMsgs: (func(x *[](*RTMsgInternal__)) (ret []RTMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMsgInternal__) (ret RTMsg) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.SeqMsgs),
	}
}
func (r RTThreadPage) Export() *RTThreadPageInternal__ {
	return &RTThreadPageInternal__{
		RangeMsgs: (func(x []RTMsgList) *[](*RTMsgListInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMsgListInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.RangeMsgs),
		SeqMsgs: (func(x []RTMsg) *[](*RTMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.SeqMsgs),
	}
}
func (r *RTThreadPage) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTThreadPage) Decode(dec rpc.Decoder) error {
	var tmp RTThreadPageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTThreadPage) Bytes() []byte { return nil }

var RealTimeProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x4f58e7d4)

type RtNewChannelArg struct {
	Md      RTChannelMetadata
	SetVers lib.RTChannelSetVersion
}
type RtNewChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *RTChannelMetadataInternal__
	SetVers *lib.RTChannelSetVersionInternal__
}

func (r RtNewChannelArgInternal__) Import() RtNewChannelArg {
	return RtNewChannelArg{
		Md: (func(x *RTChannelMetadataInternal__) (ret RTChannelMetadata) {
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

type RtListAllChannelsForTeamArg struct {
	Team  lib.TeamID
	AppID lib.RTAppID
}
type RtListAllChannelsForTeamArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.TeamIDInternal__
	AppID   *lib.RTAppIDInternal__
}

func (r RtListAllChannelsForTeamArgInternal__) Import() RtListAllChannelsForTeamArg {
	return RtListAllChannelsForTeamArg{
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
func (r RtListAllChannelsForTeamArg) Export() *RtListAllChannelsForTeamArgInternal__ {
	return &RtListAllChannelsForTeamArgInternal__{
		Team:  r.Team.Export(),
		AppID: r.AppID.Export(),
	}
}
func (r *RtListAllChannelsForTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtListAllChannelsForTeamArg) Decode(dec rpc.Decoder) error {
	var tmp RtListAllChannelsForTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtListAllChannelsForTeamArg) Bytes() []byte { return nil }

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
	Q RTThreadQuery
}
type RtGetThreadArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Q       *RTThreadQueryInternal__
}

func (r RtGetThreadArgInternal__) Import() RtGetThreadArg {
	return RtGetThreadArg{
		Q: (func(x *RTThreadQueryInternal__) (ret RTThreadQuery) {
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

type RtGetThreadRecentsArg struct {
	Ch     lib.RTChannelID
	StopAt lib.RTMsgSeq
	Lim    uint64
}
type RtGetThreadRecentsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ch      *lib.RTChannelIDInternal__
	StopAt  *lib.RTMsgSeqInternal__
	Lim     *uint64
}

func (r RtGetThreadRecentsArgInternal__) Import() RtGetThreadRecentsArg {
	return RtGetThreadRecentsArg{
		Ch: (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Ch),
		StopAt: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.StopAt),
		Lim: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Lim),
	}
}
func (r RtGetThreadRecentsArg) Export() *RtGetThreadRecentsArgInternal__ {
	return &RtGetThreadRecentsArgInternal__{
		Ch:     r.Ch.Export(),
		StopAt: r.StopAt.Export(),
		Lim:    &r.Lim,
	}
}
func (r *RtGetThreadRecentsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RtGetThreadRecentsArg) Decode(dec rpc.Decoder) error {
	var tmp RtGetThreadRecentsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RtGetThreadRecentsArg) Bytes() []byte { return nil }

type RealTimeInterface interface {
	RtNewChannel(context.Context, RtNewChannelArg) error
	RtGetChannel(context.Context, lib.RTChannelID) (RTChannelMetadata, error)
	RtListAllChannelsForTeam(context.Context, RtListAllChannelsForTeamArg) (RTChannelSet, error)
	RtSend(context.Context, RTSendArg) (RTSendRes, error)
	RtGetThread(context.Context, RTThreadQuery) (RTThreadPage, error)
	RtGetInboxVersion(context.Context, RTInboxKey) (lib.RTInboxVersion, error)
	RtGetChangedThreads(context.Context, RTGetChangedThreadsArg) (RTInboxDelta, error)
	RtReadThrough(context.Context, RTReadThroughArg) error
	RtPollInbox(context.Context, RTPollInboxArg) (lib.RTInboxPollRes, error)
	RtSelectVHost(context.Context, lib.HostID) error
	RtGetThreadRecents(context.Context, RtGetThreadRecentsArg) (RTMsgList, error)
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

func (c RealTimeClient) RtNewChannel(ctx context.Context, arg RtNewChannelArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *RtNewChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
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
	return
}
func (c RealTimeClient) RtGetChannel(ctx context.Context, channelID lib.RTChannelID) (res RTChannelMetadata, err error) {
	arg := RtGetChannelArg{
		ChannelID: channelID,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTChannelMetadataInternal__]
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
func (c RealTimeClient) RtListAllChannelsForTeam(ctx context.Context, arg RtListAllChannelsForTeamArg) (res RTChannelSet, err error) {
	warg := &rpc.DataWrap[lib.Header, *RtListAllChannelsForTeamArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTChannelSetInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 2, "RealTime.rtListAllChannelsForTeam"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) RtGetThread(ctx context.Context, q RTThreadQuery) (res RTThreadPage, err error) {
	arg := RtGetThreadArg{
		Q: q,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetThreadArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTThreadPageInternal__]
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
func (c RealTimeClient) RtGetChangedThreads(ctx context.Context, rtarg RTGetChangedThreadsArg) (res RTInboxDelta, err error) {
	arg := RtGetChangedThreadsArg{
		Rtarg: rtarg,
	}
	warg := &rpc.DataWrap[lib.Header, *RtGetChangedThreadsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTInboxDeltaInternal__]
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
func (c RealTimeClient) RtGetThreadRecents(ctx context.Context, arg RtGetThreadRecentsArg) (res RTMsgList, err error) {
	warg := &rpc.DataWrap[lib.Header, *RtGetThreadRecentsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, RTMsgListInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 10, "RealTime.rtGetThreadRecents"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
						err := i.RtNewChannel(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
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
						ret := rpc.DataWrap[lib.Header, *RTChannelMetadataInternal__]{
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
						var ret rpc.DataWrap[lib.Header, *RtListAllChannelsForTeamArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtListAllChannelsForTeamArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtListAllChannelsForTeamArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtListAllChannelsForTeam(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *RTChannelSetInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtListAllChannelsForTeam",
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
						ret := rpc.DataWrap[lib.Header, *RTThreadPageInternal__]{
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
						ret := rpc.DataWrap[lib.Header, *RTInboxDeltaInternal__]{
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
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RtGetThreadRecentsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RtGetThreadRecentsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RtGetThreadRecentsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.RtGetThreadRecents(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *RTMsgListInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "rtGetThreadRecents",
			},
		},
		WrapError: RealTimeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(RTChannelMetadataTypeUniqueID)
	rpc.AddUnique(RTMsgTypeUniqueID)
	rpc.AddUnique(RealTimeProtocolID)
}
