// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/realtime.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type RTMsgSeq uint64
type RTMsgSeqInternal__ uint64

func (r RTMsgSeq) Export() *RTMsgSeqInternal__ {
	tmp := ((uint64)(r))
	return ((*RTMsgSeqInternal__)(&tmp))
}
func (r RTMsgSeqInternal__) Import() RTMsgSeq {
	tmp := (uint64)(r)
	return RTMsgSeq((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTMsgSeq) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgSeq) Decode(dec rpc.Decoder) error {
	var tmp RTMsgSeqInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTMsgSeq) Bytes() []byte {
	return nil
}

type RTInboxVersion uint64
type RTInboxVersionInternal__ uint64

func (r RTInboxVersion) Export() *RTInboxVersionInternal__ {
	tmp := ((uint64)(r))
	return ((*RTInboxVersionInternal__)(&tmp))
}
func (r RTInboxVersionInternal__) Import() RTInboxVersion {
	tmp := (uint64)(r)
	return RTInboxVersion((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTInboxVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTInboxVersion) Decode(dec rpc.Decoder) error {
	var tmp RTInboxVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTInboxVersion) Bytes() []byte {
	return nil
}

type RTChannelSeqno uint64
type RTChannelSeqnoInternal__ uint64

func (r RTChannelSeqno) Export() *RTChannelSeqnoInternal__ {
	tmp := ((uint64)(r))
	return ((*RTChannelSeqnoInternal__)(&tmp))
}
func (r RTChannelSeqnoInternal__) Import() RTChannelSeqno {
	tmp := (uint64)(r)
	return RTChannelSeqno((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSeqno) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelSeqno) Bytes() []byte {
	return nil
}

type RTChannelName string
type RTChannelNameInternal__ string

func (r RTChannelName) Export() *RTChannelNameInternal__ {
	tmp := ((string)(r))
	return ((*RTChannelNameInternal__)(&tmp))
}
func (r RTChannelNameInternal__) Import() RTChannelName {
	tmp := (string)(r)
	return RTChannelName((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelName) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelName) Decode(dec rpc.Decoder) error {
	var tmp RTChannelNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelName) Bytes() []byte {
	return nil
}

type RTChannelDesc string
type RTChannelDescInternal__ string

func (r RTChannelDesc) Export() *RTChannelDescInternal__ {
	tmp := ((string)(r))
	return ((*RTChannelDescInternal__)(&tmp))
}
func (r RTChannelDescInternal__) Import() RTChannelDesc {
	tmp := (string)(r)
	return RTChannelDesc((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelDesc) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelDesc) Decode(dec rpc.Decoder) error {
	var tmp RTChannelDescInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelDesc) Bytes() []byte {
	return nil
}

type RTIDType int

const (
	RTIDType_Channel RTIDType = 16
	RTIDType_Msg     RTIDType = 17
)

var RTIDTypeMap = map[string]RTIDType{
	"Channel": 16,
	"Msg":     17,
}
var RTIDTypeRevMap = map[RTIDType]string{
	16: "Channel",
	17: "Msg",
}

type RTIDTypeInternal__ RTIDType

func (r RTIDTypeInternal__) Import() RTIDType {
	return RTIDType(r)
}
func (r RTIDType) Export() *RTIDTypeInternal__ {
	return ((*RTIDTypeInternal__)(&r))
}

type RTChannelIDShort int64
type RTChannelIDShortInternal__ int64

func (r RTChannelIDShort) Export() *RTChannelIDShortInternal__ {
	tmp := ((int64)(r))
	return ((*RTChannelIDShortInternal__)(&tmp))
}
func (r RTChannelIDShortInternal__) Import() RTChannelIDShort {
	tmp := (int64)(r)
	return RTChannelIDShort((func(x *int64) (ret int64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelIDShort) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelIDShort) Decode(dec rpc.Decoder) error {
	var tmp RTChannelIDShortInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelIDShort) Bytes() []byte {
	return nil
}

type RTChannelID [16]byte
type RTChannelIDInternal__ [16]byte

func (r RTChannelID) Export() *RTChannelIDInternal__ {
	tmp := (([16]byte)(r))
	return ((*RTChannelIDInternal__)(&tmp))
}
func (r RTChannelIDInternal__) Import() RTChannelID {
	tmp := ([16]byte)(r)
	return RTChannelID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelID) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelID) Decode(dec rpc.Decoder) error {
	var tmp RTChannelIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelID) Bytes() []byte {
	return (r)[:]
}

type RTMsgID [16]byte
type RTMsgIDInternal__ [16]byte

func (r RTMsgID) Export() *RTMsgIDInternal__ {
	tmp := (([16]byte)(r))
	return ((*RTMsgIDInternal__)(&tmp))
}
func (r RTMsgIDInternal__) Import() RTMsgID {
	tmp := ([16]byte)(r)
	return RTMsgID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTMsgID) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgID) Decode(dec rpc.Decoder) error {
	var tmp RTMsgIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTMsgID) Bytes() []byte {
	return (r)[:]
}

type RTID [17]byte
type RTIDInternal__ [17]byte

func (r RTID) Export() *RTIDInternal__ {
	tmp := (([17]byte)(r))
	return ((*RTIDInternal__)(&tmp))
}
func (r RTIDInternal__) Import() RTID {
	tmp := ([17]byte)(r)
	return RTID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTID) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTID) Decode(dec rpc.Decoder) error {
	var tmp RTIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTID) Bytes() []byte {
	return (r)[:]
}

type RTAppID int

const (
	RTAppID_None  RTAppID = 0
	RTAppID_Chat  RTAppID = 1
	RTAppID_Crdt  RTAppID = 2
	RTAppID_Notif RTAppID = 3
)

var RTAppIDMap = map[string]RTAppID{
	"None":  0,
	"Chat":  1,
	"Crdt":  2,
	"Notif": 3,
}
var RTAppIDRevMap = map[RTAppID]string{
	0: "None",
	1: "Chat",
	2: "Crdt",
	3: "Notif",
}

type RTAppIDInternal__ RTAppID

func (r RTAppIDInternal__) Import() RTAppID {
	return RTAppID(r)
}
func (r RTAppID) Export() *RTAppIDInternal__ {
	return ((*RTAppIDInternal__)(&r))
}

type RTMsgType int

const (
	RTMsgType_None       RTMsgType = 0
	RTMsgType_Basic      RTMsgType = 1
	RTMsgType_Edit       RTMsgType = 2
	RTMsgType_Delete     RTMsgType = 3
	RTMsgType_Reactji    RTMsgType = 4
	RTMsgType_Attachment RTMsgType = 5
	RTMsgType_Reply      RTMsgType = 6
	RTMsgType_System     RTMsgType = 7
	RTMsgType_Join       RTMsgType = 8
	RTMsgType_Leave      RTMsgType = 9
)

var RTMsgTypeMap = map[string]RTMsgType{
	"None":       0,
	"Basic":      1,
	"Edit":       2,
	"Delete":     3,
	"Reactji":    4,
	"Attachment": 5,
	"Reply":      6,
	"System":     7,
	"Join":       8,
	"Leave":      9,
}
var RTMsgTypeRevMap = map[RTMsgType]string{
	0: "None",
	1: "Basic",
	2: "Edit",
	3: "Delete",
	4: "Reactji",
	5: "Attachment",
	6: "Reply",
	7: "System",
	8: "Join",
	9: "Leave",
}

type RTMsgTypeInternal__ RTMsgType

func (r RTMsgTypeInternal__) Import() RTMsgType {
	return RTMsgType(r)
}
func (r RTMsgType) Export() *RTMsgTypeInternal__ {
	return ((*RTMsgTypeInternal__)(&r))
}

type RTKeyType int

const (
	RTKeyType_ChannelName RTKeyType = 1
	RTKeyType_ChannelDesc RTKeyType = 2
	RTKeyType_Data        RTKeyType = 3
)

var RTKeyTypeMap = map[string]RTKeyType{
	"ChannelName": 1,
	"ChannelDesc": 2,
	"Data":        3,
}
var RTKeyTypeRevMap = map[RTKeyType]string{
	1: "ChannelName",
	2: "ChannelDesc",
	3: "Data",
}

type RTKeyTypeInternal__ RTKeyType

func (r RTKeyTypeInternal__) Import() RTKeyType {
	return RTKeyType(r)
}
func (r RTKeyType) Export() *RTKeyTypeInternal__ {
	return ((*RTKeyTypeInternal__)(&r))
}

type RTKeyVar struct {
	T RTKeyType
}
type RTKeyVarInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTKeyType
	Switch__ RTKeyVarInternalSwitch__
}
type RTKeyVarInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
}

func (r RTKeyVar) GetT() (ret RTKeyType, err error) {
	switch r.T {
	default:
		break
	}
	return r.T, nil
}
func NewRTKeyVarDefault(s RTKeyType) RTKeyVar {
	return RTKeyVar{
		T: s,
	}
}
func (r RTKeyVarInternal__) Import() RTKeyVar {
	return RTKeyVar{
		T: r.T,
	}
}
func (r RTKeyVar) Export() *RTKeyVarInternal__ {
	return &RTKeyVarInternal__{
		T:        r.T,
		Switch__: RTKeyVarInternalSwitch__{},
	}
}
func (r *RTKeyVar) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTKeyVar) Decode(dec rpc.Decoder) error {
	var tmp RTKeyVarInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTKeyVar) Bytes() []byte { return nil }

type RTKeyDerivation struct {
	App RTAppID
	Var RTKeyVar
}
type RTKeyDerivationInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	App     *RTAppIDInternal__
	Var     *RTKeyVarInternal__
}

func (r RTKeyDerivationInternal__) Import() RTKeyDerivation {
	return RTKeyDerivation{
		App: (func(x *RTAppIDInternal__) (ret RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.App),
		Var: (func(x *RTKeyVarInternal__) (ret RTKeyVar) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Var),
	}
}
func (r RTKeyDerivation) Export() *RTKeyDerivationInternal__ {
	return &RTKeyDerivationInternal__{
		App: r.App.Export(),
		Var: r.Var.Export(),
	}
}
func (r *RTKeyDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTKeyDerivation) Decode(dec rpc.Decoder) error {
	var tmp RTKeyDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTKeyDerivationTypeUniqueID = rpc.TypeUniqueID(0xee6956bd3980334a)

func (r *RTKeyDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTKeyDerivationTypeUniqueID
}
func (r *RTKeyDerivation) Bytes() []byte { return nil }

type RTMsgMetadata struct {
	MsgID                  RTMsgID
	PrevID                 RTMsgID
	PrevSeq                RTMsgSeq
	SendTime               Time
	Typ                    RTMsgType
	FurtherUserAttribution *UID
}
type RTMsgMetadataInternal__ struct {
	_struct                struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	MsgID                  *RTMsgIDInternal__
	PrevID                 *RTMsgIDInternal__
	PrevSeq                *RTMsgSeqInternal__
	SendTime               *TimeInternal__
	Typ                    *RTMsgTypeInternal__
	FurtherUserAttribution *UIDInternal__
}

func (r RTMsgMetadataInternal__) Import() RTMsgMetadata {
	return RTMsgMetadata{
		MsgID: (func(x *RTMsgIDInternal__) (ret RTMsgID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.MsgID),
		PrevID: (func(x *RTMsgIDInternal__) (ret RTMsgID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PrevID),
		PrevSeq: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PrevSeq),
		SendTime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SendTime),
		Typ: (func(x *RTMsgTypeInternal__) (ret RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
		FurtherUserAttribution: (func(x *UIDInternal__) *UID {
			if x == nil {
				return nil
			}
			tmp := (func(x *UIDInternal__) (ret UID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.FurtherUserAttribution),
	}
}
func (r RTMsgMetadata) Export() *RTMsgMetadataInternal__ {
	return &RTMsgMetadataInternal__{
		MsgID:    r.MsgID.Export(),
		PrevID:   r.PrevID.Export(),
		PrevSeq:  r.PrevSeq.Export(),
		SendTime: r.SendTime.Export(),
		Typ:      r.Typ.Export(),
		FurtherUserAttribution: (func(x *UID) *UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.FurtherUserAttribution),
	}
}
func (r *RTMsgMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgMetadata) Decode(dec rpc.Decoder) error {
	var tmp RTMsgMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgMetadata) Bytes() []byte { return nil }

type RTMsgNoncer struct {
	Md     RTMsgMetadata
	Sender PartyID
	AppID  RTAppID
	Team   PartyID
	Chid   RTChannelID
}
type RTMsgNoncerInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *RTMsgMetadataInternal__
	Sender  *PartyIDInternal__
	AppID   *RTAppIDInternal__
	Team    *PartyIDInternal__
	Chid    *RTChannelIDInternal__
}

func (r RTMsgNoncerInternal__) Import() RTMsgNoncer {
	return RTMsgNoncer{
		Md: (func(x *RTMsgMetadataInternal__) (ret RTMsgMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		Sender: (func(x *PartyIDInternal__) (ret PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Sender),
		AppID: (func(x *RTAppIDInternal__) (ret RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Team: (func(x *PartyIDInternal__) (ret PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Team),
		Chid: (func(x *RTChannelIDInternal__) (ret RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Chid),
	}
}
func (r RTMsgNoncer) Export() *RTMsgNoncerInternal__ {
	return &RTMsgNoncerInternal__{
		Md:     r.Md.Export(),
		Sender: r.Sender.Export(),
		AppID:  r.AppID.Export(),
		Team:   r.Team.Export(),
		Chid:   r.Chid.Export(),
	}
}
func (r *RTMsgNoncer) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgNoncer) Decode(dec rpc.Decoder) error {
	var tmp RTMsgNoncerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTMsgNoncerTypeUniqueID = rpc.TypeUniqueID(0xd45941000217cf8a)

func (r *RTMsgNoncer) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMsgNoncerTypeUniqueID
}
func (r *RTMsgNoncer) Bytes() []byte { return nil }

type RTMsgPlaintext struct {
	Md   RTMsgMetadata
	Body RTMsgBody
}
type RTMsgPlaintextInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *RTMsgMetadataInternal__
	Body    *RTMsgBodyInternal__
}

func (r RTMsgPlaintextInternal__) Import() RTMsgPlaintext {
	return RTMsgPlaintext{
		Md: (func(x *RTMsgMetadataInternal__) (ret RTMsgMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		Body: (func(x *RTMsgBodyInternal__) (ret RTMsgBody) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Body),
	}
}
func (r RTMsgPlaintext) Export() *RTMsgPlaintextInternal__ {
	return &RTMsgPlaintextInternal__{
		Md:   r.Md.Export(),
		Body: r.Body.Export(),
	}
}
func (r *RTMsgPlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgPlaintext) Decode(dec rpc.Decoder) error {
	var tmp RTMsgPlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTMsgPlaintextTypeUniqueID = rpc.TypeUniqueID(0xd156b7500ebab236)

func (r *RTMsgPlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMsgPlaintextTypeUniqueID
}
func (r *RTMsgPlaintext) Bytes() []byte { return nil }

type RTMsgPlaintextBasic []byte
type RTMsgPlaintextBasicInternal__ []byte

func (r RTMsgPlaintextBasic) Export() *RTMsgPlaintextBasicInternal__ {
	tmp := (([]byte)(r))
	return ((*RTMsgPlaintextBasicInternal__)(&tmp))
}
func (r RTMsgPlaintextBasicInternal__) Import() RTMsgPlaintextBasic {
	tmp := ([]byte)(r)
	return RTMsgPlaintextBasic((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTMsgPlaintextBasic) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgPlaintextBasic) Decode(dec rpc.Decoder) error {
	var tmp RTMsgPlaintextBasicInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTMsgPlaintextBasic) Bytes() []byte {
	return (r)[:]
}

type RTMsgPlaintextPegged struct {
	Basic   RTMsgPlaintextBasic
	ReplyTo RTMsgID
}
type RTMsgPlaintextPeggedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Basic   *RTMsgPlaintextBasicInternal__
	ReplyTo *RTMsgIDInternal__
}

func (r RTMsgPlaintextPeggedInternal__) Import() RTMsgPlaintextPegged {
	return RTMsgPlaintextPegged{
		Basic: (func(x *RTMsgPlaintextBasicInternal__) (ret RTMsgPlaintextBasic) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Basic),
		ReplyTo: (func(x *RTMsgIDInternal__) (ret RTMsgID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ReplyTo),
	}
}
func (r RTMsgPlaintextPegged) Export() *RTMsgPlaintextPeggedInternal__ {
	return &RTMsgPlaintextPeggedInternal__{
		Basic:   r.Basic.Export(),
		ReplyTo: r.ReplyTo.Export(),
	}
}
func (r *RTMsgPlaintextPegged) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgPlaintextPegged) Decode(dec rpc.Decoder) error {
	var tmp RTMsgPlaintextPeggedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgPlaintextPegged) Bytes() []byte { return nil }

type RTMsgBody struct {
	T     RTMsgType
	F_1__ *RTMsgPlaintextBasic  `json:"f1,omitempty"`
	F_2__ *RTMsgPlaintextPegged `json:"f2,omitempty"`
}
type RTMsgBodyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTMsgType
	Switch__ RTMsgBodyInternalSwitch__
}
type RTMsgBodyInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *RTMsgPlaintextBasicInternal__  `codec:"1"`
	F_2__   *RTMsgPlaintextPeggedInternal__ `codec:"2"`
}

func (r RTMsgBody) GetT() (ret RTMsgType, err error) {
	switch r.T {
	case RTMsgType_Basic:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case RTMsgType_Reply, RTMsgType_Reactji, RTMsgType_Edit:
		if r.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return r.T, nil
}
func (r RTMsgBody) Basic() RTMsgPlaintextBasic {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Basic {
		panic(fmt.Sprintf("unexpected switch value (%v) when Basic is called", r.T))
	}
	return *r.F_1__
}
func (r RTMsgBody) Reply() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Reply {
		panic(fmt.Sprintf("unexpected switch value (%v) when Reply is called", r.T))
	}
	return *r.F_2__
}
func (r RTMsgBody) Reactji() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Reactji {
		panic(fmt.Sprintf("unexpected switch value (%v) when Reactji is called", r.T))
	}
	return *r.F_2__
}
func (r RTMsgBody) Edit() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Edit {
		panic(fmt.Sprintf("unexpected switch value (%v) when Edit is called", r.T))
	}
	return *r.F_2__
}
func NewRTMsgBodyWithBasic(v RTMsgPlaintextBasic) RTMsgBody {
	return RTMsgBody{
		T:     RTMsgType_Basic,
		F_1__: &v,
	}
}
func NewRTMsgBodyWithReply(v RTMsgPlaintextPegged) RTMsgBody {
	return RTMsgBody{
		T:     RTMsgType_Reply,
		F_2__: &v,
	}
}
func NewRTMsgBodyWithReactji(v RTMsgPlaintextPegged) RTMsgBody {
	return RTMsgBody{
		T:     RTMsgType_Reactji,
		F_2__: &v,
	}
}
func NewRTMsgBodyWithEdit(v RTMsgPlaintextPegged) RTMsgBody {
	return RTMsgBody{
		T:     RTMsgType_Edit,
		F_2__: &v,
	}
}
func (r RTMsgBodyInternal__) Import() RTMsgBody {
	return RTMsgBody{
		T: r.T,
		F_1__: (func(x *RTMsgPlaintextBasicInternal__) *RTMsgPlaintextBasic {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTMsgPlaintextBasicInternal__) (ret RTMsgPlaintextBasic) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
		F_2__: (func(x *RTMsgPlaintextPeggedInternal__) *RTMsgPlaintextPegged {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTMsgPlaintextPeggedInternal__) (ret RTMsgPlaintextPegged) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_2__),
	}
}
func (r RTMsgBody) Export() *RTMsgBodyInternal__ {
	return &RTMsgBodyInternal__{
		T: r.T,
		Switch__: RTMsgBodyInternalSwitch__{
			F_1__: (func(x *RTMsgPlaintextBasic) *RTMsgPlaintextBasicInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
			F_2__: (func(x *RTMsgPlaintextPegged) *RTMsgPlaintextPeggedInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_2__),
		},
	}
}
func (r *RTMsgBody) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgBody) Decode(dec rpc.Decoder) error {
	var tmp RTMsgBodyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTMsgBodyTypeUniqueID = rpc.TypeUniqueID(0xc830111a77ab24f6)

func (r *RTMsgBody) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMsgBodyTypeUniqueID
}
func (r *RTMsgBody) Bytes() []byte { return nil }

type RTChannelNameType int

const (
	RTChannelNameType_Utf8v1 RTChannelNameType = 1
)

var RTChannelNameTypeMap = map[string]RTChannelNameType{
	"Utf8v1": 1,
}
var RTChannelNameTypeRevMap = map[RTChannelNameType]string{
	1: "Utf8v1",
}

type RTChannelNameTypeInternal__ RTChannelNameType

func (r RTChannelNameTypeInternal__) Import() RTChannelNameType {
	return RTChannelNameType(r)
}
func (r RTChannelNameType) Export() *RTChannelNameTypeInternal__ {
	return ((*RTChannelNameTypeInternal__)(&r))
}

type RTChannelNamePlaintext struct {
	T     RTChannelNameType
	F_1__ *RTChannelName `json:"f1,omitempty"`
}
type RTChannelNamePlaintextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTChannelNameType
	Switch__ RTChannelNamePlaintextInternalSwitch__
}
type RTChannelNamePlaintextInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *RTChannelNameInternal__ `codec:"1"`
}

func (r RTChannelNamePlaintext) GetT() (ret RTChannelNameType, err error) {
	switch r.T {
	case RTChannelNameType_Utf8v1:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return r.T, nil
}
func (r RTChannelNamePlaintext) Utf8v1() RTChannelName {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelNameType_Utf8v1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Utf8v1 is called", r.T))
	}
	return *r.F_1__
}
func NewRTChannelNamePlaintextWithUtf8v1(v RTChannelName) RTChannelNamePlaintext {
	return RTChannelNamePlaintext{
		T:     RTChannelNameType_Utf8v1,
		F_1__: &v,
	}
}
func (r RTChannelNamePlaintextInternal__) Import() RTChannelNamePlaintext {
	return RTChannelNamePlaintext{
		T: r.T,
		F_1__: (func(x *RTChannelNameInternal__) *RTChannelName {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTChannelNameInternal__) (ret RTChannelName) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
	}
}
func (r RTChannelNamePlaintext) Export() *RTChannelNamePlaintextInternal__ {
	return &RTChannelNamePlaintextInternal__{
		T: r.T,
		Switch__: RTChannelNamePlaintextInternalSwitch__{
			F_1__: (func(x *RTChannelName) *RTChannelNameInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
		},
	}
}
func (r *RTChannelNamePlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelNamePlaintext) Decode(dec rpc.Decoder) error {
	var tmp RTChannelNamePlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTChannelNamePlaintextTypeUniqueID = rpc.TypeUniqueID(0xbe4f7ec6ba0b1393)

func (r *RTChannelNamePlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTChannelNamePlaintextTypeUniqueID
}
func (r *RTChannelNamePlaintext) Bytes() []byte { return nil }

type RTChannelDescType int

const (
	RTChannelDescType_Utf8v1 RTChannelDescType = 1
)

var RTChannelDescTypeMap = map[string]RTChannelDescType{
	"Utf8v1": 1,
}
var RTChannelDescTypeRevMap = map[RTChannelDescType]string{
	1: "Utf8v1",
}

type RTChannelDescTypeInternal__ RTChannelDescType

func (r RTChannelDescTypeInternal__) Import() RTChannelDescType {
	return RTChannelDescType(r)
}
func (r RTChannelDescType) Export() *RTChannelDescTypeInternal__ {
	return ((*RTChannelDescTypeInternal__)(&r))
}

type RTChannelDescPlaintext struct {
	T     RTChannelDescType
	F_1__ *RTChannelDesc `json:"f1,omitempty"`
}
type RTChannelDescPlaintextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTChannelDescType
	Switch__ RTChannelDescPlaintextInternalSwitch__
}
type RTChannelDescPlaintextInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *RTChannelDescInternal__ `codec:"1"`
}

func (r RTChannelDescPlaintext) GetT() (ret RTChannelDescType, err error) {
	switch r.T {
	case RTChannelDescType_Utf8v1:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return r.T, nil
}
func (r RTChannelDescPlaintext) Utf8v1() RTChannelDesc {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelDescType_Utf8v1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Utf8v1 is called", r.T))
	}
	return *r.F_1__
}
func NewRTChannelDescPlaintextWithUtf8v1(v RTChannelDesc) RTChannelDescPlaintext {
	return RTChannelDescPlaintext{
		T:     RTChannelDescType_Utf8v1,
		F_1__: &v,
	}
}
func (r RTChannelDescPlaintextInternal__) Import() RTChannelDescPlaintext {
	return RTChannelDescPlaintext{
		T: r.T,
		F_1__: (func(x *RTChannelDescInternal__) *RTChannelDesc {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTChannelDescInternal__) (ret RTChannelDesc) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
	}
}
func (r RTChannelDescPlaintext) Export() *RTChannelDescPlaintextInternal__ {
	return &RTChannelDescPlaintextInternal__{
		T: r.T,
		Switch__: RTChannelDescPlaintextInternalSwitch__{
			F_1__: (func(x *RTChannelDesc) *RTChannelDescInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
		},
	}
}
func (r *RTChannelDescPlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelDescPlaintext) Decode(dec rpc.Decoder) error {
	var tmp RTChannelDescPlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTChannelDescPlaintextTypeUniqueID = rpc.TypeUniqueID(0xd14f88f5ae7aaecb)

func (r *RTChannelDescPlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTChannelDescPlaintextTypeUniqueID
}
func (r *RTChannelDescPlaintext) Bytes() []byte { return nil }

type RTBoxRG struct {
	Rg  RoleAndGen
	Box SecretBox
}
type RTBoxRGInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (r RTBoxRGInternal__) Import() RTBoxRG {
	return RTBoxRG{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rg),
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Box),
	}
}
func (r RTBoxRG) Export() *RTBoxRGInternal__ {
	return &RTBoxRGInternal__{
		Rg:  r.Rg.Export(),
		Box: r.Box.Export(),
	}
}
func (r *RTBoxRG) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTBoxRG) Decode(dec rpc.Decoder) error {
	var tmp RTBoxRGInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTBoxRG) Bytes() []byte { return nil }

type RTChannelSetVersion uint64
type RTChannelSetVersionInternal__ uint64

func (r RTChannelSetVersion) Export() *RTChannelSetVersionInternal__ {
	tmp := ((uint64)(r))
	return ((*RTChannelSetVersionInternal__)(&tmp))
}
func (r RTChannelSetVersionInternal__) Import() RTChannelSetVersion {
	tmp := (uint64)(r)
	return RTChannelSetVersion((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RTChannelSetVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSetVersion) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelSetVersion) Bytes() []byte {
	return nil
}

type RTChannelClass int

const (
	RTChannelClass_Bottom RTChannelClass = 0
	RTChannelClass_Admin  RTChannelClass = 1
)

var RTChannelClassMap = map[string]RTChannelClass{
	"Bottom": 0,
	"Admin":  1,
}
var RTChannelClassRevMap = map[RTChannelClass]string{
	0: "Bottom",
	1: "Admin",
}

type RTChannelClassInternal__ RTChannelClass

func (r RTChannelClassInternal__) Import() RTChannelClass {
	return RTChannelClass(r)
}
func (r RTChannelClass) Export() *RTChannelClassInternal__ {
	return ((*RTChannelClassInternal__)(&r))
}

type MsgBodyType int

const (
	MsgBodyType_Plaintext MsgBodyType = 0
	MsgBodyType_Encrypted MsgBodyType = 1
)

var MsgBodyTypeMap = map[string]MsgBodyType{
	"Plaintext": 0,
	"Encrypted": 1,
}
var MsgBodyTypeRevMap = map[MsgBodyType]string{
	0: "Plaintext",
	1: "Encrypted",
}

type MsgBodyTypeInternal__ MsgBodyType

func (m MsgBodyTypeInternal__) Import() MsgBodyType {
	return MsgBodyType(m)
}
func (m MsgBodyType) Export() *MsgBodyTypeInternal__ {
	return ((*MsgBodyTypeInternal__)(&m))
}

type RTMsgCiphertext struct {
	T     BoxType
	F_0__ *NaclCiphertext `json:"f0,omitempty"`
}
type RTMsgCiphertextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        BoxType
	Switch__ RTMsgCiphertextInternalSwitch__
}
type RTMsgCiphertextInternalSwitch__ struct {
	_struct struct{}                  `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *NaclCiphertextInternal__ `codec:"0"`
}

func (r RTMsgCiphertext) GetT() (ret BoxType, err error) {
	switch r.T {
	case BoxType_NACL:
		if r.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return r.T, nil
}
func (r RTMsgCiphertext) Nacl() NaclCiphertext {
	if r.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != BoxType_NACL {
		panic(fmt.Sprintf("unexpected switch value (%v) when Nacl is called", r.T))
	}
	return *r.F_0__
}
func NewRTMsgCiphertextWithNacl(v NaclCiphertext) RTMsgCiphertext {
	return RTMsgCiphertext{
		T:     BoxType_NACL,
		F_0__: &v,
	}
}
func (r RTMsgCiphertextInternal__) Import() RTMsgCiphertext {
	return RTMsgCiphertext{
		T: r.T,
		F_0__: (func(x *NaclCiphertextInternal__) *NaclCiphertext {
			if x == nil {
				return nil
			}
			tmp := (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_0__),
	}
}
func (r RTMsgCiphertext) Export() *RTMsgCiphertextInternal__ {
	return &RTMsgCiphertextInternal__{
		T: r.T,
		Switch__: RTMsgCiphertextInternalSwitch__{
			F_0__: (func(x *NaclCiphertext) *NaclCiphertextInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_0__),
		},
	}
}
func (r *RTMsgCiphertext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgCiphertext) Decode(dec rpc.Decoder) error {
	var tmp RTMsgCiphertextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgCiphertext) Bytes() []byte { return nil }

type RTMsgBox struct {
	Ctext RTMsgCiphertext
	Rg    RoleAndGen
}
type RTMsgBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ctext   *RTMsgCiphertextInternal__
	Rg      *RoleAndGenInternal__
}

func (r RTMsgBoxInternal__) Import() RTMsgBox {
	return RTMsgBox{
		Ctext: (func(x *RTMsgCiphertextInternal__) (ret RTMsgCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Ctext),
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Rg),
	}
}
func (r RTMsgBox) Export() *RTMsgBoxInternal__ {
	return &RTMsgBoxInternal__{
		Ctext: r.Ctext.Export(),
		Rg:    r.Rg.Export(),
	}
}
func (r *RTMsgBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgBox) Decode(dec rpc.Decoder) error {
	var tmp RTMsgBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgBox) Bytes() []byte { return nil }

type RTMsgWrapper struct {
	T     MsgBodyType
	F_0__ *[]byte   `json:"f0,omitempty"`
	F_1__ *RTMsgBox `json:"f1,omitempty"`
}
type RTMsgWrapperInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        MsgBodyType
	Switch__ RTMsgWrapperInternalSwitch__
}
type RTMsgWrapperInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *[]byte             `codec:"0"`
	F_1__   *RTMsgBoxInternal__ `codec:"1"`
}

func (r RTMsgWrapper) GetT() (ret MsgBodyType, err error) {
	switch r.T {
	case MsgBodyType_Plaintext:
		if r.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case MsgBodyType_Encrypted:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return r.T, nil
}
func (r RTMsgWrapper) Plaintext() []byte {
	if r.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != MsgBodyType_Plaintext {
		panic(fmt.Sprintf("unexpected switch value (%v) when Plaintext is called", r.T))
	}
	return *r.F_0__
}
func (r RTMsgWrapper) Encrypted() RTMsgBox {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != MsgBodyType_Encrypted {
		panic(fmt.Sprintf("unexpected switch value (%v) when Encrypted is called", r.T))
	}
	return *r.F_1__
}
func NewRTMsgWrapperWithPlaintext(v []byte) RTMsgWrapper {
	return RTMsgWrapper{
		T:     MsgBodyType_Plaintext,
		F_0__: &v,
	}
}
func NewRTMsgWrapperWithEncrypted(v RTMsgBox) RTMsgWrapper {
	return RTMsgWrapper{
		T:     MsgBodyType_Encrypted,
		F_1__: &v,
	}
}
func (r RTMsgWrapperInternal__) Import() RTMsgWrapper {
	return RTMsgWrapper{
		T:     r.T,
		F_0__: r.Switch__.F_0__,
		F_1__: (func(x *RTMsgBoxInternal__) *RTMsgBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTMsgBoxInternal__) (ret RTMsgBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
	}
}
func (r RTMsgWrapper) Export() *RTMsgWrapperInternal__ {
	return &RTMsgWrapperInternal__{
		T: r.T,
		Switch__: RTMsgWrapperInternalSwitch__{
			F_0__: r.F_0__,
			F_1__: (func(x *RTMsgBox) *RTMsgBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
		},
	}
}
func (r *RTMsgWrapper) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgWrapper) Decode(dec rpc.Decoder) error {
	var tmp RTMsgWrapperInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgWrapper) Bytes() []byte { return nil }

type RTThreadDir int

const (
	RTThreadDir_Forward  RTThreadDir = 0
	RTThreadDir_Backward RTThreadDir = 1
)

var RTThreadDirMap = map[string]RTThreadDir{
	"Forward":  0,
	"Backward": 1,
}
var RTThreadDirRevMap = map[RTThreadDir]string{
	0: "Forward",
	1: "Backward",
}

type RTThreadDirInternal__ RTThreadDir

func (r RTThreadDirInternal__) Import() RTThreadDir {
	return RTThreadDir(r)
}
func (r RTThreadDir) Export() *RTThreadDirInternal__ {
	return ((*RTThreadDirInternal__)(&r))
}

type RTThreadRange struct {
	Start RTMsgSeq
	Dir   RTThreadDir
	Max   uint64
}
type RTThreadRangeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Start   *RTMsgSeqInternal__
	Dir     *RTThreadDirInternal__
	Max     *uint64
}

func (r RTThreadRangeInternal__) Import() RTThreadRange {
	return RTThreadRange{
		Start: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Start),
		Dir: (func(x *RTThreadDirInternal__) (ret RTThreadDir) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Dir),
		Max: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Max),
	}
}
func (r RTThreadRange) Export() *RTThreadRangeInternal__ {
	return &RTThreadRangeInternal__{
		Start: r.Start.Export(),
		Dir:   r.Dir.Export(),
		Max:   &r.Max,
	}
}
func (r *RTThreadRange) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTThreadRange) Decode(dec rpc.Decoder) error {
	var tmp RTThreadRangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTThreadRange) Bytes() []byte { return nil }

type RTThreadQuery struct {
	ChannelID RTChannelID
	Range     *RTThreadRange
	Seqs      []RTMsgSeq
}
type RTThreadQueryInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *RTChannelIDInternal__
	Range     *RTThreadRangeInternal__
	Seqs      *[](*RTMsgSeqInternal__)
}

func (r RTThreadQueryInternal__) Import() RTThreadQuery {
	return RTThreadQuery{
		ChannelID: (func(x *RTChannelIDInternal__) (ret RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
		Range: (func(x *RTThreadRangeInternal__) *RTThreadRange {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTThreadRangeInternal__) (ret RTThreadRange) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Range),
		Seqs: (func(x *[](*RTMsgSeqInternal__)) (ret []RTMsgSeq) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMsgSeq, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
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
		Range: (func(x *RTThreadRange) *RTThreadRangeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Range),
		Seqs: (func(x []RTMsgSeq) *[](*RTMsgSeqInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMsgSeqInternal__), len(x))
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

type RTInboxPollRes struct {
	Bumped       bool
	InboxVersion RTInboxVersion
}
type RTInboxPollResInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Bumped       *bool
	InboxVersion *RTInboxVersionInternal__
}

func (r RTInboxPollResInternal__) Import() RTInboxPollRes {
	return RTInboxPollRes{
		Bumped: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Bumped),
		InboxVersion: (func(x *RTInboxVersionInternal__) (ret RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InboxVersion),
	}
}
func (r RTInboxPollRes) Export() *RTInboxPollResInternal__ {
	return &RTInboxPollResInternal__{
		Bumped:       &r.Bumped,
		InboxVersion: r.InboxVersion.Export(),
	}
}
func (r *RTInboxPollRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTInboxPollRes) Decode(dec rpc.Decoder) error {
	var tmp RTInboxPollResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTInboxPollRes) Bytes() []byte { return nil }

type RTMsgCached struct {
	Md  RTMsgNoncer
	Mw  RTMsgWrapper
	Sit Time
}
type RTMsgCachedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *RTMsgNoncerInternal__
	Mw      *RTMsgWrapperInternal__
	Sit     *TimeInternal__
}

func (r RTMsgCachedInternal__) Import() RTMsgCached {
	return RTMsgCached{
		Md: (func(x *RTMsgNoncerInternal__) (ret RTMsgNoncer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Md),
		Mw: (func(x *RTMsgWrapperInternal__) (ret RTMsgWrapper) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mw),
		Sit: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Sit),
	}
}
func (r RTMsgCached) Export() *RTMsgCachedInternal__ {
	return &RTMsgCachedInternal__{
		Md:  r.Md.Export(),
		Mw:  r.Mw.Export(),
		Sit: r.Sit.Export(),
	}
}
func (r *RTMsgCached) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgCached) Decode(dec rpc.Decoder) error {
	var tmp RTMsgCachedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgCached) Bytes() []byte { return nil }

type RTMsgCachedWithSeq struct {
	Cm  RTMsgCached
	Seq RTMsgSeq
}
type RTMsgCachedWithSeqInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cm      *RTMsgCachedInternal__
	Seq     *RTMsgSeqInternal__
}

func (r RTMsgCachedWithSeqInternal__) Import() RTMsgCachedWithSeq {
	return RTMsgCachedWithSeq{
		Cm: (func(x *RTMsgCachedInternal__) (ret RTMsgCached) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Cm),
		Seq: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
	}
}
func (r RTMsgCachedWithSeq) Export() *RTMsgCachedWithSeqInternal__ {
	return &RTMsgCachedWithSeqInternal__{
		Cm:  r.Cm.Export(),
		Seq: r.Seq.Export(),
	}
}
func (r *RTMsgCachedWithSeq) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgCachedWithSeq) Decode(dec rpc.Decoder) error {
	var tmp RTMsgCachedWithSeqInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgCachedWithSeq) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(RTKeyDerivationTypeUniqueID)
	rpc.AddUnique(RTMsgNoncerTypeUniqueID)
	rpc.AddUnique(RTMsgPlaintextTypeUniqueID)
	rpc.AddUnique(RTMsgBodyTypeUniqueID)
	rpc.AddUnique(RTChannelNamePlaintextTypeUniqueID)
	rpc.AddUnique(RTChannelDescPlaintextTypeUniqueID)
}
