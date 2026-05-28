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
)

var RTIDTypeMap = map[string]RTIDType{
	"Channel": 16,
}
var RTIDTypeRevMap = map[RTIDType]string{
	16: "Channel",
}

type RTIDTypeInternal__ RTIDType

func (r RTIDTypeInternal__) Import() RTIDType {
	return RTIDType(r)
}
func (r RTIDType) Export() *RTIDTypeInternal__ {
	return ((*RTIDTypeInternal__)(&r))
}

type RTChannelIDShort uint64
type RTChannelIDShortInternal__ uint64

func (r RTChannelIDShort) Export() *RTChannelIDShortInternal__ {
	tmp := ((uint64)(r))
	return ((*RTChannelIDShortInternal__)(&tmp))
}
func (r RTChannelIDShortInternal__) Import() RTChannelIDShort {
	tmp := (uint64)(r)
	return RTChannelIDShort((func(x *uint64) (ret uint64) {
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
	ReplyTo RTMsgSeq
}
type RTMsgPlaintextPeggedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Basic   *RTMsgPlaintextBasicInternal__
	ReplyTo *RTMsgSeqInternal__
}

func (r RTMsgPlaintextPeggedInternal__) Import() RTMsgPlaintextPegged {
	return RTMsgPlaintextPegged{
		Basic: (func(x *RTMsgPlaintextBasicInternal__) (ret RTMsgPlaintextBasic) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Basic),
		ReplyTo: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
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

type RTMsgPlaintext struct {
	T     RTMsgType
	F_1__ *RTMsgPlaintextBasic  `json:"f1,omitempty"`
	F_2__ *RTMsgPlaintextPegged `json:"f2,omitempty"`
}
type RTMsgPlaintextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTMsgType
	Switch__ RTMsgPlaintextInternalSwitch__
}
type RTMsgPlaintextInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *RTMsgPlaintextBasicInternal__  `codec:"1"`
	F_2__   *RTMsgPlaintextPeggedInternal__ `codec:"2"`
}

func (r RTMsgPlaintext) GetT() (ret RTMsgType, err error) {
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
func (r RTMsgPlaintext) Basic() RTMsgPlaintextBasic {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Basic {
		panic(fmt.Sprintf("unexpected switch value (%v) when Basic is called", r.T))
	}
	return *r.F_1__
}
func (r RTMsgPlaintext) Reply() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Reply {
		panic(fmt.Sprintf("unexpected switch value (%v) when Reply is called", r.T))
	}
	return *r.F_2__
}
func (r RTMsgPlaintext) Reactji() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Reactji {
		panic(fmt.Sprintf("unexpected switch value (%v) when Reactji is called", r.T))
	}
	return *r.F_2__
}
func (r RTMsgPlaintext) Edit() RTMsgPlaintextPegged {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTMsgType_Edit {
		panic(fmt.Sprintf("unexpected switch value (%v) when Edit is called", r.T))
	}
	return *r.F_2__
}
func NewRTMsgPlaintextWithBasic(v RTMsgPlaintextBasic) RTMsgPlaintext {
	return RTMsgPlaintext{
		T:     RTMsgType_Basic,
		F_1__: &v,
	}
}
func NewRTMsgPlaintextWithReply(v RTMsgPlaintextPegged) RTMsgPlaintext {
	return RTMsgPlaintext{
		T:     RTMsgType_Reply,
		F_2__: &v,
	}
}
func NewRTMsgPlaintextWithReactji(v RTMsgPlaintextPegged) RTMsgPlaintext {
	return RTMsgPlaintext{
		T:     RTMsgType_Reactji,
		F_2__: &v,
	}
}
func NewRTMsgPlaintextWithEdit(v RTMsgPlaintextPegged) RTMsgPlaintext {
	return RTMsgPlaintext{
		T:     RTMsgType_Edit,
		F_2__: &v,
	}
}
func (r RTMsgPlaintextInternal__) Import() RTMsgPlaintext {
	return RTMsgPlaintext{
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
func (r RTMsgPlaintext) Export() *RTMsgPlaintextInternal__ {
	return &RTMsgPlaintextInternal__{
		T: r.T,
		Switch__: RTMsgPlaintextInternalSwitch__{
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

var RTMsgPlaintextTypeUniqueID = rpc.TypeUniqueID(0xc830111a77ab24f6)

func (r *RTMsgPlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMsgPlaintextTypeUniqueID
}
func (r *RTMsgPlaintext) Bytes() []byte { return nil }

type RTRolePair struct {
	Read  Role
	Write Role
}
type RTRolePairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Read    *RoleInternal__
	Write   *RoleInternal__
}

func (r RTRolePairInternal__) Import() RTRolePair {
	return RTRolePair{
		Read: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Read),
		Write: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Write),
	}
}
func (r RTRolePair) Export() *RTRolePairInternal__ {
	return &RTRolePairInternal__{
		Read:  r.Read.Export(),
		Write: r.Write.Export(),
	}
}
func (r *RTRolePair) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTRolePair) Decode(dec rpc.Decoder) error {
	var tmp RTRolePairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTRolePair) Bytes() []byte { return nil }

type RTChannelNameType int

const (
	RTChannelNameType_Named RTChannelNameType = 1
)

var RTChannelNameTypeMap = map[string]RTChannelNameType{
	"Named": 1,
}
var RTChannelNameTypeRevMap = map[RTChannelNameType]string{
	1: "Named",
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
	case RTChannelNameType_Named:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return r.T, nil
}
func (r RTChannelNamePlaintext) Named() RTChannelName {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelNameType_Named {
		panic(fmt.Sprintf("unexpected switch value (%v) when Named is called", r.T))
	}
	return *r.F_1__
}
func NewRTChannelNamePlaintextWithNamed(v RTChannelName) RTChannelNamePlaintext {
	return RTChannelNamePlaintext{
		T:     RTChannelNameType_Named,
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
	RTChannelDescType_Plain RTChannelDescType = 0
)

var RTChannelDescTypeMap = map[string]RTChannelDescType{
	"Plain": 0,
}
var RTChannelDescTypeRevMap = map[RTChannelDescType]string{
	0: "Plain",
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
	F_0__ *RTChannelDesc `json:"f0,omitempty"`
}
type RTChannelDescPlaintextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTChannelDescType
	Switch__ RTChannelDescPlaintextInternalSwitch__
}
type RTChannelDescPlaintextInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *RTChannelDescInternal__ `codec:"0"`
}

func (r RTChannelDescPlaintext) GetT() (ret RTChannelDescType, err error) {
	switch r.T {
	case RTChannelDescType_Plain:
		if r.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return r.T, nil
}
func (r RTChannelDescPlaintext) Plain() RTChannelDesc {
	if r.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelDescType_Plain {
		panic(fmt.Sprintf("unexpected switch value (%v) when Plain is called", r.T))
	}
	return *r.F_0__
}
func NewRTChannelDescPlaintextWithPlain(v RTChannelDesc) RTChannelDescPlaintext {
	return RTChannelDescPlaintext{
		T:     RTChannelDescType_Plain,
		F_0__: &v,
	}
}
func (r RTChannelDescPlaintextInternal__) Import() RTChannelDescPlaintext {
	return RTChannelDescPlaintext{
		T: r.T,
		F_0__: (func(x *RTChannelDescInternal__) *RTChannelDesc {
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
		})(r.Switch__.F_0__),
	}
}
func (r RTChannelDescPlaintext) Export() *RTChannelDescPlaintextInternal__ {
	return &RTChannelDescPlaintextInternal__{
		T: r.T,
		Switch__: RTChannelDescPlaintextInternalSwitch__{
			F_0__: (func(x *RTChannelDesc) *RTChannelDescInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_0__),
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

type RTChannelNameBox struct {
	Rg  RoleAndGen
	Box SecretBox
}
type RTChannelNameBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (r RTChannelNameBoxInternal__) Import() RTChannelNameBox {
	return RTChannelNameBox{
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
func (r RTChannelNameBox) Export() *RTChannelNameBoxInternal__ {
	return &RTChannelNameBoxInternal__{
		Rg:  r.Rg.Export(),
		Box: r.Box.Export(),
	}
}
func (r *RTChannelNameBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelNameBox) Decode(dec rpc.Decoder) error {
	var tmp RTChannelNameBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelNameBox) Bytes() []byte { return nil }

type RTChannelDescBox struct {
	Rg  RoleAndGen
	Box SecretBox
}
type RTChannelDescBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (r RTChannelDescBoxInternal__) Import() RTChannelDescBox {
	return RTChannelDescBox{
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
func (r RTChannelDescBox) Export() *RTChannelDescBoxInternal__ {
	return &RTChannelDescBoxInternal__{
		Rg:  r.Rg.Export(),
		Box: r.Box.Export(),
	}
}
func (r *RTChannelDescBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelDescBox) Decode(dec rpc.Decoder) error {
	var tmp RTChannelDescBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelDescBox) Bytes() []byte { return nil }

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

type RTChannelMetadata struct {
	Id                  RTChannelID
	ParentTeam          TeamID
	AppID               RTAppID
	Seqno               RTChannelSeqno
	NameBox             RTChannelNameBox
	DescBox             *RTChannelDescBox
	Roles               RTRolePair
	LastMsgType         RTMsgType
	LastMsgSeq          RTMsgSeq
	LastSenderUid       *UID
	LastSenderPartyID   *PartyID
	LastSendTime        *Time
	Ctime               Time
	Mtime               Time
	UpdatedAtSetVersion RTChannelSetVersion
}
type RTChannelMetadataInternal__ struct {
	_struct             struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id                  *RTChannelIDInternal__
	ParentTeam          *TeamIDInternal__
	AppID               *RTAppIDInternal__
	Seqno               *RTChannelSeqnoInternal__
	NameBox             *RTChannelNameBoxInternal__
	DescBox             *RTChannelDescBoxInternal__
	Roles               *RTRolePairInternal__
	LastMsgType         *RTMsgTypeInternal__
	LastMsgSeq          *RTMsgSeqInternal__
	LastSenderUid       *UIDInternal__
	LastSenderPartyID   *PartyIDInternal__
	LastSendTime        *TimeInternal__
	Ctime               *TimeInternal__
	Mtime               *TimeInternal__
	UpdatedAtSetVersion *RTChannelSetVersionInternal__
}

func (r RTChannelMetadataInternal__) Import() RTChannelMetadata {
	return RTChannelMetadata{
		Id: (func(x *RTChannelIDInternal__) (ret RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Id),
		ParentTeam: (func(x *TeamIDInternal__) (ret TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ParentTeam),
		AppID: (func(x *RTAppIDInternal__) (ret RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Seqno: (func(x *RTChannelSeqnoInternal__) (ret RTChannelSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seqno),
		NameBox: (func(x *RTChannelNameBoxInternal__) (ret RTChannelNameBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.NameBox),
		DescBox: (func(x *RTChannelDescBoxInternal__) *RTChannelDescBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTChannelDescBoxInternal__) (ret RTChannelDescBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.DescBox),
		Roles: (func(x *RTRolePairInternal__) (ret RTRolePair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		LastMsgType: (func(x *RTMsgTypeInternal__) (ret RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.LastMsgType),
		LastMsgSeq: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.LastMsgSeq),
		LastSenderUid: (func(x *UIDInternal__) *UID {
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
		})(r.LastSenderUid),
		LastSenderPartyID: (func(x *PartyIDInternal__) *PartyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *PartyIDInternal__) (ret PartyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.LastSenderPartyID),
		LastSendTime: (func(x *TimeInternal__) *Time {
			if x == nil {
				return nil
			}
			tmp := (func(x *TimeInternal__) (ret Time) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.LastSendTime),
		Ctime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Ctime),
		Mtime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Mtime),
		UpdatedAtSetVersion: (func(x *RTChannelSetVersionInternal__) (ret RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.UpdatedAtSetVersion),
	}
}
func (r RTChannelMetadata) Export() *RTChannelMetadataInternal__ {
	return &RTChannelMetadataInternal__{
		Id:         r.Id.Export(),
		ParentTeam: r.ParentTeam.Export(),
		AppID:      r.AppID.Export(),
		Seqno:      r.Seqno.Export(),
		NameBox:    r.NameBox.Export(),
		DescBox: (func(x *RTChannelDescBox) *RTChannelDescBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.DescBox),
		Roles:       r.Roles.Export(),
		LastMsgType: r.LastMsgType.Export(),
		LastMsgSeq:  r.LastMsgSeq.Export(),
		LastSenderUid: (func(x *UID) *UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.LastSenderUid),
		LastSenderPartyID: (func(x *PartyID) *PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.LastSenderPartyID),
		LastSendTime: (func(x *Time) *TimeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.LastSendTime),
		Ctime:               r.Ctime.Export(),
		Mtime:               r.Mtime.Export(),
		UpdatedAtSetVersion: r.UpdatedAtSetVersion.Export(),
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
	Vers  RTChannelSetVersion
	Lst   []RTChannelMetadata
	Mtime Time
}
type RTChannelSetInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Vers    *RTChannelSetVersionInternal__
	Lst     *[](*RTChannelMetadataInternal__)
	Mtime   *TimeInternal__
}

func (r RTChannelSetInternal__) Import() RTChannelSet {
	return RTChannelSet{
		Vers: (func(x *RTChannelSetVersionInternal__) (ret RTChannelSetVersion) {
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
		Mtime: (func(x *TimeInternal__) (ret Time) {
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

type RTMsgBox struct {
	Rg  RoleAndGen
	Box SecretBox
}
type RTMsgBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (r RTMsgBoxInternal__) Import() RTMsgBox {
	return RTMsgBox{
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
func (r RTMsgBox) Export() *RTMsgBoxInternal__ {
	return &RTMsgBoxInternal__{
		Rg:  r.Rg.Export(),
		Box: r.Box.Export(),
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

type RTMsgBody struct {
	T     MsgBodyType
	F_0__ *[]byte   `json:"f0,omitempty"`
	F_1__ *RTMsgBox `json:"f1,omitempty"`
}
type RTMsgBodyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        MsgBodyType
	Switch__ RTMsgBodyInternalSwitch__
}
type RTMsgBodyInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *[]byte             `codec:"0"`
	F_1__   *RTMsgBoxInternal__ `codec:"1"`
}

func (r RTMsgBody) GetT() (ret MsgBodyType, err error) {
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
func (r RTMsgBody) Plaintext() []byte {
	if r.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != MsgBodyType_Plaintext {
		panic(fmt.Sprintf("unexpected switch value (%v) when Plaintext is called", r.T))
	}
	return *r.F_0__
}
func (r RTMsgBody) Encrypted() RTMsgBox {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != MsgBodyType_Encrypted {
		panic(fmt.Sprintf("unexpected switch value (%v) when Encrypted is called", r.T))
	}
	return *r.F_1__
}
func NewRTMsgBodyWithPlaintext(v []byte) RTMsgBody {
	return RTMsgBody{
		T:     MsgBodyType_Plaintext,
		F_0__: &v,
	}
}
func NewRTMsgBodyWithEncrypted(v RTMsgBox) RTMsgBody {
	return RTMsgBody{
		T:     MsgBodyType_Encrypted,
		F_1__: &v,
	}
}
func (r RTMsgBodyInternal__) Import() RTMsgBody {
	return RTMsgBody{
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
func (r RTMsgBody) Export() *RTMsgBodyInternal__ {
	return &RTMsgBodyInternal__{
		T: r.T,
		Switch__: RTMsgBodyInternalSwitch__{
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

func (r *RTMsgBody) Bytes() []byte { return nil }

type RTMessage struct {
	ChannelID     RTChannelID
	Seq           RTMsgSeq
	Typ           RTMsgType
	Body          RTMsgBody
	SenderUid     *UID
	SenderPartyID *PartyID
	SentAtTime    Time
	InsertTime    Time
}
type RTMessageInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID     *RTChannelIDInternal__
	Seq           *RTMsgSeqInternal__
	Typ           *RTMsgTypeInternal__
	Body          *RTMsgBodyInternal__
	SenderUid     *UIDInternal__
	SenderPartyID *PartyIDInternal__
	SentAtTime    *TimeInternal__
	InsertTime    *TimeInternal__
}

func (r RTMessageInternal__) Import() RTMessage {
	return RTMessage{
		ChannelID: (func(x *RTChannelIDInternal__) (ret RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
		Seq: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		Typ: (func(x *RTMsgTypeInternal__) (ret RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
		Body: (func(x *RTMsgBodyInternal__) (ret RTMsgBody) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Body),
		SenderUid: (func(x *UIDInternal__) *UID {
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
		})(r.SenderUid),
		SenderPartyID: (func(x *PartyIDInternal__) *PartyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *PartyIDInternal__) (ret PartyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.SenderPartyID),
		SentAtTime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SentAtTime),
		InsertTime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InsertTime),
	}
}
func (r RTMessage) Export() *RTMessageInternal__ {
	return &RTMessageInternal__{
		ChannelID: r.ChannelID.Export(),
		Seq:       r.Seq.Export(),
		Typ:       r.Typ.Export(),
		Body:      r.Body.Export(),
		SenderUid: (func(x *UID) *UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.SenderUid),
		SenderPartyID: (func(x *PartyID) *PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.SenderPartyID),
		SentAtTime: r.SentAtTime.Export(),
		InsertTime: r.InsertTime.Export(),
	}
}
func (r *RTMessage) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMessage) Decode(dec rpc.Decoder) error {
	var tmp RTMessageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTMessageTypeUniqueID = rpc.TypeUniqueID(0x7bcd22765c8cd757)

func (r *RTMessage) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTMessageTypeUniqueID
}
func (r *RTMessage) Bytes() []byte { return nil }

type RTInboxChannel struct {
	Md           RTChannelMetadata
	InboxVersion RTInboxVersion
	ReadThrough  RTMsgSeq
	Hidden       bool
	Muted        bool
}
type RTInboxChannelInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md           *RTChannelMetadataInternal__
	InboxVersion *RTInboxVersionInternal__
	ReadThrough  *RTMsgSeqInternal__
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
		InboxVersion: (func(x *RTInboxVersionInternal__) (ret RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InboxVersion),
		ReadThrough: (func(x *RTMsgSeqInternal__) (ret RTMsgSeq) {
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
	InboxVersion RTInboxVersion
	AppID        RTAppID
	Channels     []RTInboxChannel
}
type RTInboxDeltaInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	InboxVersion *RTInboxVersionInternal__
	AppID        *RTAppIDInternal__
	Channels     *[](*RTInboxChannelInternal__)
}

func (r RTInboxDeltaInternal__) Import() RTInboxDelta {
	return RTInboxDelta{
		InboxVersion: (func(x *RTInboxVersionInternal__) (ret RTInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InboxVersion),
		AppID: (func(x *RTAppIDInternal__) (ret RTAppID) {
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

type RTThreadPage struct {
	Msgs  []RTMessage
	Final bool
}
type RTThreadPageInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Msgs    *[](*RTMessageInternal__)
	Final   *bool
}

func (r RTThreadPageInternal__) Import() RTThreadPage {
	return RTThreadPage{
		Msgs: (func(x *[](*RTMessageInternal__)) (ret []RTMessage) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMessage, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMessageInternal__) (ret RTMessage) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Msgs),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Final),
	}
}
func (r RTThreadPage) Export() *RTThreadPageInternal__ {
	return &RTThreadPageInternal__{
		Msgs: (func(x []RTMessage) *[](*RTMessageInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMessageInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Msgs),
		Final: &r.Final,
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

type RTThreadQuery struct {
	ChannelID RTChannelID
	Start     RTMsgSeq
	Dir       RTThreadDir
	Max       uint64
}
type RTThreadQueryInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *RTChannelIDInternal__
	Start     *RTMsgSeqInternal__
	Dir       *RTThreadDirInternal__
	Max       *uint64
}

func (r RTThreadQueryInternal__) Import() RTThreadQuery {
	return RTThreadQuery{
		ChannelID: (func(x *RTChannelIDInternal__) (ret RTChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.ChannelID),
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
func (r RTThreadQuery) Export() *RTThreadQueryInternal__ {
	return &RTThreadQueryInternal__{
		ChannelID: r.ChannelID.Export(),
		Start:     r.Start.Export(),
		Dir:       r.Dir.Export(),
		Max:       &r.Max,
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

func init() {
	rpc.AddUnique(RTMsgPlaintextTypeUniqueID)
	rpc.AddUnique(RTChannelNamePlaintextTypeUniqueID)
	rpc.AddUnique(RTChannelDescPlaintextTypeUniqueID)
	rpc.AddUnique(RTChannelMetadataTypeUniqueID)
	rpc.AddUnique(RTMessageTypeUniqueID)
}
