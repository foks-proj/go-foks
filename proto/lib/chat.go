// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/chat.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type ChatChannelID [16]byte
type ChatChannelIDInternal__ [16]byte

func (c ChatChannelID) Export() *ChatChannelIDInternal__ {
	tmp := (([16]byte)(c))
	return ((*ChatChannelIDInternal__)(&tmp))
}
func (c ChatChannelIDInternal__) Import() ChatChannelID {
	tmp := ([16]byte)(c)
	return ChatChannelID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *ChatChannelID) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelID) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c ChatChannelID) Bytes() []byte {
	return (c)[:]
}

type ChatMsgSeq uint64
type ChatMsgSeqInternal__ uint64

func (c ChatMsgSeq) Export() *ChatMsgSeqInternal__ {
	tmp := ((uint64)(c))
	return ((*ChatMsgSeqInternal__)(&tmp))
}
func (c ChatMsgSeqInternal__) Import() ChatMsgSeq {
	tmp := (uint64)(c)
	return ChatMsgSeq((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *ChatMsgSeq) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatMsgSeq) Decode(dec rpc.Decoder) error {
	var tmp ChatMsgSeqInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c ChatMsgSeq) Bytes() []byte {
	return nil
}

type ChatInboxVersion uint64
type ChatInboxVersionInternal__ uint64

func (c ChatInboxVersion) Export() *ChatInboxVersionInternal__ {
	tmp := ((uint64)(c))
	return ((*ChatInboxVersionInternal__)(&tmp))
}
func (c ChatInboxVersionInternal__) Import() ChatInboxVersion {
	tmp := (uint64)(c)
	return ChatInboxVersion((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *ChatInboxVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatInboxVersion) Decode(dec rpc.Decoder) error {
	var tmp ChatInboxVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c ChatInboxVersion) Bytes() []byte {
	return nil
}

type ChatChannelSeqno uint64
type ChatChannelSeqnoInternal__ uint64

func (c ChatChannelSeqno) Export() *ChatChannelSeqnoInternal__ {
	tmp := ((uint64)(c))
	return ((*ChatChannelSeqnoInternal__)(&tmp))
}
func (c ChatChannelSeqnoInternal__) Import() ChatChannelSeqno {
	tmp := (uint64)(c)
	return ChatChannelSeqno((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *ChatChannelSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelSeqno) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c ChatChannelSeqno) Bytes() []byte {
	return nil
}

type ChatAppID int

const (
	ChatAppID_None  ChatAppID = 0
	ChatAppID_Chat  ChatAppID = 1
	ChatAppID_Crdt  ChatAppID = 2
	ChatAppID_Notif ChatAppID = 3
)

var ChatAppIDMap = map[string]ChatAppID{
	"None":  0,
	"Chat":  1,
	"Crdt":  2,
	"Notif": 3,
}
var ChatAppIDRevMap = map[ChatAppID]string{
	0: "None",
	1: "Chat",
	2: "Crdt",
	3: "Notif",
}

type ChatAppIDInternal__ ChatAppID

func (c ChatAppIDInternal__) Import() ChatAppID {
	return ChatAppID(c)
}
func (c ChatAppID) Export() *ChatAppIDInternal__ {
	return ((*ChatAppIDInternal__)(&c))
}

type ChatMsgType int

const (
	ChatMsgType_None       ChatMsgType = 0
	ChatMsgType_Basic      ChatMsgType = 1
	ChatMsgType_Edit       ChatMsgType = 2
	ChatMsgType_Delete     ChatMsgType = 3
	ChatMsgType_Reactji    ChatMsgType = 4
	ChatMsgType_Attachment ChatMsgType = 5
	ChatMsgType_Reply      ChatMsgType = 6
	ChatMsgType_System     ChatMsgType = 7
	ChatMsgType_Join       ChatMsgType = 8
	ChatMsgType_Leave      ChatMsgType = 9
)

var ChatMsgTypeMap = map[string]ChatMsgType{
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
var ChatMsgTypeRevMap = map[ChatMsgType]string{
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

type ChatMsgTypeInternal__ ChatMsgType

func (c ChatMsgTypeInternal__) Import() ChatMsgType {
	return ChatMsgType(c)
}
func (c ChatMsgType) Export() *ChatMsgTypeInternal__ {
	return ((*ChatMsgTypeInternal__)(&c))
}

type ChatRolePair struct {
	Read  Role
	Write Role
}
type ChatRolePairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Read    *RoleInternal__
	Write   *RoleInternal__
}

func (c ChatRolePairInternal__) Import() ChatRolePair {
	return ChatRolePair{
		Read: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Read),
		Write: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Write),
	}
}
func (c ChatRolePair) Export() *ChatRolePairInternal__ {
	return &ChatRolePairInternal__{
		Read:  c.Read.Export(),
		Write: c.Write.Export(),
	}
}
func (c *ChatRolePair) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatRolePair) Decode(dec rpc.Decoder) error {
	var tmp ChatRolePairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatRolePair) Bytes() []byte { return nil }

type ChatChannelNamePlaintext struct {
	T     bool
	F_0__ *NameUtf8 `json:"f0,omitempty"`
}
type ChatChannelNamePlaintextInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        bool
	Switch__ ChatChannelNamePlaintextInternalSwitch__
}
type ChatChannelNamePlaintextInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *NameUtf8Internal__ `codec:"0"`
}

func (c ChatChannelNamePlaintext) GetT() (ret bool, err error) {
	switch c.T {
	case false:
		break
	case true:
		if c.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return c.T, nil
}
func (c ChatChannelNamePlaintext) True() NameUtf8 {
	if c.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if !c.T {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", c.T))
	}
	return *c.F_0__
}
func NewChatChannelNamePlaintextWithFalse() ChatChannelNamePlaintext {
	return ChatChannelNamePlaintext{
		T: false,
	}
}
func NewChatChannelNamePlaintextWithTrue(v NameUtf8) ChatChannelNamePlaintext {
	return ChatChannelNamePlaintext{
		T:     true,
		F_0__: &v,
	}
}
func (c ChatChannelNamePlaintextInternal__) Import() ChatChannelNamePlaintext {
	return ChatChannelNamePlaintext{
		T: c.T,
		F_0__: (func(x *NameUtf8Internal__) *NameUtf8 {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameUtf8Internal__) (ret NameUtf8) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_0__),
	}
}
func (c ChatChannelNamePlaintext) Export() *ChatChannelNamePlaintextInternal__ {
	return &ChatChannelNamePlaintextInternal__{
		T: c.T,
		Switch__: ChatChannelNamePlaintextInternalSwitch__{
			F_0__: (func(x *NameUtf8) *NameUtf8Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_0__),
		},
	}
}
func (c *ChatChannelNamePlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelNamePlaintext) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelNamePlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChatChannelNamePlaintextTypeUniqueID = rpc.TypeUniqueID(0x980ac7b3438c1271)

func (c *ChatChannelNamePlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChatChannelNamePlaintextTypeUniqueID
}
func (c *ChatChannelNamePlaintext) Bytes() []byte { return nil }

type ChatChannelNameBox struct {
	Rg  RoleAndGen
	Box SecretBox
}
type ChatChannelNameBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (c ChatChannelNameBoxInternal__) Import() ChatChannelNameBox {
	return ChatChannelNameBox{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Rg),
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Box),
	}
}
func (c ChatChannelNameBox) Export() *ChatChannelNameBoxInternal__ {
	return &ChatChannelNameBoxInternal__{
		Rg:  c.Rg.Export(),
		Box: c.Box.Export(),
	}
}
func (c *ChatChannelNameBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelNameBox) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelNameBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatChannelNameBox) Bytes() []byte { return nil }

type ChatChannelMetadata struct {
	Id                ChatChannelID
	ParentTeam        TeamID
	AppID             ChatAppID
	Seqno             ChatChannelSeqno
	NameBox           ChatChannelNameBox
	Roles             ChatRolePair
	LastMsgType       ChatMsgType
	LastMsgSeq        ChatMsgSeq
	LastSenderUid     *UID
	LastSenderPartyID *PartyID
	LastSendTime      *Time
	Ctime             Time
	Mtime             Time
}
type ChatChannelMetadataInternal__ struct {
	_struct           struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id                *ChatChannelIDInternal__
	ParentTeam        *TeamIDInternal__
	AppID             *ChatAppIDInternal__
	Seqno             *ChatChannelSeqnoInternal__
	NameBox           *ChatChannelNameBoxInternal__
	Roles             *ChatRolePairInternal__
	LastMsgType       *ChatMsgTypeInternal__
	LastMsgSeq        *ChatMsgSeqInternal__
	LastSenderUid     *UIDInternal__
	LastSenderPartyID *PartyIDInternal__
	LastSendTime      *TimeInternal__
	Ctime             *TimeInternal__
	Mtime             *TimeInternal__
}

func (c ChatChannelMetadataInternal__) Import() ChatChannelMetadata {
	return ChatChannelMetadata{
		Id: (func(x *ChatChannelIDInternal__) (ret ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		ParentTeam: (func(x *TeamIDInternal__) (ret TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ParentTeam),
		AppID: (func(x *ChatAppIDInternal__) (ret ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
		Seqno: (func(x *ChatChannelSeqnoInternal__) (ret ChatChannelSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Seqno),
		NameBox: (func(x *ChatChannelNameBoxInternal__) (ret ChatChannelNameBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.NameBox),
		Roles: (func(x *ChatRolePairInternal__) (ret ChatRolePair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Roles),
		LastMsgType: (func(x *ChatMsgTypeInternal__) (ret ChatMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.LastMsgType),
		LastMsgSeq: (func(x *ChatMsgSeqInternal__) (ret ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.LastMsgSeq),
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
		})(c.LastSenderUid),
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
		})(c.LastSenderPartyID),
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
		})(c.LastSendTime),
		Ctime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Ctime),
		Mtime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Mtime),
	}
}
func (c ChatChannelMetadata) Export() *ChatChannelMetadataInternal__ {
	return &ChatChannelMetadataInternal__{
		Id:          c.Id.Export(),
		ParentTeam:  c.ParentTeam.Export(),
		AppID:       c.AppID.Export(),
		Seqno:       c.Seqno.Export(),
		NameBox:     c.NameBox.Export(),
		Roles:       c.Roles.Export(),
		LastMsgType: c.LastMsgType.Export(),
		LastMsgSeq:  c.LastMsgSeq.Export(),
		LastSenderUid: (func(x *UID) *UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.LastSenderUid),
		LastSenderPartyID: (func(x *PartyID) *PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.LastSenderPartyID),
		LastSendTime: (func(x *Time) *TimeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.LastSendTime),
		Ctime: c.Ctime.Export(),
		Mtime: c.Mtime.Export(),
	}
}
func (c *ChatChannelMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelMetadata) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChatChannelMetadataTypeUniqueID = rpc.TypeUniqueID(0xddf6b26b2ace1535)

func (c *ChatChannelMetadata) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChatChannelMetadataTypeUniqueID
}
func (c *ChatChannelMetadata) Bytes() []byte { return nil }

type ChatMsgBox struct {
	Rg  RoleAndGen
	Box SecretBox
}
type ChatMsgBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (c ChatMsgBoxInternal__) Import() ChatMsgBox {
	return ChatMsgBox{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Rg),
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Box),
	}
}
func (c ChatMsgBox) Export() *ChatMsgBoxInternal__ {
	return &ChatMsgBoxInternal__{
		Rg:  c.Rg.Export(),
		Box: c.Box.Export(),
	}
}
func (c *ChatMsgBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatMsgBox) Decode(dec rpc.Decoder) error {
	var tmp ChatMsgBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatMsgBox) Bytes() []byte { return nil }

type ChatMsgBody struct {
	Encrypted bool
	F_0__     *ChatMsgBox `json:"f0,omitempty"`
	F_1__     *[]byte     `json:"f1,omitempty"`
}
type ChatMsgBodyInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Encrypted bool
	Switch__  ChatMsgBodyInternalSwitch__
}
type ChatMsgBodyInternalSwitch__ struct {
	_struct struct{}              `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *ChatMsgBoxInternal__ `codec:"0"`
	F_1__   *[]byte               `codec:"1"`
}

func (c ChatMsgBody) GetEncrypted() (ret bool, err error) {
	switch c.Encrypted {
	case true:
		if c.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case false:
		if c.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return c.Encrypted, nil
}
func (c ChatMsgBody) True() ChatMsgBox {
	if c.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if !c.Encrypted {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", c.Encrypted))
	}
	return *c.F_0__
}
func (c ChatMsgBody) False() []byte {
	if c.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.Encrypted {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", c.Encrypted))
	}
	return *c.F_1__
}
func NewChatMsgBodyWithTrue(v ChatMsgBox) ChatMsgBody {
	return ChatMsgBody{
		Encrypted: true,
		F_0__:     &v,
	}
}
func NewChatMsgBodyWithFalse(v []byte) ChatMsgBody {
	return ChatMsgBody{
		Encrypted: false,
		F_1__:     &v,
	}
}
func (c ChatMsgBodyInternal__) Import() ChatMsgBody {
	return ChatMsgBody{
		Encrypted: c.Encrypted,
		F_0__: (func(x *ChatMsgBoxInternal__) *ChatMsgBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *ChatMsgBoxInternal__) (ret ChatMsgBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_0__),
		F_1__: c.Switch__.F_1__,
	}
}
func (c ChatMsgBody) Export() *ChatMsgBodyInternal__ {
	return &ChatMsgBodyInternal__{
		Encrypted: c.Encrypted,
		Switch__: ChatMsgBodyInternalSwitch__{
			F_0__: (func(x *ChatMsgBox) *ChatMsgBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_0__),
			F_1__: c.F_1__,
		},
	}
}
func (c *ChatMsgBody) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatMsgBody) Decode(dec rpc.Decoder) error {
	var tmp ChatMsgBodyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatMsgBody) Bytes() []byte { return nil }

type ChatMessage struct {
	ChannelID     ChatChannelID
	Seq           ChatMsgSeq
	Typ           ChatMsgType
	Body          ChatMsgBody
	SenderUid     *UID
	SenderPartyID *PartyID
	SentAtTime    Time
	InsertTime    Time
}
type ChatMessageInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID     *ChatChannelIDInternal__
	Seq           *ChatMsgSeqInternal__
	Typ           *ChatMsgTypeInternal__
	Body          *ChatMsgBodyInternal__
	SenderUid     *UIDInternal__
	SenderPartyID *PartyIDInternal__
	SentAtTime    *TimeInternal__
	InsertTime    *TimeInternal__
}

func (c ChatMessageInternal__) Import() ChatMessage {
	return ChatMessage{
		ChannelID: (func(x *ChatChannelIDInternal__) (ret ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ChannelID),
		Seq: (func(x *ChatMsgSeqInternal__) (ret ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Seq),
		Typ: (func(x *ChatMsgTypeInternal__) (ret ChatMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Typ),
		Body: (func(x *ChatMsgBodyInternal__) (ret ChatMsgBody) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Body),
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
		})(c.SenderUid),
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
		})(c.SenderPartyID),
		SentAtTime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SentAtTime),
		InsertTime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InsertTime),
	}
}
func (c ChatMessage) Export() *ChatMessageInternal__ {
	return &ChatMessageInternal__{
		ChannelID: c.ChannelID.Export(),
		Seq:       c.Seq.Export(),
		Typ:       c.Typ.Export(),
		Body:      c.Body.Export(),
		SenderUid: (func(x *UID) *UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.SenderUid),
		SenderPartyID: (func(x *PartyID) *PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.SenderPartyID),
		SentAtTime: c.SentAtTime.Export(),
		InsertTime: c.InsertTime.Export(),
	}
}
func (c *ChatMessage) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatMessage) Decode(dec rpc.Decoder) error {
	var tmp ChatMessageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChatMessageTypeUniqueID = rpc.TypeUniqueID(0x7bcd22765c8cd757)

func (c *ChatMessage) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChatMessageTypeUniqueID
}
func (c *ChatMessage) Bytes() []byte { return nil }

type ChatInboxChannel struct {
	Md           ChatChannelMetadata
	InboxVersion ChatInboxVersion
	ReadThrough  ChatMsgSeq
	Hidden       bool
	Muted        bool
}
type ChatInboxChannelInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md           *ChatChannelMetadataInternal__
	InboxVersion *ChatInboxVersionInternal__
	ReadThrough  *ChatMsgSeqInternal__
	Hidden       *bool
	Muted        *bool
}

func (c ChatInboxChannelInternal__) Import() ChatInboxChannel {
	return ChatInboxChannel{
		Md: (func(x *ChatChannelMetadataInternal__) (ret ChatChannelMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Md),
		InboxVersion: (func(x *ChatInboxVersionInternal__) (ret ChatInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InboxVersion),
		ReadThrough: (func(x *ChatMsgSeqInternal__) (ret ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ReadThrough),
		Hidden: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Hidden),
		Muted: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Muted),
	}
}
func (c ChatInboxChannel) Export() *ChatInboxChannelInternal__ {
	return &ChatInboxChannelInternal__{
		Md:           c.Md.Export(),
		InboxVersion: c.InboxVersion.Export(),
		ReadThrough:  c.ReadThrough.Export(),
		Hidden:       &c.Hidden,
		Muted:        &c.Muted,
	}
}
func (c *ChatInboxChannel) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatInboxChannel) Decode(dec rpc.Decoder) error {
	var tmp ChatInboxChannelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatInboxChannel) Bytes() []byte { return nil }

type ChatInboxDelta struct {
	InboxVersion ChatInboxVersion
	AppID        ChatAppID
	Channels     []ChatInboxChannel
}
type ChatInboxDeltaInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	InboxVersion *ChatInboxVersionInternal__
	AppID        *ChatAppIDInternal__
	Channels     *[](*ChatInboxChannelInternal__)
}

func (c ChatInboxDeltaInternal__) Import() ChatInboxDelta {
	return ChatInboxDelta{
		InboxVersion: (func(x *ChatInboxVersionInternal__) (ret ChatInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InboxVersion),
		AppID: (func(x *ChatAppIDInternal__) (ret ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
		Channels: (func(x *[](*ChatInboxChannelInternal__)) (ret []ChatInboxChannel) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]ChatInboxChannel, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *ChatInboxChannelInternal__) (ret ChatInboxChannel) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(c.Channels),
	}
}
func (c ChatInboxDelta) Export() *ChatInboxDeltaInternal__ {
	return &ChatInboxDeltaInternal__{
		InboxVersion: c.InboxVersion.Export(),
		AppID:        c.AppID.Export(),
		Channels: (func(x []ChatInboxChannel) *[](*ChatInboxChannelInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*ChatInboxChannelInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(c.Channels),
	}
}
func (c *ChatInboxDelta) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatInboxDelta) Decode(dec rpc.Decoder) error {
	var tmp ChatInboxDeltaInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatInboxDelta) Bytes() []byte { return nil }

type ChatThreadPage struct {
	Msgs  []ChatMessage
	Final bool
}
type ChatThreadPageInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Msgs    *[](*ChatMessageInternal__)
	Final   *bool
}

func (c ChatThreadPageInternal__) Import() ChatThreadPage {
	return ChatThreadPage{
		Msgs: (func(x *[](*ChatMessageInternal__)) (ret []ChatMessage) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]ChatMessage, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *ChatMessageInternal__) (ret ChatMessage) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(c.Msgs),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Final),
	}
}
func (c ChatThreadPage) Export() *ChatThreadPageInternal__ {
	return &ChatThreadPageInternal__{
		Msgs: (func(x []ChatMessage) *[](*ChatMessageInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*ChatMessageInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(c.Msgs),
		Final: &c.Final,
	}
}
func (c *ChatThreadPage) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatThreadPage) Decode(dec rpc.Decoder) error {
	var tmp ChatThreadPageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatThreadPage) Bytes() []byte { return nil }

type ChatThreadDir int

const (
	ChatThreadDir_Forward  ChatThreadDir = 0
	ChatThreadDir_Backward ChatThreadDir = 1
)

var ChatThreadDirMap = map[string]ChatThreadDir{
	"Forward":  0,
	"Backward": 1,
}
var ChatThreadDirRevMap = map[ChatThreadDir]string{
	0: "Forward",
	1: "Backward",
}

type ChatThreadDirInternal__ ChatThreadDir

func (c ChatThreadDirInternal__) Import() ChatThreadDir {
	return ChatThreadDir(c)
}
func (c ChatThreadDir) Export() *ChatThreadDirInternal__ {
	return ((*ChatThreadDirInternal__)(&c))
}

type ChatThreadQuery struct {
	ChannelID ChatChannelID
	Start     ChatMsgSeq
	Dir       ChatThreadDir
	Max       uint64
}
type ChatThreadQueryInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *ChatChannelIDInternal__
	Start     *ChatMsgSeqInternal__
	Dir       *ChatThreadDirInternal__
	Max       *uint64
}

func (c ChatThreadQueryInternal__) Import() ChatThreadQuery {
	return ChatThreadQuery{
		ChannelID: (func(x *ChatChannelIDInternal__) (ret ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ChannelID),
		Start: (func(x *ChatMsgSeqInternal__) (ret ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Start),
		Dir: (func(x *ChatThreadDirInternal__) (ret ChatThreadDir) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Dir),
		Max: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Max),
	}
}
func (c ChatThreadQuery) Export() *ChatThreadQueryInternal__ {
	return &ChatThreadQueryInternal__{
		ChannelID: c.ChannelID.Export(),
		Start:     c.Start.Export(),
		Dir:       c.Dir.Export(),
		Max:       &c.Max,
	}
}
func (c *ChatThreadQuery) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatThreadQuery) Decode(dec rpc.Decoder) error {
	var tmp ChatThreadQueryInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatThreadQuery) Bytes() []byte { return nil }

type ChatChannelCreate struct {
	Md ChatChannelMetadata
}
type ChatChannelCreateInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Md      *ChatChannelMetadataInternal__
}

func (c ChatChannelCreateInternal__) Import() ChatChannelCreate {
	return ChatChannelCreate{
		Md: (func(x *ChatChannelMetadataInternal__) (ret ChatChannelMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Md),
	}
}
func (c ChatChannelCreate) Export() *ChatChannelCreateInternal__ {
	return &ChatChannelCreateInternal__{
		Md: c.Md.Export(),
	}
}
func (c *ChatChannelCreate) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatChannelCreate) Decode(dec rpc.Decoder) error {
	var tmp ChatChannelCreateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChatChannelCreateTypeUniqueID = rpc.TypeUniqueID(0x1bae4ba70272da77)

func (c *ChatChannelCreate) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChatChannelCreateTypeUniqueID
}
func (c *ChatChannelCreate) Bytes() []byte { return nil }

type ChatInboxPollRes struct {
	Bumped       bool
	InboxVersion ChatInboxVersion
}
type ChatInboxPollResInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Bumped       *bool
	InboxVersion *ChatInboxVersionInternal__
}

func (c ChatInboxPollResInternal__) Import() ChatInboxPollRes {
	return ChatInboxPollRes{
		Bumped: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Bumped),
		InboxVersion: (func(x *ChatInboxVersionInternal__) (ret ChatInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InboxVersion),
	}
}
func (c ChatInboxPollRes) Export() *ChatInboxPollResInternal__ {
	return &ChatInboxPollResInternal__{
		Bumped:       &c.Bumped,
		InboxVersion: c.InboxVersion.Export(),
	}
}
func (c *ChatInboxPollRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatInboxPollRes) Decode(dec rpc.Decoder) error {
	var tmp ChatInboxPollResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatInboxPollRes) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(ChatChannelNamePlaintextTypeUniqueID)
	rpc.AddUnique(ChatChannelMetadataTypeUniqueID)
	rpc.AddUnique(ChatMessageTypeUniqueID)
	rpc.AddUnique(ChatChannelCreateTypeUniqueID)
}
