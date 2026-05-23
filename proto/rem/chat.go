// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/rem/chat.snowp

package rem

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type ChatAuthType int

const (
	ChatAuthType_User ChatAuthType = 0
	ChatAuthType_Team ChatAuthType = 1
)

var ChatAuthTypeMap = map[string]ChatAuthType{
	"User": 0,
	"Team": 1,
}
var ChatAuthTypeRevMap = map[ChatAuthType]string{
	0: "User",
	1: "Team",
}

type ChatAuthTypeInternal__ ChatAuthType

func (c ChatAuthTypeInternal__) Import() ChatAuthType {
	return ChatAuthType(c)
}
func (c ChatAuthType) Export() *ChatAuthTypeInternal__ {
	return ((*ChatAuthTypeInternal__)(&c))
}

type ChatAuth struct {
	T     ChatAuthType
	F_1__ *TeamVOBearerToken `json:"f1,omitempty"`
}
type ChatAuthInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        ChatAuthType
	Switch__ ChatAuthInternalSwitch__
}
type ChatAuthInternalSwitch__ struct {
	_struct struct{}                     `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *TeamVOBearerTokenInternal__ `codec:"1"`
}

func (c ChatAuth) GetT() (ret ChatAuthType, err error) {
	switch c.T {
	case ChatAuthType_Team:
		if c.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return c.T, nil
}
func (c ChatAuth) Team() TeamVOBearerToken {
	if c.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.T != ChatAuthType_Team {
		panic(fmt.Sprintf("unexpected switch value (%v) when Team is called", c.T))
	}
	return *c.F_1__
}
func NewChatAuthWithTeam(v TeamVOBearerToken) ChatAuth {
	return ChatAuth{
		T:     ChatAuthType_Team,
		F_1__: &v,
	}
}
func (c ChatAuthInternal__) Import() ChatAuth {
	return ChatAuth{
		T: c.T,
		F_1__: (func(x *TeamVOBearerTokenInternal__) *TeamVOBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_1__),
	}
}
func (c ChatAuth) Export() *ChatAuthInternal__ {
	return &ChatAuthInternal__{
		T: c.T,
		Switch__: ChatAuthInternalSwitch__{
			F_1__: (func(x *TeamVOBearerToken) *TeamVOBearerTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_1__),
		},
	}
}
func (c *ChatAuth) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatAuth) Decode(dec rpc.Decoder) error {
	var tmp ChatAuthInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatAuth) Bytes() []byte { return nil }

type ChatInboxKey struct {
	AppID lib.ChatAppID
}
type ChatInboxKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.ChatAppIDInternal__
}

func (c ChatInboxKeyInternal__) Import() ChatInboxKey {
	return ChatInboxKey{
		AppID: (func(x *lib.ChatAppIDInternal__) (ret lib.ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
	}
}
func (c ChatInboxKey) Export() *ChatInboxKeyInternal__ {
	return &ChatInboxKeyInternal__{
		AppID: c.AppID.Export(),
	}
}
func (c *ChatInboxKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatInboxKey) Decode(dec rpc.Decoder) error {
	var tmp ChatInboxKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatInboxKey) Bytes() []byte { return nil }

type ChatNewChannelArg struct {
	Create lib.ChatChannelCreate
}
type ChatNewChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Create  *lib.ChatChannelCreateInternal__
}

func (c ChatNewChannelArgInternal__) Import() ChatNewChannelArg {
	return ChatNewChannelArg{
		Create: (func(x *lib.ChatChannelCreateInternal__) (ret lib.ChatChannelCreate) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Create),
	}
}
func (c ChatNewChannelArg) Export() *ChatNewChannelArgInternal__ {
	return &ChatNewChannelArgInternal__{
		Create: c.Create.Export(),
	}
}
func (c *ChatNewChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatNewChannelArg) Decode(dec rpc.Decoder) error {
	var tmp ChatNewChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatNewChannelArg) Bytes() []byte { return nil }

type ChatSendArg struct {
	ChannelID       lib.ChatChannelID
	Typ             lib.ChatMsgType
	Body            lib.ChatMsgBody
	SentAtTime      lib.Time
	ExpectedPrevSeq *lib.ChatMsgSeq
}
type ChatSendArgInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID       *lib.ChatChannelIDInternal__
	Typ             *lib.ChatMsgTypeInternal__
	Body            *lib.ChatMsgBodyInternal__
	SentAtTime      *lib.TimeInternal__
	ExpectedPrevSeq *lib.ChatMsgSeqInternal__
}

func (c ChatSendArgInternal__) Import() ChatSendArg {
	return ChatSendArg{
		ChannelID: (func(x *lib.ChatChannelIDInternal__) (ret lib.ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ChannelID),
		Typ: (func(x *lib.ChatMsgTypeInternal__) (ret lib.ChatMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Typ),
		Body: (func(x *lib.ChatMsgBodyInternal__) (ret lib.ChatMsgBody) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Body),
		SentAtTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SentAtTime),
		ExpectedPrevSeq: (func(x *lib.ChatMsgSeqInternal__) *lib.ChatMsgSeq {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.ChatMsgSeqInternal__) (ret lib.ChatMsgSeq) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.ExpectedPrevSeq),
	}
}
func (c ChatSendArg) Export() *ChatSendArgInternal__ {
	return &ChatSendArgInternal__{
		ChannelID:  c.ChannelID.Export(),
		Typ:        c.Typ.Export(),
		Body:       c.Body.Export(),
		SentAtTime: c.SentAtTime.Export(),
		ExpectedPrevSeq: (func(x *lib.ChatMsgSeq) *lib.ChatMsgSeqInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.ExpectedPrevSeq),
	}
}
func (c *ChatSendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatSendArg) Decode(dec rpc.Decoder) error {
	var tmp ChatSendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatSendArg) Bytes() []byte { return nil }

type ChatSendRes struct {
	Seq        lib.ChatMsgSeq
	InsertTime lib.Time
}
type ChatSendResInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq        *lib.ChatMsgSeqInternal__
	InsertTime *lib.TimeInternal__
}

func (c ChatSendResInternal__) Import() ChatSendRes {
	return ChatSendRes{
		Seq: (func(x *lib.ChatMsgSeqInternal__) (ret lib.ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Seq),
		InsertTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.InsertTime),
	}
}
func (c ChatSendRes) Export() *ChatSendResInternal__ {
	return &ChatSendResInternal__{
		Seq:        c.Seq.Export(),
		InsertTime: c.InsertTime.Export(),
	}
}
func (c *ChatSendRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatSendRes) Decode(dec rpc.Decoder) error {
	var tmp ChatSendResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatSendRes) Bytes() []byte { return nil }

type ChatGetChangedThreadsArg struct {
	AppID lib.ChatAppID
	Since lib.ChatInboxVersion
	Max   uint64
}
type ChatGetChangedThreadsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.ChatAppIDInternal__
	Since   *lib.ChatInboxVersionInternal__
	Max     *uint64
}

func (c ChatGetChangedThreadsArgInternal__) Import() ChatGetChangedThreadsArg {
	return ChatGetChangedThreadsArg{
		AppID: (func(x *lib.ChatAppIDInternal__) (ret lib.ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
		Since: (func(x *lib.ChatInboxVersionInternal__) (ret lib.ChatInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Since),
		Max: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Max),
	}
}
func (c ChatGetChangedThreadsArg) Export() *ChatGetChangedThreadsArgInternal__ {
	return &ChatGetChangedThreadsArgInternal__{
		AppID: c.AppID.Export(),
		Since: c.Since.Export(),
		Max:   &c.Max,
	}
}
func (c *ChatGetChangedThreadsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatGetChangedThreadsArg) Decode(dec rpc.Decoder) error {
	var tmp ChatGetChangedThreadsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatGetChangedThreadsArg) Bytes() []byte { return nil }

type ChatReadThroughArg struct {
	ChannelID lib.ChatChannelID
	Seq       lib.ChatMsgSeq
}
type ChatReadThroughArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *lib.ChatChannelIDInternal__
	Seq       *lib.ChatMsgSeqInternal__
}

func (c ChatReadThroughArgInternal__) Import() ChatReadThroughArg {
	return ChatReadThroughArg{
		ChannelID: (func(x *lib.ChatChannelIDInternal__) (ret lib.ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ChannelID),
		Seq: (func(x *lib.ChatMsgSeqInternal__) (ret lib.ChatMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Seq),
	}
}
func (c ChatReadThroughArg) Export() *ChatReadThroughArgInternal__ {
	return &ChatReadThroughArgInternal__{
		ChannelID: c.ChannelID.Export(),
		Seq:       c.Seq.Export(),
	}
}
func (c *ChatReadThroughArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatReadThroughArg) Decode(dec rpc.Decoder) error {
	var tmp ChatReadThroughArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatReadThroughArg) Bytes() []byte { return nil }

type ChatPollInboxArg struct {
	AppID   lib.ChatAppID
	Since   lib.ChatInboxVersion
	Timeout lib.DurationMilli
}
type ChatPollInboxArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	AppID   *lib.ChatAppIDInternal__
	Since   *lib.ChatInboxVersionInternal__
	Timeout *lib.DurationMilliInternal__
}

func (c ChatPollInboxArgInternal__) Import() ChatPollInboxArg {
	return ChatPollInboxArg{
		AppID: (func(x *lib.ChatAppIDInternal__) (ret lib.ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
		Since: (func(x *lib.ChatInboxVersionInternal__) (ret lib.ChatInboxVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Since),
		Timeout: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Timeout),
	}
}
func (c ChatPollInboxArg) Export() *ChatPollInboxArgInternal__ {
	return &ChatPollInboxArgInternal__{
		AppID:   c.AppID.Export(),
		Since:   c.Since.Export(),
		Timeout: c.Timeout.Export(),
	}
}
func (c *ChatPollInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatPollInboxArg) Decode(dec rpc.Decoder) error {
	var tmp ChatPollInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatPollInboxArg) Bytes() []byte { return nil }

var ChatProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x4f58e7d4)

type ChatNewChannelArg struct {
	Auth ChatAuth
	Arg  ChatNewChannelArg
}
type ChatNewChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *ChatAuthInternal__
	Arg     *ChatNewChannelArgInternal__
}

func (c ChatNewChannelArgInternal__) Import() ChatNewChannelArg {
	return ChatNewChannelArg{
		Auth: (func(x *ChatAuthInternal__) (ret ChatAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Auth),
		Arg: (func(x *ChatNewChannelArgInternal__) (ret ChatNewChannelArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Arg),
	}
}
func (c ChatNewChannelArg) Export() *ChatNewChannelArgInternal__ {
	return &ChatNewChannelArgInternal__{
		Auth: c.Auth.Export(),
		Arg:  c.Arg.Export(),
	}
}
func (c *ChatNewChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatNewChannelArg) Decode(dec rpc.Decoder) error {
	var tmp ChatNewChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatNewChannelArg) Bytes() []byte { return nil }

type ChatGetChannelArg struct {
	ChannelID lib.ChatChannelID
}
type ChatGetChannelArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ChannelID *lib.ChatChannelIDInternal__
}

func (c ChatGetChannelArgInternal__) Import() ChatGetChannelArg {
	return ChatGetChannelArg{
		ChannelID: (func(x *lib.ChatChannelIDInternal__) (ret lib.ChatChannelID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.ChannelID),
	}
}
func (c ChatGetChannelArg) Export() *ChatGetChannelArgInternal__ {
	return &ChatGetChannelArgInternal__{
		ChannelID: c.ChannelID.Export(),
	}
}
func (c *ChatGetChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatGetChannelArg) Decode(dec rpc.Decoder) error {
	var tmp ChatGetChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatGetChannelArg) Bytes() []byte { return nil }

type ChatListTeamChannelsArg struct {
	Team  lib.TeamID
	AppID lib.ChatAppID
}
type ChatListTeamChannelsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.TeamIDInternal__
	AppID   *lib.ChatAppIDInternal__
}

func (c ChatListTeamChannelsArgInternal__) Import() ChatListTeamChannelsArg {
	return ChatListTeamChannelsArg{
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Team),
		AppID: (func(x *lib.ChatAppIDInternal__) (ret lib.ChatAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.AppID),
	}
}
func (c ChatListTeamChannelsArg) Export() *ChatListTeamChannelsArgInternal__ {
	return &ChatListTeamChannelsArgInternal__{
		Team:  c.Team.Export(),
		AppID: c.AppID.Export(),
	}
}
func (c *ChatListTeamChannelsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatListTeamChannelsArg) Decode(dec rpc.Decoder) error {
	var tmp ChatListTeamChannelsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatListTeamChannelsArg) Bytes() []byte { return nil }

type ChatSendArg struct {
	Auth ChatAuth
	Arg  ChatSendArg
}
type ChatSendArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *ChatAuthInternal__
	Arg     *ChatSendArgInternal__
}

func (c ChatSendArgInternal__) Import() ChatSendArg {
	return ChatSendArg{
		Auth: (func(x *ChatAuthInternal__) (ret ChatAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Auth),
		Arg: (func(x *ChatSendArgInternal__) (ret ChatSendArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Arg),
	}
}
func (c ChatSendArg) Export() *ChatSendArgInternal__ {
	return &ChatSendArgInternal__{
		Auth: c.Auth.Export(),
		Arg:  c.Arg.Export(),
	}
}
func (c *ChatSendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatSendArg) Decode(dec rpc.Decoder) error {
	var tmp ChatSendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatSendArg) Bytes() []byte { return nil }

type ChatGetThreadArg struct {
	Q lib.ChatThreadQuery
}
type ChatGetThreadArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Q       *lib.ChatThreadQueryInternal__
}

func (c ChatGetThreadArgInternal__) Import() ChatGetThreadArg {
	return ChatGetThreadArg{
		Q: (func(x *lib.ChatThreadQueryInternal__) (ret lib.ChatThreadQuery) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Q),
	}
}
func (c ChatGetThreadArg) Export() *ChatGetThreadArgInternal__ {
	return &ChatGetThreadArgInternal__{
		Q: c.Q.Export(),
	}
}
func (c *ChatGetThreadArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatGetThreadArg) Decode(dec rpc.Decoder) error {
	var tmp ChatGetThreadArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatGetThreadArg) Bytes() []byte { return nil }

type ChatGetInboxVersionArg struct {
	Key ChatInboxKey
}
type ChatGetInboxVersionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *ChatInboxKeyInternal__
}

func (c ChatGetInboxVersionArgInternal__) Import() ChatGetInboxVersionArg {
	return ChatGetInboxVersionArg{
		Key: (func(x *ChatInboxKeyInternal__) (ret ChatInboxKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Key),
	}
}
func (c ChatGetInboxVersionArg) Export() *ChatGetInboxVersionArgInternal__ {
	return &ChatGetInboxVersionArgInternal__{
		Key: c.Key.Export(),
	}
}
func (c *ChatGetInboxVersionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatGetInboxVersionArg) Decode(dec rpc.Decoder) error {
	var tmp ChatGetInboxVersionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatGetInboxVersionArg) Bytes() []byte { return nil }

type ChatGetChangedThreadsArg struct {
	Arg ChatGetChangedThreadsArg
}
type ChatGetChangedThreadsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Arg     *ChatGetChangedThreadsArgInternal__
}

func (c ChatGetChangedThreadsArgInternal__) Import() ChatGetChangedThreadsArg {
	return ChatGetChangedThreadsArg{
		Arg: (func(x *ChatGetChangedThreadsArgInternal__) (ret ChatGetChangedThreadsArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Arg),
	}
}
func (c ChatGetChangedThreadsArg) Export() *ChatGetChangedThreadsArgInternal__ {
	return &ChatGetChangedThreadsArgInternal__{
		Arg: c.Arg.Export(),
	}
}
func (c *ChatGetChangedThreadsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatGetChangedThreadsArg) Decode(dec rpc.Decoder) error {
	var tmp ChatGetChangedThreadsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatGetChangedThreadsArg) Bytes() []byte { return nil }

type ChatReadThroughArg struct {
	Arg ChatReadThroughArg
}
type ChatReadThroughArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Arg     *ChatReadThroughArgInternal__
}

func (c ChatReadThroughArgInternal__) Import() ChatReadThroughArg {
	return ChatReadThroughArg{
		Arg: (func(x *ChatReadThroughArgInternal__) (ret ChatReadThroughArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Arg),
	}
}
func (c ChatReadThroughArg) Export() *ChatReadThroughArgInternal__ {
	return &ChatReadThroughArgInternal__{
		Arg: c.Arg.Export(),
	}
}
func (c *ChatReadThroughArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatReadThroughArg) Decode(dec rpc.Decoder) error {
	var tmp ChatReadThroughArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatReadThroughArg) Bytes() []byte { return nil }

type ChatPollInboxArg struct {
	Arg ChatPollInboxArg
}
type ChatPollInboxArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Arg     *ChatPollInboxArgInternal__
}

func (c ChatPollInboxArgInternal__) Import() ChatPollInboxArg {
	return ChatPollInboxArg{
		Arg: (func(x *ChatPollInboxArgInternal__) (ret ChatPollInboxArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Arg),
	}
}
func (c ChatPollInboxArg) Export() *ChatPollInboxArgInternal__ {
	return &ChatPollInboxArgInternal__{
		Arg: c.Arg.Export(),
	}
}
func (c *ChatPollInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatPollInboxArg) Decode(dec rpc.Decoder) error {
	var tmp ChatPollInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatPollInboxArg) Bytes() []byte { return nil }

type ChatSelectVhost struct {
	Host lib.HostID
}
type ChatSelectVhostInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostIDInternal__
}

func (c ChatSelectVhostInternal__) Import() ChatSelectVhost {
	return ChatSelectVhost{
		Host: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Host),
	}
}
func (c ChatSelectVhost) Export() *ChatSelectVhostInternal__ {
	return &ChatSelectVhostInternal__{
		Host: c.Host.Export(),
	}
}
func (c *ChatSelectVhost) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChatSelectVhost) Decode(dec rpc.Decoder) error {
	var tmp ChatSelectVhostInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChatSelectVhost) Bytes() []byte { return nil }

type ChatInterface interface {
	ChatNewChannel(context.Context, ChatNewChannelArg) (lib.ChatChannelMetadata, error)
	ChatGetChannel(context.Context, lib.ChatChannelID) (lib.ChatChannelMetadata, error)
	ChatListTeamChannels(context.Context, ChatListTeamChannelsArg) ([]lib.ChatChannelMetadata, error)
	ChatSend(context.Context, ChatSendArg) (ChatSendRes, error)
	ChatGetThread(context.Context, lib.ChatThreadQuery) (lib.ChatThreadPage, error)
	ChatGetInboxVersion(context.Context, ChatInboxKey) (lib.ChatInboxVersion, error)
	ChatGetChangedThreads(context.Context, ChatGetChangedThreadsArg) (lib.ChatInboxDelta, error)
	ChatReadThrough(context.Context, ChatReadThroughArg) error
	ChatPollInbox(context.Context, ChatPollInboxArg) (lib.ChatInboxPollRes, error)
	SelectVHost(context.Context, lib.HostID) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error
	MakeResHeader() lib.Header
}

func ChatMakeGenericErrorWrapper(f ChatErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type ChatErrorUnwrapper func(lib.Status) error
type ChatErrorWrapper func(error) lib.Status

type chatErrorUnwrapperAdapter struct {
	h ChatErrorUnwrapper
}

func (c chatErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (c chatErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return c.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = chatErrorUnwrapperAdapter{}

type ChatClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper ChatErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c ChatClient) ChatNewChannel(ctx context.Context, arg ChatNewChannelArg) (res lib.ChatChannelMetadata, err error) {
	warg := &rpc.DataWrap[lib.Header, *ChatNewChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatChannelMetadataInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 0, "Chat.chatNewChannel"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatGetChannel(ctx context.Context, channelID lib.ChatChannelID) (res lib.ChatChannelMetadata, err error) {
	arg := ChatGetChannelArg{
		ChannelID: channelID,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatGetChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatChannelMetadataInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 1, "Chat.chatGetChannel"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatListTeamChannels(ctx context.Context, arg ChatListTeamChannelsArg) (res []lib.ChatChannelMetadata, err error) {
	warg := &rpc.DataWrap[lib.Header, *ChatListTeamChannelsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, [](*lib.ChatChannelMetadataInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 2, "Chat.chatListTeamChannels"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*lib.ChatChannelMetadataInternal__)) (ret []lib.ChatChannelMetadata) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]lib.ChatChannelMetadata, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *lib.ChatChannelMetadataInternal__) (ret lib.ChatChannelMetadata) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp.Data)
	return
}
func (c ChatClient) ChatSend(ctx context.Context, arg ChatSendArg) (res ChatSendRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *ChatSendArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ChatSendResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 3, "Chat.chatSend"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatGetThread(ctx context.Context, q lib.ChatThreadQuery) (res lib.ChatThreadPage, err error) {
	arg := ChatGetThreadArg{
		Q: q,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatGetThreadArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatThreadPageInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 4, "Chat.chatGetThread"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatGetInboxVersion(ctx context.Context, key ChatInboxKey) (res lib.ChatInboxVersion, err error) {
	arg := ChatGetInboxVersionArg{
		Key: key,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatGetInboxVersionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatInboxVersionInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 5, "Chat.chatGetInboxVersion"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatGetChangedThreads(ctx context.Context, arg ChatGetChangedThreadsArg) (res lib.ChatInboxDelta, err error) {
	arg := ChatGetChangedThreadsArg{
		Arg: arg,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatGetChangedThreadsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatInboxDeltaInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 6, "Chat.chatGetChangedThreads"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatReadThrough(ctx context.Context, arg ChatReadThroughArg) (err error) {
	arg := ChatReadThroughArg{
		Arg: arg,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatReadThroughArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 7, "Chat.chatReadThrough"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) ChatPollInbox(ctx context.Context, arg ChatPollInboxArg) (res lib.ChatInboxPollRes, err error) {
	arg := ChatPollInboxArg{
		Arg: arg,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatPollInboxArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.ChatInboxPollResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 8, "Chat.chatPollInbox"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c ChatClient) SelectVHost(ctx context.Context, host lib.HostID) (err error) {
	arg := ChatSelectVhost{
		Host: host,
	}
	warg := &rpc.DataWrap[lib.Header, *ChatSelectVhostInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ChatProtocolID, 9, "Chat.selectVHost"), warg, &tmp, 0*time.Millisecond, chatErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func ChatProtocol(i ChatInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Chat",
		ID:   ChatProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatNewChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatNewChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatNewChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatNewChannel(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatChannelMetadataInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatNewChannel",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatGetChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatGetChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatGetChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatGetChannel(ctx, (typedArg.Import()).ChannelID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatChannelMetadataInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatGetChannel",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatListTeamChannelsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatListTeamChannelsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatListTeamChannelsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatListTeamChannels(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						lst := (func(x []lib.ChatChannelMetadata) *[](*lib.ChatChannelMetadataInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*lib.ChatChannelMetadataInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[lib.Header, [](*lib.ChatChannelMetadataInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "chatListTeamChannels",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatSendArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatSendArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatSendArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatSend(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ChatSendResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatSend",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatGetThreadArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatGetThreadArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatGetThreadArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatGetThread(ctx, (typedArg.Import()).Q)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatThreadPageInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatGetThread",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatGetInboxVersionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatGetInboxVersionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatGetInboxVersionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatGetInboxVersion(ctx, (typedArg.Import()).Key)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatInboxVersionInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatGetInboxVersion",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatGetChangedThreadsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatGetChangedThreadsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatGetChangedThreadsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatGetChangedThreads(ctx, (typedArg.Import()).Arg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatInboxDeltaInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatGetChangedThreads",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatReadThroughArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatReadThroughArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatReadThroughArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ChatReadThrough(ctx, (typedArg.Import()).Arg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatReadThrough",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatPollInboxArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatPollInboxArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatPollInboxArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ChatPollInbox(ctx, (typedArg.Import()).Arg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.ChatInboxPollResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "chatPollInbox",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChatSelectVhostInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChatSelectVhostInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChatSelectVhostInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SelectVHost(ctx, (typedArg.Import()).Host)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "selectVHost",
			},
		},
		WrapError: ChatMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(ChatProtocolID)
}
