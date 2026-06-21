// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/realtime.snowp

package lcl

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type RTChannelNameAndTier struct {
	Name lib.RTChannelName
	Tier lib.RTChannelTier
}
type RTChannelNameAndTierInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *lib.RTChannelNameInternal__
	Tier    *lib.RTChannelTierInternal__
}

func (r RTChannelNameAndTierInternal__) Import() RTChannelNameAndTier {
	return RTChannelNameAndTier{
		Name: (func(x *lib.RTChannelNameInternal__) (ret lib.RTChannelName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Name),
		Tier: (func(x *lib.RTChannelTierInternal__) (ret lib.RTChannelTier) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Tier),
	}
}
func (r RTChannelNameAndTier) Export() *RTChannelNameAndTierInternal__ {
	return &RTChannelNameAndTierInternal__{
		Name: r.Name.Export(),
		Tier: r.Tier.Export(),
	}
}
func (r *RTChannelNameAndTier) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelNameAndTier) Decode(dec rpc.Decoder) error {
	var tmp RTChannelNameAndTierInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelNameAndTier) Bytes() []byte { return nil }

type RTChannelSpecifierType int

const (
	RTChannelSpecifierType_None RTChannelSpecifierType = 0
	RTChannelSpecifierType_ID   RTChannelSpecifierType = 1
	RTChannelSpecifierType_Name RTChannelSpecifierType = 2
)

var RTChannelSpecifierTypeMap = map[string]RTChannelSpecifierType{
	"None": 0,
	"ID":   1,
	"Name": 2,
}
var RTChannelSpecifierTypeRevMap = map[RTChannelSpecifierType]string{
	0: "None",
	1: "ID",
	2: "Name",
}

type RTChannelSpecifierTypeInternal__ RTChannelSpecifierType

func (r RTChannelSpecifierTypeInternal__) Import() RTChannelSpecifierType {
	return RTChannelSpecifierType(r)
}
func (r RTChannelSpecifierType) Export() *RTChannelSpecifierTypeInternal__ {
	return ((*RTChannelSpecifierTypeInternal__)(&r))
}

type RTChannelSpecifier struct {
	T     RTChannelSpecifierType
	F_1__ *lib.RTChannelID      `json:"f1,omitempty"`
	F_2__ *RTChannelNameAndTier `json:"f2,omitempty"`
}
type RTChannelSpecifierInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        RTChannelSpecifierType
	Switch__ RTChannelSpecifierInternalSwitch__
}
type RTChannelSpecifierInternalSwitch__ struct {
	_struct struct{}                        `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *lib.RTChannelIDInternal__      `codec:"1"`
	F_2__   *RTChannelNameAndTierInternal__ `codec:"2"`
}

func (r RTChannelSpecifier) GetT() (ret RTChannelSpecifierType, err error) {
	switch r.T {
	case RTChannelSpecifierType_ID:
		if r.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case RTChannelSpecifierType_Name:
		if r.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	default:
		break
	}
	return r.T, nil
}
func (r RTChannelSpecifier) Id() lib.RTChannelID {
	if r.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelSpecifierType_ID {
		panic(fmt.Sprintf("unexpected switch value (%v) when Id is called", r.T))
	}
	return *r.F_1__
}
func (r RTChannelSpecifier) Name() RTChannelNameAndTier {
	if r.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if r.T != RTChannelSpecifierType_Name {
		panic(fmt.Sprintf("unexpected switch value (%v) when Name is called", r.T))
	}
	return *r.F_2__
}
func NewRTChannelSpecifierWithId(v lib.RTChannelID) RTChannelSpecifier {
	return RTChannelSpecifier{
		T:     RTChannelSpecifierType_ID,
		F_1__: &v,
	}
}
func NewRTChannelSpecifierWithName(v RTChannelNameAndTier) RTChannelSpecifier {
	return RTChannelSpecifier{
		T:     RTChannelSpecifierType_Name,
		F_2__: &v,
	}
}
func NewRTChannelSpecifierDefault(s RTChannelSpecifierType) RTChannelSpecifier {
	return RTChannelSpecifier{
		T: s,
	}
}
func (r RTChannelSpecifierInternal__) Import() RTChannelSpecifier {
	return RTChannelSpecifier{
		T: r.T,
		F_1__: (func(x *lib.RTChannelIDInternal__) *lib.RTChannelID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTChannelIDInternal__) (ret lib.RTChannelID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_1__),
		F_2__: (func(x *RTChannelNameAndTierInternal__) *RTChannelNameAndTier {
			if x == nil {
				return nil
			}
			tmp := (func(x *RTChannelNameAndTierInternal__) (ret RTChannelNameAndTier) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Switch__.F_2__),
	}
}
func (r RTChannelSpecifier) Export() *RTChannelSpecifierInternal__ {
	return &RTChannelSpecifierInternal__{
		T: r.T,
		Switch__: RTChannelSpecifierInternalSwitch__{
			F_1__: (func(x *lib.RTChannelID) *lib.RTChannelIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_1__),
			F_2__: (func(x *RTChannelNameAndTier) *RTChannelNameAndTierInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(r.F_2__),
		},
	}
}
func (r *RTChannelSpecifier) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSpecifier) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSpecifierInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelSpecifier) Bytes() []byte { return nil }

type RTConfig struct {
	Team    *lib.FQTeamParsed
	AppID   lib.RTAppID
	Roles   lib.RolePairOpt
	Channel RTChannelSpecifier
}
type RTConfigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	AppID   *lib.RTAppIDInternal__
	Roles   *lib.RolePairOptInternal__
	Channel *RTChannelSpecifierInternal__
}

func (r RTConfigInternal__) Import() RTConfig {
	return RTConfig{
		Team: (func(x *lib.FQTeamParsedInternal__) *lib.FQTeamParsed {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Team),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Roles: (func(x *lib.RolePairOptInternal__) (ret lib.RolePairOpt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		Channel: (func(x *RTChannelSpecifierInternal__) (ret RTChannelSpecifier) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Channel),
	}
}
func (r RTConfig) Export() *RTConfigInternal__ {
	return &RTConfigInternal__{
		Team: (func(x *lib.FQTeamParsed) *lib.FQTeamParsedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Team),
		AppID:   r.AppID.Export(),
		Roles:   r.Roles.Export(),
		Channel: r.Channel.Export(),
	}
}
func (r *RTConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTConfig) Decode(dec rpc.Decoder) error {
	var tmp RTConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTConfig) Bytes() []byte { return nil }

type RTChannelMetadataPlaintext struct {
	Id         lib.RTChannelID
	ParentTeam lib.TeamID
	AppID      lib.RTAppID
	Name       lib.RTChannelName
	Desc       *lib.RTChannelDesc
	Roles      lib.RolePair
	Tier       lib.RTChannelTier
	UpdatedAt  lib.RTChannelSetVersion
	Unreadable bool
}
type RTChannelMetadataPlaintextInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id         *lib.RTChannelIDInternal__
	ParentTeam *lib.TeamIDInternal__
	AppID      *lib.RTAppIDInternal__
	Name       *lib.RTChannelNameInternal__
	Desc       *lib.RTChannelDescInternal__
	Roles      *lib.RolePairInternal__
	Tier       *lib.RTChannelTierInternal__
	UpdatedAt  *lib.RTChannelSetVersionInternal__
	Unreadable *bool
}

func (r RTChannelMetadataPlaintextInternal__) Import() RTChannelMetadataPlaintext {
	return RTChannelMetadataPlaintext{
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
		Name: (func(x *lib.RTChannelNameInternal__) (ret lib.RTChannelName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Name),
		Desc: (func(x *lib.RTChannelDescInternal__) *lib.RTChannelDesc {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTChannelDescInternal__) (ret lib.RTChannelDesc) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Desc),
		Roles: (func(x *lib.RolePairInternal__) (ret lib.RolePair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Roles),
		Tier: (func(x *lib.RTChannelTierInternal__) (ret lib.RTChannelTier) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Tier),
		UpdatedAt: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.UpdatedAt),
		Unreadable: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Unreadable),
	}
}
func (r RTChannelMetadataPlaintext) Export() *RTChannelMetadataPlaintextInternal__ {
	return &RTChannelMetadataPlaintextInternal__{
		Id:         r.Id.Export(),
		ParentTeam: r.ParentTeam.Export(),
		AppID:      r.AppID.Export(),
		Name:       r.Name.Export(),
		Desc: (func(x *lib.RTChannelDesc) *lib.RTChannelDescInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Desc),
		Roles:      r.Roles.Export(),
		Tier:       r.Tier.Export(),
		UpdatedAt:  r.UpdatedAt.Export(),
		Unreadable: &r.Unreadable,
	}
}
func (r *RTChannelMetadataPlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelMetadataPlaintext) Decode(dec rpc.Decoder) error {
	var tmp RTChannelMetadataPlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelMetadataPlaintext) Bytes() []byte { return nil }

type RTChannelSetForTeam struct {
	Channels []RTChannelMetadataPlaintext
	Vers     lib.RTChannelSetVersion
	AppID    lib.RTAppID
	Team     lib.TeamID
}
type RTChannelSetForTeamInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Channels *[](*RTChannelMetadataPlaintextInternal__)
	Vers     *lib.RTChannelSetVersionInternal__
	AppID    *lib.RTAppIDInternal__
	Team     *lib.TeamIDInternal__
}

func (r RTChannelSetForTeamInternal__) Import() RTChannelSetForTeam {
	return RTChannelSetForTeam{
		Channels: (func(x *[](*RTChannelMetadataPlaintextInternal__)) (ret []RTChannelMetadataPlaintext) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTChannelMetadataPlaintext, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTChannelMetadataPlaintextInternal__) (ret RTChannelMetadataPlaintext) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Channels),
		Vers: (func(x *lib.RTChannelSetVersionInternal__) (ret lib.RTChannelSetVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Vers),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Team),
	}
}
func (r RTChannelSetForTeam) Export() *RTChannelSetForTeamInternal__ {
	return &RTChannelSetForTeamInternal__{
		Channels: (func(x []RTChannelMetadataPlaintext) *[](*RTChannelMetadataPlaintextInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTChannelMetadataPlaintextInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Channels),
		Vers:  r.Vers.Export(),
		AppID: r.AppID.Export(),
		Team:  r.Team.Export(),
	}
}
func (r *RTChannelSetForTeam) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSetForTeam) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetForTeamInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelSetForTeam) Bytes() []byte { return nil }

type RTMsgView struct {
	Seq        lib.RTMsgSeq
	MsgID      lib.RTMsgID
	PrevID     lib.RTMsgID
	PrevSeq    lib.RTMsgSeq
	Typ        lib.RTMsgType
	Sender     *lib.PartyID
	SentAtTime lib.Time
	InsertTime lib.Time
	Body       []byte
	SenderName *lib.NameUtf8
}
type RTMsgViewInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq        *lib.RTMsgSeqInternal__
	MsgID      *lib.RTMsgIDInternal__
	PrevID     *lib.RTMsgIDInternal__
	PrevSeq    *lib.RTMsgSeqInternal__
	Typ        *lib.RTMsgTypeInternal__
	Sender     *lib.PartyIDInternal__
	SentAtTime *lib.TimeInternal__
	InsertTime *lib.TimeInternal__
	Body       *[]byte
	SenderName *lib.NameUtf8Internal__
}

func (r RTMsgViewInternal__) Import() RTMsgView {
	return RTMsgView{
		Seq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Seq),
		MsgID: (func(x *lib.RTMsgIDInternal__) (ret lib.RTMsgID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.MsgID),
		PrevID: (func(x *lib.RTMsgIDInternal__) (ret lib.RTMsgID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PrevID),
		PrevSeq: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PrevSeq),
		Typ: (func(x *lib.RTMsgTypeInternal__) (ret lib.RTMsgType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
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
		SentAtTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SentAtTime),
		InsertTime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.InsertTime),
		Body: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Body),
		SenderName: (func(x *lib.NameUtf8Internal__) *lib.NameUtf8 {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.SenderName),
	}
}
func (r RTMsgView) Export() *RTMsgViewInternal__ {
	return &RTMsgViewInternal__{
		Seq:     r.Seq.Export(),
		MsgID:   r.MsgID.Export(),
		PrevID:  r.PrevID.Export(),
		PrevSeq: r.PrevSeq.Export(),
		Typ:     r.Typ.Export(),
		Sender: (func(x *lib.PartyID) *lib.PartyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Sender),
		SentAtTime: r.SentAtTime.Export(),
		InsertTime: r.InsertTime.Export(),
		Body:       &r.Body,
		SenderName: (func(x *lib.NameUtf8) *lib.NameUtf8Internal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.SenderName),
	}
}
func (r *RTMsgView) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTMsgView) Decode(dec rpc.Decoder) error {
	var tmp RTMsgViewInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTMsgView) Bytes() []byte { return nil }

type RTThreadView struct {
	Msgs        []RTMsgView
	AtBeginning bool
}
type RTThreadViewInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Msgs        *[](*RTMsgViewInternal__)
	AtBeginning *bool
}

func (r RTThreadViewInternal__) Import() RTThreadView {
	return RTThreadView{
		Msgs: (func(x *[](*RTMsgViewInternal__)) (ret []RTMsgView) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RTMsgView, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RTMsgViewInternal__) (ret RTMsgView) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.Msgs),
		AtBeginning: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.AtBeginning),
	}
}
func (r RTThreadView) Export() *RTThreadViewInternal__ {
	return &RTThreadViewInternal__{
		Msgs: (func(x []RTMsgView) *[](*RTMsgViewInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RTMsgViewInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.Msgs),
		AtBeginning: &r.AtBeginning,
	}
}
func (r *RTThreadView) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTThreadView) Decode(dec rpc.Decoder) error {
	var tmp RTThreadViewInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTThreadView) Bytes() []byte { return nil }

var RealTimeProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xaaf0cd97)

type ClientRTMakeChannelArg struct {
	Cfg  RTConfig
	Desc lib.RTChannelDesc
}
type ClientRTMakeChannelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
	Desc    *lib.RTChannelDescInternal__
}

func (c ClientRTMakeChannelArgInternal__) Import() ClientRTMakeChannelArg {
	return ClientRTMakeChannelArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Desc: (func(x *lib.RTChannelDescInternal__) (ret lib.RTChannelDesc) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Desc),
	}
}
func (c ClientRTMakeChannelArg) Export() *ClientRTMakeChannelArgInternal__ {
	return &ClientRTMakeChannelArgInternal__{
		Cfg:  c.Cfg.Export(),
		Desc: c.Desc.Export(),
	}
}
func (c *ClientRTMakeChannelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTMakeChannelArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTMakeChannelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTMakeChannelArg) Bytes() []byte { return nil }

type ClientRTListChannelsForTeamArg struct {
	Cfg RTConfig
}
type ClientRTListChannelsForTeamArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
}

func (c ClientRTListChannelsForTeamArgInternal__) Import() ClientRTListChannelsForTeamArg {
	return ClientRTListChannelsForTeamArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
	}
}
func (c ClientRTListChannelsForTeamArg) Export() *ClientRTListChannelsForTeamArgInternal__ {
	return &ClientRTListChannelsForTeamArgInternal__{
		Cfg: c.Cfg.Export(),
	}
}
func (c *ClientRTListChannelsForTeamArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTListChannelsForTeamArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTListChannelsForTeamArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTListChannelsForTeamArg) Bytes() []byte { return nil }

type ClientRTSendArg struct {
	Cfg  RTConfig
	Body []byte
}
type ClientRTSendArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
	Body    *[]byte
}

func (c ClientRTSendArgInternal__) Import() ClientRTSendArg {
	return ClientRTSendArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Body: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Body),
	}
}
func (c ClientRTSendArg) Export() *ClientRTSendArgInternal__ {
	return &ClientRTSendArgInternal__{
		Cfg:  c.Cfg.Export(),
		Body: &c.Body,
	}
}
func (c *ClientRTSendArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTSendArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTSendArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTSendArg) Bytes() []byte { return nil }

type ClientRTGetThreadArg struct {
	Cfg    RTConfig
	Num    uint64
	Before lib.RTMsgSeq
}
type ClientRTGetThreadArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *RTConfigInternal__
	Num     *uint64
	Before  *lib.RTMsgSeqInternal__
}

func (c ClientRTGetThreadArgInternal__) Import() ClientRTGetThreadArg {
	return ClientRTGetThreadArg{
		Cfg: (func(x *RTConfigInternal__) (ret RTConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Num: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Num),
		Before: (func(x *lib.RTMsgSeqInternal__) (ret lib.RTMsgSeq) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Before),
	}
}
func (c ClientRTGetThreadArg) Export() *ClientRTGetThreadArgInternal__ {
	return &ClientRTGetThreadArgInternal__{
		Cfg:    c.Cfg.Export(),
		Num:    &c.Num,
		Before: c.Before.Export(),
	}
}
func (c *ClientRTGetThreadArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientRTGetThreadArg) Decode(dec rpc.Decoder) error {
	var tmp ClientRTGetThreadArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientRTGetThreadArg) Bytes() []byte { return nil }

type RealTimeInterface interface {
	ClientRTMakeChannel(context.Context, ClientRTMakeChannelArg) (lib.RTChannelID, error)
	ClientRTListChannelsForTeam(context.Context, RTConfig) (RTChannelSetForTeam, error)
	ClientRTSend(context.Context, ClientRTSendArg) (lib.RTMsgSeq, error)
	ClientRTGetThread(context.Context, ClientRTGetThreadArg) (RTThreadView, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
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
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c RealTimeClient) ClientRTMakeChannel(ctx context.Context, arg ClientRTMakeChannelArg) (res lib.RTChannelID, err error) {
	warg := &rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RTChannelIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 0, "RealTime.clientRTMakeChannel"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) ClientRTListChannelsForTeam(ctx context.Context, cfg RTConfig) (res RTChannelSetForTeam, err error) {
	arg := ClientRTListChannelsForTeamArg{
		Cfg: cfg,
	}
	warg := &rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, RTChannelSetForTeamInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 1, "RealTime.clientRTListChannelsForTeam"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) ClientRTSend(ctx context.Context, arg ClientRTSendArg) (res lib.RTMsgSeq, err error) {
	warg := &rpc.DataWrap[Header, *ClientRTSendArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RTMsgSeqInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 2, "RealTime.clientRTSend"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c RealTimeClient) ClientRTGetThread(ctx context.Context, arg ClientRTGetThreadArg) (res RTThreadView, err error) {
	warg := &rpc.DataWrap[Header, *ClientRTGetThreadArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, RTThreadViewInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(RealTimeProtocolID, 3, "RealTime.clientRTGetThread"), warg, &tmp, 0*time.Millisecond, realTimeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
						var ret rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTMakeChannelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTMakeChannel(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RTChannelIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTMakeChannel",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTListChannelsForTeamArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTListChannelsForTeam(ctx, (typedArg.Import()).Cfg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *RTChannelSetForTeamInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTListChannelsForTeam",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientRTSendArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTSendArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTSendArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTSend(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RTMsgSeqInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTSend",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientRTGetThreadArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientRTGetThreadArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientRTGetThreadArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientRTGetThread(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *RTThreadViewInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientRTGetThread",
			},
		},
		WrapError: RealTimeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

type RTChannelSetHashInput struct {
	Fqp   lib.FQParty
	AppID lib.RTAppID
}
type RTChannelSetHashInputInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqp     *lib.FQPartyInternal__
	AppID   *lib.RTAppIDInternal__
}

func (r RTChannelSetHashInputInternal__) Import() RTChannelSetHashInput {
	return RTChannelSetHashInput{
		Fqp: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Fqp),
		AppID: (func(x *lib.RTAppIDInternal__) (ret lib.RTAppID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.AppID),
	}
}
func (r RTChannelSetHashInput) Export() *RTChannelSetHashInputInternal__ {
	return &RTChannelSetHashInputInternal__{
		Fqp:   r.Fqp.Export(),
		AppID: r.AppID.Export(),
	}
}
func (r *RTChannelSetHashInput) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSetHashInput) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetHashInputInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RTChannelSetHashInputTypeUniqueID = rpc.TypeUniqueID(0xc6985a2917572061)

func (r *RTChannelSetHashInput) GetTypeUniqueID() rpc.TypeUniqueID {
	return RTChannelSetHashInputTypeUniqueID
}
func (r *RTChannelSetHashInput) Bytes() []byte { return nil }

type RTChannelSetID lib.StdHash
type RTChannelSetIDInternal__ lib.StdHashInternal__

func (r RTChannelSetID) Export() *RTChannelSetIDInternal__ {
	tmp := ((lib.StdHash)(r))
	return ((*RTChannelSetIDInternal__)(tmp.Export()))
}
func (r RTChannelSetIDInternal__) Import() RTChannelSetID {
	tmp := (lib.StdHashInternal__)(r)
	return RTChannelSetID((func(x *lib.StdHashInternal__) (ret lib.StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (r *RTChannelSetID) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelSetID) Decode(dec rpc.Decoder) error {
	var tmp RTChannelSetIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RTChannelSetID) Bytes() []byte {
	return ((lib.StdHash)(r)).Bytes()
}

type RTChannelMetadataPlaintextAbbrev struct {
	Name lib.RTChannelName
	Desc *lib.RTChannelDesc
}
type RTChannelMetadataPlaintextAbbrevInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *lib.RTChannelNameInternal__
	Desc    *lib.RTChannelDescInternal__
}

func (r RTChannelMetadataPlaintextAbbrevInternal__) Import() RTChannelMetadataPlaintextAbbrev {
	return RTChannelMetadataPlaintextAbbrev{
		Name: (func(x *lib.RTChannelNameInternal__) (ret lib.RTChannelName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Name),
		Desc: (func(x *lib.RTChannelDescInternal__) *lib.RTChannelDesc {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RTChannelDescInternal__) (ret lib.RTChannelDesc) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Desc),
	}
}
func (r RTChannelMetadataPlaintextAbbrev) Export() *RTChannelMetadataPlaintextAbbrevInternal__ {
	return &RTChannelMetadataPlaintextAbbrevInternal__{
		Name: r.Name.Export(),
		Desc: (func(x *lib.RTChannelDesc) *lib.RTChannelDescInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Desc),
	}
}
func (r *RTChannelMetadataPlaintextAbbrev) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RTChannelMetadataPlaintextAbbrev) Decode(dec rpc.Decoder) error {
	var tmp RTChannelMetadataPlaintextAbbrevInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RTChannelMetadataPlaintextAbbrev) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(RealTimeProtocolID)
	rpc.AddUnique(RTChannelSetHashInputTypeUniqueID)
}
