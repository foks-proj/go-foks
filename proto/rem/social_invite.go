// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/rem/social_invite.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SocialInviteMsg struct {
	Seq    uint64
	Sender lib.SocialInviteParty
	Box    lib.SecretBox
}
type SocialInviteMsgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq     *uint64
	Sender  *lib.SocialInvitePartyInternal__
	Box     *lib.SecretBoxInternal__
}

func (s SocialInviteMsgInternal__) Import() SocialInviteMsg {
	return SocialInviteMsg{
		Seq: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Seq),
		Sender: (func(x *lib.SocialInvitePartyInternal__) (ret lib.SocialInviteParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sender),
		Box: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Box),
	}
}
func (s SocialInviteMsg) Export() *SocialInviteMsgInternal__ {
	return &SocialInviteMsgInternal__{
		Seq:    &s.Seq,
		Sender: s.Sender.Export(),
		Box:    s.Box.Export(),
	}
}
func (s *SocialInviteMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteMsg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteMsg) Bytes() []byte { return nil }

type SocialInviteGuestView struct {
	State lib.SocialInviteState
	Msgs  []SocialInviteMsg
}
type SocialInviteGuestViewInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	State   *lib.SocialInviteStateInternal__
	Msgs    *[](*SocialInviteMsgInternal__)
}

func (s SocialInviteGuestViewInternal__) Import() SocialInviteGuestView {
	return SocialInviteGuestView{
		State: (func(x *lib.SocialInviteStateInternal__) (ret lib.SocialInviteState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.State),
		Msgs: (func(x *[](*SocialInviteMsgInternal__)) (ret []SocialInviteMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SocialInviteMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SocialInviteMsgInternal__) (ret SocialInviteMsg) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Msgs),
	}
}
func (s SocialInviteGuestView) Export() *SocialInviteGuestViewInternal__ {
	return &SocialInviteGuestViewInternal__{
		State: s.State.Export(),
		Msgs: (func(x []SocialInviteMsg) *[](*SocialInviteMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SocialInviteMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Msgs),
	}
}
func (s *SocialInviteGuestView) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteGuestView) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteGuestViewInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteGuestView) Bytes() []byte { return nil }

type SocialInviteRow struct {
	Id      lib.SocialInviteID
	Team    lib.TeamID
	State   lib.SocialInviteState
	SeedBox lib.SharedKeyBox
	Msgs    []SocialInviteMsg
	Invitee *lib.UID
	Ctime   lib.Time
	Mtime   lib.Time
	Etime   lib.Time
}
type SocialInviteRowInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	Team    *lib.TeamIDInternal__
	State   *lib.SocialInviteStateInternal__
	SeedBox *lib.SharedKeyBoxInternal__
	Msgs    *[](*SocialInviteMsgInternal__)
	Invitee *lib.UIDInternal__
	Ctime   *lib.TimeInternal__
	Mtime   *lib.TimeInternal__
	Etime   *lib.TimeInternal__
}

func (s SocialInviteRowInternal__) Import() SocialInviteRow {
	return SocialInviteRow{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Team),
		State: (func(x *lib.SocialInviteStateInternal__) (ret lib.SocialInviteState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.State),
		SeedBox: (func(x *lib.SharedKeyBoxInternal__) (ret lib.SharedKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SeedBox),
		Msgs: (func(x *[](*SocialInviteMsgInternal__)) (ret []SocialInviteMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SocialInviteMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SocialInviteMsgInternal__) (ret SocialInviteMsg) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Msgs),
		Invitee: (func(x *lib.UIDInternal__) *lib.UID {
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
		})(s.Invitee),
		Ctime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Ctime),
		Mtime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Mtime),
		Etime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Etime),
	}
}
func (s SocialInviteRow) Export() *SocialInviteRowInternal__ {
	return &SocialInviteRowInternal__{
		Id:      s.Id.Export(),
		Team:    s.Team.Export(),
		State:   s.State.Export(),
		SeedBox: s.SeedBox.Export(),
		Msgs: (func(x []SocialInviteMsg) *[](*SocialInviteMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SocialInviteMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Msgs),
		Invitee: (func(x *lib.UID) *lib.UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Invitee),
		Ctime: s.Ctime.Export(),
		Mtime: s.Mtime.Export(),
		Etime: s.Etime.Export(),
	}
}
func (s *SocialInviteRow) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteRow) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteRowInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteRow) Bytes() []byte { return nil }

type SocialInviteMsgPayload struct {
	Text       string
	InviteCode *InviteCode
	Team       *lib.FQTeam
	User       *lib.FQUser
}
type SocialInviteMsgPayloadInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Text       *string
	InviteCode *InviteCodeInternal__
	Team       *lib.FQTeamInternal__
	User       *lib.FQUserInternal__
}

func (s SocialInviteMsgPayloadInternal__) Import() SocialInviteMsgPayload {
	return SocialInviteMsgPayload{
		Text: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Text),
		InviteCode: (func(x *InviteCodeInternal__) *InviteCode {
			if x == nil {
				return nil
			}
			tmp := (func(x *InviteCodeInternal__) (ret InviteCode) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.InviteCode),
		Team: (func(x *lib.FQTeamInternal__) *lib.FQTeam {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Team),
		User: (func(x *lib.FQUserInternal__) *lib.FQUser {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.User),
	}
}
func (s SocialInviteMsgPayload) Export() *SocialInviteMsgPayloadInternal__ {
	return &SocialInviteMsgPayloadInternal__{
		Text: &s.Text,
		InviteCode: (func(x *InviteCode) *InviteCodeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.InviteCode),
		Team: (func(x *lib.FQTeam) *lib.FQTeamInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.Team),
		User: (func(x *lib.FQUser) *lib.FQUserInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.User),
	}
}
func (s *SocialInviteMsgPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteMsgPayload) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteMsgPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SocialInviteMsgPayloadTypeUniqueID = rpc.TypeUniqueID(0x85d21f4e60b7c9aa)

func (s *SocialInviteMsgPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return SocialInviteMsgPayloadTypeUniqueID
}
func (s *SocialInviteMsgPayload) Bytes() []byte { return nil }

var SocialInviteGuestProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xc6f4b985)

type FetchArg struct {
	Id lib.SocialInviteID
}
type FetchArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
}

func (f FetchArgInternal__) Import() FetchArg {
	return FetchArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Id),
	}
}
func (f FetchArg) Export() *FetchArgInternal__ {
	return &FetchArgInternal__{
		Id: f.Id.Export(),
	}
}
func (f *FetchArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FetchArg) Decode(dec rpc.Decoder) error {
	var tmp FetchArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FetchArg) Bytes() []byte { return nil }

type SocialInviteGuestInterface interface {
	Fetch(context.Context, lib.SocialInviteID) (SocialInviteGuestView, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error
	MakeResHeader() lib.Header
}

func SocialInviteGuestMakeGenericErrorWrapper(f SocialInviteGuestErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type SocialInviteGuestErrorUnwrapper func(lib.Status) error
type SocialInviteGuestErrorWrapper func(error) lib.Status

type socialInviteGuestErrorUnwrapperAdapter struct {
	h SocialInviteGuestErrorUnwrapper
}

func (s socialInviteGuestErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (s socialInviteGuestErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return s.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = socialInviteGuestErrorUnwrapperAdapter{}

type SocialInviteGuestClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper SocialInviteGuestErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c SocialInviteGuestClient) Fetch(ctx context.Context, id lib.SocialInviteID) (res SocialInviteGuestView, err error) {
	arg := FetchArg{
		Id: id,
	}
	warg := &rpc.DataWrap[lib.Header, *FetchArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, SocialInviteGuestViewInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteGuestProtocolID, 0, "SocialInviteGuest.fetch"), warg, &tmp, 0*time.Millisecond, socialInviteGuestErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func SocialInviteGuestProtocol(i SocialInviteGuestInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "SocialInviteGuest",
		ID:   SocialInviteGuestProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *FetchArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *FetchArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *FetchArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Fetch(ctx, (typedArg.Import()).Id)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *SocialInviteGuestViewInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "fetch",
			},
		},
		WrapError: SocialInviteGuestMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var SocialInviteProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xee2c9d1c)

type CreateArg struct {
	Id         lib.SocialInviteID
	Team       lib.TeamID
	SeedBox    lib.SharedKeyBox
	Msg        lib.SecretBox
	WkCommit   lib.SocialInviteWriteKeyCommitment
	InviteCode *InviteCode
	Etime      lib.Time
}
type CreateArgInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id         *lib.SocialInviteIDInternal__
	Team       *lib.TeamIDInternal__
	SeedBox    *lib.SharedKeyBoxInternal__
	Msg        *lib.SecretBoxInternal__
	WkCommit   *lib.SocialInviteWriteKeyCommitmentInternal__
	InviteCode *InviteCodeInternal__
	Etime      *lib.TimeInternal__
}

func (c CreateArgInternal__) Import() CreateArg {
	return CreateArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		Team: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Team),
		SeedBox: (func(x *lib.SharedKeyBoxInternal__) (ret lib.SharedKeyBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SeedBox),
		Msg: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Msg),
		WkCommit: (func(x *lib.SocialInviteWriteKeyCommitmentInternal__) (ret lib.SocialInviteWriteKeyCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.WkCommit),
		InviteCode: (func(x *InviteCodeInternal__) *InviteCode {
			if x == nil {
				return nil
			}
			tmp := (func(x *InviteCodeInternal__) (ret InviteCode) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.InviteCode),
		Etime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Etime),
	}
}
func (c CreateArg) Export() *CreateArgInternal__ {
	return &CreateArgInternal__{
		Id:       c.Id.Export(),
		Team:     c.Team.Export(),
		SeedBox:  c.SeedBox.Export(),
		Msg:      c.Msg.Export(),
		WkCommit: c.WkCommit.Export(),
		InviteCode: (func(x *InviteCode) *InviteCodeInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.InviteCode),
		Etime: c.Etime.Export(),
	}
}
func (c *CreateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CreateArg) Decode(dec rpc.Decoder) error {
	var tmp CreateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CreateArg) Bytes() []byte { return nil }

type ListArg struct {
}
type ListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (l ListArgInternal__) Import() ListArg {
	return ListArg{}
}
func (l ListArg) Export() *ListArgInternal__ {
	return &ListArgInternal__{}
}
func (l *ListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *ListArg) Decode(dec rpc.Decoder) error {
	var tmp ListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *ListArg) Bytes() []byte { return nil }

type ReplyArg struct {
	Id        lib.SocialInviteID
	Wk        lib.SocialInviteWriteKey
	InReplyTo uint64
	Msg       lib.SecretBox
}
type ReplyArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id        *lib.SocialInviteIDInternal__
	Wk        *lib.SocialInviteWriteKeyInternal__
	InReplyTo *uint64
	Msg       *lib.SecretBoxInternal__
}

func (r ReplyArgInternal__) Import() ReplyArg {
	return ReplyArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Id),
		Wk: (func(x *lib.SocialInviteWriteKeyInternal__) (ret lib.SocialInviteWriteKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Wk),
		InReplyTo: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.InReplyTo),
		Msg: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Msg),
	}
}
func (r ReplyArg) Export() *ReplyArgInternal__ {
	return &ReplyArgInternal__{
		Id:        r.Id.Export(),
		Wk:        r.Wk.Export(),
		InReplyTo: &r.InReplyTo,
		Msg:       r.Msg.Export(),
	}
}
func (r *ReplyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReplyArg) Decode(dec rpc.Decoder) error {
	var tmp ReplyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReplyArg) Bytes() []byte { return nil }

type AskAgainArg struct {
	Id  lib.SocialInviteID
	Msg lib.SecretBox
}
type AskAgainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	Msg     *lib.SecretBoxInternal__
}

func (a AskAgainArgInternal__) Import() AskAgainArg {
	return AskAgainArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Id),
		Msg: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.Msg),
	}
}
func (a AskAgainArg) Export() *AskAgainArgInternal__ {
	return &AskAgainArgInternal__{
		Id:  a.Id.Export(),
		Msg: a.Msg.Export(),
	}
}
func (a *AskAgainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AskAgainArg) Decode(dec rpc.Decoder) error {
	var tmp AskAgainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AskAgainArg) Bytes() []byte { return nil }

type CloseArg struct {
	Id lib.SocialInviteID
	St lib.SocialInviteState
}
type CloseArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	St      *lib.SocialInviteStateInternal__
}

func (c CloseArgInternal__) Import() CloseArg {
	return CloseArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		St: (func(x *lib.SocialInviteStateInternal__) (ret lib.SocialInviteState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.St),
	}
}
func (c CloseArg) Export() *CloseArgInternal__ {
	return &CloseArgInternal__{
		Id: c.Id.Export(),
		St: c.St.Export(),
	}
}
func (c *CloseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CloseArg) Decode(dec rpc.Decoder) error {
	var tmp CloseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CloseArg) Bytes() []byte { return nil }

type SocialInviteInterface interface {
	Create(context.Context, CreateArg) error
	List(context.Context) ([]SocialInviteRow, error)
	Reply(context.Context, ReplyArg) error
	AskAgain(context.Context, AskAgainArg) error
	Close(context.Context, CloseArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error
	MakeResHeader() lib.Header
}

func SocialInviteMakeGenericErrorWrapper(f SocialInviteErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type SocialInviteErrorUnwrapper func(lib.Status) error
type SocialInviteErrorWrapper func(error) lib.Status

type socialInviteErrorUnwrapperAdapter struct {
	h SocialInviteErrorUnwrapper
}

func (s socialInviteErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (s socialInviteErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return s.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = socialInviteErrorUnwrapperAdapter{}

type SocialInviteClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper SocialInviteErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c SocialInviteClient) Create(ctx context.Context, arg CreateArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *CreateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 0, "SocialInvite.create"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) List(ctx context.Context) (res []SocialInviteRow, err error) {
	var arg ListArg
	warg := &rpc.DataWrap[lib.Header, *ListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, [](*SocialInviteRowInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 1, "SocialInvite.list"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*SocialInviteRowInternal__)) (ret []SocialInviteRow) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]SocialInviteRow, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *SocialInviteRowInternal__) (ret SocialInviteRow) {
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
func (c SocialInviteClient) Reply(ctx context.Context, arg ReplyArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ReplyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 2, "SocialInvite.reply"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) AskAgain(ctx context.Context, arg AskAgainArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *AskAgainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 3, "SocialInvite.askAgain"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) Close(ctx context.Context, arg CloseArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *CloseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 4, "SocialInvite.close"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func SocialInviteProtocol(i SocialInviteInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "SocialInvite",
		ID:   SocialInviteProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CreateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CreateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CreateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.Create(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "create",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.List(ctx)
						if err != nil {
							return nil, err
						}
						lst := (func(x []SocialInviteRow) *[](*SocialInviteRowInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*SocialInviteRowInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[lib.Header, [](*SocialInviteRowInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "list",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ReplyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ReplyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ReplyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.Reply(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "reply",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *AskAgainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *AskAgainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *AskAgainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.AskAgain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "askAgain",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CloseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CloseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CloseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.Close(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "close",
			},
		},
		WrapError: SocialInviteMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(SocialInviteMsgPayloadTypeUniqueID)
	rpc.AddUnique(SocialInviteGuestProtocolID)
	rpc.AddUnique(SocialInviteProtocolID)
}
