// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/social_invite.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SocialInviteLocalMsg struct {
	Seq    uint64
	Sender lib.SocialInviteParty
	Text   string
	Team   *lib.FQTeam
	User   *lib.FQUser
}
type SocialInviteLocalMsgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seq     *uint64
	Sender  *lib.SocialInvitePartyInternal__
	Text    *string
	Team    *lib.FQTeamInternal__
	User    *lib.FQUserInternal__
}

func (s SocialInviteLocalMsgInternal__) Import() SocialInviteLocalMsg {
	return SocialInviteLocalMsg{
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
		Text: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Text),
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
func (s SocialInviteLocalMsg) Export() *SocialInviteLocalMsgInternal__ {
	return &SocialInviteLocalMsgInternal__{
		Seq:    &s.Seq,
		Sender: s.Sender.Export(),
		Text:   &s.Text,
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
func (s *SocialInviteLocalMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteLocalMsg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteLocalMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteLocalMsg) Bytes() []byte { return nil }

type SocialInviteLocalView struct {
	Id    lib.SocialInviteID
	State lib.SocialInviteState
	Msgs  []SocialInviteLocalMsg
}
type SocialInviteLocalViewInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	State   *lib.SocialInviteStateInternal__
	Msgs    *[](*SocialInviteLocalMsgInternal__)
}

func (s SocialInviteLocalViewInternal__) Import() SocialInviteLocalView {
	return SocialInviteLocalView{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		State: (func(x *lib.SocialInviteStateInternal__) (ret lib.SocialInviteState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.State),
		Msgs: (func(x *[](*SocialInviteLocalMsgInternal__)) (ret []SocialInviteLocalMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SocialInviteLocalMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SocialInviteLocalMsgInternal__) (ret SocialInviteLocalMsg) {
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
func (s SocialInviteLocalView) Export() *SocialInviteLocalViewInternal__ {
	return &SocialInviteLocalViewInternal__{
		Id:    s.Id.Export(),
		State: s.State.Export(),
		Msgs: (func(x []SocialInviteLocalMsg) *[](*SocialInviteLocalMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SocialInviteLocalMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Msgs),
	}
}
func (s *SocialInviteLocalView) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteLocalView) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteLocalViewInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteLocalView) Bytes() []byte { return nil }

type SocialInviteLocalRow struct {
	Id    lib.SocialInviteID
	Seed  lib.SocialInviteSeed
	Team  lib.FQTeam
	State lib.SocialInviteState
	Msgs  []SocialInviteLocalMsg
	Ctime lib.Time
	Mtime lib.Time
	Etime lib.Time
}
type SocialInviteLocalRowInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	Seed    *lib.SocialInviteSeedInternal__
	Team    *lib.FQTeamInternal__
	State   *lib.SocialInviteStateInternal__
	Msgs    *[](*SocialInviteLocalMsgInternal__)
	Ctime   *lib.TimeInternal__
	Mtime   *lib.TimeInternal__
	Etime   *lib.TimeInternal__
}

func (s SocialInviteLocalRowInternal__) Import() SocialInviteLocalRow {
	return SocialInviteLocalRow{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Seed: (func(x *lib.SocialInviteSeedInternal__) (ret lib.SocialInviteSeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
		Team: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
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
		Msgs: (func(x *[](*SocialInviteLocalMsgInternal__)) (ret []SocialInviteLocalMsg) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SocialInviteLocalMsg, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SocialInviteLocalMsgInternal__) (ret SocialInviteLocalMsg) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Msgs),
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
func (s SocialInviteLocalRow) Export() *SocialInviteLocalRowInternal__ {
	return &SocialInviteLocalRowInternal__{
		Id:    s.Id.Export(),
		Seed:  s.Seed.Export(),
		Team:  s.Team.Export(),
		State: s.State.Export(),
		Msgs: (func(x []SocialInviteLocalMsg) *[](*SocialInviteLocalMsgInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SocialInviteLocalMsgInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Msgs),
		Ctime: s.Ctime.Export(),
		Mtime: s.Mtime.Export(),
		Etime: s.Etime.Export(),
	}
}
func (s *SocialInviteLocalRow) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteLocalRow) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteLocalRowInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteLocalRow) Bytes() []byte { return nil }

type SocialInviteCreateRes struct {
	Id   lib.SocialInviteID
	Seed lib.SocialInviteSeed
}
type SocialInviteCreateResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	Seed    *lib.SocialInviteSeedInternal__
}

func (s SocialInviteCreateResInternal__) Import() SocialInviteCreateRes {
	return SocialInviteCreateRes{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Seed: (func(x *lib.SocialInviteSeedInternal__) (ret lib.SocialInviteSeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
	}
}
func (s SocialInviteCreateRes) Export() *SocialInviteCreateResInternal__ {
	return &SocialInviteCreateResInternal__{
		Id:   s.Id.Export(),
		Seed: s.Seed.Export(),
	}
}
func (s *SocialInviteCreateRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteCreateRes) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteCreateResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteCreateRes) Bytes() []byte { return nil }

var SocialInviteProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x91f668da)

type SocialInviteCreateArg struct {
	Team  lib.FQTeamParsed
	Text  string
	Etime lib.Time
}
type SocialInviteCreateArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Text    *string
	Etime   *lib.TimeInternal__
}

func (s SocialInviteCreateArgInternal__) Import() SocialInviteCreateArg {
	return SocialInviteCreateArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Team),
		Text: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Text),
		Etime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Etime),
	}
}
func (s SocialInviteCreateArg) Export() *SocialInviteCreateArgInternal__ {
	return &SocialInviteCreateArgInternal__{
		Team:  s.Team.Export(),
		Text:  &s.Text,
		Etime: s.Etime.Export(),
	}
}
func (s *SocialInviteCreateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteCreateArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteCreateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteCreateArg) Bytes() []byte { return nil }

type SocialInviteListArg struct {
}
type SocialInviteListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (s SocialInviteListArgInternal__) Import() SocialInviteListArg {
	return SocialInviteListArg{}
}
func (s SocialInviteListArg) Export() *SocialInviteListArgInternal__ {
	return &SocialInviteListArgInternal__{}
}
func (s *SocialInviteListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteListArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteListArg) Bytes() []byte { return nil }

type SocialInviteFetchArg struct {
	Host lib.TCPAddr
	Seed lib.SocialInviteSeed
}
type SocialInviteFetchArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.TCPAddrInternal__
	Seed    *lib.SocialInviteSeedInternal__
}

func (s SocialInviteFetchArgInternal__) Import() SocialInviteFetchArg {
	return SocialInviteFetchArg{
		Host: (func(x *lib.TCPAddrInternal__) (ret lib.TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Host),
		Seed: (func(x *lib.SocialInviteSeedInternal__) (ret lib.SocialInviteSeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
	}
}
func (s SocialInviteFetchArg) Export() *SocialInviteFetchArgInternal__ {
	return &SocialInviteFetchArgInternal__{
		Host: s.Host.Export(),
		Seed: s.Seed.Export(),
	}
}
func (s *SocialInviteFetchArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteFetchArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteFetchArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteFetchArg) Bytes() []byte { return nil }

type SocialInviteReplyArg struct {
	Seed      lib.SocialInviteSeed
	InReplyTo uint64
	Text      string
}
type SocialInviteReplyArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seed      *lib.SocialInviteSeedInternal__
	InReplyTo *uint64
	Text      *string
}

func (s SocialInviteReplyArgInternal__) Import() SocialInviteReplyArg {
	return SocialInviteReplyArg{
		Seed: (func(x *lib.SocialInviteSeedInternal__) (ret lib.SocialInviteSeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
		InReplyTo: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.InReplyTo),
		Text: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Text),
	}
}
func (s SocialInviteReplyArg) Export() *SocialInviteReplyArgInternal__ {
	return &SocialInviteReplyArgInternal__{
		Seed:      s.Seed.Export(),
		InReplyTo: &s.InReplyTo,
		Text:      &s.Text,
	}
}
func (s *SocialInviteReplyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteReplyArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteReplyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteReplyArg) Bytes() []byte { return nil }

type SocialInviteAskAgainArg struct {
	Seed lib.SocialInviteSeed
	Text string
}
type SocialInviteAskAgainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seed    *lib.SocialInviteSeedInternal__
	Text    *string
}

func (s SocialInviteAskAgainArgInternal__) Import() SocialInviteAskAgainArg {
	return SocialInviteAskAgainArg{
		Seed: (func(x *lib.SocialInviteSeedInternal__) (ret lib.SocialInviteSeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Seed),
		Text: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Text),
	}
}
func (s SocialInviteAskAgainArg) Export() *SocialInviteAskAgainArgInternal__ {
	return &SocialInviteAskAgainArgInternal__{
		Seed: s.Seed.Export(),
		Text: &s.Text,
	}
}
func (s *SocialInviteAskAgainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteAskAgainArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteAskAgainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteAskAgainArg) Bytes() []byte { return nil }

type SocialInviteCloseArg struct {
	Id lib.SocialInviteID
	St lib.SocialInviteState
}
type SocialInviteCloseArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.SocialInviteIDInternal__
	St      *lib.SocialInviteStateInternal__
}

func (s SocialInviteCloseArgInternal__) Import() SocialInviteCloseArg {
	return SocialInviteCloseArg{
		Id: (func(x *lib.SocialInviteIDInternal__) (ret lib.SocialInviteID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		St: (func(x *lib.SocialInviteStateInternal__) (ret lib.SocialInviteState) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.St),
	}
}
func (s SocialInviteCloseArg) Export() *SocialInviteCloseArgInternal__ {
	return &SocialInviteCloseArgInternal__{
		Id: s.Id.Export(),
		St: s.St.Export(),
	}
}
func (s *SocialInviteCloseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SocialInviteCloseArg) Decode(dec rpc.Decoder) error {
	var tmp SocialInviteCloseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SocialInviteCloseArg) Bytes() []byte { return nil }

type SocialInviteInterface interface {
	SocialInviteCreate(context.Context, SocialInviteCreateArg) (SocialInviteCreateRes, error)
	SocialInviteList(context.Context) ([]SocialInviteLocalRow, error)
	SocialInviteFetch(context.Context, SocialInviteFetchArg) (SocialInviteLocalView, error)
	SocialInviteReply(context.Context, SocialInviteReplyArg) error
	SocialInviteAskAgain(context.Context, SocialInviteAskAgainArg) error
	SocialInviteClose(context.Context, SocialInviteCloseArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
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
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c SocialInviteClient) SocialInviteCreate(ctx context.Context, arg SocialInviteCreateArg) (res SocialInviteCreateRes, err error) {
	warg := &rpc.DataWrap[Header, *SocialInviteCreateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SocialInviteCreateResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 0, "SocialInvite.socialInviteCreate"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) SocialInviteList(ctx context.Context) (res []SocialInviteLocalRow, err error) {
	var arg SocialInviteListArg
	warg := &rpc.DataWrap[Header, *SocialInviteListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, [](*SocialInviteLocalRowInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 1, "SocialInvite.socialInviteList"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*SocialInviteLocalRowInternal__)) (ret []SocialInviteLocalRow) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]SocialInviteLocalRow, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *SocialInviteLocalRowInternal__) (ret SocialInviteLocalRow) {
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
func (c SocialInviteClient) SocialInviteFetch(ctx context.Context, arg SocialInviteFetchArg) (res SocialInviteLocalView, err error) {
	warg := &rpc.DataWrap[Header, *SocialInviteFetchArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SocialInviteLocalViewInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 2, "SocialInvite.socialInviteFetch"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) SocialInviteReply(ctx context.Context, arg SocialInviteReplyArg) (err error) {
	warg := &rpc.DataWrap[Header, *SocialInviteReplyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 3, "SocialInvite.socialInviteReply"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) SocialInviteAskAgain(ctx context.Context, arg SocialInviteAskAgainArg) (err error) {
	warg := &rpc.DataWrap[Header, *SocialInviteAskAgainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 4, "SocialInvite.socialInviteAskAgain"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c SocialInviteClient) SocialInviteClose(ctx context.Context, arg SocialInviteCloseArg) (err error) {
	warg := &rpc.DataWrap[Header, *SocialInviteCloseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(SocialInviteProtocolID, 5, "SocialInvite.socialInviteClose"), warg, &tmp, 0*time.Millisecond, socialInviteErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
						var ret rpc.DataWrap[Header, *SocialInviteCreateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteCreateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteCreateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.SocialInviteCreate(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SocialInviteCreateResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "socialInviteCreate",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SocialInviteListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.SocialInviteList(ctx)
						if err != nil {
							return nil, err
						}
						lst := (func(x []SocialInviteLocalRow) *[](*SocialInviteLocalRowInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*SocialInviteLocalRowInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[Header, [](*SocialInviteLocalRowInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "socialInviteList",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SocialInviteFetchArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteFetchArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteFetchArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.SocialInviteFetch(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SocialInviteLocalViewInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "socialInviteFetch",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SocialInviteReplyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteReplyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteReplyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SocialInviteReply(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "socialInviteReply",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SocialInviteAskAgainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteAskAgainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteAskAgainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SocialInviteAskAgain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "socialInviteAskAgain",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SocialInviteCloseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SocialInviteCloseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SocialInviteCloseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SocialInviteClose(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "socialInviteClose",
			},
		},
		WrapError: SocialInviteMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(SocialInviteProtocolID)
}
