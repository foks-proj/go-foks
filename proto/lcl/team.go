// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/team.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type TeamCreateRes struct {
	Id lib.TeamID
}
type TeamCreateResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.TeamIDInternal__
}

func (t TeamCreateResInternal__) Import() TeamCreateRes {
	return TeamCreateRes{
		Id: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Id),
	}
}
func (t TeamCreateRes) Export() *TeamCreateResInternal__ {
	return &TeamCreateResInternal__{
		Id: t.Id.Export(),
	}
}
func (t *TeamCreateRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCreateRes) Decode(dec rpc.Decoder) error {
	var tmp TeamCreateResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamCreateRes) Bytes() []byte { return nil }

type NamedFQParty struct {
	Fqp  lib.FQParty
	Name lib.NameUtf8
	Host lib.Hostname
}
type NamedFQPartyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqp     *lib.FQPartyInternal__
	Name    *lib.NameUtf8Internal__
	Host    *lib.HostnameInternal__
}

func (n NamedFQPartyInternal__) Import() NamedFQParty {
	return NamedFQParty{
		Fqp: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Fqp),
		Name: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Name),
		Host: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Host),
	}
}
func (n NamedFQParty) Export() *NamedFQPartyInternal__ {
	return &NamedFQPartyInternal__{
		Fqp:  n.Fqp.Export(),
		Name: n.Name.Export(),
		Host: n.Host.Export(),
	}
}
func (n *NamedFQParty) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NamedFQParty) Decode(dec rpc.Decoder) error {
	var tmp NamedFQPartyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NamedFQParty) Bytes() []byte { return nil }

type ChainDate struct {
	Seqno lib.Seqno
	Time  lib.Time
}
type ChainDateInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *lib.SeqnoInternal__
	Time    *lib.TimeInternal__
}

func (c ChainDateInternal__) Import() ChainDate {
	return ChainDate{
		Seqno: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Seqno),
		Time: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Time),
	}
}
func (c ChainDate) Export() *ChainDateInternal__ {
	return &ChainDateInternal__{
		Seqno: c.Seqno.Export(),
		Time:  c.Time.Export(),
	}
}
func (c *ChainDate) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChainDate) Decode(dec rpc.Decoder) error {
	var tmp ChainDateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChainDate) Bytes() []byte { return nil }

type TeamRosterMember struct {
	Mem        NamedFQParty
	SrcRole    lib.Role
	DstRole    lib.Role
	PtkGen     lib.Generation
	Added      ChainDate
	NumMembers int64
}
type TeamRosterMemberInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Mem        *NamedFQPartyInternal__
	SrcRole    *lib.RoleInternal__
	DstRole    *lib.RoleInternal__
	PtkGen     *lib.GenerationInternal__
	Added      *ChainDateInternal__
	NumMembers *int64
}

func (t TeamRosterMemberInternal__) Import() TeamRosterMember {
	return TeamRosterMember{
		Mem: (func(x *NamedFQPartyInternal__) (ret NamedFQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Mem),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		DstRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.DstRole),
		PtkGen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.PtkGen),
		Added: (func(x *ChainDateInternal__) (ret ChainDate) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Added),
		NumMembers: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(t.NumMembers),
	}
}
func (t TeamRosterMember) Export() *TeamRosterMemberInternal__ {
	return &TeamRosterMemberInternal__{
		Mem:        t.Mem.Export(),
		SrcRole:    t.SrcRole.Export(),
		DstRole:    t.DstRole.Export(),
		PtkGen:     t.PtkGen.Export(),
		Added:      t.Added.Export(),
		NumMembers: &t.NumMembers,
	}
}
func (t *TeamRosterMember) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRosterMember) Decode(dec rpc.Decoder) error {
	var tmp TeamRosterMemberInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRosterMember) Bytes() []byte { return nil }

type FQTeamParsedAndRole struct {
	Fqtp lib.FQTeamParsed
	Role lib.Role
}
type FQTeamParsedAndRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqtp    *lib.FQTeamParsedInternal__
	Role    *lib.RoleInternal__
}

func (f FQTeamParsedAndRoleInternal__) Import() FQTeamParsedAndRole {
	return FQTeamParsedAndRole{
		Fqtp: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Fqtp),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Role),
	}
}
func (f FQTeamParsedAndRole) Export() *FQTeamParsedAndRoleInternal__ {
	return &FQTeamParsedAndRoleInternal__{
		Fqtp: f.Fqtp.Export(),
		Role: f.Role.Export(),
	}
}
func (f *FQTeamParsedAndRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQTeamParsedAndRole) Decode(dec rpc.Decoder) error {
	var tmp FQTeamParsedAndRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQTeamParsedAndRole) Bytes() []byte { return nil }

type TeamRoster struct {
	Fqp     NamedFQParty
	Members []TeamRosterMember
}
type TeamRosterInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqp     *NamedFQPartyInternal__
	Members *[](*TeamRosterMemberInternal__)
}

func (t TeamRosterInternal__) Import() TeamRoster {
	return TeamRoster{
		Fqp: (func(x *NamedFQPartyInternal__) (ret NamedFQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Fqp),
		Members: (func(x *[](*TeamRosterMemberInternal__)) (ret []TeamRosterMember) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamRosterMember, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamRosterMemberInternal__) (ret TeamRosterMember) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Members),
	}
}
func (t TeamRoster) Export() *TeamRosterInternal__ {
	return &TeamRosterInternal__{
		Fqp: t.Fqp.Export(),
		Members: (func(x []TeamRosterMember) *[](*TeamRosterMemberInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamRosterMemberInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Members),
	}
}
func (t *TeamRoster) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRoster) Decode(dec rpc.Decoder) error {
	var tmp TeamRosterInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamRoster) Bytes() []byte { return nil }

type FQNamedTeam struct {
	Id   lib.FQTeam
	Name lib.NameUtf8
	Host lib.Hostname
}
type FQNamedTeamInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.FQTeamInternal__
	Name    *lib.NameUtf8Internal__
	Host    *lib.HostnameInternal__
}

func (f FQNamedTeamInternal__) Import() FQNamedTeam {
	return FQNamedTeam{
		Id: (func(x *lib.FQTeamInternal__) (ret lib.FQTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Id),
		Name: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Name),
		Host: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Host),
	}
}
func (f FQNamedTeam) Export() *FQNamedTeamInternal__ {
	return &FQNamedTeamInternal__{
		Id:   f.Id.Export(),
		Name: f.Name.Export(),
		Host: f.Host.Export(),
	}
}
func (f *FQNamedTeam) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQNamedTeam) Decode(dec rpc.Decoder) error {
	var tmp FQNamedTeamInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQNamedTeam) Bytes() []byte { return nil }

type TeamAcceptInviteRes struct {
	Tok  *lib.TeamRSVPRemote
	Team FQNamedTeam
}
type TeamAcceptInviteResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *lib.TeamRSVPRemoteInternal__
	Team    *FQNamedTeamInternal__
}

func (t TeamAcceptInviteResInternal__) Import() TeamAcceptInviteRes {
	return TeamAcceptInviteRes{
		Tok: (func(x *lib.TeamRSVPRemoteInternal__) *lib.TeamRSVPRemote {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.TeamRSVPRemoteInternal__) (ret lib.TeamRSVPRemote) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Tok),
		Team: (func(x *FQNamedTeamInternal__) (ret FQNamedTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamAcceptInviteRes) Export() *TeamAcceptInviteResInternal__ {
	return &TeamAcceptInviteResInternal__{
		Tok: (func(x *lib.TeamRSVPRemote) *lib.TeamRSVPRemoteInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Tok),
		Team: t.Team.Export(),
	}
}
func (t *TeamAcceptInviteRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamAcceptInviteRes) Decode(dec rpc.Decoder) error {
	var tmp TeamAcceptInviteResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamAcceptInviteRes) Bytes() []byte { return nil }

type TeamInboxRow struct {
	Time          lib.Time
	Status        lib.Status
	Tok           lib.TeamRSVP
	SrcRole       lib.Role
	Nfqp          NamedFQParty
	Tmk           lib.TeamMemberKeys
	Ptok          *lib.PermissionToken
	Hepks         lib.HEPKSet
	AutofixStatus *lib.Status
}
type TeamInboxRowInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Time          *lib.TimeInternal__
	Status        *lib.StatusInternal__
	Tok           *lib.TeamRSVPInternal__
	SrcRole       *lib.RoleInternal__
	Nfqp          *NamedFQPartyInternal__
	Tmk           *lib.TeamMemberKeysInternal__
	Ptok          *lib.PermissionTokenInternal__
	Hepks         *lib.HEPKSetInternal__
	AutofixStatus *lib.StatusInternal__
}

func (t TeamInboxRowInternal__) Import() TeamInboxRow {
	return TeamInboxRow{
		Time: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Time),
		Status: (func(x *lib.StatusInternal__) (ret lib.Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Status),
		Tok: (func(x *lib.TeamRSVPInternal__) (ret lib.TeamRSVP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		Nfqp: (func(x *NamedFQPartyInternal__) (ret NamedFQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Nfqp),
		Tmk: (func(x *lib.TeamMemberKeysInternal__) (ret lib.TeamMemberKeys) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tmk),
		Ptok: (func(x *lib.PermissionTokenInternal__) *lib.PermissionToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Ptok),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Hepks),
		AutofixStatus: (func(x *lib.StatusInternal__) *lib.Status {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.StatusInternal__) (ret lib.Status) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.AutofixStatus),
	}
}
func (t TeamInboxRow) Export() *TeamInboxRowInternal__ {
	return &TeamInboxRowInternal__{
		Time:    t.Time.Export(),
		Status:  t.Status.Export(),
		Tok:     t.Tok.Export(),
		SrcRole: t.SrcRole.Export(),
		Nfqp:    t.Nfqp.Export(),
		Tmk:     t.Tmk.Export(),
		Ptok: (func(x *lib.PermissionToken) *lib.PermissionTokenInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Ptok),
		Hepks: t.Hepks.Export(),
		AutofixStatus: (func(x *lib.Status) *lib.StatusInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.AutofixStatus),
	}
}
func (t *TeamInboxRow) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInboxRow) Decode(dec rpc.Decoder) error {
	var tmp TeamInboxRowInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamInboxRow) Bytes() []byte { return nil }

type TeamInboxReject struct {
	Fpq    lib.FQParty
	Status lib.Status
}
type TeamInboxRejectInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fpq     *lib.FQPartyInternal__
	Status  *lib.StatusInternal__
}

func (t TeamInboxRejectInternal__) Import() TeamInboxReject {
	return TeamInboxReject{
		Fpq: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Fpq),
		Status: (func(x *lib.StatusInternal__) (ret lib.Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Status),
	}
}
func (t TeamInboxReject) Export() *TeamInboxRejectInternal__ {
	return &TeamInboxRejectInternal__{
		Fpq:    t.Fpq.Export(),
		Status: t.Status.Export(),
	}
}
func (t *TeamInboxReject) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInboxReject) Decode(dec rpc.Decoder) error {
	var tmp TeamInboxRejectInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamInboxReject) Bytes() []byte { return nil }

type TeamInbox struct {
	Rows []TeamInboxRow
}
type TeamInboxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rows    *[](*TeamInboxRowInternal__)
}

func (t TeamInboxInternal__) Import() TeamInbox {
	return TeamInbox{
		Rows: (func(x *[](*TeamInboxRowInternal__)) (ret []TeamInboxRow) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamInboxRow, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamInboxRowInternal__) (ret TeamInboxRow) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Rows),
	}
}
func (t TeamInbox) Export() *TeamInboxInternal__ {
	return &TeamInboxInternal__{
		Rows: (func(x []TeamInboxRow) *[](*TeamInboxRowInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamInboxRowInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Rows),
	}
}
func (t *TeamInbox) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInbox) Decode(dec rpc.Decoder) error {
	var tmp TeamInboxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamInbox) Bytes() []byte { return nil }

type TokRole struct {
	Tok  lib.TeamRSVP
	Role lib.Role
}
type TokRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Tok     *lib.TeamRSVPInternal__
	Role    *lib.RoleInternal__
}

func (t TokRoleInternal__) Import() TokRole {
	return TokRole{
		Tok: (func(x *lib.TeamRSVPInternal__) (ret lib.TeamRSVP) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tok),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Role),
	}
}
func (t TokRole) Export() *TokRoleInternal__ {
	return &TokRoleInternal__{
		Tok:  t.Tok.Export(),
		Role: t.Role.Export(),
	}
}
func (t *TokRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TokRole) Decode(dec rpc.Decoder) error {
	var tmp TokRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TokRole) Bytes() []byte { return nil }

type FQPartyAndRoleString string
type FQPartyAndRoleStringInternal__ string

func (f FQPartyAndRoleString) Export() *FQPartyAndRoleStringInternal__ {
	tmp := ((string)(f))
	return ((*FQPartyAndRoleStringInternal__)(&tmp))
}
func (f FQPartyAndRoleStringInternal__) Import() FQPartyAndRoleString {
	tmp := (string)(f)
	return FQPartyAndRoleString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FQPartyAndRoleString) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQPartyAndRoleString) Decode(dec rpc.Decoder) error {
	var tmp FQPartyAndRoleStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FQPartyAndRoleString) Bytes() []byte {
	return nil
}

type RoleChangeString string
type RoleChangeStringInternal__ string

func (r RoleChangeString) Export() *RoleChangeStringInternal__ {
	tmp := ((string)(r))
	return ((*RoleChangeStringInternal__)(&tmp))
}
func (r RoleChangeStringInternal__) Import() RoleChangeString {
	tmp := (string)(r)
	return RoleChangeString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RoleChangeString) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleChangeString) Decode(dec rpc.Decoder) error {
	var tmp RoleChangeStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RoleChangeString) Bytes() []byte {
	return nil
}

type FQPartyParsedAndRole struct {
	Fqp  lib.FQPartyParsed
	Role *lib.Role
}
type FQPartyParsedAndRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqp     *lib.FQPartyParsedInternal__
	Role    *lib.RoleInternal__
}

func (f FQPartyParsedAndRoleInternal__) Import() FQPartyParsedAndRole {
	return FQPartyParsedAndRole{
		Fqp: (func(x *lib.FQPartyParsedInternal__) (ret lib.FQPartyParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Fqp),
		Role: (func(x *lib.RoleInternal__) *lib.Role {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RoleInternal__) (ret lib.Role) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(f.Role),
	}
}
func (f FQPartyParsedAndRole) Export() *FQPartyParsedAndRoleInternal__ {
	return &FQPartyParsedAndRoleInternal__{
		Fqp: f.Fqp.Export(),
		Role: (func(x *lib.Role) *lib.RoleInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(f.Role),
	}
}
func (f *FQPartyParsedAndRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQPartyParsedAndRole) Decode(dec rpc.Decoder) error {
	var tmp FQPartyParsedAndRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQPartyParsedAndRole) Bytes() []byte { return nil }

type RoleChange struct {
	Member  FQPartyParsedAndRole
	NewRole lib.Role
}
type RoleChangeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Member  *FQPartyParsedAndRoleInternal__
	NewRole *lib.RoleInternal__
}

func (r RoleChangeInternal__) Import() RoleChange {
	return RoleChange{
		Member: (func(x *FQPartyParsedAndRoleInternal__) (ret FQPartyParsedAndRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Member),
		NewRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.NewRole),
	}
}
func (r RoleChange) Export() *RoleChangeInternal__ {
	return &RoleChangeInternal__{
		Member:  r.Member.Export(),
		NewRole: r.NewRole.Export(),
	}
}
func (r *RoleChange) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleChange) Decode(dec rpc.Decoder) error {
	var tmp RoleChangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RoleChange) Bytes() []byte { return nil }

type TeamMembership struct {
	Team    NamedFQParty
	SrcRole lib.Role
	DstRole lib.Role
	Via     *NamedFQParty
	Tir     lib.RationalRange
}
type TeamMembershipInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *NamedFQPartyInternal__
	SrcRole *lib.RoleInternal__
	DstRole *lib.RoleInternal__
	Via     *NamedFQPartyInternal__
	Tir     *lib.RationalRangeInternal__
}

func (t TeamMembershipInternal__) Import() TeamMembership {
	return TeamMembership{
		Team: (func(x *NamedFQPartyInternal__) (ret NamedFQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.SrcRole),
		DstRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.DstRole),
		Via: (func(x *NamedFQPartyInternal__) *NamedFQParty {
			if x == nil {
				return nil
			}
			tmp := (func(x *NamedFQPartyInternal__) (ret NamedFQParty) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.Via),
		Tir: (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Tir),
	}
}
func (t TeamMembership) Export() *TeamMembershipInternal__ {
	return &TeamMembershipInternal__{
		Team:    t.Team.Export(),
		SrcRole: t.SrcRole.Export(),
		DstRole: t.DstRole.Export(),
		Via: (func(x *NamedFQParty) *NamedFQPartyInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.Via),
		Tir: t.Tir.Export(),
	}
}
func (t *TeamMembership) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamMembership) Decode(dec rpc.Decoder) error {
	var tmp TeamMembershipInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamMembership) Bytes() []byte { return nil }

type ListMembershipsRes struct {
	HomeHost lib.HostID
	Teams    []TeamMembership
}
type ListMembershipsResInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HomeHost *lib.HostIDInternal__
	Teams    *[](*TeamMembershipInternal__)
}

func (l ListMembershipsResInternal__) Import() ListMembershipsRes {
	return ListMembershipsRes{
		HomeHost: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.HomeHost),
		Teams: (func(x *[](*TeamMembershipInternal__)) (ret []TeamMembership) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TeamMembership, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TeamMembershipInternal__) (ret TeamMembership) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(l.Teams),
	}
}
func (l ListMembershipsRes) Export() *ListMembershipsResInternal__ {
	return &ListMembershipsResInternal__{
		HomeHost: l.HomeHost.Export(),
		Teams: (func(x []TeamMembership) *[](*TeamMembershipInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TeamMembershipInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(l.Teams),
	}
}
func (l *ListMembershipsRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *ListMembershipsRes) Decode(dec rpc.Decoder) error {
	var tmp ListMembershipsResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *ListMembershipsRes) Bytes() []byte { return nil }

type TokRoleString string
type TokRoleStringInternal__ string

func (t TokRoleString) Export() *TokRoleStringInternal__ {
	tmp := ((string)(t))
	return ((*TokRoleStringInternal__)(&tmp))
}
func (t TokRoleStringInternal__) Import() TokRoleString {
	tmp := (string)(t)
	return TokRoleString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TokRoleString) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TokRoleString) Decode(dec rpc.Decoder) error {
	var tmp TokRoleStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TokRoleString) Bytes() []byte {
	return nil
}

var TeamProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xa7b878de)

type TeamCreateArg struct {
	NameUtf8 lib.NameUtf8
}
type TeamCreateArgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	NameUtf8 *lib.NameUtf8Internal__
}

func (t TeamCreateArgInternal__) Import() TeamCreateArg {
	return TeamCreateArg{
		NameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.NameUtf8),
	}
}
func (t TeamCreateArg) Export() *TeamCreateArgInternal__ {
	return &TeamCreateArgInternal__{
		NameUtf8: t.NameUtf8.Export(),
	}
}
func (t *TeamCreateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCreateArg) Decode(dec rpc.Decoder) error {
	var tmp TeamCreateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamCreateArg) Bytes() []byte { return nil }

type TeamListArg struct {
	Team lib.FQTeamParsed
}
type TeamListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamListArgInternal__) Import() TeamListArg {
	return TeamListArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamListArg) Export() *TeamListArgInternal__ {
	return &TeamListArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamListArg) Decode(dec rpc.Decoder) error {
	var tmp TeamListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamListArg) Bytes() []byte { return nil }

type TeamCreateInviteArg struct {
	Team lib.FQTeamParsed
}
type TeamCreateInviteArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamCreateInviteArgInternal__) Import() TeamCreateInviteArg {
	return TeamCreateInviteArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamCreateInviteArg) Export() *TeamCreateInviteArgInternal__ {
	return &TeamCreateInviteArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamCreateInviteArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamCreateInviteArg) Decode(dec rpc.Decoder) error {
	var tmp TeamCreateInviteArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamCreateInviteArg) Bytes() []byte { return nil }

type TeamAcceptInviteArg struct {
	I        lib.TeamInvite
	ActingAs *FQTeamParsedAndRole
}
type TeamAcceptInviteArgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	I        *lib.TeamInviteInternal__
	ActingAs *FQTeamParsedAndRoleInternal__
}

func (t TeamAcceptInviteArgInternal__) Import() TeamAcceptInviteArg {
	return TeamAcceptInviteArg{
		I: (func(x *lib.TeamInviteInternal__) (ret lib.TeamInvite) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.I),
		ActingAs: (func(x *FQTeamParsedAndRoleInternal__) *FQTeamParsedAndRole {
			if x == nil {
				return nil
			}
			tmp := (func(x *FQTeamParsedAndRoleInternal__) (ret FQTeamParsedAndRole) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.ActingAs),
	}
}
func (t TeamAcceptInviteArg) Export() *TeamAcceptInviteArgInternal__ {
	return &TeamAcceptInviteArgInternal__{
		I: t.I.Export(),
		ActingAs: (func(x *FQTeamParsedAndRole) *FQTeamParsedAndRoleInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.ActingAs),
	}
}
func (t *TeamAcceptInviteArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamAcceptInviteArg) Decode(dec rpc.Decoder) error {
	var tmp TeamAcceptInviteArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamAcceptInviteArg) Bytes() []byte { return nil }

type TeamInboxArg struct {
	Team lib.FQTeamParsed
}
type TeamInboxArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamInboxArgInternal__) Import() TeamInboxArg {
	return TeamInboxArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamInboxArg) Export() *TeamInboxArgInternal__ {
	return &TeamInboxArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamInboxArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamInboxArg) Decode(dec rpc.Decoder) error {
	var tmp TeamInboxArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamInboxArg) Bytes() []byte { return nil }

type TeamAdmitArg struct {
	Team    lib.FQTeamParsed
	Members []TokRole
}
type TeamAdmitArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Members *[](*TokRoleInternal__)
}

func (t TeamAdmitArgInternal__) Import() TeamAdmitArg {
	return TeamAdmitArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Members: (func(x *[](*TokRoleInternal__)) (ret []TokRole) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]TokRole, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *TokRoleInternal__) (ret TokRole) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Members),
	}
}
func (t TeamAdmitArg) Export() *TeamAdmitArgInternal__ {
	return &TeamAdmitArgInternal__{
		Team: t.Team.Export(),
		Members: (func(x []TokRole) *[](*TokRoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*TokRoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Members),
	}
}
func (t *TeamAdmitArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamAdmitArg) Decode(dec rpc.Decoder) error {
	var tmp TeamAdmitArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamAdmitArg) Bytes() []byte { return nil }

type TeamIndexRangeGetArg struct {
	Team lib.FQTeamParsed
}
type TeamIndexRangeGetArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamIndexRangeGetArgInternal__) Import() TeamIndexRangeGetArg {
	return TeamIndexRangeGetArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamIndexRangeGetArg) Export() *TeamIndexRangeGetArgInternal__ {
	return &TeamIndexRangeGetArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamIndexRangeGetArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeGetArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeGetArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeGetArg) Bytes() []byte { return nil }

type TeamIndexRangeLowerArg struct {
	Team lib.FQTeamParsed
}
type TeamIndexRangeLowerArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamIndexRangeLowerArgInternal__) Import() TeamIndexRangeLowerArg {
	return TeamIndexRangeLowerArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamIndexRangeLowerArg) Export() *TeamIndexRangeLowerArgInternal__ {
	return &TeamIndexRangeLowerArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamIndexRangeLowerArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeLowerArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeLowerArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeLowerArg) Bytes() []byte { return nil }

type TeamIndexRangeRaiseArg struct {
	Team lib.FQTeamParsed
}
type TeamIndexRangeRaiseArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
}

func (t TeamIndexRangeRaiseArgInternal__) Import() TeamIndexRangeRaiseArg {
	return TeamIndexRangeRaiseArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
	}
}
func (t TeamIndexRangeRaiseArg) Export() *TeamIndexRangeRaiseArgInternal__ {
	return &TeamIndexRangeRaiseArgInternal__{
		Team: t.Team.Export(),
	}
}
func (t *TeamIndexRangeRaiseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeRaiseArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeRaiseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeRaiseArg) Bytes() []byte { return nil }

type TeamIndexRangeSetArg struct {
	Team  lib.FQTeamParsed
	Range lib.RationalRange
}
type TeamIndexRangeSetArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Range   *lib.RationalRangeInternal__
}

func (t TeamIndexRangeSetArgInternal__) Import() TeamIndexRangeSetArg {
	return TeamIndexRangeSetArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Range: (func(x *lib.RationalRangeInternal__) (ret lib.RationalRange) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Range),
	}
}
func (t TeamIndexRangeSetArg) Export() *TeamIndexRangeSetArgInternal__ {
	return &TeamIndexRangeSetArgInternal__{
		Team:  t.Team.Export(),
		Range: t.Range.Export(),
	}
}
func (t *TeamIndexRangeSetArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeSetArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeSetArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeSetArg) Bytes() []byte { return nil }

type TeamIndexRangeSetLowArg struct {
	Team lib.FQTeamParsed
	Low  lib.Rational
}
type TeamIndexRangeSetLowArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Low     *lib.RationalInternal__
}

func (t TeamIndexRangeSetLowArgInternal__) Import() TeamIndexRangeSetLowArg {
	return TeamIndexRangeSetLowArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Low: (func(x *lib.RationalInternal__) (ret lib.Rational) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Low),
	}
}
func (t TeamIndexRangeSetLowArg) Export() *TeamIndexRangeSetLowArgInternal__ {
	return &TeamIndexRangeSetLowArgInternal__{
		Team: t.Team.Export(),
		Low:  t.Low.Export(),
	}
}
func (t *TeamIndexRangeSetLowArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeSetLowArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeSetLowArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeSetLowArg) Bytes() []byte { return nil }

type TeamIndexRangeSetHighArg struct {
	Team lib.FQTeamParsed
	High lib.Rational
}
type TeamIndexRangeSetHighArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	High    *lib.RationalInternal__
}

func (t TeamIndexRangeSetHighArgInternal__) Import() TeamIndexRangeSetHighArg {
	return TeamIndexRangeSetHighArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		High: (func(x *lib.RationalInternal__) (ret lib.Rational) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.High),
	}
}
func (t TeamIndexRangeSetHighArg) Export() *TeamIndexRangeSetHighArgInternal__ {
	return &TeamIndexRangeSetHighArgInternal__{
		Team: t.Team.Export(),
		High: t.High.Export(),
	}
}
func (t *TeamIndexRangeSetHighArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamIndexRangeSetHighArg) Decode(dec rpc.Decoder) error {
	var tmp TeamIndexRangeSetHighArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamIndexRangeSetHighArg) Bytes() []byte { return nil }

type TeamListMembershipsArg struct {
}
type TeamListMembershipsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (t TeamListMembershipsArgInternal__) Import() TeamListMembershipsArg {
	return TeamListMembershipsArg{}
}
func (t TeamListMembershipsArg) Export() *TeamListMembershipsArgInternal__ {
	return &TeamListMembershipsArgInternal__{}
}
func (t *TeamListMembershipsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamListMembershipsArg) Decode(dec rpc.Decoder) error {
	var tmp TeamListMembershipsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamListMembershipsArg) Bytes() []byte { return nil }

type TeamAddArg struct {
	Team    lib.FQTeamParsed
	Members []FQPartyParsedAndRole
	DstRole *lib.Role
}
type TeamAddArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Members *[](*FQPartyParsedAndRoleInternal__)
	DstRole *lib.RoleInternal__
}

func (t TeamAddArgInternal__) Import() TeamAddArg {
	return TeamAddArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Members: (func(x *[](*FQPartyParsedAndRoleInternal__)) (ret []FQPartyParsedAndRole) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]FQPartyParsedAndRole, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *FQPartyParsedAndRoleInternal__) (ret FQPartyParsedAndRole) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Members),
		DstRole: (func(x *lib.RoleInternal__) *lib.Role {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.RoleInternal__) (ret lib.Role) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(t.DstRole),
	}
}
func (t TeamAddArg) Export() *TeamAddArgInternal__ {
	return &TeamAddArgInternal__{
		Team: t.Team.Export(),
		Members: (func(x []FQPartyParsedAndRole) *[](*FQPartyParsedAndRoleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*FQPartyParsedAndRoleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Members),
		DstRole: (func(x *lib.Role) *lib.RoleInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(t.DstRole),
	}
}
func (t *TeamAddArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamAddArg) Decode(dec rpc.Decoder) error {
	var tmp TeamAddArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamAddArg) Bytes() []byte { return nil }

type TeamChangeRolesArg struct {
	Team    lib.FQTeamParsed
	Changes []RoleChange
}
type TeamChangeRolesArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *lib.FQTeamParsedInternal__
	Changes *[](*RoleChangeInternal__)
}

func (t TeamChangeRolesArgInternal__) Import() TeamChangeRolesArg {
	return TeamChangeRolesArg{
		Team: (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Team),
		Changes: (func(x *[](*RoleChangeInternal__)) (ret []RoleChange) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]RoleChange, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *RoleChangeInternal__) (ret RoleChange) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Changes),
	}
}
func (t TeamChangeRolesArg) Export() *TeamChangeRolesArgInternal__ {
	return &TeamChangeRolesArgInternal__{
		Team: t.Team.Export(),
		Changes: (func(x []RoleChange) *[](*RoleChangeInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*RoleChangeInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Changes),
	}
}
func (t *TeamChangeRolesArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamChangeRolesArg) Decode(dec rpc.Decoder) error {
	var tmp TeamChangeRolesArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TeamChangeRolesArg) Bytes() []byte { return nil }

type TeamInterface interface {
	TeamCreate(context.Context, lib.NameUtf8) (TeamCreateRes, error)
	TeamList(context.Context, lib.FQTeamParsed) (TeamRoster, error)
	TeamCreateInvite(context.Context, lib.FQTeamParsed) (lib.TeamInvite, error)
	TeamAcceptInvite(context.Context, TeamAcceptInviteArg) (TeamAcceptInviteRes, error)
	TeamInbox(context.Context, lib.FQTeamParsed) (TeamInbox, error)
	TeamAdmit(context.Context, TeamAdmitArg) error
	TeamIndexRangeGet(context.Context, lib.FQTeamParsed) (lib.RationalRange, error)
	TeamIndexRangeLower(context.Context, lib.FQTeamParsed) (lib.RationalRange, error)
	TeamIndexRangeRaise(context.Context, lib.FQTeamParsed) (lib.RationalRange, error)
	TeamIndexRangeSet(context.Context, TeamIndexRangeSetArg) (lib.RationalRange, error)
	TeamIndexRangeSetLow(context.Context, TeamIndexRangeSetLowArg) (lib.RationalRange, error)
	TeamIndexRangeSetHigh(context.Context, TeamIndexRangeSetHighArg) (lib.RationalRange, error)
	TeamListMemberships(context.Context) (ListMembershipsRes, error)
	TeamAdd(context.Context, TeamAddArg) error
	TeamChangeRoles(context.Context, TeamChangeRolesArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func TeamMakeGenericErrorWrapper(f TeamErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type TeamErrorUnwrapper func(lib.Status) error
type TeamErrorWrapper func(error) lib.Status

type teamErrorUnwrapperAdapter struct {
	h TeamErrorUnwrapper
}

func (t teamErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (t teamErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return t.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = teamErrorUnwrapperAdapter{}

type TeamClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper TeamErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c TeamClient) TeamCreate(ctx context.Context, nameUtf8 lib.NameUtf8) (res TeamCreateRes, err error) {
	arg := TeamCreateArg{
		NameUtf8: nameUtf8,
	}
	warg := &rpc.DataWrap[Header, *TeamCreateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, TeamCreateResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 0, "Team.teamCreate"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamList(ctx context.Context, team lib.FQTeamParsed) (res TeamRoster, err error) {
	arg := TeamListArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, TeamRosterInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 1, "Team.teamList"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamCreateInvite(ctx context.Context, team lib.FQTeamParsed) (res lib.TeamInvite, err error) {
	arg := TeamCreateInviteArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamCreateInviteArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.TeamInviteInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 2, "Team.teamCreateInvite"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamAcceptInvite(ctx context.Context, arg TeamAcceptInviteArg) (res TeamAcceptInviteRes, err error) {
	warg := &rpc.DataWrap[Header, *TeamAcceptInviteArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, TeamAcceptInviteResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 3, "Team.teamAcceptInvite"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamInbox(ctx context.Context, team lib.FQTeamParsed) (res TeamInbox, err error) {
	arg := TeamInboxArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamInboxArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, TeamInboxInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 4, "Team.teamInbox"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamAdmit(ctx context.Context, arg TeamAdmitArg) (err error) {
	warg := &rpc.DataWrap[Header, *TeamAdmitArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 5, "Team.teamAdmit"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeGet(ctx context.Context, team lib.FQTeamParsed) (res lib.RationalRange, err error) {
	arg := TeamIndexRangeGetArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamIndexRangeGetArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 6, "Team.teamIndexRangeGet"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeLower(ctx context.Context, team lib.FQTeamParsed) (res lib.RationalRange, err error) {
	arg := TeamIndexRangeLowerArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamIndexRangeLowerArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 7, "Team.teamIndexRangeLower"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeRaise(ctx context.Context, team lib.FQTeamParsed) (res lib.RationalRange, err error) {
	arg := TeamIndexRangeRaiseArg{
		Team: team,
	}
	warg := &rpc.DataWrap[Header, *TeamIndexRangeRaiseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 8, "Team.teamIndexRangeRaise"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeSet(ctx context.Context, arg TeamIndexRangeSetArg) (res lib.RationalRange, err error) {
	warg := &rpc.DataWrap[Header, *TeamIndexRangeSetArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 9, "Team.teamIndexRangeSet"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeSetLow(ctx context.Context, arg TeamIndexRangeSetLowArg) (res lib.RationalRange, err error) {
	warg := &rpc.DataWrap[Header, *TeamIndexRangeSetLowArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 10, "Team.teamIndexRangeSetLow"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamIndexRangeSetHigh(ctx context.Context, arg TeamIndexRangeSetHighArg) (res lib.RationalRange, err error) {
	warg := &rpc.DataWrap[Header, *TeamIndexRangeSetHighArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.RationalRangeInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 11, "Team.teamIndexRangeSetHigh"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamListMemberships(ctx context.Context) (res ListMembershipsRes, err error) {
	var arg TeamListMembershipsArg
	warg := &rpc.DataWrap[Header, *TeamListMembershipsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, ListMembershipsResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 12, "Team.teamListMemberships"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamAdd(ctx context.Context, arg TeamAddArg) (err error) {
	warg := &rpc.DataWrap[Header, *TeamAddArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 13, "Team.teamAdd"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c TeamClient) TeamChangeRoles(ctx context.Context, arg TeamChangeRolesArg) (err error) {
	warg := &rpc.DataWrap[Header, *TeamChangeRolesArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(TeamProtocolID, 14, "Team.teamChangeRoles"), warg, &tmp, 0*time.Millisecond, teamErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func TeamProtocol(i TeamInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Team",
		ID:   TeamProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamCreateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamCreateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamCreateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamCreate(ctx, (typedArg.Import()).NameUtf8)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *TeamCreateResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamCreate",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamList(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *TeamRosterInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamList",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamCreateInviteArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamCreateInviteArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamCreateInviteArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamCreateInvite(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.TeamInviteInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamCreateInvite",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamAcceptInviteArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamAcceptInviteArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamAcceptInviteArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamAcceptInvite(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *TeamAcceptInviteResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamAcceptInvite",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamInboxArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamInboxArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamInboxArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamInbox(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *TeamInboxInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamInbox",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamAdmitArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamAdmitArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamAdmitArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.TeamAdmit(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamAdmit",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeGetArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeGetArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeGetArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeGet(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeGet",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeLowerArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeLowerArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeLowerArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeLower(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeLower",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeRaiseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeRaiseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeRaiseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeRaise(ctx, (typedArg.Import()).Team)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeRaise",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeSetArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeSetArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeSetArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeSet(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeSet",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeSetLowArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeSetLowArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeSetLowArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeSetLow(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeSetLow",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamIndexRangeSetHighArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamIndexRangeSetHighArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamIndexRangeSetHighArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.TeamIndexRangeSetHigh(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.RationalRangeInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamIndexRangeSetHigh",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamListMembershipsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamListMembershipsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamListMembershipsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.TeamListMemberships(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *ListMembershipsResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamListMemberships",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamAddArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamAddArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamAddArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.TeamAdd(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamAdd",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *TeamChangeRolesArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *TeamChangeRolesArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *TeamChangeRolesArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.TeamChangeRoles(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "teamChangeRoles",
			},
		},
		WrapError: TeamMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(TeamProtocolID)
}
