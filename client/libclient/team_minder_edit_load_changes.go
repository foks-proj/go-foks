package libclient

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type teamChangeRolesPartyLoader struct {
	tm    *TeamMinder
	tr    *TeamRecord
	res   []proto.MemberRole
	hepks *core.HEPKSet
}

func (t *teamChangeRolesPartyLoader) checkPartySrcRole(
	m MetaContext,
	pos int,
	party proto.FQParty,
	givenSrcRole *proto.Role,
) (
	*proto.Role,
	error,
) {
	foundSrcRoles, err := t.tr.Tw().GetSourceRolesForParty(party)
	if err != nil {
		return nil, err
	}
	if len(foundSrcRoles) == 0 {
		return nil, core.TeamRosterError(
			fmt.Sprintf("party at position %d not found in team roster", pos),
		)
	}
	if len(foundSrcRoles) == 1 && givenSrcRole == nil {
		givenSrcRole = &foundSrcRoles[0]
		return givenSrcRole, nil
	}

	if len(foundSrcRoles) > 1 && givenSrcRole == nil {
		return nil, core.TeamRosterError(
			fmt.Sprintf("party at position %d is ambiguous, since has multiple roles", pos),
		)
	}

	for _, r := range foundSrcRoles {
		eq, err := r.Eq(*givenSrcRole)
		if err != nil {
			return nil, err
		}
		if eq {
			return givenSrcRole, nil
		}
	}
	return nil, core.TeamRosterError(
		fmt.Sprintf("party at position %d with given source role not found in team", pos),
	)
}

func (t *teamChangeRolesPartyLoader) loadUser(
	m MetaContext,
	pos int,
	user *proto.FQUserParsed,
	srcRole *proto.Role,
	newRole proto.Role,
) error {
	uw, err := LoadUserByFQUserParsed(m, *user)
	if err != nil {
		return err
	}
	srcRole, err = t.checkPartySrcRole(m, pos, uw.fqu.FQParty(), srcRole)
	if err != nil {
		return err
	}
	srk, err := core.ImportRole(*srcRole)
	if err != nil {
		return err
	}
	tmk, hepk, err := uw.TeamMemberKeys(*srk)
	if err != nil {
		return err
	}

	id := uw.fqu.ToFQEntity().AtHost(t.tr.FQT().Host)
	mr := proto.MemberRole{
		DstRole: newRole,
		Member: proto.Member{
			Id:      id,
			SrcRole: *srcRole,
		},
	}

	none, err := newRole.IsNone()
	if err != nil {
		return err
	}

	if !none {
		mr.Member.Keys = proto.NewMemberKeysWithTeam(*tmk)
		err = t.hepks.Add(*hepk)
		if err != nil {
			return err
		}
	}
	t.res = append(t.res, mr)

	return nil
}

func (t *teamChangeRolesPartyLoader) loadTeam(
	m MetaContext,
	pos int,
	team *proto.FQTeamParsed,
	srcRole *proto.Role,
	newRole proto.Role,
) error {
	return t.tm.withLoadedTeam(
		m,
		*team,
		LoadTeamOpts{LoadMembers: false, Refresh: true},
		func(m MetaContext, tr *TeamRecord) error {

			srcRole, err := t.checkPartySrcRole(m, pos, tr.FQT().FQParty(), srcRole)
			if err != nil {
				return err
			}
			srk, err := core.ImportRole(*srcRole)
			if err != nil {
				return err
			}
			id := tr.FQT().ToFQEntity().AtHost(t.tr.FQT().Host)
			tmk, hepk, err := tr.tw.TeamMemberKeys(*srk)
			if err != nil {
				return err
			}
			mr := proto.MemberRole{
				DstRole: newRole,
				Member: proto.Member{
					Id:      id,
					SrcRole: *srcRole,
				},
			}
			none, err := newRole.IsNone()
			if err != nil {
				return err
			}
			if !none {
				mr.Member.Keys = proto.NewMemberKeysWithTeam(*tmk)
				err = t.hepks.Add(*hepk)
				if err != nil {
					return err
				}
			}
			t.res = append(t.res, mr)
			return nil
		},
	)
}

func (t *teamChangeRolesPartyLoader) loadOne(
	m MetaContext,
	pos int,
	change lcl.RoleChange,
) error {

	user, team, err := change.Member.Fqp.Select()
	if err != nil {
		return err
	}
	switch {
	case user != nil:
		return t.loadUser(m, pos, user, change.Member.Role, change.NewRole)
	case team != nil:
		return t.loadTeam(m, pos, team, change.Member.Role, change.NewRole)
	default:
		return core.InternalError("no user or team")
	}
}

func (t *teamChangeRolesPartyLoader) run(
	m MetaContext,
	changes []lcl.RoleChange,
) error {
	for pos, change := range changes {
		if err := t.loadOne(m, pos, change); err != nil {
			return err
		}
	}
	return nil
}

func (t *TeamMinder) teamChangeRolesLoadChanges(
	m MetaContext,
	tr *TeamRecord,
	changes []lcl.RoleChange,
) (
	[]proto.MemberRole,
	*core.HEPKSet,
	error,
) {
	ldr := &teamChangeRolesPartyLoader{
		tm:    t,
		tr:    tr,
		res:   make([]proto.MemberRole, 0, len(changes)),
		hepks: core.NewHEPKSet(),
	}
	err := ldr.run(m, changes)
	if err != nil {
		return nil, nil, err
	}
	return ldr.res, ldr.hepks, nil
}
