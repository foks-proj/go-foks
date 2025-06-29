package libclient

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type teamChangeRolesPartyLoader struct {
	tm    *TeamMinder
	tr    *TeamRecord
	res   []proto.MemberRole
	hepks *core.HEPKSet
}

func (t *teamChangeRolesPartyLoader) loadOne(
	m MetaContext,
	pos int,
	change lcl.RoleChange,
) error {
	lmr, err := t.tr.tw.LookupMember(m, change.Member.Fqp, change.Member.Role)
	if err != nil {
		return core.TeamRosterError(
			fmt.Sprintf("for member at position %d: %s", pos, err),
		)
	}

	none, err := change.NewRole.IsNone()
	if err != nil {
		return err
	}

	if none {
		lmr.Mem.Keys = proto.NewMemberKeysWithNone()
	} else if lmr.Hepk != nil {
		err = t.hepks.Add(*lmr.Hepk)
		if err != nil {
			return err
		}
	}
	t.res = append(t.res, proto.MemberRole{
		DstRole: change.NewRole,
		Member:  lmr.Mem,
	})
	return nil
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

func (t *TeamMinder) TeamChangeRoles(
	m MetaContext,
	arg lcl.TeamChangeRolesArg,
) error {
	// We need to load members so we can (1) lookup them up by name;
	// and (2) key for them on rekey
	err := t.withLoadedTeamAndAdminToken(
		m,
		arg.Team,
		LoadTeamOpts{LoadMembers: true, Refresh: true},
		func(m MetaContext, tr *TeamRecord, tok *rem.TeamBearerToken) error {
			cli, err := t.au.TeamAdminClient(m)
			if err != nil {
				return err
			}
			cfg, err := t.loadConfig(m, cli)
			if err != nil {
				return err
			}
			rows, hepks, err := t.teamChangeRolesLoadChanges(m, tr, arg.Changes)
			if err != nil {
				return err
			}

			tr.Lock()
			defer tr.Unlock()

			editor := TeamEditor{
				tl:      tr.ldr,
				tw:      tr.tw,
				id:      tr.ldr.TeamID(),
				tok:     tok,
				pre:     tr.ldr.rosterPost,
				cp:      tr.member,
				hepks:   hepks,
				changes: rows,
				cfg:     cfg,
			}

			return editor.Run(m)
		})

	if err != nil {
		return err
	}
	return nil
}
