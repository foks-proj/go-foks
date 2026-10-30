// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/foks-proj/go-foks/proto/lib"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type teamAdder struct {
	tm      *TeamMinder
	tr      *TeamRecord
	tok     *rem.TeamBearerToken
	mrs     []proto.MemberRole
	arg     lcl.TeamAddArg
	hepks   *core.HEPKSet
	dstRole proto.Role

	// On a host with closed user viewership, users are loaded on the team's
	// behalf, which the server allows only if the user granted the team a
	// local view permission (e.g. step 5 of docs/social_signup_spec.md).
	closedView bool
}

func (t *teamAdder) hostID() proto.HostID {
	return t.tr.FQT().Host
}

func newTeamAdder(tm *TeamMinder, tr *TeamRecord, tok *rem.TeamBearerToken, arg lcl.TeamAddArg) *teamAdder {
	return &teamAdder{
		tm:    tm,
		tr:    tr,
		tok:   tok,
		arg:   arg,
		hepks: core.NewHEPKSet(),
	}
}

func (t *teamAdder) loadMember(m MetaContext, u lcl.FQPartyParsedAndRole) error {
	user, team, err := u.Fqp.Select()
	if err != nil {
		return err
	}
	srcRole := core.Sel(user != nil, proto.OwnerRole, proto.DefaultRole)
	if u.Role != nil {
		srcRole = *u.Role
	}
	rk, err := core.ImportRole(srcRole)
	if err != nil {
		return err
	}
	switch {
	case user != nil && t.closedView:
		return t.loadUserAsTeam(m, *user, *rk)
	case user != nil:
		return t.loadUser(m, *user, *rk)
	case team != nil && t.closedView:
		return core.PermissionError("host does not allow open viewership; must use 3-way invitation flow")
	case team != nil:
		return t.loadTeam(m, *team, *rk)
	default:
		return core.InternalError("no user or team")
	}
}

func (t *teamAdder) loadTeam(m MetaContext, tm lib.FQTeamParsed, srcRole core.RoleKey) error {
	return t.tm.withLoadedTeam(
		m,
		tm,
		LoadTeamOpts{Refresh: true},
		func(m MetaContext, tr *TeamRecord) error {
			id := tr.FQT().ToFQEntity().AtHost(t.hostID())
			tmk, hepk, err := tr.tw.TeamMemberKeys(srcRole)
			if err != nil {
				return err
			}
			err = t.hepks.Add(*hepk)
			if err != nil {
				return err
			}
			mr := proto.MemberRole{
				DstRole: t.dstRole,
				Member: proto.Member{
					Id:      id,
					SrcRole: srcRole.Export(),
					Keys:    proto.NewMemberKeysWithTeam(*tmk),
				},
			}
			t.mrs = append(t.mrs, mr)
			return nil
		},
	)
}

func (t *teamAdder) loadUser(m MetaContext, u lib.FQUserParsed, srcRole core.RoleKey) error {
	uw, err := LoadUserByFQUserParsed(m, u)
	if err != nil {
		return err
	}
	return t.addUser(uw, srcRole)
}

// loadUserAsTeam loads a local user on the team's behalf, as the team inbox
// does for a joiner. Closed viewership refuses username resolution, so the
// user must be named by UID. A host may be named, but it must be the team's.
func (t *teamAdder) loadUserAsTeam(m MetaContext, u lib.FQUserParsed, srcRole core.RoleKey) error {
	arg, err := loadUserArgFromFQUserParsed(u)
	if err != nil {
		return err
	}
	if arg.Username != "" {
		return core.BadArgsError("host has closed viewership; add users by UID")
	}
	tw := t.tr.Tw()
	if arg.Host != nil {
		same := core.Sel(
			arg.Host.HostID.IsZero(),
			arg.Host.Addr.Hostname().NormEq(tw.Hostname()),
			arg.Host.HostID.Eq(t.hostID()),
		)
		if !same {
			return core.HostMismatchError{}
		}
		// A named host sends the loader down its remote path, which wants a
		// permission token rather than the team's view token.
		arg.Host = nil
	}
	tok := t.tr.ldr.Tok()
	if tok == nil {
		return core.InternalError("no team view token")
	}
	arg.LoadMode = LoadModeOthers
	arg.ActiveUser = t.tm.au
	arg.TeamVOBearerToken = tok

	// Members at the team's member-load floor load the roster with their own
	// token, so check the user's grant there rather than at our admin role.
	floor := tw.MemberLoadFloor()
	arg.AsTeamRole = &floor

	uw, err := LoadUser(m, arg)
	var perr core.PermissionError
	if errors.As(err, &perr) {
		return core.PermissionError(string(perr) + "; on a closed host the user must grant this team " +
			"a view permission at its member-load floor, or join through the team's invitation flow")
	}
	if err != nil {
		return err
	}
	return t.addUser(uw, srcRole)
}

func (t *teamAdder) addUser(uw *UserWrapper, srcRole core.RoleKey) error {
	if !uw.fqu.HostID.Eq(t.hostID()) {
		return core.HostMismatchError{}
	}
	id := uw.fqu.ToFQEntity().AtHost(t.hostID())
	tmk, hepk, err := uw.TeamMemberKeys(srcRole)
	if err != nil {
		return err
	}
	err = t.hepks.Add(*hepk)
	if err != nil {
		return err
	}
	mr := proto.MemberRole{
		DstRole: t.dstRole,
		Member: proto.Member{
			Id:      id,
			SrcRole: srcRole.Export(),
			Keys:    proto.NewMemberKeysWithTeam(*tmk),
		},
	}
	t.mrs = append(t.mrs, mr)
	return nil
}

func (t *teamAdder) loadMembers(m MetaContext) error {
	for _, u := range t.arg.Members {
		err := t.loadMember(m, u)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *teamAdder) post(m MetaContext) error {
	tr := t.tr
	host := t.hostID() // takes tr's lock
	tr.Lock()
	defer tr.Unlock()

	// Adding a party that is already in the roster would silently rewrite
	// its membership at dstRole (e.g. demote an owner), as with TeamAdmit.
	err := checkAdmitteesNotAlreadyMembers(t.mrs, host, tr.ldr.rosterPost)
	if err != nil {
		return err
	}

	cfg, err := t.tm.loadConfig(m, nil)
	if err != nil {
		return err
	}

	ed := teamEditorFromTeamRecord(tr)
	ed.tok = t.tok
	ed.changes = t.mrs
	ed.hepks = t.hepks
	ed.cfg = cfg
	ed.testOpts = t.tm.teamEditorTestOpts()

	// The server inserts these only on open hosts. On a closed host each
	// added user already granted the team view permission, which is how
	// loadUserAsTeam was able to load them.
	if t.closedView {
		return ed.Run(m)
	}
	for _, mr := range t.mrs {
		pid, err := mr.Member.Id.Entity.ToPartyID()
		if err != nil {
			return err
		}
		ed.lvpf = append(ed.lvpf, pid)
	}
	return ed.Run(m)
}

func (t *teamAdder) loadDstRole(m MetaContext) error {
	t.dstRole = proto.DefaultRole
	if t.arg.DstRole != nil {
		t.dstRole = *t.arg.DstRole
	}
	return nil
}

func (t *teamAdder) run(m MetaContext) error {
	err := t.loadDstRole(m)
	if err != nil {
		return err
	}
	err = t.loadMembers(m)
	if err != nil {
		return err
	}
	err = t.post(m)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) Add(m MetaContext, arg lcl.TeamAddArg) error {

	open, err := t.au.HasOpenUserViewership(m)
	if err != nil {
		return err
	}

	return t.withLoadedTeamAndAdminToken(
		m,
		arg.Team,
		LoadTeamOpts{Refresh: true},
		func(m MetaContext, tr *TeamRecord, tok *rem.TeamBearerToken) error {
			adder := newTeamAdder(t, tr, tok, arg)
			adder.closedView = !open
			return adder.run(m)
		},
	)
}
