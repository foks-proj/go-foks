// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// The Team Membership Loader (TML) works on behalf of users and teams. This interface
// abstracts away the party who the TML is working on behalf of. We'll have on instantiation
// for users, and one for a team.
type TMLParty interface {
	EntityID() proto.EntityID
	HostID() proto.HostID // hostID of the team membership chain to load
	Init(m MetaContext) error
	SeedCommitment() *proto.TreeLocationCommitment
	Fetch(m MetaContext, arg rem.LoadGenericChainArg) (rem.GenericChain, error)
	Scoper() Scoper
	MerkleAgent(m MetaContext) (*merkle.Agent, error)
	BookendSigningKey(m MetaContext, owner proto.FQEntity, key proto.EntityID,
		epno proto.MerkleEpno) (*KeyBookends, error)

	// What Role the loader has for the chain. For users, it's the role of the device.
	// For teams, it's the role the current (loading) member has in the target chain.
	// This data is passed in during construction, and copied out to the result, but it's
	// convenient to keep it close to the chain data.
	RoleInChain() proto.Role
	LatestSharedKey() core.SharedPrivateSuiter

	// For users, this is going to be the current device key (for updating, let's say, the
	// user's team membership chain). For teams, this is going to be the team's latest shared
	// key.
	SigningKey(ctx context.Context) (core.PrivateSuiter, error)

	PostLink(m MetaContext, arg rem.PostGenericLinkArg) error
}

type TMLTeam struct {
	au        *UserContext
	arg       LoadTeamArg // what to load the underlying team with
	tmLoader  *TeamLoader
	tmWrapper *TeamWrapper
	ric       proto.Role
}

func NewTMLTeam(m MetaContext, arg LoadTeamArg, ric proto.Role) (*TMLTeam, error) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	return &TMLTeam{
		au:  au,
		arg: arg,
		ric: ric,
	}, nil
}

func (t *TMLTeam) SeedCommitment() *proto.TreeLocationCommitment {
	return t.tmWrapper.SeedCommitment()
}

func (t *TMLTeam) Fetch(m MetaContext, arg rem.LoadGenericChainArg) (rem.GenericChain, error) {
	tok := t.tmLoader.Tok()
	if tok == nil {
		return rem.GenericChain{}, core.InternalError("no token in TMLTeam.Fetch")
	}
	targ := rem.LoadTeamMembershipChainArg{
		Team:  t.arg.Team,
		Tok:   *tok,
		Start: arg.Start,
	}
	var zed rem.GenericChain
	cli, _, closer, err := t.tmLoader.RpcLoaderClient(m)
	if err != nil {
		return zed, err
	}
	defer closer()
	return cli.LoadTeamMembershipChain(m.Ctx(), targ)
}

func (t *TMLTeam) Scoper() Scoper {
	ret := t.arg.Team
	return &ret
}

func (t *TMLTeam) MerkleAgent(m MetaContext) (*merkle.Agent, error) {
	return t.tmLoader.MerkleAgent(m)
}

func (t *TMLTeam) BookendSigningKey(
	m MetaContext,
	owner proto.FQEntity,
	key proto.EntityID,
	epno proto.MerkleEpno,
) (
	*KeyBookends,
	error,
) {
	return t.tmWrapper.BookendSigningKey(key, epno)
}

func (t *TMLTeam) Init(m MetaContext) error {
	l := NewTeamLoader(t.au, t.arg)
	w, err := l.Run(m)
	if err != nil {
		return err
	}
	t.tmLoader = l
	t.tmWrapper = w
	return nil
}

func (t *TMLTeam) EntityID() proto.EntityID {
	return t.arg.Team.Team.EntityID()
}

func (t *TMLTeam) HostID() proto.HostID {
	return t.arg.Team.Host
}

func (t *TMLTeam) RoleInChain() proto.Role {
	return t.ric
}

func (t *TMLTeam) SigningKey(_ context.Context) (core.PrivateSuiter, error) {
	ret := t.LatestSharedKey()
	if ret == nil {
		return nil, core.KeyNotFoundError{Which: "LatestSharedKey for team"}
	}
	return ret, nil
}

func (t *TMLTeam) LatestSharedKey() core.SharedPrivateSuiter {
	seq := t.tmLoader.ptks.AdminOrOwnerKey()
	if seq == nil {
		return nil
	}
	return seq.Current()
}

func (t *TMLTeam) PostLink(m MetaContext, arg rem.PostGenericLinkArg) error {
	tok, cli, err := t.tmLoader.readyTeamMutation(m)
	if err != nil {
		return err
	}
	return cli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok:  *tok,
		Link: arg,
	})
}

var _ TMLParty = (*TMLTeam)(nil)

type TMLUser struct {
	au  *UserContext
	uw  *UserWrapper
	ric proto.Role
}

func (t *TMLUser) EntityID() proto.EntityID {
	return t.au.UID().EntityID()
}

func (t *TMLUser) Init(m MetaContext) error {
	if t.uw != nil {
		return nil
	}
	uw, err := LoadMe(m, t.au)
	if err != nil {
		return err
	}
	t.uw = uw
	return nil
}

func (t *TMLUser) SeedCommitment() *proto.TreeLocationCommitment {
	return &t.uw.prot.Sctlsc
}

func (t *TMLUser) Fetch(m MetaContext, arg rem.LoadGenericChainArg) (rem.GenericChain, error) {
	var ret rem.GenericChain
	ucli, err := t.au.UserClient(m)
	if err != nil {
		return ret, err
	}
	return ucli.LoadGenericChain(m.Ctx(), arg)
}

func (t *TMLUser) Scoper() Scoper {
	fqu := t.au.FQU()
	return &fqu
}

func (t *TMLUser) MerkleAgent(m MetaContext) (*merkle.Agent, error) {
	ma, err := t.au.MerkleAgent(m)
	if err != nil {
		return nil, err
	}
	return ma, nil
}

func (u *TMLUser) BookendSigningKey(
	m MetaContext,
	owner proto.FQEntity,
	key proto.EntityID,
	epno proto.MerkleEpno,
) (
	*KeyBookends,
	error,
) {
	fqe := u.au.FQU().ToFQEntity()
	if !fqe.Eq(owner) {
		return nil, core.PermissionError("wrong owner")
	}
	return u.uw.BookendSigningKey(proto.FQEntity{Entity: key, Host: owner.Host}, epno)
}

func NewTMLUser(m MetaContext, ric proto.Role) (*TMLUser, error) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	return &TMLUser{
		au:  au,
		ric: ric,
	}, nil
}

func (t *TMLUser) RoleInChain() proto.Role {
	return t.ric
}

func (t *TMLUser) HostID() proto.HostID {
	return t.au.HostID()
}

func (t *TMLUser) LatestSharedKey() core.SharedPrivateSuiter {
	return t.au.PrivKeys.LatestPuk()
}

func (t *TMLUser) SigningKey(ctx context.Context) (core.PrivateSuiter, error) {
	return t.au.Devkey(ctx)
}

func (t *TMLUser) PostLink(m MetaContext, arg rem.PostGenericLinkArg) error {
	ucli, err := t.au.UserClient(m)
	if err != nil {
		return err
	}
	return ucli.PostGenericLink(m.Ctx(), arg)
}

var _ TMLParty = (*TMLUser)(nil)

type FQTeamSrcRole struct {
	proto.FQTeam
	SrcRole core.RoleKey
}

func (f *FQTeamSrcRole) Import(team proto.FQTeam, srcRole proto.Role) error {
	f.FQTeam = team
	sr, err := core.ImportRole(srcRole)
	if err != nil {
		return err
	}
	f.SrcRole = *sr
	return nil
}

type TeamMembershipLoader struct {
	gcl   *GenericChainLoader
	party TMLParty
	data  map[FQTeamSrcRole]proto.TeamMembershipLink
}

type TeamMembershipWrapper struct {
	Prot        *lcl.GenericChainState
	Map         map[FQTeamSrcRole]proto.TeamMembershipLink
	RoleInChain proto.Role
}

var _ ChainLoaderSubclass = (*TeamMembershipLoader)(nil)

func NewTeamMembershipLoader(party TMLParty) *TeamMembershipLoader {
	ret := &TeamMembershipLoader{
		party: party,
		data:  make(map[FQTeamSrcRole]proto.TeamMembershipLink),
	}
	ret.gcl = NewGenericChainLoader(party.EntityID(), ret)
	return ret
}

func (t *TeamMembershipLoader) Fetch(m MetaContext, arg rem.LoadGenericChainArg) (rem.GenericChain, error) {
	return t.party.Fetch(m, arg)
}

func (t *TeamMembershipLoader) SeedCommitment() *proto.TreeLocationCommitment {
	return t.party.SeedCommitment()
}

func (t *TeamMembershipLoader) Type() proto.ChainType {
	return proto.ChainType_TeamMembership
}

func (t *TeamMembershipLoader) Scoper() Scoper {
	return t.party.Scoper()
}

func (t *TeamMembershipLoader) MerkleAgent(m MetaContext) (*merkle.Agent, error) {
	return t.party.MerkleAgent(m)
}

func (t *TeamMembershipLoader) LoadState(p lcl.GenericChainStatePayload) error {
	typ, err := p.GetT()
	if err != nil {
		return err
	}
	if typ != proto.ChainType_TeamMembership {
		return core.ChainLoaderError{
			Err: core.UserSettingsError("wrong chain type stored"),
		}
	}
	tmp := p.Teammembership()
	t.data = make(map[FQTeamSrcRole]proto.TeamMembershipLink)
	for _, link := range tmp.Teams {
		var key FQTeamSrcRole
		err := key.Import(link.Team, link.SrcRole)
		if err != nil {
			return err
		}
		t.data[key] = link
	}
	return nil
}

func (t *TeamMembershipLoader) PlayLink(m MetaContext, l proto.LinkOuter, g proto.GenericLinkPayload) error {
	typ, err := g.GetT()
	if err != nil {
		return err
	}
	if typ != proto.ChainType_TeamMembership {
		return core.ChainLoaderError{
			Err: core.UserSettingsError("wrong chain type in playback"),
		}
	}
	tm := g.Teammembership()
	var key FQTeamSrcRole
	err = key.Import(tm.Team, tm.SrcRole)
	if err != nil {
		return err
	}
	t.data[key] = tm
	return nil
}

func (t *TeamMembershipLoader) SaveState() (lcl.GenericChainStatePayload, error) {

	lst := make([]proto.TeamMembershipLink, 0, len(t.data))
	for _, v := range t.data {
		lst = append(lst, v)
	}
	slices.SortFunc(lst, func(i, j proto.TeamMembershipLink) int {
		return i.Team.Cmp(j.Team)
	})
	return lcl.NewGenericChainStatePayloadWithTeammembership(
		lcl.TeamMembershipChainPayload{
			Teams: lst,
		},
	), nil
}

func (t *TeamMembershipLoader) BookendSigningKey(
	m MetaContext,
	owner proto.FQEntity,
	key proto.EntityID,
	epno proto.MerkleEpno,
) (
	*KeyBookends,
	error,
) {
	return t.party.BookendSigningKey(m, owner, key, epno)
}

func (t *TeamMembershipLoader) Run(m MetaContext) (*TeamMembershipWrapper, error) {
	err := t.party.Init(m)
	if err != nil {
		return nil, err
	}
	err = t.gcl.Run(m)
	if err != nil {
		return nil, err
	}
	ret := TeamMembershipWrapper{
		Prot:        t.gcl.res,
		Map:         t.data,
		RoleInChain: t.party.RoleInChain(),
	}
	return &ret, nil
}

func LoadTeamMembership(m MetaContext, party TMLParty) (*TeamMembershipWrapper, error) {
	both, err := LoadTeamMembershipReturnLoader(m, party)
	if err != nil {
		return nil, err
	}
	return both.Wrapper, err
}

type TeamMembershipLoaderAndWrapper struct {
	Loader  *TeamMembershipLoader
	Wrapper *TeamMembershipWrapper
}

func LoadTeamMembershipReturnLoader(
	m MetaContext,
	party TMLParty,
) (
	*TeamMembershipLoaderAndWrapper,
	error,
) {
	tml := NewTeamMembershipLoader(party)
	ret, err := tml.Run(m)
	if err != nil {
		return nil, err
	}
	return &TeamMembershipLoaderAndWrapper{
		Loader:  tml,
		Wrapper: ret,
	}, nil
}

func (t *TeamMembershipLoader) postLink(
	m MetaContext,
	tml proto.TeamMembershipLink,
) error {
	if t.gcl.res == nil {
		return core.InternalError("no chain preloaded in TeamMembershipLoader.RemoveMembership")
	}
	ma, err := t.party.MerkleAgent(m)
	if err != nil {
		return err
	}
	tr, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return err
	}
	glp := proto.NewGenericLinkPayloadWithTeammembership(tml)

	signingKey, err := t.party.SigningKey(m.Ctx())
	if err != nil {
		return err
	}
	glink, err := core.MakeGenericLink(
		t.party.EntityID(),
		t.party.HostID(),
		signingKey,
		glp,
		t.gcl.res.Tail.Base.Seqno+1,
		t.gcl.lastHash,
		tr,
	)
	if err != nil {
		return err
	}
	err = t.party.PostLink(m, rem.PostGenericLinkArg{
		Link:             *glink.Link,
		NextTreeLocation: *glink.NextTreeLocation,
	})
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMembershipLoader) RemoveMembership(
	m MetaContext,
	team proto.FQTeam,
	member proto.FQParty,
	srcRole proto.Role,
) error {
	tml := proto.TeamMembershipLink{
		Team:    team,
		SrcRole: srcRole,
		State:   proto.NewTeamMembershipDetailsDefault(proto.TeamMembershipLinkState_Removed),
	}
	return t.postLink(m, tml)
}

func (t *TeamMembershipLoader) PostApprovedMembership(
	m MetaContext,
	team proto.FQTeam,
	member proto.FQParty,
	srcRole proto.Role,
	dstRoleAndSeqno proto.RoleAndSeqno,
	keyComm proto.KeyCommitment,
) error {
	tml := proto.TeamMembershipLink{
		Team:    team,
		SrcRole: srcRole,
		State: proto.NewTeamMembershipDetailsWithApproved(
			proto.TeamMembershipApprovedDetails{
				Dst:     dstRoleAndSeqno,
				KeyComm: keyComm,
			},
		),
	}
	return t.postLink(m, tml)
}
