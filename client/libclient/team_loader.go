// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"slices"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type rosterPackageRemote struct {
	tokBox proto.TeamRemoteMemberViewTokenInner
	tok    *proto.PermissionToken
}

type rosterPackage struct {
	fqp      proto.FQParty
	srcRole  proto.Role
	info     team.MemberInfo
	remote   *rosterPackageRemote
	isRemote bool
	err      error
	uw       *UserWrapper
	tw       *TeamWrapper
}

type HistoricalSenders struct {
	raw []proto.SenderPair
	m   map[proto.FixedEntityID]proto.HEPKFingerprint
}

func (h *HistoricalSenders) Load(v []proto.SenderPair) {
	h.raw = v
	h.m = nil
}

func (h *HistoricalSenders) init() error {
	if h.m != nil {
		return nil
	}
	h.m = make(map[proto.FixedEntityID]proto.HEPKFingerprint)
	for _, v := range h.raw {
		fx, err := v.VerifyKey.Fixed()
		if err != nil {
			return err
		}
		h.m[fx] = v.HepkFp
	}
	return nil
}

func (h *HistoricalSenders) Push(sp proto.SenderPair) error {
	err := h.init()
	if err != nil {
		return err
	}
	fx, err := sp.VerifyKey.Fixed()
	if err != nil {
		return err
	}
	h.m[fx] = sp.HepkFp
	return nil
}

func (h *HistoricalSenders) Lookup(v proto.EntityID) (*proto.HEPKFingerprint, error) {
	err := h.init()
	if err != nil {
		return nil, err
	}
	fx, err := v.Fixed()
	if err != nil {
		return nil, err
	}
	fp, ok := h.m[fx]
	if !ok {
		return nil, nil
	}
	return &fp, nil
}

func (h *HistoricalSenders) Export() []proto.SenderPair {
	if h.m == nil {
		return h.raw
	}
	var ret []proto.SenderPair
	for k, v := range h.m {
		ret = append(ret, proto.SenderPair{
			VerifyKey: k.Unfix(),
			HepkFp:    v,
		})
	}
	return ret
}

type TeamLoader struct {
	BaseChainLoader
	Arg LoadTeamArg

	au              *UserContext // active user
	ntn             proto.Name
	rpcLoader       rem.TeamLoaderClient
	stopFn          func()
	voTok           *rem.TeamVOBearerToken
	tok             rem.TokenVariant
	existing        *lcl.TeamChainState
	newState        *lcl.TeamChainState
	preload         *lcl.TeamChainState
	probe           *chains.Probe
	msess           *merkle.Session
	raw             rem.TeamChain
	ptks            *TeamKeyRing
	rosterPre       *team.Roster
	rosterPost      *team.Roster
	otlrs           []team.OpeanTeamLinkRes
	allMerkleLeaves []proto.MerkleLeaf
	sctlsc          *proto.TreeLocationCommitment
	tncs            []proto.Commitment // team name commitments
	tnseq           proto.NameSeqno
	removalKey      *rem.TeamRemovalKey
	rosterDetails   map[proto.FQEntityFixed]*rosterPackage
	isAdmin         bool
	hepks           *core.HEPKSet
	indexRange      *core.RationalRange
	histSend        HistoricalSenders
}

type TeamWrapper struct {
	prot          *lcl.TeamChainState
	ptks          *TeamKeyRing
	rk            *rem.TeamRemovalKey
	memberMap     map[team.MemberID]proto.MemberRoleSeqno
	srcRoleMap    map[proto.FQEntityFixed][]proto.Role
	hostname      proto.Hostname
	rosterDetails map[proto.FQEntityFixed]*rosterPackage
	voTok         *rem.TeamVOBearerToken
	hepks         *core.HEPKSet
}

var _ PartyWrapper = (*TeamWrapper)(nil)

func (t *TeamWrapper) VOBearerToken() *rem.TeamVOBearerToken { return t.voTok }
func (t *TeamWrapper) Hostname() proto.Hostname              { return t.hostname }
func (t *TeamWrapper) Name() proto.NameUtf8                  { return t.prot.Name.B.NameUtf8 }
func (t *TeamWrapper) TeamMemberKeys(r core.RoleKey) (*proto.TeamMemberKeys, *proto.HEPK, error) {
	ptk := t.ptks.CurrentPublicKeyAtRole(r)
	if ptk == nil {
		return nil, nil, nil
	}
	fp := ptk.Sk.HepkFp
	hepk, ok := t.ptks.hepks.Lookup(&fp)
	if !ok {
		return nil, nil, core.KeyNotFoundError{Which: "hepk"}
	}
	return &proto.TeamMemberKeys{
		VerifyKey: ptk.Sk.VerifyKey,
		HepkFp:    fp,
		Gen:       ptk.Sk.Gen,
		Tir:       &t.prot.Tir,
	}, hepk.Obj(), nil
}

func (t *TeamWrapper) CheckTeamIndexRange(targetTeam core.RationalRange, tirInJoinReq *proto.RationalRange) error {
	if tirInJoinReq == nil {
		return core.TeamIndexRangeError("missing team index range for joining team")
	}
	high := targetTeam
	low := core.NewRationalRange(*tirInJoinReq)
	currLow := t.IndexRange()
	if !low.Includes(currLow) {
		return core.TeamIndexRangeError("joining team's index weirdly grew")
	}
	if !low.LessThan(high) {
		return core.NewTeamCycleError(low, high)
	}
	return nil
}

func (t *TeamWrapper) FQName() proto.FQTeamString {
	return proto.FQTeamString(
		string(t.prot.Name.B.NameUtf8) + "@" + string(t.hostname),
	)
}

func (t *TeamWrapper) FQTeam() proto.FQTeam { return t.Prot().Fqt }

func (t *TeamWrapper) IndexRange() core.RationalRange {
	return core.NewRationalRange(t.prot.Tir)
}

// returns {name X ID } @ { name X ID }
func (t *TeamWrapper) AllFQStrings() ([]proto.FQTeamString, error) {
	var ret []proto.FQTeamString
	var names []string
	var hosts []string
	names = []string{
		string(t.prot.Name.B.Name),
	}
	idString, err := t.prot.Fqt.Team.StringErr()
	if err != nil {
		return nil, err
	}
	names = append(names, idString)
	hosts = []string{
		string(t.hostname.Normalize()),
	}
	hostString, err := t.prot.Fqt.Host.StringErr()
	if err != nil {
		return nil, err
	}
	hosts = append(hosts, hostString)
	for _, name := range names {
		for _, host := range hosts {
			ret = append(ret, proto.FQTeamString(name+"@"+host))
		}
	}
	return ret, nil
}

func (l *TeamWrapper) KeyRing() *TeamKeyRing {
	return l.ptks
}

func (l *TeamWrapper) RemovalKey() *rem.TeamRemovalKey {
	return l.rk
}

func (l *TeamWrapper) SeedCommitment() *proto.TreeLocationCommitment {
	return &l.prot.Sctlsc
}

func (l *TeamLoader) Tok() *rem.TeamVOBearerToken {
	return l.voTok
}

func (l *TeamLoader) WrappedRes() *TeamWrapper {
	return &TeamWrapper{
		prot:          l.newState,
		ptks:          l.ptks,
		rk:            l.removalKey,
		hostname:      l.probe.Hostname(),
		rosterDetails: l.rosterDetails,
		voTok:         l.voTok,
		hepks:         l.hepks,
	}
}

func (l *TeamWrapper) Prot() *lcl.TeamChainState {
	return l.prot
}

func (l *TeamWrapper) index() error {
	if l.memberMap != nil {
		return nil
	}
	mm := make(map[team.MemberID]proto.MemberRoleSeqno)
	sri := make(map[proto.FQEntityFixed][]proto.Role)
	for _, m := range l.prot.Members {
		var id team.MemberID
		err := id.ImportFromMember(m.Mr.Member, l.prot.Fqt.Host)
		if err != nil {
			return err
		}
		mm[id] = m

		// also keep track of, for each FQE, which src roles it appears as
		lst := sri[id.Fqe]
		lst = append(lst, id.SrcRole.Export())
		sri[id.Fqe] = lst

	}
	l.memberMap = mm
	l.srcRoleMap = sri
	return nil
}

func (l *TeamWrapper) GetSourceRolesForParty(p proto.FQParty) ([]proto.Role, error) {
	err := l.index()
	if err != nil {
		return nil, err
	}
	fqe, err := p.FQEntity().Fixed()
	if err != nil {
		return nil, err
	}
	lst, ok := l.srcRoleMap[*fqe]
	if !ok {
		return nil, nil
	}
	return lst, nil
}

func (l *TeamWrapper) GetMember(p proto.FQParty, srcRole proto.Role) (*proto.MemberRoleSeqno, error) {
	err := l.index()
	if err != nil {
		return nil, err
	}
	var id team.MemberID
	err = id.ImportFromFQPartyAndRole(p, srcRole)
	if err != nil {
		return nil, err
	}
	mr, ok := l.memberMap[id]
	if !ok {
		return nil, nil
	}
	return &mr, nil
}

func (w *TeamWrapper) BookendSigningKey(
	e proto.EntityID,
	epno proto.MerkleEpno,
) (
	*KeyBookends,
	error,
) {
	fe, err := e.Fixed()
	if err != nil {
		return nil, err
	}
	key, ok := w.ptks.i[fe]
	if !ok {
		return nil, core.KeyNotFoundError{Which: "PTK"}
	}
	if key.Ri == nil {
		return nil, nil
	}
	return &KeyBookends{
		Provision: key.Pi,
		Revoke:    *key.Ri,
	}, nil
}

func (r *rosterPackage) Export() lcl.TeamRosterMember {
	ret := lcl.TeamRosterMember{
		Mem: lcl.NamedFQParty{
			Fqp: r.fqp,
		},
		Added: lcl.ChainDate{
			Time:  r.info.Time,
			Seqno: r.info.Seqno,
		},
		SrcRole: r.srcRole,
		DstRole: r.info.Role.Export(),
		PtkGen:  r.info.Gen,
	}
	switch {
	case r.uw != nil:
		ret.Mem.Name = r.uw.prot.Username.B.NameUtf8
		ret.Mem.Host = r.uw.Hostname()
		ret.NumMembers = int64(len(r.uw.prot.Devices))
	case r.tw != nil:
		ret.Mem.Name = r.tw.prot.Name.B.NameUtf8
		ret.Mem.Host = r.tw.hostname
		ret.NumMembers = int64(len(r.tw.prot.Members))
	}
	return ret
}

func (w *TeamWrapper) ExportToNamedFQParty() lcl.NamedFQParty {
	return lcl.NamedFQParty{
		Fqp:  w.prot.Fqt.FQParty(),
		Name: w.prot.Name.B.NameUtf8,
		Host: w.hostname,
	}
}

func (w *TeamWrapper) ExportToRoster() (*lcl.TeamRoster, error) {
	ret := lcl.TeamRoster{
		Fqp: w.ExportToNamedFQParty(),
	}
	var roster []lcl.TeamRosterMember
	for _, v := range w.rosterDetails {
		if v.err == nil {
			x := v.Export()
			roster = append(roster, x)
		}
	}
	slices.SortFunc(roster, func(a, b lcl.TeamRosterMember) int {
		i := -1 * a.DstRole.SimpleCmp(b.DstRole)
		if i != 0 {
			return i
		}
		return a.Mem.Cmp(b.Mem)
	})
	ret.Members = roster
	return &ret, nil
}

func (l *TeamLoader) TeamID() proto.TeamID {
	return l.Arg.Team.Team
}

func (l *TeamLoader) Run(m MetaContext) (*TeamWrapper, error) {
	m = m.WithLogTag("teamload")
	err := l.checkArgs(m)
	if err != nil {
		return nil, err
	}
	err = l.BaseChainLoader.runMany(m, l.runOnce, l.resetState)
	if err != nil {
		return nil, err
	}
	w := l.WrappedRes()
	return w, nil
}

func NewTeamLoader(au *UserContext, arg LoadTeamArg) *TeamLoader {
	return &TeamLoader{
		au:   au,
		Arg:  arg,
		ptks: NewTeamKeyRing(),
	}
}

func (l *TeamLoader) checkArgs(m MetaContext) error {
	return nil
}

func (l *TeamLoader) setHEPKs(h *core.HEPKSet) {
	l.hepks = h
	l.ptks.hepks = h
}

func (l *TeamLoader) MerkleAgent(m MetaContext) (*merkle.Agent, error) {
	return l.probe.MerkleAgent(m)
}

func (l *TeamLoader) connectHost(m MetaContext) error {
	gcli, pr, closer, err := l.RpcLoaderClient(m)
	if err != nil {
		return err
	}
	l.stopFn = core.Compose(l.stopFn, closer)
	l.rpcLoader = *gcli
	l.probe = pr
	return nil
}

func (l *TeamLoader) adminClient(m MetaContext) (*rem.TeamAdminClient, error) {
	gcli, err := l.au.UserGCli(m)
	if err != nil {
		return nil, err
	}
	ret := rem.TeamAdminClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &ret, nil
}

func (l *TeamLoader) RpcLoaderClient(m MetaContext) (*rem.TeamLoaderClient, *chains.Probe, func(), error) {
	var gcli *core.RpcClient
	var closer func()
	var err error
	var pr *chains.Probe

	makeCliFromProbe := func(hostID proto.HostID) (*core.RpcClient, *chains.Probe, func(), error) {
		pr, err := m.Probe(chains.ProbeArg{HostID: hostID})
		if err != nil {
			return nil, nil, nil, err
		}
		gcli, err := pr.RegGCli(m)
		if err != nil {
			return nil, nil, nil, err
		}
		return gcli, pr, gcli.Shutdown, nil
	}

	if l.au != nil && l.au.HostID().Eq(l.Arg.As.Host) && l.au.HostID().Eq(l.Arg.Team.Host) {
		pr = l.au.HomeServer()
		gcli, err = l.au.UserGCli(m)
		closer = func() {}
	} else {
		gcli, pr, closer, err = makeCliFromProbe(l.Arg.Team.Host)
	}

	if err != nil {
		return nil, nil, nil, err
	}
	ret := rem.TeamLoaderClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &ret, pr, closer, nil
}

func (l *TeamLoader) finish() {
	if l.stopFn != nil {
		l.stopFn()
		l.stopFn = nil
	}
}

func (l *TeamLoader) readyTeamMutation(m MetaContext) (*rem.TeamBearerToken, *rem.TeamAdminClient, error) {
	cli, err := l.adminClient(m)
	if err != nil {
		return nil, nil, err
	}
	ptks := l.ptks.AdminOrOwnerKey()
	if ptks == nil {
		return nil, nil, core.PermissionError("no write privileges for team")
	}
	curr := ptks.Current()
	tok, err := cli.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: l.Arg.Team.Team,
		Role: curr.GetRole(),
		Gen:  curr.Metadata().Gen,
	})
	if err != nil {
		return nil, nil, err
	}
	sig, obj, err := team.SignBearerTokenChallenge(
		l.au.FQU(),
		l.TeamID(),
		curr.GetRole(),
		curr.Metadata().Gen,
		tok,
		curr,
	)
	if err != nil {
		return nil, nil, err
	}
	err = cli.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	if err != nil {
		return nil, nil, err
	}
	return &tok, cli, nil
}

func (l *TeamLoader) makeViewToken(m MetaContext) error {

	// In test, we can override the token to use
	if l.Arg.TestTokenVariant != nil {
		l.tok = *l.Arg.TestTokenVariant
		return nil
	}

	// If we've been passed a permission token, use that instead of making a
	// View-only bearer token.
	if l.Arg.Tok != nil {
		l.tok = rem.NewTokenVariantWithPermission(*l.Arg.Tok)
		return nil
	}
	if l.Arg.LocalParentTeamTok != nil {
		l.tok = rem.NewTokenVariantWithLocalparentteam(*l.Arg.LocalParentTeamTok)
		return nil
	}
	if l.Arg.Keys == nil {
		return nil
	}

	curr := l.Arg.Keys.Current()
	if curr == nil {
		return core.KeyNotFoundError{Which: "PUK"}
	}

	gen := curr.Metadata().Gen

	idOrName := core.Sel(
		!l.ntn.IsZero(),
		proto.NewTeamIDOrNameWithFalse(l.ntn),
		proto.NewTeamIDOrNameWithTrue(l.Arg.Team.Team),
	)

	req := rem.TeamVOBearerTokenReq{
		Team: proto.FQTeamIDOrName{
			Host:     l.Arg.Team.Host,
			IdOrName: idOrName,
		},
		Member:  l.Arg.As,
		SrcRole: l.Arg.SrcRole,
	}

	tried := make(map[proto.Generation]bool)

	tokAtGen := func(gen proto.Generation) (*rem.ActivatedVOBearerToken, error) {
		if tried[gen] {
			return nil, core.PermissionError("already tried this PUK")
		}
		tried[gen] = true
		req.Gen = gen
		chal, err := l.rpcLoader.GetTeamVOBearerTokenChallenge(m.Ctx(), req)
		if err != nil {
			return nil, err
		}
		// Ignore and stomp what the server sent back, only sign what we generated
		chal.Payload.Req = req
		key := l.Arg.Keys.At(gen)
		if key == nil {
			return nil, core.KeyNotFoundError{Which: "PUK"}
		}
		sig, err := key.Sign(&chal)
		if err != nil {
			return nil, err
		}
		tok, err := l.rpcLoader.ActivateTeamVOBearerToken(m.Ctx(), rem.ActivateTeamVOBearerTokenArg{
			Ch:  chal,
			Sig: *sig,
		})
		if err != nil {
			return nil, err
		}
		return &tok, nil
	}

	// Usually we can authenticate to load this team with the most up-to-date PUK/PTK,
	// but not always. If the PUK/PTK just rotated, and the team hasn't been updated yet,
	// we will have to try again with older PUK/PTKs. Hence this loop. In a slightly different
	// case, if the team we're loading has updated, and the keys we originally loaded with are
	// stale, we'll fail to load since we'll be requesting a view-only bearer token for an
	// older generation. So in that case, we need to retry a later generation, after we
	// refresh. If the user has been removed from the team, they will wind up trying all of
	// their PUKs/PTKs, which isn't great.
	findTok := func() (*rem.ActivatedVOBearerToken, error) {
		tok, err := tokAtGen(gen)
		if err == nil {
			return tok, nil
		}

		if !core.IsPermissionError(err) {
			return nil, err
		}

		firstErr := err

		m.Warnw("TeamLoader.makeViewToken",
			"stage", "failed latest gen",
			"err", err,
			"gen", gen,
		)

		if core.IsPermissionError(err) && l.Arg.KeyRefresher != nil {
			keys, err := l.Arg.KeyRefresher(m)
			if err != nil {
				m.Warnw("TeamLoader.makeViewToken", "stage", "refresh-1", "err", err)
				return nil, err
			}

			if keys == nil || keys.Current() == nil {
				// If members are demoted from the team as in `TestExactRolesInTeamGraphRemovals`,
				// they can only load public and now private PTK parts, and therefore, should
				// come back with an empty key set here.
				m.Warnw("TeamLoader.makeViewToken", "stage", "refresh-2", "err", "empty keys")
			} else if gen < keys.Current().Metadata().Gen {
				l.Arg.Keys = keys
				gen = keys.Current().Metadata().Gen
				m.Infow("TeamLoader.makeViewToken", "stage", "refresh-3", "gen", gen)
				// Slight hack, we're going to decrement the generation below
				// at the top of the retry loop, so increment to compensate.
				gen++
			} else {
				m.Infow("TeamLoader.makeViewToken", "stage", "refresh-4", "gen", gen)
			}
		}

		for {
			gen--
			if !gen.IsValid() {
				break
			}
			tok, err := tokAtGen(gen)
			m.Infow("TeamLoader.makeViewToken", "stage", "retry", "gen", gen, "err", err)
			if err == nil {
				return tok, nil
			}
			if !core.IsPermissionError(err) {
				return nil, err
			}
		}
		return nil, firstErr
	}

	tok, err := findTok()
	if err != nil {
		return err
	}

	if !l.Arg.Team.Team.IsZero() && !l.Arg.Team.Team.Eq(tok.Id) {
		return core.ChainLoaderError{
			Err: core.TeamError("wrong team ID came back with view token"),
		}
	}
	l.Arg.Team.Team = tok.Id
	l.voTok = &tok.Tok
	l.tok = rem.NewTokenVariantWithTeamvobearer(tok.Tok)
	return nil
}

func (l *TeamLoader) dbType() DbType {
	return DbTypeSoft
}

func (l *TeamLoader) readKeysFromState(m MetaContext, st *lcl.TeamChainState) (*TeamKeyRing, error) {
	ret := NewTeamKeyRing()
	for _, key := range st.Ptks {
		err := ret.AddPub(key)
		if err != nil {
			return nil, err
		}
	}
	for _, parc := range st.PrivateKeys {
		err := ret.AddPrivBoxed(parc)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (l *TeamLoader) readRoster(m MetaContext, st *lcl.TeamChainState, kg team.KeyGens) (*team.Roster, error) {
	ret := team.NewRosterWithKeyGens(kg)
	err := ret.Load(st.Members, l.Arg.Team.Host)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (l *TeamLoader) loadExistingTeam(m MetaContext) error {
	var ret lcl.TeamChainState

	loadHEPKs := func() error {
		tmp, err := core.ImportHEPKSet(&l.existing.Hepks)
		if err != nil {
			return err
		}
		l.setHEPKs(tmp)
		return nil
	}

	// We've previously ran this team loaded before, and it's
	// up-to-date w/r/t what's on disk. Slight advantage here in
	// that we won't have to unbox everything again.
	if l.preload != nil {

		// Note that afer the prior run, if it was successful, we don't reset the
		// state. So we need to reset it here, otherwise the loader will get confused.
		l.resetState()

		l.existing = l.preload
		l.preload = nil
		l.sctlsc = &l.existing.Sctlsc
		err := loadHEPKs()
		if err != nil {
			return err
		}
		return nil
	}

	scoper := l.au.FQU()
	_, err := m.DbGet(&ret, l.dbType(), &scoper, lcl.DataType_TeamChainState, l.Arg)
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}

	// Treat a failure to load a team as non-fatal. We can reload the team from scratch.
	ptks, err := l.readKeysFromState(m, &ret)
	if err != nil {
		m.Warnw("TeamLoader.loadExistingToken", "err", err, "stage", "readKeysFromState")
		return err
	}

	roster, err := l.readRoster(m, &ret, ptks.ToKeyGens())
	if err != nil {
		m.Warnw("TeamLoader.loadExistingToken", "err", err, "stage", "readRoster")
		return nil
	}

	l.existing = &ret
	l.ptks = ptks
	l.rosterPre = roster
	l.newState = l.existing
	l.histSend.Load(ret.HistoricalSenders)
	l.sctlsc = &ret.Sctlsc

	err = loadHEPKs()
	if err != nil {
		return err
	}

	return nil
}

func (l *TeamLoader) loadTeamFromServer(m MetaContext) error {
	ma, err := l.probe.MerkleAgent(m)
	if err != nil {
		return err
	}
	l.msess = merkle.NewSession(ma)
	err = l.msess.Init(m.Ctx())
	if err != nil {
		return err
	}

	toktyp, err := l.tok.GetT()
	if err != nil {
		return err
	}
	if toktyp == rem.TokenType_None && !l.Arg.TestSkipArgCheck {
		return core.InternalError("expected a token to load the team with")
	}

	arg := rem.LoadTeamChainArg{
		Team:  l.Arg.Team,
		Tok:   l.tok,
		Start: proto.ChainEldestSeqno,
	}

	if l.Arg.Keys != nil && (l.existing == nil || l.existing.RemovalKey == nil) {
		arg.LoadRemovalKey = true
	}

	if l.existing != nil {
		arg.HavePtkGens = l.ptks.HaveKeysFor()
		arg.Start = l.existing.Tail.Base.Seqno + 1
		arg.Name = &rem.NameSeqnoPair{
			N: l.existing.Name.B.Name,
			S: l.existing.Name.S + 1,
		}
	}
	if l.Arg.LoadMembers && (l.existing == nil || len(l.existing.RemoteViewTokens) == 0) {
		arg.LoadRemoteViewTokens = true
	}
	res, err := l.rpcLoader.LoadTeamChain(m.Ctx(), arg)
	if err != nil {
		return err
	}
	l.raw = res
	return nil
}

func (l *TeamLoader) checkMerkleRoot(m MetaContext) error {
	err := l.msess.Run(m.Ctx(), &l.raw.Merkle.Root)
	if err != nil {
		return core.ChainLoaderError{Err: err}
	}
	return nil
}

func (l *TeamLoader) openLinks(m MetaContext) error {
	roster := l.rosterPre
	for n, link := range l.raw.Links {
		otlr, err := team.OpenTeamLink(&link, l.hepks, &l.Arg.Team.Team, l.Arg.Team.Host, roster)
		if err != nil {
			return core.ChainLoaderError{Err: core.CLOpenLinkError{Err: err, N: n}}
		}
		roster = otlr.RosterPost
		l.otlrs = append(l.otlrs, *otlr)
	}
	l.rosterPost = roster
	return nil
}

func (l *TeamLoader) checkMerkleTeamIDPaths(m MetaContext) error {

	// The first few are username links, the rest are UID
	// links.
	offset := int(l.raw.NumTeamnameLinks)
	var ntlc *proto.TreeLocationCommitment
	seqno := proto.ChainEldestSeqno

	if l.existing != nil {
		ntlc = &l.existing.Tail.NextLocationCommitment
		seqno = l.existing.Tail.Base.Seqno + 1
	}

	err := l.BaseChainLoader.checkMerklePaths(
		m,
		l.TeamID().EntityID(),
		proto.ChainType_Team,
		l.raw.Locations,
		l.raw.Links,
		l.chainerAtIndex,
		l.raw.Merkle,
		ntlc,
		seqno,
		nil,
		offset,
		"team",
		l.testing,
	)
	if err != nil {
		return err
	}

	// Make a list of all merkle keys known, one for each chainlink
	var keys []proto.MerkleLeaf
	if l.existing != nil {
		keys = append(keys, l.existing.MerkleLeaves...)
	}
	keys = append(keys, l.BaseChainLoader.merkleLeaves...)
	l.allMerkleLeaves = keys

	return nil
}

func (l *TeamLoader) checkRes(m MetaContext) error {
	err := l.checkMerkleRoot(m)
	if err != nil {
		return err
	}
	err = l.openLinks(m)
	if err != nil {
		return err
	}
	err = l.checkUIDChain(m)
	if err != nil {
		return err
	}
	err = l.checkMerkleTeamIDPaths(m)
	if err != nil {
		return err
	}
	return nil
}

func (l *TeamLoader) playLinkEldest(m MetaContext, link *proto.LinkOuter, otlr team.OpeanTeamLinkRes) error {
	res, err := team.OpenEldestLinkWithOTLR(link, l.Arg.Team.Host, &otlr)
	if err != nil {
		return err
	}
	l.sctlsc = &res.Stltc

	return nil
}

func (l *TeamLoader) addIndexRangeEldest(rng *core.RationalRange) error {
	if rng == nil {
		return core.InternalError("eldest link must have an index range")
	}
	if l.indexRange != nil {
		return core.InternalError("eldest link must be the first link")
	}

	l.indexRange = rng
	return nil
}

func (l *TeamLoader) playLink(m MetaContext, link *proto.LinkOuter, otlr team.OpeanTeamLinkRes) error {

	// Hold onto all team names
	if otlr.Tnc != nil {
		l.tncs = append(l.tncs, *otlr.Tnc)
	}

	// reminder that chain-link seqnos are 1-indexed, and the
	// allMerkleLeaves array is 0-indexed, so we need to subtract 1
	q := otlr.Gc.Chainer.Base.Seqno
	if !q.IsValid() {
		return core.InternalError("invalid seqno; refusing to -1 on 0")
	}
	idx := int(q) - 1
	if idx < 0 {
		return core.InternalError("invalid seqno; wound up with < 0 index")
	}
	// This should never happen, so it's an internal error when it does
	if idx >= len(l.allMerkleLeaves) {
		return core.InternalError("ran out of merkle leaves for seqno")
	}
	leaf := l.allMerkleLeaves[idx]

	// Add all public keys to our keyring
	for _, sk := range otlr.SharedKeys {

		ski := lcl.SharedKeyWithInfo{
			Sk: sk.SharedKey,
			Pi: proto.ProvisionInfo{
				Signer: otlr.Gc.Signer.Key,
				Chain:  otlr.Gc.Chainer.Base,
				Leaf:   leaf,
			},
		}

		err := l.ptks.AddPub(ski)
		if err != nil {
			return err
		}
	}
	err := l.addIndexRange(otlr.Range, otlr.Gc.Chainer.Base.Seqno)
	if err != nil {
		return err
	}

	// and done, most of the work was done in the Roster system...
	return nil
}

func (l *TeamLoader) getIndexRange() *core.RationalRange {
	if l.indexRange != nil {
		return l.indexRange
	}
	if l.existing == nil {
		return nil
	}
	tmp := core.NewRationalRange(l.existing.Tir)
	return &tmp
}

func (l *TeamLoader) addIndexRange(r *core.RationalRange, q proto.Seqno) error {

	if q.IsEldest() {
		return l.addIndexRangeEldest(r)
	}

	prev := l.getIndexRange()
	if prev == nil {
		return core.InternalError("index range must be set after first link")
	}

	if r == nil {
		return nil
	}

	if prev.Eq(*r) {
		return core.ChainLoaderError{
			Err: core.CLIndexRangeError{
				Msg:   "new index range is the same as previous",
				Seqno: q,
			},
		}
	}
	if !prev.Includes(*r) {
		return core.ChainLoaderError{
			Err: core.CLIndexRangeError{
				Msg:   "new index range does not include previous",
				Seqno: q,
			},
		}
	}
	l.indexRange = r
	return nil
}

func (l *TeamLoader) playLinks(m MetaContext) error {

	for i, otlr := range l.otlrs {

		link := l.raw.Links[i]

		if otlr.Gc.Chainer.Base.Seqno.IsEldest() {
			err := l.playLinkEldest(m, &link, otlr)
			if err != nil {
				return err
			}
		}
		err := l.playLink(m, &link, otlr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (l *TeamLoader) chainerAtIndex(n int) *proto.HidingChainer {
	if n > len(l.otlrs) {
		return nil
	}
	return &l.otlrs[n].Gc.Chainer
}

func (l *TeamLoader) checkUIDChain(m MetaContext) error {
	var prev *proto.LinkHash
	seqno := proto.ChainEldestSeqno
	if l.existing != nil {
		prev = &l.existing.LastHash
		seqno = l.existing.Tail.Base.Seqno + 1
	}
	return l.BaseChainLoader.checkChain(m, prev, seqno, l.raw.Links, l.chainerAtIndex, "team_id", nil)
}

func (l *TeamLoader) loadBoxesFromServer(m MetaContext) error {
	local := l.Arg.As.Host.Eq(l.Arg.Team.Host)
	for _, ptk := range l.raw.Boxes {
		myerr := func(msg string) error {
			return core.ChainLoaderError{
				Err: core.CLBoxError{
					Desc: msg,
					Role: ptk.Box.Role,
					Gen:  ptk.Box.Gen,
				},
			}
		}

		if !ptk.Box.Targ.Eid.Eq(l.Arg.As.Party.EntityID()) {
			return myerr("bad box target; not equal to loader")
		}
		if local != (ptk.Box.Targ.Host == nil) {
			return myerr("bad box target; local mismatch")
		}
		if !local && !ptk.Box.Targ.Host.Eq(l.Arg.As.Host) {
			return myerr("bad box target host; not equal to As.Host")
		}
		err := l.ptks.AddPrivBoxed(ptk)
		if err != nil {
			return err
		}
	}
	return nil

}

func (l *TeamLoader) checkArg(m MetaContext) error {
	err := l.Arg.Check()
	if err != nil {
		return err
	}
	if !l.Arg.Name.IsZero() {
		l.ntn, err = core.NormalizeName(l.Arg.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *TeamLoader) runOnce(m MetaContext) error {
	defer l.finish()

	err := l.checkArg(m)
	if err != nil {
		return err
	}
	err = l.connectHost(m)
	if err != nil {
		return err
	}
	err = l.loadExistingTeam(m)
	if err != nil {
		return err
	}
	err = l.makeViewToken(m)
	if err != nil {
		return err
	}
	err = l.loadTeamFromServer(m)
	if err != nil {
		return err
	}
	err = l.updateHEPKs(m)
	if err != nil {
		return err
	}
	err = l.checkRes(m)
	if err != nil {
		return err
	}
	err = l.playLinks(m)
	if err != nil {
		return err
	}
	// must play links before we can check username
	err = l.checkTeamname(m)
	if err != nil {
		return err
	}
	err = l.loadBoxesFromServer(m)
	if err != nil {
		return err
	}
	err = l.runUnbox(m)
	if err != nil {
		return err
	}
	err = l.unboxRemovalKey(m)
	if err != nil {
		return err
	}
	err = l.loadTokensAndMembers(m)
	if err != nil {
		return err
	}

	// In testing we might want to skip errors, but if we do, they
	// are remembered here, so there is no path through by accident
	// where the error is skipped
	if l.fatalError != nil {
		return l.fatalError
	}

	err = l.saveState(m)
	if err != nil {
		return err
	}

	return nil
}

var RemoteViewTokenEncryptionRole = core.AdminRole

func (p *rosterPackage) decrypt(
	m MetaContext,
	ptks *TeamKeysForRole,
) error {
	if p.remote == nil {
		return nil
	}
	gen := p.remote.tokBox.PtkGen
	key := ptks.At(gen)
	if key == nil {
		return core.PTKNotFound{Gen: gen, Role: RemoteViewTokenEncryptionRole.Export()}
	}
	sbkey := key.SecretBoxKey()
	var payload proto.TeamRemoteMemberViewTokenBoxPayload
	err := core.OpenSecretBoxInto(&payload,
		p.remote.tokBox.SecretBox,
		&sbkey,
	)
	if err != nil {
		return err
	}
	if !payload.Party.Eq(p.remote.tokBox.Member) {
		return core.ValidationError("party mismatch for decrypted token")
	}
	p.remote.tok = &payload.Tok
	return nil
}

func (l *TeamLoader) updateHEPKs(m MetaContext) error {
	s2, err := core.ImportHEPKSet(&l.raw.Hepks)
	if err != nil {
		return err
	}
	l.setHEPKs(l.hepks.Merge(s2))
	return nil
}

func (l *TeamLoader) openRemoteViewTokens(
	m MetaContext,
) error {
	if !l.isAdmin {
		return nil
	}
	ptks := l.ptks.KeysForRole(RemoteViewTokenEncryptionRole)
	if !ptks.HasPrivates() {
		return core.KeyNotFoundError{Which: "remote view token decrypt"}
	}
	for _, tok := range l.rosterDetails {
		// Just warn if we can't decrypt
		err := tok.decrypt(m, ptks)
		if err != nil {
			m.Warnw("TeamLoader.openRemoteViewTokens", "err", err, "stage", "decrypt")
		}
	}
	return nil
}

func (p *rosterPackage) load(m MetaContext, l *TeamLoader) error {
	tok := l.voTok
	uid, tid, err := p.fqp.Party.Select()
	if err != nil {
		return err
	}
	if p.isRemote && (p.remote == nil || p.remote.tok == nil) {
		return core.PermissionError("remote member has no view token")
	}
	switch {
	case uid != nil:
		arg := LoadUserArg{Uid: *uid, LoadMode: LoadModeOthers}
		if p.isRemote {
			arg.Host = &LoadUserHost{
				HostID: p.fqp.Host,
				Tok:    *p.remote.tok,
			}
		} else {
			if tok == nil {
				return core.PermissionError("need VO bearer token to load local user")
			}
			arg.TeamVOBearerToken = tok
		}
		uw, err := LoadUser(m, arg)
		if err != nil {
			return err
		}
		p.uw = uw
	case tid != nil:
		larg := LoadTeamArg{
			Team: proto.FQTeam{Host: p.fqp.Host, Team: *tid},
			As:   l.Arg.Team.FQParty(),
		}
		if p.isRemote {
			larg.Tok = p.remote.tok
		} else {
			larg.LocalParentTeamTok = tok
		}
		tw, err := LoadTeam(m, larg)
		if err != nil {
			return err
		}
		p.tw = tw
	default:
		return core.InternalError("no valid select case for party")
	}
	return nil
}

func (l *TeamLoader) loadMembers(
	m MetaContext,
) error {
	if !l.isAdmin {
		return nil
	}
	for _, rd := range l.rosterDetails {
		err := rd.load(m, l)
		if err != nil {
			m.Warnw("TeamLoader.loadMember", "err", err)
			rd.err = err
		}
	}
	return nil
}

func (l *TeamLoader) setAdminFlag(m MetaContext) error {
	role, err := l.destRoleForLoader(m)
	if err != nil {
		return err
	}
	if role == nil {
		return core.TeamError("loader wasn't found in loaded team")
	}
	l.isAdmin = role.IsAdminOrAbove()
	return nil
}

func (l *TeamLoader) destRoleForLoader(m MetaContext) (*core.RoleKey, error) {
	return l.rosterPost.LookupRoleForMember(l.Arg.As, l.Arg.SrcRole)
}

func (l *TeamLoader) loadTokensAndMembers(
	m MetaContext,
) error {
	if !l.Arg.LoadMembers {
		return nil
	}
	if l.Arg.Keys == nil {
		return nil
	}
	err := l.setAdminFlag(m)
	if err != nil {
		return err
	}
	err = l.setupRosterDetails(m)
	if err != nil {
		return err
	}
	err = l.loadAllRemoteViewTokens(m)
	if err != nil {
		return err
	}
	err = l.openRemoteViewTokens(m)
	if err != nil {
		return err
	}
	err = l.loadMembers(m)
	if err != nil {
		return err
	}
	return nil
}

func (l *TeamLoader) setupRosterDetails(
	m MetaContext,
) error {
	all, closer := l.rosterPost.BorrowMembers()
	defer closer()
	ret := make(map[proto.FQEntityFixed]*rosterPackage)
	for k, v := range all {
		fqp, err := k.Fqe.Unfix().FQParty()
		if err != nil {
			return err
		}
		isRemote := !fqp.Host.Eq(l.au.HostID())
		rp := &rosterPackage{
			info:     v,
			fqp:      *fqp,
			isRemote: isRemote,
			srcRole:  k.SrcRole.Export(),
		}
		ret[k.Fqe] = rp
	}
	l.rosterDetails = ret
	return nil
}

func (l *TeamLoader) loadAllRemoteViewTokens(
	m MetaContext,
) error {

	if !l.isAdmin {
		return nil
	}

	conv := func(p proto.FQParty) (*proto.FQEntityFixed, error) {
		return p.FQEntity().Fixed()
	}

	loadTokens := func(v []proto.TeamRemoteMemberViewTokenInner) error {
		for _, tok := range v {
			idp, err := conv(tok.Member)
			if err != nil {
				return err
			}
			l.rosterDetails[*idp].remote = &rosterPackageRemote{
				tokBox: tok,
			}
		}
		return nil
	}

	missingMembers := func() []proto.FQParty {
		var ret []proto.FQParty
		for _, v := range l.rosterDetails {
			if v.isRemote && v.remote == nil {
				ret = append(ret, v.fqp)
			}
		}
		return ret
	}

	var err error
	switch {
	case len(l.raw.RemoteViewTokens) > 0:
		err = loadTokens(l.raw.RemoteViewTokens)
	case l.existing != nil && len(l.existing.RemoteViewTokens) > 0:
		err = loadTokens(l.existing.RemoteViewTokens)
	}
	if err != nil {
		return err
	}

	// Now we figure out which view tokens we don't have, and add them to a list.
	missing := missingMembers()
	if len(missing) == 0 {
		return nil
	}

	typ, err := l.tok.GetT()
	if err != nil {
		return err
	}
	if typ != rem.TokenType_TeamVOBearer {
		return core.BadArgsError("expected a team VO bearer token for loading members")
	}
	arg := rem.LoadTeamRemoteViewTokensArg{
		Team:    l.Arg.Team,
		Tok:     l.tok.Teamvobearer(),
		Members: missing,
	}

	set, err := l.rpcLoader.LoadTeamRemoteViewTokens(m.Ctx(), arg)
	if err != nil {
		return err
	}

	for _, vt := range set.Tokens {
		fqe, err := conv(vt.Member)
		if err != nil {
			return err
		}
		l.rosterDetails[*fqe].remote = &rosterPackageRemote{tokBox: vt}
	}
	return nil
}

func (l *TeamLoader) loadAndMACRemovalKey(
	m MetaContext,
	comm *proto.KeyCommitment,
) (
	*rem.TeamRemovalMACPayload,
	error,
) {
	var key *rem.TeamRemovalKey
	rkb := l.RemovalKeyBox()

	if rkb != nil {
		var err error
		key, err = UnboxRemovalKey(m, l.Arg, rkb)
		if err != nil {
			return nil, err
		}
		computed, err := core.ComputeKeyCommitment(key)
		if err != nil {
			return nil, err
		}
		if comm == nil {
			comm = computed
		} else if !computed.Eq(*comm) {
			return nil, core.KeyMismatchError{}
		}
	}
	if comm == nil {
		return nil, core.KeyNotFoundError{Which: "removal key commitment"}
	}

	arg := rem.LoadRemovalForMemberArg{
		Team: l.Arg.Team,
		Comm: *comm,
	}
	res, err := l.rpcLoader.LoadRemovalForMember(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}
	key2, err := UnboxRemovalKey(m, l.Arg, &res.KeyBox)
	if err != nil {
		return nil, err
	}
	if key == nil {
		key = key2
	} else if !key.Eq(*key2) {
		return nil, core.KeyMismatchError{}
	}

	computed, err := core.ComputeKeyCommitment(key)
	if err != nil {
		return nil, err
	}
	if !computed.Eq(*comm) {
		return nil, core.VerifyError("key commitment didn't match")
	}

	macComputed, err := core.Hmac(&res.Removal.Payload, (*proto.HMACKey)(key))
	if err != nil {
		return nil, err
	}
	if !macComputed.Eq(res.Removal.Mac) {
		return nil, core.VerifyError("removal didn't pass MAC check")
	}
	return &res.Removal.Payload, nil
}

func (l *TeamLoader) checkRemovalKeyPayload(
	m MetaContext,
	rkp rem.TeamRemovalMACPayload,
) error {
	if !rkp.Team.Eq(l.Arg.Team) {
		return core.TeamError("removal key payload team mismatch")
	}
	if !rkp.Member.Eq(l.Arg.As) {
		return core.TeamError("removal key payload member mismatch")
	}
	ok, err := rkp.SrcRole.Eq(l.Arg.SrcRole)
	if err != nil {
		return err
	}
	if !ok {
		return core.RoleError("removal key payload role mismatch")
	}
	return nil
}

func (l *TeamLoader) VerifyRemoval(
	m MetaContext,
	comm *proto.KeyCommitment,
) error {

	if !l.Arg.Name.IsZero() {
		return core.InternalError("cannot verify removal with team name (need ID)")
	}
	err := l.checkArg(m)
	if err != nil {
		return err
	}
	err = l.connectHost(m)
	if err != nil {
		return err
	}
	defer l.finish()

	rkp, err := l.loadAndMACRemovalKey(m, comm)
	if err != nil {
		return err
	}
	err = l.checkRemovalKeyPayload(m, *rkp)
	if err != nil {
		return err
	}

	return nil
}

func (l *TeamLoader) exportIndexRange() (proto.RationalRange, error) {
	ir := l.getIndexRange()
	if ir == nil {
		var ret proto.RationalRange
		return ret, core.InternalError("no index range loaded")
	}
	return ir.Export(), nil
}

func (l *TeamLoader) saveState(m MetaContext) error {
	n := len(l.raw.Links)
	if l.existing == nil && n == 0 {
		return core.InternalError("no links in team sigchain")
	}

	unb, err := core.NewNameBundle(l.raw.TeamnameUtf8)
	if err != nil {
		return err
	}

	if n == 0 && len(l.raw.RemoteViewTokens) == 0 {
		l.newState = l.existing
		l.preload = l.existing
		l.rosterPre = l.rosterPost

		// The user might have updated the UTf8 preimage of the normalized username,
		// so update that here. This is based on server-trust, for now.
		l.newState.Name.B = unb
		return nil
	}

	var tail *proto.HidingChainer
	if n > 0 {
		tail = &l.otlrs[n-1].Gc.Chainer
	} else {
		tail = &l.existing.Tail
	}

	ir, err := l.exportIndexRange()
	if err != nil {
		return err
	}

	a, c := l.ptks.Export()
	res := lcl.TeamChainState{
		Fqt: proto.FQTeam{
			Team: l.TeamID(),
			Host: l.Arg.Team.Host,
		},
		Tail:     *tail,
		LastHash: *l.lastHash,
		Name: proto.NameAndSeqnoBundle{
			B: unb,
			S: l.tnseq,
		},
		MerkleLeaves:      l.allMerkleLeaves,
		Ptks:              a,
		PrivateKeys:       c,
		Members:           l.rosterPost.Export(l.Arg.Team.Host),
		RemovalKey:        l.RemovalKeyBox(),
		RemoteViewTokens:  l.raw.RemoteViewTokens,
		Hepks:             l.hepks.Export(),
		Tir:               ir,
		HistoricalSenders: l.histSend.Export(),
	}
	if l.sctlsc == nil {
		return core.InternalError("no 'sctlsc' set; it should be set in save(); refusing to save")
	}

	// Issue 241 fix; see TestIssue241
	res.Sctlsc = *l.sctlsc

	switch {
	case l.Arg.LoadMembers:
		lst := make([]proto.TeamRemoteMemberViewTokenInner, 0, len(l.rosterDetails))
		for _, v := range l.rosterDetails {
			if v.remote != nil {
				lst = append(lst, v.remote.tokBox)
			}
		}
		res.RemoteViewTokens = lst
	case l.existing != nil:
		res.RemoteViewTokens = l.existing.RemoteViewTokens
	}

	scoper := l.au.FQU()
	err = m.DbPut(l.dbType(), PutArg{
		Scope: &scoper,
		Typ:   lcl.DataType_TeamChainState,
		Val:   &res,
		Key:   l.Arg,
	})
	if err != nil {
		return err
	}
	l.newState = &res

	// in case we ever run this same team loader again,
	// let's just set the state up for right after
	// we loaaded it from disk.
	l.preload = &res // for next time we load
	l.rosterPre = l.rosterPost

	return nil
}

func UnboxRemovalKey(
	m MetaContext,
	lta LoadTeamArg,
	rkb *proto.TeamRemovalKeyBox,
) (
	*rem.TeamRemovalKey,
	error,
) {

	ok, err := rkb.EncKey.Role.Eq(lta.SrcRole)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.ChainLoaderError{
			Err: core.RoleError("removal key role mismatch"),
		}
	}
	unboxKey := lta.Keys.At(rkb.EncKey.Gen)
	if unboxKey == nil {
		return nil, core.ChainLoaderError{
			Err: core.KeyNotFoundError{Which: "removal unbox"},
		}
	}
	var out rem.TeamRemovalKeyBoxPayload
	_, err = unboxKey.UnboxFor(&out, rkb.Box, nil)
	if err != nil {
		return nil, err
	}
	if !out.Md.Tm.Eq(lta.Team) {
		return nil, core.ChainLoaderError{
			Err: core.TeamError("wrong team in key box payload"),
		}
	}
	if !out.Md.Member.Eq(lta.As) {
		return nil, core.ChainLoaderError{
			Err: core.WrongUserError{},
		}
	}
	ok, err = out.Md.SrcRole.Eq(lta.SrcRole)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.ChainLoaderError{
			Err: core.RoleError("removal key box payload role mismatch"),
		}
	}
	return &out.Key, nil
}

func (l *TeamLoader) RemovalKeyBox() *proto.TeamRemovalKeyBox {
	if l.existing != nil && l.existing.RemovalKey != nil {
		return l.existing.RemovalKey
	}
	return l.raw.RemovalKey
}

func (l *TeamLoader) unboxRemovalKey(m MetaContext) error {
	if l.Arg.Keys == nil {
		return nil
	}
	rkb := l.RemovalKeyBox()
	if rkb == nil {
		return core.ChainLoaderError{
			Err: core.KeyNotFoundError{Which: "removal"},
		}
	}
	key, err := UnboxRemovalKey(m, l.Arg, rkb)
	if err != nil {
		return err
	}
	l.removalKey = key
	return nil
}

func (l *TeamLoader) runUnbox(m MetaContext) error {

	// If not decrypting, early-out
	if l.Arg.Keys == nil {
		return nil
	}

	// Unbox all the keys we have; at each role ensure that we have an unbroken
	// string of PTKs from gen=0 all the way up

	role, err := l.rosterPost.LookupRoleForMember(l.Arg.As, l.Arg.SrcRole)
	if err != nil {
		return err
	}
	if role == nil {
		return core.TeamRosterError("cannot find role for loading user")
	}

	rcvr := TeamUnboxReceiver{Keys: l.Arg.Keys, Host: l.Arg.Team.Host}
	for _, ptk := range l.ptks.All() {
		if role.LessThan(ptk.Role()) {
			continue
		}
		err := ptk.Unbox(m, l.hepks, rcvr, l.Arg.Team.Host, l.rosterPost, &l.histSend)
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *TeamLoader) checkTeamname(m MetaContext) error {
	var existingName *proto.NameAndSeqnoBundle
	if l.existing != nil {
		existingName = &l.existing.Name
	}
	nseq, err := l.checkNameLoad(
		m,
		l.TeamID().ToPartyID(),
		l.probe.Chain().HostID(),
		l.tncs,
		l.raw.Teamnames,
		existingName,
		l.raw.TeamnameUtf8,
		int(l.raw.NumTeamnameLinks),
		l.raw.Merkle,
	)
	if err != nil {
		return err
	}

	// If we loaded by name, check that we got the same name out the other side.
	if !l.Arg.Name.IsZero() {
		ntn, err := core.NormalizeName(l.raw.TeamnameUtf8)
		if err != nil {
			return err
		}
		if !ntn.Eq(l.ntn) {
			return core.ChainLoaderError{
				Err: core.NameError("teamname mismatch"),
			}
		}
	}
	l.tnseq = nseq
	return nil

}

func (l *TeamLoader) resetState() {
	l.otlrs = nil
	l.existing = nil
	l.tncs = nil
	l.linkHashes = nil
}

func (l *TeamLoader) Shutdown() {}

func (l *TeamLoader) Existing() *lcl.TeamChainState {
	return l.existing
}

type LoadTeamArg struct {
	Team               proto.FQTeam
	Name               proto.NameUtf8 // Either this is nonzero, or Team.Team
	As                 proto.FQParty
	SrcRole            proto.Role
	Keys               SharedKeySequence
	Tok                *proto.PermissionToken
	LocalParentTeamTok *rem.TeamVOBearerToken
	LoadMembers        bool
	TestSkipArgCheck   bool
	TestTokenVariant   *rem.TokenVariant

	// If true, the keys are stale and need to be refreshed.
	// Also, we can auto-try a key refresh on a permissions error.
	KeysAreStale bool
	KeyRefresher func(MetaContext) (SharedKeySequence, error)
}

func (l LoadTeamArg) Check() error {
	n := !l.Name.IsZero()
	i := !l.Team.Team.IsZero()
	k := l.Keys != nil
	t := l.Tok != nil
	ptt := l.LocalParentTeamTok != nil

	// In test, we want to test that server errors out under all conditions.
	if l.TestSkipArgCheck {
		return nil
	}

	if !n && !i {
		return core.InternalError("must specify either name or team")
	}
	if n && i {
		return core.InternalError("must specify either name or team, not both")
	}
	if ptt && t {
		return core.InternalError("must specify either local parent team token or permission token, not both")
	}
	if k && t {
		return core.InternalError("must specify either keys or token, not both")
	}
	if !t && !k && !ptt {
		return core.InternalError("need keys, a permission token, or a local parent team token")
	}
	if ptt && !l.Team.Host.Eq(l.As.Host) {
		return core.InternalError("local parent team token must be for the same host as the As party")
	}
	return nil
}

func (a LoadTeamArg) DbKey() (proto.DbKey, error) {
	tmp := lcl.TeamChainIndex{
		Team:     a.Team,
		AsLoader: a.As,
		SrcRole:  a.SrcRole,
		Priv:     (a.Keys != nil),
	}
	ret := make([]byte, 32)
	err := core.PrefixedHashInto(&tmp, ret)
	if err != nil {
		return nil, err
	}
	return proto.DbKey(ret), nil
}

func LoadTeam(
	m MetaContext,
	arg LoadTeamArg,
) (
	*TeamWrapper,
	error,
) {
	_, w, err := LoadTeamReturnLoader(m, arg)
	return w, err
}

func LoadTeamReturnLoader(
	m MetaContext,
	arg LoadTeamArg,
) (
	*TeamLoader,
	*TeamWrapper,
	error,
) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, nil, core.NeedLoginError{}
	}
	l := NewTeamLoader(au, arg)
	res, err := l.Run(m)
	if err != nil {
		return l, nil, err
	}
	return l, res, nil
}

type TeamCryptoPartier struct {
	Fqt  proto.FQTeam
	Role proto.Role
	Kr   *TeamKeyRing
}

var _ CryptoPartier = (*TeamCryptoPartier)(nil)

func (t *TeamCryptoPartier) SrcRole() proto.Role {
	return t.Role
}

func (t *TeamCryptoPartier) FQParty() proto.FQParty {
	return t.Fqt.FQParty()
}

func (t *TeamCryptoPartier) CurrentAdminKey(m MetaContext) (core.SharedPrivateSuiter, error) {
	return t.Kr.AdminOrOwnerKey().Current(), nil
}

func (t *TeamCryptoPartier) PrivateKeyAt(m MetaContext, g proto.Generation) (core.SharedPrivateSuiter, error) {
	return t.Kr.AdminOrOwnerKey().At(g), nil
}

func (t *TeamCryptoPartier) Refresh(m MetaContext, tm *TeamMinder) (CryptoPartier, error) {

	m.Infow("TeamCryptoPartier.Refresh", "fqt", t.Fqt, "role", t.Role)

	tr, err := tm.LoadTeamWithFQTeam(m, t.Fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return nil, err
	}
	return &TeamCryptoPartier{
		Fqt:  t.Fqt,
		Role: t.Role,
		Kr:   tr.tw.KeyRing(),
	}, nil
}
