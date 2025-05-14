// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type TeamMinderTestHooks struct {
	PostChainHook func() error
}

type teamCert struct {
	cert rem.TeamCert
	gen  proto.Generation
}

type inboxCacheRow struct {
	row  lcl.TeamInboxRow
	team proto.FQTeam
}

// TeamMinder is a high-level class that is in charge of managing all of the user's
// teams, via some combination of team loader, and team membership loader. There should
// be one per active user, since each active user has their own team memberships.
type TeamMinder struct {
	au *UserContext

	exploreMu sync.Mutex
	// The team membership wrapper for the current user. We'll have others for
	// the teams that we are members of.
	userTMW *TeamMembershipLoaderAndWrapper

	indexMu sync.RWMutex
	// Master list of all loaded teams, we just hold onto the wrappers, not the full
	// loaders. We might change this.
	loadedTeams map[proto.FQTeam]*TeamRecord
	// Various indices to drive lookups based on different query combinations. They point
	// back into the loadedTeams map.
	teamIndex map[proto.FQTeamString]proto.FQTeam
	// When the last indexing happened
	lastIndex time.Time

	certsMu sync.Mutex
	// hold on to certs that we have loaded. they will get stale on admin PUK
	// rotation, and we should swap them then
	certs map[proto.FQTeam](*teamCert)

	inboxMu sync.Mutex
	// Cached inbox which persists across CLI calls
	inbox map[proto.TeamRSVP]inboxCacheRow

	// For testing
	TestHooks *TeamMinderTestHooks

	// Only one CLKR should be running at once, so
	// single flight them with this lock
	clkrMu sync.Mutex

	// team config right now contains the Max# of supported roles per team;
	// Varies per host; this one is on the current active user's host
	configMu sync.Mutex
	config   *rem.TeamConfig
}

func (t *TeamMinder) ActiveUser() *UserContext {
	return t.au
}

func (t *TeamMinder) UserTMW() *TeamMembershipLoaderAndWrapper {
	t.exploreMu.Lock()
	defer t.exploreMu.Unlock()
	return t.userTMW
}

func (t *TeamMinder) activeUser(m MetaContext) (*UserContext, error) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	return au, nil
}

func (t *TeamMinder) refreshUserTML(m MetaContext) (*TeamMembershipWrapper, error) {
	t.exploreMu.Lock()
	defer t.exploreMu.Unlock()

	// The role in user's team membership chain is the role of the device that
	// the user is on. Read-only devices won't be able to update the chain
	// if the user loses membership.
	tmlu, err := NewTMLUser(m, t.au.Info.Role)
	if err != nil {
		return nil, err
	}
	t.userTMW, err = LoadTeamMembershipReturnLoader(m, tmlu)
	if err != nil {
		return nil, err
	}

	return t.userTMW.Wrapper, nil
}

func (t *TeamMinder) loadUserTMLLocked(m MetaContext) error {

	// The role in user's team membership chain is the role of the device that
	// the user is on. Read-only devices won't be able to update the chain
	// if the user loses membership.
	tmlu, err := NewTMLUser(m, t.au.Info.Role)
	if err != nil {
		return err
	}
	t.userTMW, err = LoadTeamMembershipReturnLoader(m, tmlu)
	if err != nil {
		return err
	}

	return nil
}

func getApprovedDetails(l proto.TeamMembershipLink) (*MembershipDetails, error) {
	typ, err := l.State.GetT()
	if err != nil {
		return nil, err
	}
	switch typ {
	case proto.TeamMembershipLinkState_Requested:
		return &MembershipDetails{
			SrcRole: l.SrcRole,
		}, nil
	case proto.TeamMembershipLinkState_Approved:
		appr := l.State.Approved()
		return &MembershipDetails{
			SrcRole:  l.SrcRole,
			Approved: true,
			DstRole:  &appr.Dst.Role,
			KeyComm:  &appr.KeyComm,
		}, nil
	default:
		return nil, nil
	}
}

func (t *TeamMinder) checkSingleTeamInMembershipChain(
	m MetaContext,
	tm rem.LocalTeamListEntry,
) (
	bool,
	*proto.FQTeam,
	error,
) {
	fqt := proto.FQTeam{Host: t.au.HostID(), Team: tm.Id}
	var key FQTeamSrcRole
	err := key.Import(fqt, tm.SrcRole)
	if err != nil {
		return false, nil, err
	}
	// chceck against preloaded userTMW
	etm, ok := t.userTMW.Wrapper.Map[key]
	if !ok {
		return false, &fqt, nil
	}
	appr, err := getApprovedDetails(etm)
	if err != nil {
		return false, nil, err
	}
	if appr == nil {
		return false, &fqt, nil
	}
	eq, err := appr.SrcRole.Eq(tm.SrcRole)
	if err != nil {
		return false, nil, err
	}
	return eq, &fqt, nil
}

type TeamRecord struct {
	sync.Mutex
	tw     *TeamWrapper
	Tmw    *TeamMembershipWrapper
	Time   time.Time
	ldr    *TeamLoader
	mldr   *TeamMembershipLoader
	member CryptoPartier // The group or user that is controlling this team as admin
}

func (t *TeamRecord) Tw() *TeamWrapper {
	t.Lock()
	defer t.Unlock()
	return t.tw
}

func (t *TeamRecord) IndexRange() core.RationalRange {
	t.Lock()
	defer t.Unlock()
	return t.tw.IndexRange()
}

func (t *TeamRecord) IndexRangeWithOverride(m MetaContext) core.RationalRange {
	t.Lock()
	defer t.Unlock()
	tmp := m.G().Cfg().FakeTeamIndexRangeFor(t.tw.prot.Fqt)
	if tmp != nil {
		return *tmp
	}
	return t.tw.IndexRange()
}

func (t *TeamRecord) FQT() proto.FQTeam {
	return t.Tw().prot.Fqt
}

func (t *TeamRecord) Member() CryptoPartier {
	t.Lock()
	defer t.Unlock()
	return t.member
}

type LoadTeamOpts struct {
	LoadMembers bool
	Refresh     bool
}

func (t *TeamMinder) GetTeam(fqt proto.FQTeam) *TeamRecord {
	return t.getTeam(fqt)
}

func (t *TeamMinder) AllLoadedTeams() []*TeamRecord {
	ret := make([]*TeamRecord, 0, len(t.loadedTeams))
	t.indexMu.RLock()
	defer t.indexMu.RUnlock()
	for _, v := range t.loadedTeams {
		ret = append(ret, v)
	}
	return ret
}

func (t *TeamMinder) getTeam(fqt proto.FQTeam) *TeamRecord {
	t.indexMu.RLock()
	defer t.indexMu.RUnlock()
	return t.loadedTeams[fqt]
}

func (t *TeamMinder) loadTeamMembership(
	m MetaContext,
	fqt proto.FQTeam,
	opts LoadTeamOpts,
) (
	*TeamMembershipWrapper,
	error,
) {
	tr, err := t.getTeamWithRefresh(m, fqt, opts.Refresh)
	if err != nil {
		return nil, err
	}
	if !opts.Refresh {
		return tr.Tmw, nil
	}
	tr.Lock()
	defer tr.Unlock()
	tmw, err := tr.mldr.Run(m)
	if err != nil {
		return nil, err
	}
	tr.Tmw = tmw
	return tmw, nil
}

func (t *TeamMinder) getTeamWithRefresh(
	m MetaContext,
	fqt proto.FQTeam,
	refresh bool,
) (
	*TeamRecord,
	error,
) {
	get := func() *TeamRecord { return t.getTeam(fqt) }
	tr := get()
	if tr == nil && refresh {
		err := t.ExploreAndIndex(m)
		if err != nil {
			return nil, err
		}
		tr = get()
	}
	if tr == nil {
		return nil, core.TeamNotFoundError{}
	}
	return tr, nil
}

// LoadTeamWithFQTeam is a high-level function that accesses the result of prior explorations,
// or a new one if the opts.Refresh flag is set to true.
func (t *TeamMinder) LoadTeamWithFQTeam(
	m MetaContext,
	fqt proto.FQTeam,
	opts LoadTeamOpts,
) (
	*TeamRecord,
	error,
) {
	tr, err := t.getTeamWithRefresh(m, fqt, opts.Refresh)
	if err != nil {
		return nil, err
	}

	tr.Lock()
	defer tr.Unlock()
	if !opts.Refresh && (!opts.LoadMembers || tr.ldr.Arg.LoadMembers) {
		return tr, nil
	}

	tr.ldr.Arg.LoadMembers = opts.LoadMembers

	tw, err := tr.ldr.Run(m)
	if err != nil {
		return nil, err
	}
	tr.tw = tw
	return tr, nil
}

func (w *TeamRecord) LoadArg() LoadTeamArg {
	w.Lock()
	defer w.Unlock()
	return w.ldr.Arg
}

func (w *TeamRecord) findDst() (*proto.RoleAndSeqno, error) {
	w.Lock()
	defer w.Unlock()
	return w.findDstLocked()
}

func (w *TeamRecord) findDstLocked() (*proto.RoleAndSeqno, error) {
	mrq, err := w.tw.GetMember(w.ldr.Arg.As, w.ldr.Arg.SrcRole)
	if err != nil {
		return nil, err
	}
	return &proto.RoleAndSeqno{
		Role:  mrq.Mr.DstRole,
		Seqno: mrq.Seqno,
	}, nil
}

func (r *TeamRecord) ExportToTeamMembership() (*lcl.TeamMembership, error) {
	r.Lock()
	defer r.Unlock()

	dr, err := r.findDstLocked()
	if err != nil {
		return nil, err
	}

	ret := lcl.TeamMembership{
		Team:    r.tw.ExportToNamedFQParty(),
		DstRole: dr.Role,
		SrcRole: r.member.SrcRole(),
		Tir:     r.tw.prot.Tir,
	}

	via := r.member.FQParty()
	if via.Party.IsTeam() {
		ret.Via = &lcl.NamedFQParty{
			Fqp: via,
		}
	}
	return &ret, nil

}

func (t *TeamMinder) postMembershipLink(
	m MetaContext,
	fqt proto.FQTeam,
	tw *TeamRecord,
) error {

	dst, err := tw.findDst()
	if err != nil {
		return err
	}
	comm, err := core.ComputeKeyCommitment(tw.Tw().rk)
	if err != nil {
		return err
	}
	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    fqt,
			SrcRole: tw.LoadArg().SrcRole,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst:     *dst,
					KeyComm: *comm,
				},
			),
		},
	)

	ma, err := t.au.MerkleAgent(m)
	if err != nil {
		return err
	}
	tr, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return err
	}

	var prev *proto.LinkHash
	seqno := proto.ChainEldestSeqno

	if t.userTMW.Wrapper.Prot != nil {
		seqno = t.userTMW.Wrapper.Prot.Tail.Base.Seqno + 1
		prev = &t.userTMW.Wrapper.Prot.LastHash
	}

	glink, err := core.MakeGenericLink(
		t.au.UID().EntityID(),
		fqt.Host,
		t.au.PrivKeys.GetDevkey(),
		glp,
		seqno,
		prev,
		tr,
	)
	if err != nil {
		return err
	}

	ucli, err := t.au.UserClient(m)
	if err != nil {
		return err
	}

	err = ucli.PostGenericLink(m.Ctx(), rem.PostGenericLinkArg{
		Link:             *glink.Link,
		NextTreeLocation: *glink.NextTreeLocation,
	})

	if err != nil {
		return err
	}

	if t.TestHooks != nil && t.TestHooks.PostChainHook != nil {
		err = t.TestHooks.PostChainHook()
		if err != nil {
			return err
		}
	}

	err = t.loadUserTMLLocked(m)
	if err != nil {
		return err
	}

	return nil
}

// directLoadTeam loads the given team, using the active user, without going through the
// caching machinery of the TeamMinder. This is useful in exploration, so we don't recursively
// call into the TeamMinder under the same lock. Note that the TeamRecord returned does not
// have a valid Tmw field, since team membership isn't loaded here.
func (t *TeamMinder) directLoadTeam(m MetaContext, fqt proto.FQTeam) (*TeamRecord, error) {
	puks, err := t.au.RefreshPUKs(m)
	if err != nil {
		return nil, err
	}
	arg := LoadTeamArg{
		Team:    fqt,
		As:      t.au.FQU().FQParty(),
		SrcRole: team.UserSrcRole,
		Keys:    puks,
	}
	ldr, tw, err := LoadTeamReturnLoader(m, arg)
	if err != nil {
		return nil, err
	}
	return &TeamRecord{tw: tw, ldr: ldr, Time: time.Now()}, nil
}

func (t *TeamMinder) storeMembershipToChain(m MetaContext, fqt proto.FQTeam) error {
	tw, err := t.directLoadTeam(m, fqt)
	if err != nil {
		return err
	}
	err = t.postMembershipLink(m, fqt, tw)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) serverTrustListForUser(m MetaContext) error {

	ucli, err := t.au.UserClient(m)
	if err != nil {
		return err
	}

	tmList, err := ucli.GetTeamListServerTrust(m.Ctx())
	if err != nil {
		return err
	}

	for _, tm := range tmList {
		found, fqt, err := t.checkSingleTeamInMembershipChain(m, tm)
		if err != nil {
			m.Warnw("checkSingleTeamInMembershipChain", "err", err, "tm", tm.Id)
			return err
		}
		if !found {
			err = t.storeMembershipToChain(m, *fqt)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *TeamMinder) seedExplore(m MetaContext) error {

	err := t.loadUserTMLLocked(m)
	if err != nil {
		return err
	}

	err = t.serverTrustListForUser(m)
	if err != nil {
		return err
	}
	return nil
}

type MembershipDetails struct {
	SrcRole  proto.Role
	Approved bool // if not approved, we're in "requested" mode

	// the following two are only valid if Approved is true
	DstRole *proto.Role
	KeyComm *proto.KeyCommitment
}

type ExploreNode struct {
	Fqt     proto.FQTeam
	Tir     proto.RationalRange
	SrcRole core.RoleKey
	Member  *proto.FQTeam // If nil, then it's the user direct membership
	Details MembershipDetails
	Parent  *TeamMembershipLoaderAndWrapper
}

type ExploreWarning struct {
	Err    error
	Loader *TeamLoader
	Node   ExploreNode
}

type TeamUpdate struct {
	Loader  *TeamLoader
	MLoader *TeamMembershipLoader
	Node    ExploreNode
	Mrs     proto.MemberRoleSeqno
}

type ExploreState struct {
	Teams      map[proto.FQTeam]*TeamRecord
	Visisted   map[proto.FQTeam]bool
	puks       *PUKSet
	Warnings   map[proto.FQTeam]*ExploreWarning
	Updates    map[proto.FQTeam]*TeamUpdate
	Edges      map[proto.FQTeam][]proto.FQTeam
	StartNodes []proto.FQTeam
}

func newExploreState(puks *PUKSet) *ExploreState {
	return &ExploreState{
		Teams:    make(map[proto.FQTeam]*TeamRecord),
		Visisted: make(map[proto.FQTeam]bool),
		Warnings: make(map[proto.FQTeam]*ExploreWarning),
		Updates:  make(map[proto.FQTeam]*TeamUpdate),
		Edges:    make(map[proto.FQTeam][]proto.FQTeam),
		puks:     puks,
	}
}

// SortedTeams takes the output of an exploration and provides a topological sort of
// the team visited, from lowest index to highest index. The output is randomized, with
// sibling nodes sorted randomly. This will prevent mashing the same teams in the same order,
// since in some sense all admins will be racing to rekey the same teams. The order output
// is a reasonable order in which to rotate teams, with the simple property that if A is a member
// of B, then A will be rotated first, since often a rotation of A can trigger a rotation of B
// (but not the other way around).
func (e *ExploreState) SortedTeams() ([]proto.FQTeam, error) {
	return core.TopoTraverseOrder(e.Edges)
}

// loadTeamArg figures out the LoadTeamArg to pass to the team loader when loading
// the ExploreNode tm in the context of the ExploreState e. It returns the arg
// as well as the CryptoPartier, the party that will be doing the loading. This can
// be the user, or a team, if the user is loading the team on behalf of another team.
func (tm *TeamMinder) loadTeamArg(
	exnode ExploreNode,
	e *ExploreState,
) (
	CryptoPartier,
	*LoadTeamArg,
	error,
) {
	au := tm.au
	arg := LoadTeamArg{
		Team: exnode.Fqt,
	}
	var cp CryptoPartier
	if exnode.Member != nil {
		fqt := *exnode.Member
		srcRole := exnode.Details.SrcRole
		arg.As = exnode.Member.FQParty()
		arg.SrcRole = srcRole
		tr := e.Teams[*exnode.Member]
		if tr == nil {
			return nil, nil, core.TeamExploreError("team not found in exploration")
		}
		rk, err := core.ImportRole(arg.SrcRole)
		if err != nil {
			return nil, nil, err
		}

		// This can go stale if the teamwrapper is updated.
		// We'll be stuck holding onto the keys from the old team.
		// In a single CLKR session this can go stale, but it also
		// can happen if the team is updated somewhere else.
		// We use the KeyRefresher for a codepath on how to fix this
		// situation. That does a (potentially recursive!) team load
		// to fetch any new PTKs the member team has.
		arg.Keys = tr.Tw().KeyRing().KeysForRole(*rk)
		arg.KeyRefresher = tr.LoadArg().makeKeyRingRefresher()
		cp = &TeamCryptoPartier{
			Fqt:  fqt,
			Role: srcRole,
			Kr:   tr.Tw().KeyRing(),
		}
	} else {
		arg.As = au.FQU().FQParty()
		arg.SrcRole = team.UserSrcRole
		arg.Keys = e.puks
		arg.KeyRefresher = au.KeyRefresher
		cp = au
	}
	return cp, &arg, nil
}

func (t *TeamMinder) explore(
	m MetaContext,
	state *ExploreState,
	tm ExploreNode,
) (
	[]ExploreNode,
	error,
) {
	cp, arg, err := t.loadTeamArg(tm, state)
	if err != nil {
		return nil, err
	}
	ldr, tw, err := LoadTeamReturnLoader(m, *arg)
	if core.IsPermissionError(err) {
		state.Warnings[tm.Fqt] = &ExploreWarning{
			Err:    err,
			Loader: ldr,
			Node:   tm,
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tmem, err := tw.GetMember(arg.As, arg.SrcRole)
	if err != nil {
		return nil, err
	}
	if tmem == nil {
		return nil, core.TeamExploreError("load as party not found in team")
	}
	dstRole := tmem.Mr.DstRole

	var doUpdate bool
	if !tm.Details.Approved {
		doUpdate = true
	} else {
		ok, err := dstRole.Eq(*tm.Details.DstRole)
		if err != nil {
			return nil, err
		}
		if !ok {
			doUpdate = true
		}
	}
	if doUpdate {
		state.Updates[tm.Fqt] = &TeamUpdate{
			Loader: ldr,
			Node:   tm,
			Mrs:    *tmem,
		}
	}

	tmlt, err := NewTMLTeam(m, *arg, dstRole)
	if err != nil {
		return nil, err
	}
	tmemb, err := LoadTeamMembershipReturnLoader(m, tmlt)
	if err != nil {
		return nil, err
	}

	state.Teams[tm.Fqt] = &TeamRecord{
		tw:     tw,
		Tmw:    tmemb.Wrapper,
		Time:   time.Now(),
		ldr:    ldr,
		mldr:   tmemb.Loader,
		member: cp,
	}

	ret, err := tmemb.explore(&tm.Fqt)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (t *TeamMembershipLoaderAndWrapper) explore(
	member *proto.FQTeam,
) (
	[]ExploreNode,
	error,
) {
	var queue []ExploreNode
	for fqt, val := range t.Wrapper.Map {
		details, err := getApprovedDetails(val)
		if err != nil {
			return nil, err
		}
		if details == nil {
			continue
		}
		node := ExploreNode{
			Fqt:     fqt.FQTeam,
			SrcRole: fqt.SrcRole,
			Details: *details,
			Member:  member,
			Parent:  t,
		}
		queue = append(queue, node)
	}
	return queue, nil
}

func (t *TeamMinder) Explore(
	m MetaContext,
) (
	*ExploreState,
	error,
) {

	// For now, let's single-flight all explorations. This guards
	// access to t.UserTWM, which is the seed of the exploration.
	t.exploreMu.Lock()
	defer t.exploreMu.Unlock()

	err := t.seedExplore(m)
	if err != nil {
		return nil, err
	}

	puks, err := t.au.RefreshPUKs(m)
	if err != nil {
		return nil, err
	}
	state := newExploreState(puks)

	// Seed the BFS with the user's local teams. The user is an owner
	// for this chain, so can modify it.
	queue, err := t.userTMW.explore(nil)
	if err != nil {
		return nil, err
	}

	// Write down the start nodes for doing a topological sort in the case
	// of a CLKR. Note these start nodes need to be sorted by team index range,
	// and we can't do that until later, after we've loaded the corresponding teams.
	for _, tm := range queue {
		state.StartNodes = append(state.StartNodes, tm.Fqt)
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		state.Visisted[curr.Fqt] = true

		teams, err := t.explore(m, state, curr)
		if err != nil {
			return nil, err
		}

		// Even if no outgoing edges, we still want to record the node
		state.Edges[curr.Fqt] = []proto.FQTeam{}

		for _, t := range teams {

			// Maintain a graph of edges so that we can do a topological sort for CLKRs
			// This graph is the inverted graph of team memberships. An edge goes from
			// A to B if A is a member of B. In CLKR, we'll do a BFS of this graph
			// and visit teams in that order. That is we'll rotate A, which will force
			// a rotation of B, so we have to visit A first.
			edges := state.Edges[curr.Fqt]
			edges = append(edges, t.Fqt)
			state.Edges[curr.Fqt] = edges

			if !state.Visisted[t.Fqt] {
				queue = append(queue, t)
			}
		}
	}

	for _, w := range state.Warnings {
		err := t.fixExploreWarning(m, state, w)
		if err != nil {
			return nil, err
		}
	}

	for _, u := range state.Updates {
		err := t.fixViaUpdate(m, state, u)
		if err != nil {
			return nil, err
		}
	}

	return state, nil
}

func (t *TeamMinder) fixViaUpdate(
	m MetaContext,
	state *ExploreState,
	u *TeamUpdate,
) error {
	role := u.Node.Parent.Wrapper.RoleInChain
	adm, err := role.IsAdminOrAbove()
	if err != nil {
		return err
	}
	if !adm {
		m.Warnw("TeamMinder.fixViaUpdate", "skip", "non-admin", "role", role)
		return nil
	}
	if !u.Node.Details.Approved {
		m.Warnw("TeamMinder.fixViaUpdate", "skip", "not-approved", "role", role)
		return nil
	}

	larg := u.Loader.Arg

	typ, err := u.Mrs.Mr.Member.Keys.GetT()
	if err != nil {
		return err
	}
	if typ != proto.MemberKeysType_Team {
		return core.InternalError("expected team keys")
	}
	comm := u.Mrs.Mr.Member.Keys.Team().Trkc
	if comm == nil {
		return core.InternalError("expected team removal key commitment")
	}
	err = u.Node.Parent.Loader.PostApprovedMembership(
		m,
		larg.Team,
		larg.As,
		larg.SrcRole,
		proto.RoleAndSeqno{
			Role:  u.Mrs.Mr.DstRole,
			Seqno: u.Mrs.Seqno,
		},
		*comm,
	)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) fixExploreWarning(
	m MetaContext,
	state *ExploreState,
	w *ExploreWarning,
) error {
	if !core.IsPermissionError(w.Err) {
		m.Warnw("TeamMinder.fixExploreWarning", "skip", "non-permission-error", "err", w.Err)
		return nil
	}
	role := w.Node.Parent.Wrapper.RoleInChain
	adm, err := role.IsAdminOrAbove()
	if err != nil {
		return err
	}
	if !adm {
		m.Warnw("TeamMinder.fixExploreWarning", "skip", "non-admin", "role", role)
		return nil
	}
	if !w.Node.Details.Approved {
		m.Warnw("TeamMinder.fixExploreWarning", "skip", "not-approved", "role", role)
		return nil
	}
	err = w.Loader.VerifyRemoval(m, w.Node.Details.KeyComm)
	if err != nil {
		return err
	}

	larg := w.Loader.Arg
	err = w.Node.Parent.Loader.RemoveMembership(m, larg.Team, larg.As, larg.SrcRole)
	if err != nil {
		return err
	}

	return nil
}

func (t *TeamMinder) reindex(state *ExploreState) error {
	t.indexMu.Lock()
	defer t.indexMu.Unlock()

	t.loadedTeams = make(map[proto.FQTeam]*TeamRecord)
	t.teamIndex = make(map[proto.FQTeamString]proto.FQTeam)
	t.lastIndex = time.Now()

	for fqt, tr := range state.Teams {
		t.loadedTeams[fqt] = tr
		names, err := tr.Tw().AllFQStrings()
		if err != nil {
			return err
		}
		for _, n := range names {
			t.teamIndex[n] = fqt
		}
	}
	return nil
}

func NewTeamMinder(u *UserContext) *TeamMinder {
	return &TeamMinder{au: u}
}

func (t *TeamMinder) ExploreAndIndex(m MetaContext) error {
	state, err := t.Explore(m)
	if err != nil {
		return err
	}
	err = t.reindex(state)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) PopulateTeamName(p *lcl.NamedFQParty) error {
	if p == nil {
		return nil
	}
	fqt := p.Fqp.FQTeam()
	if fqt == nil {
		return nil
	}
	t.indexMu.RLock()
	defer t.indexMu.RUnlock()
	tr, ok := t.loadedTeams[*fqt]
	if !ok {
		return core.TeamNotFoundError{}
	}
	p.Host = tr.tw.Hostname()
	p.Name = tr.tw.Name()
	return nil
}

func (t *TeamMinder) resolveTeam(arg proto.FQTeamParsed) (*proto.FQTeam, error) {

	var hostID *proto.HostID

	if arg.Host == nil {
		tmp := t.au.HostID()
		hostID = &tmp
	} else {
		isHostName, err := arg.Host.GetS()
		if err != nil {
			return nil, err
		}
		if !isHostName {
			tmp := arg.Host.False()
			hostID = &tmp
		}
	}

	var teamID *proto.TeamID
	isTeamName, err := arg.Team.GetS()
	if err != nil {
		return nil, nil
	}
	if !isTeamName {
		tmp := arg.Team.False()
		teamID = &tmp
	}

	if teamID != nil && hostID != nil {
		return &proto.FQTeam{Host: *hostID, Team: *teamID}, nil
	}

	t.indexMu.RLock()
	defer t.indexMu.RUnlock()

	if t.teamIndex == nil {
		return nil, nil
	}

	var h string
	switch {
	case hostID != nil:
		h, err = hostID.StringErr()
	case arg.Host != nil:
		h, err = arg.Host.StringErr()
	default:
		err = core.InternalError("unexpeecected nil host")
	}
	if err != nil {
		return nil, err
	}

	tm, err := arg.Team.StringErr()
	if err != nil {
		return nil, err
	}
	ntm, err := core.NormalizeName(proto.NameUtf8(tm))
	if err != nil {
		return nil, err
	}
	i := proto.FQTeamString(ntm.String() + "@" + h)

	fqt, ok := t.teamIndex[i]
	if !ok {
		return nil, nil
	}

	return &fqt, nil
}

func (t *TeamMinder) Resolve(m MetaContext, arg proto.FQTeamParsed) (*proto.FQTeam, error) {
	return t.resolveTeam(arg)
}

func (t *TeamMinder) ResolveAndReindex(m MetaContext, arg proto.FQTeamParsed) (*proto.FQTeam, error) {
	fqt, err := t.resolveTeam(arg)
	if err != nil {
		return nil, err
	}
	if fqt != nil {
		return fqt, nil
	}
	err = t.ExploreAndIndex(m)
	if err != nil {
		return nil, err
	}
	fqt, err = t.resolveTeam(arg)
	if err != nil {
		return nil, err
	}
	if fqt == nil {
		return nil, core.TeamNotFoundError{}
	}
	return fqt, nil
}

func (t *TeamMinder) LoadTeam(
	m MetaContext,
	arg proto.FQTeamParsed,
	opts LoadTeamOpts,
) (
	*TeamWrapper,
	error,
) {
	fqt, err := t.ResolveAndReindex(m, arg)
	if err != nil {
		return nil, err
	}
	if fqt == nil {
		return nil, core.TeamNotFoundError{}
	}
	tm, err := t.LoadTeamWithFQTeam(m, *fqt, opts)
	if err != nil {
		return nil, err
	}
	return tm.Tw(), nil
}

func (t *TeamMinder) withLoadedTeam(
	m MetaContext,
	arg proto.FQTeamParsed,
	opts LoadTeamOpts,
	f func(m MetaContext, tm *TeamRecord) error,
) error {
	fqt, err := t.ResolveAndReindex(m, arg)
	if err != nil {
		return err
	}
	if fqt == nil {
		return core.TeamNotFoundError{}
	}
	tm, err := t.LoadTeamWithFQTeam(m, *fqt, opts)
	if err != nil {
		return err
	}
	return f(m, tm)
}

func (t *TeamMinder) withLoadedTeamAndAdminToken(
	m MetaContext,
	arg proto.FQTeamParsed,
	opts LoadTeamOpts,
	f func(m MetaContext, tr *TeamRecord, token *rem.TeamBearerToken) error,
) error {
	fqt, err := t.ResolveAndReindex(m, arg)
	if err != nil {
		return err
	}
	if fqt == nil {
		return core.TeamNotFoundError{}
	}
	tm, tok, err := t.loadTeamAndAdminToken(m, *fqt, opts)
	if err != nil {
		return err
	}
	return f(m, tm, tok)
}

func (t *TeamMinder) ListTeamRoster(
	m MetaContext,
	arg proto.FQTeamParsed,
) (
	*lcl.TeamRoster,
	error,
) {
	var ret *lcl.TeamRoster
	err := t.withLoadedTeam(
		m,
		arg,
		LoadTeamOpts{LoadMembers: true, Refresh: true},
		func(m MetaContext, tm *TeamRecord) error {
			tmp, err := tm.Tw().ExportToRoster()
			if err != nil {
				return err
			}
			ret = tmp
			return nil
		},
	)
	return ret, err
}

func (t *TeamMinder) Create(
	m MetaContext,
	nm proto.NameUtf8,
) (
	*proto.TeamID,
	error,
) {
	var hepks core.HEPKSet
	au, err := t.activeUser(m)
	if err != nil {
		return nil, err
	}
	cli, err := au.TeamAdminClient(m)
	if err != nil {
		return nil, err
	}

	nmn, err := core.NormalizeName(nm)
	if err != nil {
		return nil, err
	}

	rtr, err := cli.ReserveTeamname(m.Ctx(), nmn)
	if err != nil {
		return nil, err
	}

	// For now, only possible to have the user's owner PUK as the time creator, but
	// thhat is an artificial limitation, can potentially relax it.
	srcRole := team.UserSrcRole
	puk := au.PrivKeys.LatestPuk()
	if puk == nil {
		return nil, core.KeyNotFoundError{Which: "puk"}
	}
	dstRole := proto.OwnerRole

	hostid := au.HostID()

	skb, err := core.NewSharedKeyBoxer(hostid, puk)
	if err != nil {
		return nil, err
	}
	mePub, err := core.PublicizeToSPSBoxer(puk, au.FQU().FQParty())
	if err != nil {
		return nil, err
	}

	var ptks []core.SharedPrivateSuiter
	ptkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)

	roles := team.EldestRoles()

	for _, role := range roles {
		ss := core.RandomSecretSeed32()
		ptk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_Team,
			role,
			ss,
			proto.FirstGeneration, // == 1, not 0.
			hostid,
		)
		if err != nil {
			return nil, err
		}
		err = hepks.AddHEPKExporter(ptk)
		if err != nil {
			return nil, err
		}

		ptks = append(ptks, ptk)
		err = skb.Box(ptk, mePub)
		if err != nil {
			return nil, err
		}
		rk, err := core.ImportRole(role)
		if err != nil {
			return nil, err
		}
		ptkMap[*rk] = ptk
	}

	boxes, err := skb.Finish()
	if err != nil {
		return nil, err
	}

	ma, err := au.MerkleAgent(m)
	if err != nil {
		return nil, err
	}

	tr, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return nil, err
	}

	nc := rem.NameCommitment{
		Name: nmn,
		Seq:  rtr.Seq,
	}

	rmkey, err := team.NewTeamRemovalKey()
	if err != nil {
		return nil, err
	}
	comm, err := core.ComputeKeyCommitment(rmkey)
	if err != nil {
		return nil, err
	}

	mlr, err := team.MakeEldestLink(
		hostid,
		nc,
		proto.KeyOwner{
			Party:   au.UID().ToPartyID(),
			SrcRole: srcRole,
		},
		puk,
		ptks,
		tr,
		*comm,
	)
	seqno := mlr.Seqno
	if err != nil {
		return nil, err
	}

	tid, err := mlr.TeamID.ToTeamID()
	if err != nil {
		return nil, err
	}

	fqt := proto.FQTeam{
		Team: tid,
		Host: hostid,
	}

	adminPtk, found := ptkMap[core.AdminRole]
	if !found {
		return nil, core.KeyNotFoundError{Which: "admin PTK"}
	}

	adminPtkPub, err := core.PublicizeToSPSBoxer(adminPtk, fqt.FQParty())
	if err != nil {
		return nil, err
	}

	trkbp, err := team.BoxTeamRemovalKey(
		puk,
		adminPtkPub,
		mePub,
		rem.TeamRemovalKeyMetadata{
			Tm:     fqt,
			Member: au.FQU().FQParty(),
			Dst: proto.RoleAndSeqno{
				Seqno: seqno,
				Role:  dstRole,
			},
			SrcRole: srcRole,
		},
		rmkey,
	)
	if err != nil {
		return nil, err
	}

	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    fqt,
			SrcRole: srcRole,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst: proto.RoleAndSeqno{
						Seqno: seqno,
						Role:  dstRole,
					},
					KeyComm: trkbp.Comm,
				},
			),
		},
	)

	glink, err := t.makeMembershipChainLink(
		m, nil, glp, &tr,
	)
	if err != nil {
		return nil, err
	}

	arg := rem.CreateTeamArg{
		NameUtf8:                 nm,
		TeamnameCommitmentKey:    *mlr.TeamnameCommitmentKey,
		SubchainTreeLocationSeed: *mlr.SubchainTreeLocationSeed,
		Rnr:                      rtr,
		Eta: rem.EditTeamArg{
			Link:             *mlr.Link,
			NextTreeLocation: *mlr.NextTreeLocation,
			Obd: rem.OffchainBoxData{
				PtkBoxes:    *boxes,
				RemovalKeys: []rem.TeamRemovalBoxData{*trkbp},
				Hepks:       hepks.Export(),
			},
		},
		TeamMembershipLink: rem.PostGenericLinkArg{
			Link:             glink.Link,
			NextTreeLocation: glink.NextTreeLocation,
		},
	}

	err = cli.CreateTeam(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}

	teamID, err := mlr.TeamID.ToTeamID()
	if err != nil {
		return nil, err
	}

	return &teamID, nil
}

// makeKeyRingRefesher returns a function that is used to reload the team with the same args,
// and to refresh keys for that team. It can't call back into TeamMinder as that can deadlock
// it, so it does a raw and direct team load. Should usually be a noop but in the case of CLKR,
// can maybe put the PTK one generation forward, allowing parent teams to be editted.
func (arg LoadTeamArg) makeKeyRingRefresher() func(m MetaContext) (SharedKeySequence, error) {
	return func(m MetaContext) (SharedKeySequence, error) {
		m.Infow("LoadTeamArg.Refresh", "team", arg.Team, "srcRole", arg.SrcRole)
		wr, err := LoadTeam(m, arg)
		if err != nil {
			return nil, err
		}
		rk, err := core.ImportRole(arg.SrcRole)
		if err != nil {
			return nil, err
		}
		ret := wr.KeyRing().KeysForRole(*rk)
		if ret == nil {
			return nil, nil
		}
		return ret, nil
	}
}

func (t *TeamMinder) ListMemberships(
	m MetaContext,
) (
	*lcl.ListMembershipsRes,
	error,
) {
	var ret lcl.ListMembershipsRes
	err := t.ExploreAndIndex(m)
	if err != nil {
		return nil, err
	}
	all := t.AllLoadedTeams()

	for _, team := range all {

		tmp, err := team.ExportToTeamMembership()
		if err != nil {
			return nil, err
		}

		err = t.PopulateTeamName(tmp.Via)
		if err != nil {
			return nil, err
		}

		ret.Teams = append(ret.Teams, *tmp)
	}

	cmp := func(m1, m2 lcl.TeamMembership) int {
		if m1.Via == nil && m1.Via != nil {
			return -1
		}
		if m1.Via != nil && m1.Via == nil {
			return 1
		}
		isLocal := func(m lcl.TeamMembership) bool {
			return m.Team.Fqp.Host.Eq(t.au.HostID())
		}
		m1IsLocal := isLocal(m1)
		m2IsLocal := isLocal(m2)
		if m1IsLocal && !m2IsLocal {
			return -1
		}
		if !m1IsLocal && m2IsLocal {
			return 1
		}
		cmp := strings.Compare(m1.Team.Host.String(), m2.Team.Host.String())
		if cmp != 0 {
			return cmp
		}
		cmp = strings.Compare(m1.Team.Name.String(), m2.Team.Name.String())
		return cmp
	}
	ret.HomeHost = t.au.HostID()

	slices.SortFunc(ret.Teams, cmp)

	return &ret, nil
}

func (t *TeamMinder) loadConfig(
	m MetaContext,
	cli *rem.TeamAdminClient,
) (
	*rem.TeamConfig,
	error,
) {
	t.configMu.Lock()
	defer t.configMu.Unlock()

	if t.config != nil {
		tmp := *t.config
		return &tmp, nil
	}
	if cli == nil {
		var err error
		cli, err = t.au.TeamAdminClient(m)
		if err != nil {
			return nil, err
		}
	}
	cfg, err := cli.GetTeamConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	t.config = &cfg
	tmp := cfg
	return &tmp, nil
}
