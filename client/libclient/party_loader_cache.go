package libclient

import (
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type PLCNode struct {
	sync.RWMutex
	id            proto.FQParty
	au            proto.FQUser
	tm            *lcl.ConfigTeam // how this party was named on load; nil for the active user
	skm           SharedKeyManager
	voTok         *rem.TeamVOBearerToken
	refreshTime   time.Time
	directDstRole *proto.Role // might be null if we don't have direct membership
	// genAheadMu serializes the reloads PrivateKeysForRoleAtGen runs for a
	// generation the node does not hold, and guards genAheadAt, when the last
	// one started. It is held across the reload, so it is taken before the
	// fqptLocks entry and the node lock, never while holding either.
	genAheadMu sync.Mutex
	genAheadAt time.Time
	plc        *PartyLoaderCache // the cache that owns this node, for reloads
}

// Invalidate expires the node's cached state -- crucially its VO bearer token --
// so the next Load re-mints rather than handing back a token the server has
// already rejected. The stale token is deliberately left in place: if the reload
// fails we'd rather retry with a doomed token than fail differently ("no VO
// token") on a path that only wanted to refresh it.
func (p *PLCNode) Invalidate() {
	p.Lock()
	defer p.Unlock()
	p.refreshTime = time.Time{}
}

func (p *PLCNode) configTeam() *lcl.ConfigTeam {
	p.RLock()
	defer p.RUnlock()
	return p.tm
}

func (p *PLCNode) DirectDstRole() *proto.Role {
	p.RLock()
	defer p.RUnlock()
	return p.directDstRole
}

func (p *PLCNode) ActiveUser() proto.FQUser {
	p.RLock()
	defer p.RUnlock()
	return p.au
}

func (p *PLCNode) FQEntityFixed() (*proto.FQEntityFixed, error) {
	p.RLock()
	defer p.RUnlock()
	return p.id.FQEntity().Fixed()
}

func (p *PLCNode) FQParty() proto.FQParty {
	p.RLock()
	defer p.RUnlock()
	return p.id
}

func (p *PLCNode) ViewTok() *rem.TeamVOBearerToken {
	p.RLock()
	defer p.RUnlock()
	if p.voTok == nil {
		return nil
	}
	ret := *p.voTok
	return &ret
}

func (p *PLCNode) SKM() SharedKeyManager {
	p.RLock()
	defer p.RUnlock()
	return p.skm
}

type PartyLoaderCache struct {
	sync.RWMutex
	au        *UserContext
	parties   map[proto.FQEntityFixed]*PLCNode
	fqptLocks core.Locktab[proto.StdHash]
	fqptCache map[proto.StdHash]*proto.FQParty // Cache of FQTeamParsed -> FQParty
}

func NewPartyLoaderCache(au *UserContext) *PartyLoaderCache {
	return &PartyLoaderCache{
		au:        au,
		parties:   make(map[proto.FQEntityFixed]*PLCNode),
		fqptCache: make(map[proto.StdHash]*proto.FQParty),
	}
}

type PLCOpts struct {
	Lock bool
	// ForceRefresh bypasses the node-freshness shortcut for team loads, forcing
	// a reload (and hence a fresh view bearer token). Used to recover when a
	// cached token turns out to be stale server-side -- e.g. the caller's role
	// in the team changed inside the freshness window.
	ForceRefresh bool
}

// getLockedNode returns the node for fqp, creating it if needed, locked.
//
// p is never held while waiting on another lock. loadTeam holds a node's lock
// across a network reload and then takes p, so waiting on the node under p
// deadlocks. fqptLocks does not serialize the two: it is keyed by how the team
// was named, and a team named two ways (e.g. by name and by ID) is two keys but
// one node. p.au.FQU() is called outside p for the same reason: it takes the
// user lock, which is held across I/O.
//
// A new node is visible in p.parties before its creator locks it. That is
// fine: nothing reads a node without locking it, and an empty node is filled
// in by whoever locks it first (loadUser: skm == nil; loadTeam: !isFresh).
func (p *PartyLoaderCache) getLockedNode(
	fqp proto.FQParty,
) (
	*PLCNode, // new KVP, return locked so we can initialize it
	error,
) {
	fqef, err := fqp.FQEntity().Fixed()
	if err != nil {
		return nil, err
	}
	ret := p.lookupNode(*fqef, nil)
	if ret == nil {
		ret = p.lookupNode(*fqef, &PLCNode{
			id:  fqp,
			au:  p.au.FQU(),
			plc: p,
		})
	}
	ret.Lock()
	return ret, nil
}

// lookupNode returns the node for fqef. If there is none and fresh is non-nil,
// fresh is inserted and returned. Holds p only for the map access.
func (p *PartyLoaderCache) lookupNode(fqef proto.FQEntityFixed, fresh *PLCNode) *PLCNode {
	p.Lock()
	defer p.Unlock()
	if ret := p.parties[fqef]; ret != nil {
		return ret
	}
	if fresh != nil {
		p.parties[fqef] = fresh
	}
	return fresh
}

func (p *PartyLoaderCache) loadUser(m MetaContext, opts *PLCOpts) (*PLCNode, error) {
	plcn, err := p.getLockedNode(p.au.FQParty())
	if err != nil {
		return nil, err
	}
	defer plcn.Unlock()
	if plcn.skm != nil {
		return plcn, nil
	}
	skm, err := p.au.GetSharedKeyManager(m)
	if err != nil {
		return plcn, nil
	}
	plcn.skm = skm
	return plcn, nil
}

func (n *PLCNode) isFresh(m MetaContext) (bool, error) {
	if n.voTok == nil || n.skm == nil {
		return false, nil
	}
	if n.refreshTime.IsZero() {
		return false, nil
	}
	now := m.G().Now()
	diff := now.Sub(n.refreshTime)
	dur, err := m.G().Cfg().TeamCacheTimeout()
	if err != nil {
		return false, err
	}
	return (diff < dur), nil
}

func (k *PLCNode) refresh(
	m MetaContext,
	tm lcl.ConfigTeam,
	tw *TeamWrapper,
	userRoleInTeam *proto.Role,
) {
	k.refreshTime = m.G().Now()
	k.tm = &tm
	k.skm = tw.KeyRing()
	k.voTok = tw.VOBearerToken()
	k.directDstRole = userRoleInTeam
}

func (p *PartyLoaderCache) loadTeam(
	m MetaContext,
	tm lcl.ConfigTeam,
	opts *PLCOpts,
) (
	*PLCNode, error,
) {
	hsh, err := core.PrefixedHash(&tm)
	if err != nil {
		return nil, err
	}

	// Single-flight all activity for this FQTeamParsed, which otherwise is hard to lock
	// using our various caches.
	lh := p.fqptLocks.Acquire(*hsh)
	defer lh.Release()

	p.Lock()
	membId := p.fqptCache[*hsh]
	p.Unlock()

	// Cache hit path --- if team is fresh enough
	var plcn *PLCNode

	if membId != nil {
		plcn, err = p.getLockedNode(*membId)
		if err != nil {
			return nil, err
		}
		defer plcn.Unlock()
		isFresh, err := plcn.isFresh(m)
		if err != nil {
			return nil, err
		}
		if isFresh && (opts == nil || !opts.ForceRefresh) {
			return plcn, nil
		}
	}

	// cache miss path, or cache was hit but team wasn't fresh

	tw, err := p.au.TeamMinder().LoadTeam(m, tm, LoadTeamOpts{Refresh: true})
	if err != nil {
		return nil, err
	}
	fqp := tw.Prot().Fqt.FQParty()

	p.Lock()
	p.fqptCache[*hsh] = &fqp
	p.Unlock()

	if plcn == nil {
		plcn, err = p.getLockedNode(fqp)
		if err != nil {
			return nil, err
		}
		defer plcn.Unlock()
		isFresh, err := plcn.isFresh(m)
		if err != nil {
			return nil, err
		}
		if isFresh {
			return plcn, nil
		}
	}

	// also keep track of the active user's direct role in the loaded team.
	// it might be indirect membership, so it might not be known

	// the role of the user's device
	srcRole := p.au.Role()
	memb, err := tw.GetMember(p.au.FQParty(), srcRole)
	if err != nil {
		return nil, err
	}
	var mr *proto.Role
	if memb != nil {
		mr = &memb.Mr.DstRole
	}
	plcn.refresh(m, tm, tw, mr)

	return plcn, nil
}

// Refresh forces a reload of a node whose cached VO bearer token the server has
// rejected, bypassing the TeamCacheTimeout freshness window. Without it a token
// invalidated by a roster change (see the "stale member" rejection in
// CheckTeamVOBearerToken) keeps being replayed until the window expires -- on
// mobile that window is minutes, so every team KV op fails in the meantime.
// Reloading via TeamMinder alone does not help: it refreshes a different cache,
// and the token callers actually present comes from here.
//
// A no-op for the active user's own node, which carries no token.
func (p *PartyLoaderCache) Refresh(m MetaContext, n *PLCNode) error {
	if n == nil {
		return nil
	}
	tm := n.configTeam()
	if tm == nil {
		return nil
	}
	n.Invalidate()
	_, err := p.loadTeam(m, *tm, &PLCOpts{})
	return err
}

// genAheadReloadFloor is the least time between two reloads of one node that a
// key lookup may trigger for a generation the node does not hold. The
// generation comes from the box being opened, which its sender chose, so
// without a floor a crafted generation would force a team reload per lookup.
const genAheadReloadFloor = 30 * time.Second

// PrivateKeysForRoleAtGen returns n's private keys for role, first reloading n
// once when gen is newer than every generation n holds for that role.
//
// That is the state after a rekey (a member removed) since n was cached. The
// reader's own team_members row is untouched by it, so the node's view token
// stays valid and nothing else reloads n before TeamCacheTimeout lapses --
// minutes on mobile -- while every box sealed under the new generation fails
// with KeyNotFoundError. A gen at or below the newest held is an ordinary miss
// and never reloads.
//
// Lookups that miss at the same time wait for one reload and then look again.
// A failed reload is returned as the error: the lookup could not have
// succeeded without it. The returned sequence may still lack gen (a reload
// inside the floor is skipped); callers report that exactly as before.
func (n *PLCNode) PrivateKeysForRoleAtGen(
	m MetaContext,
	role proto.Role,
	gen proto.Generation,
) (
	SharedKeySequence,
	error,
) {
	seq, err := n.SKM().PrivateKeysForRole(m, role)
	if err != nil || seq == nil || n.plc == nil || !genAhead(seq, gen) {
		return seq, err
	}
	n.genAheadMu.Lock()
	defer n.genAheadMu.Unlock()
	// Another lookup may have reloaded n while this one waited.
	seq, err = n.SKM().PrivateKeysForRole(m, role)
	if err != nil || seq == nil || !genAhead(seq, gen) || !n.claimGenAheadReloadLocked(m.G().Now()) {
		return seq, err
	}
	err = n.plc.Refresh(m, n)
	if err != nil {
		return nil, err
	}
	return n.SKM().PrivateKeysForRole(m, role)
}

func genAhead(seq SharedKeySequence, gen proto.Generation) bool {
	if seq.At(gen) != nil {
		return false
	}
	cur := seq.Current()
	return cur != nil && gen > cur.Metadata().Gen
}

// claimGenAheadReloadLocked reports whether a generation-ahead reload of n may
// run now, and if so records it. The caller holds n.genAheadMu.
func (n *PLCNode) claimGenAheadReloadLocked(now time.Time) bool {
	if !n.genAheadAt.IsZero() && now.Sub(n.genAheadAt) < genAheadReloadFloor {
		return false
	}
	n.genAheadAt = now
	return true
}

// Load a PLCNode, from a FQTeamParsed if specified. Return a PLCNode, which
// has a party's FQParty, its keys, and also a VOBearerToken in the case
// of a team. Refresh from time to time. The PLCNode returned can be **locked**
// if specified so we don't need to worry about races in the case of creating
// a new object
func (p *PartyLoaderCache) Load(
	m MetaContext,
	actingAs lcl.ConfigTeam,
	opts *PLCOpts,
) (
	*PLCNode,
	error,
) {
	typ, err := actingAs.GetT()
	if err != nil {
		return nil, err
	}
	if typ == lcl.ConfigTeamType_None {
		return p.loadUser(m, opts)
	}
	return p.loadTeam(m, actingAs, opts)
}

type BaseMinderNoder interface {
	SetPLCNode(n *PLCNode)
}

type BaseMinder[
	N any, P interface {
		*N
		BaseMinderNoder
	}] struct {
	plc        *PartyLoaderCache
	partiesMu  sync.Mutex
	parties    map[proto.FQEntityFixed]P
	initNodeFn func(n *N)
}

func NewBaseMinder[N any, P interface {
	*N
	BaseMinderNoder
}](
	au *UserContext,
	initNodeFn func(n *N),
) *BaseMinder[N, P] {
	return &BaseMinder[N, P]{
		plc:        au.PartyLoaderCache(),
		parties:    make(map[proto.FQEntityFixed]P),
		initNodeFn: initNodeFn,
	}
}

func (a *BaseMinder[N, P]) GetParty(
	m MetaContext,
	t lcl.ConfigTeam,
) (
	*N,
	error,
) {
	return a.getParty(m, t, &PLCOpts{})
}

// GetPartyForceRefresh is GetParty, but reloads the party's backing team even
// if the cached node is still fresh -- e.g. to mint a new view bearer token
// after the server rejected the cached one as stale.
func (a *BaseMinder[N, P]) GetPartyForceRefresh(
	m MetaContext,
	t lcl.ConfigTeam,
) (
	*N,
	error,
) {
	return a.getParty(m, t, &PLCOpts{ForceRefresh: true})
}

func (a *BaseMinder[N, P]) getParty(
	m MetaContext,
	t lcl.ConfigTeam,
	opts *PLCOpts,
) (
	*N,
	error,
) {
	plcn, err := a.plc.Load(m, t, opts)
	if err != nil {
		return nil, err
	}
	fqef, err := plcn.FQEntityFixed()
	if err != nil {
		return nil, err
	}

	a.partiesMu.Lock()
	defer a.partiesMu.Unlock()
	ret := a.parties[*fqef]
	if ret != nil {
		return ret, nil
	}

	ret = new(N)
	ret.SetPLCNode(plcn)
	a.initNodeFn(ret)
	a.parties[*fqef] = ret

	return ret, nil
}
