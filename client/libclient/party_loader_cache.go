package libclient

import (
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type PLCNode struct {
	sync.RWMutex
	id            proto.FQParty
	au            proto.FQUser
	skm           SharedKeyManager
	voTok         *rem.TeamVOBearerToken
	refreshTime   time.Time
	directDstRole *proto.Role // might be null if we don't have direct membership
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
}

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
	p.Lock()
	defer p.Unlock()
	ret := p.parties[*fqef]
	if ret != nil {
		ret.Lock()
		return ret, nil
	}
	ret = &PLCNode{
		id: fqp,
		au: p.au.FQU(),
	}
	ret.Lock()
	p.parties[*fqef] = ret
	return ret, nil
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
	tw *TeamWrapper,
	userRoleInTeam *proto.Role,
) {
	k.refreshTime = m.G().Now()
	k.skm = tw.KeyRing()
	k.voTok = tw.VOBearerToken()
	k.directDstRole = userRoleInTeam
}

func (p *PartyLoaderCache) loadTeam(
	m MetaContext,
	tm proto.FQTeamParsed,
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
		if isFresh {
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
	plcn.refresh(m, tw, mr)

	return plcn, nil
}

// Load a PLCNode, from a FQTeamParsed if specified. Return a PLCNode, which
// has a party's FQParty, its keys, and also a VOBearerToken in the case
// of a team. Refresh from time to time. The PLCNode returned can be **locked**
// if specified so we don't need to worry about races in the case of creating
// a new object
func (p *PartyLoaderCache) Load(
	m MetaContext,
	actingAs *proto.FQTeamParsed,
	opts *PLCOpts,
) (
	*PLCNode,
	error,
) {
	if actingAs == nil {
		return p.loadUser(m, opts)
	}
	return p.loadTeam(m, *actingAs, opts)
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
	t *proto.FQTeamParsed,
) (
	*N,
	error,
) {
	plcn, err := a.plc.Load(m, t, &PLCOpts{})
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
