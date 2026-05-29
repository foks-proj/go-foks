package libclient

import (
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type PLCNode struct {
	sync.Mutex
	id          proto.FQParty
	au          proto.FQUser
	skm         SharedKeyManager
	voTok       *rem.TeamVOBearerToken
	refreshTime time.Time
}

type PartyLoaderCache struct {
	sync.RWMutex
	parties map[proto.FQEntityFixed]*PLCNode
	au      *UserContext
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
	return nil, core.NotImplementedError{}
}

func (p *PartyLoaderCache) loadTeam(m MetaContext, tm proto.FQTeamParsed, opts *PLCOpts) (*PLCNode, error) {
	return nil, core.NotImplementedError{}
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
