// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func NewPUKMinder(u *UserContext) *PUKMinder {
	return &PUKMinder{
		u:    u,
		puks: make(map[core.RoleKey](*PUKSet)),
	}
}

type PUKSet struct {
	l    []core.SharedPrivateSuiter
	host proto.HostID
}

func NewPUKSet(l []core.SharedPrivateSuiter, h proto.HostID) *PUKSet {
	return &PUKSet{l: l, host: h}
}

func (p PUKSet) All() []core.SharedPrivateSuiter {
	return p.l
}

func (p PUKSet) Current() core.SharedPrivateSuiter {
	if len(p.l) == 0 {
		return nil
	}
	return p.l[len(p.l)-1]
}

func (p PUKSet) NextGen() proto.Generation {
	return proto.Generation(len(p.l))
}

func (p PUKSet) HostID() proto.HostID {
	return p.host
}

func newPUKSet(l []core.SharedPrivateSuiter, h proto.HostID) *PUKSet {
	return &PUKSet{l: l, host: h}
}

func (p PUKSet) At(g proto.Generation) core.SharedPrivateSuiter {
	idx := g.ToIndex()
	if idx < 0 || idx >= len(p.l) {
		return nil
	}
	return p.l[idx]
}

type PUKMinder struct {
	sync.Mutex
	u     *UserContext
	chain *UserWrapper
	puks  map[core.RoleKey](*PUKSet)
}

func (p *PUKMinder) GetPUKAtRoleAndGeneration(m MetaContext, r proto.Role, g proto.Generation) (core.SharedPrivateSuiter, error) {
	p.Lock()
	defer p.Unlock()

	set, err := p.getPUKSetForRoleMinGenLocked(m, r, g)
	if err != nil {
		return nil, err
	}
	ret := set.At(g)
	if ret == nil {
		return nil, core.KeyNotFoundError{Which: "PUK"}
	}
	return ret, nil
}

func (p *PUKMinder) RefreshUser() {
	p.Lock()
	defer p.Unlock()
	p.chain = nil
}

func (p *PUKMinder) SetUser(u *UserWrapper) *PUKMinder {
	p.Lock()
	defer p.Unlock()
	p.chain = u
	return p
}

func (p *PUKMinder) GetPUKSetForRole(m MetaContext, r proto.Role) (*PUKSet, error) {
	p.Lock()
	defer p.Unlock()

	u, err := p.loadUser(m)
	if err != nil {
		return nil, err
	}
	gen, err := u.LatestPUKGenForRole(r)
	if err != nil {
		return nil, err
	}

	return p.getPUKSetForRoleMinGenLocked(m, r, gen)
}

func (p *PUKMinder) index(r proto.Role) (*core.RoleKey, error) {
	return core.ImportRole(r)
}

func (p *PUKMinder) getPUKSetForRoleMinGenLocked(m MetaContext, r proto.Role, minGen proto.Generation) (*PUKSet, error) {

	indx, err := p.index(r)
	if err != nil {
		return nil, err
	}
	lst := p.puks[*indx]
	if lst != nil && lst.At(minGen) != nil {
		return lst, nil
	}

	raw, err := p.getPUKParcelForRoleMinGen(m, r, minGen)
	if err != nil {
		return nil, err
	}
	lst, err = p.decryptPUKParcel(m, raw)
	if err != nil {
		return nil, err
	}
	p.puks[*indx] = lst
	return lst, nil
}

func (p *PUKMinder) getPUKParcelForRoleFromDB(
	m MetaContext,
	r proto.Role,
	eid proto.EntityID,
) (*proto.SharedKeyParcel, error) {
	var ret proto.SharedKeyParcel
	key := lcl.PUKBoxDBKey{
		Rg: lcl.RoleAndGenus{
			Role:  r,
			Genus: p.u.Info.KeyGenus,
		},
		Eid: eid,
	}

	uid := p.u.UID()
	_, err := m.DbGet(
		&ret,
		DbTypeSoft,
		&uid,
		lcl.DataType_SharedKeyCacheEntry,
		key,
	)
	if errors.Is(err, core.RowNotFoundError{}) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (p *PUKMinder) storePUKParcelForRoleToDB(
	m MetaContext,
	r proto.Role,
	eid proto.EntityID,
	pp proto.SharedKeyParcel,
) error {
	uid := p.u.UID()
	key := lcl.PUKBoxDBKey{
		Rg: lcl.RoleAndGenus{
			Role:  r,
			Genus: p.u.Info.KeyGenus,
		},
		Eid: eid,
	}
	return m.DbPut(
		DbTypeSoft,
		PutArg{
			Scope: &uid,
			Typ:   lcl.DataType_SharedKeyCacheEntry,
			Val:   &pp,
			Key:   key,
		},
	)
}

func (p *PUKMinder) getPUKParcelForRoleMinGen(m MetaContext, r proto.Role, minGen proto.Generation) (*proto.SharedKeyParcel, error) {
	devkey, err := p.u.Devkey(m.Ctx())
	if err != nil {
		return nil, err
	}
	eid, err := devkey.EntityID()
	if err != nil {
		return nil, err
	}
	ret, err := p.getPUKParcelForRoleFromDB(m, r, eid)
	if err != nil {
		return nil, err
	}
	if ret != nil && ret.Box.Gen >= minGen {
		return ret, nil
	}
	ucli, err := p.u.UserClient(m)
	if err != nil {
		return nil, err
	}
	pp, err := ucli.GetPUKForRole(m.Ctx(), rem.GetPUKForRoleArg{
		Role:              r,
		TargetPublicKeyId: eid,
	})
	if err != nil {
		return nil, err
	}
	if pp.Box.Gen < minGen {
		return nil, core.PUKChainError("server didn't return PUK gen advertised in sigchain")
	}
	err = p.storePUKParcelForRoleToDB(m, r, eid, pp)
	if err != nil {
		return nil, err
	}
	return &pp, nil
}

func (p *PUKMinder) loadUser(m MetaContext) (*UserWrapper, error) {
	if p.chain != nil {
		return p.chain, nil
	}
	var err error
	p.chain, err = LoadMe(m, p.u)
	if err != nil {
		return nil, err
	}
	return p.chain, nil
}

func (p *PUKMinder) decryptPUKParcel(m MetaContext, raw *proto.SharedKeyParcel) (*PUKSet, error) {
	u, err := p.loadUser(m)
	if err != nil {
		return nil, err
	}

	dev, err := u.FindDevice(raw.Sender)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, core.KeyNotFoundError{Which: "Sender device"}
	}

	sender, err := core.ImportPublicSuiteFromDeviceInfo(*dev, u.Hepks, p.u.HostID())
	if err != nil {
		return nil, err
	}

	rcvr, err := p.u.Devkey(m.Ctx())
	if err != nil {
		return nil, err
	}

	var sks proto.SharedKeySeed
	err = core.OpenBoxInSet(
		&sks,
		raw.Box.Box,
		raw.TempDHKeySigned,
		&raw.BoxId,
		sender,
		rcvr,
	)
	if err != nil {
		return nil, err
	}
	puk, err := core.ImportSharedPrivateSuite25519(proto.EntityType_PUKVerify, sks)
	if err != nil {
		return nil, err
	}

	if err := u.AssertPUK(puk); err != nil {
		return nil, err
	}

	ret := []core.SharedPrivateSuiter{puk}
	prev := puk
	gen := puk.Metadata().Gen - 1
	for i := len(raw.SeedChain) - 1; i >= 0; i-- {
		seed := raw.SeedChain[i]
		if seed.Gen != gen {
			return nil, core.PUKChainError("bad generation")
		}
		key := prev.SecretBoxKey()
		err := core.OpenSecretBoxInto(&sks, seed.Box, &key)
		if err != nil {
			return nil, err
		}
		puk, err := core.ImportSharedPrivateSuite25519(proto.EntityType_PUKVerify, sks)
		if err != nil {
			return nil, err
		}
		ret = append(ret, puk)
		gen--
		prev = puk
	}

	core.Reverse(ret)
	return newPUKSet(ret, p.u.HostID()), nil
}

func (pm *PUKMinder) PrivateKeysForRole(m MetaContext, r proto.Role) (SharedKeySequence, error) {
	return pm.GetPUKSetForRole(m, r)
}

func (pm *PUKMinder) highestRole() *core.RoleKey {
	var ret *core.RoleKey
	for k := range pm.puks {
		if ret == nil || k.Cmp(*ret) > 0 {
			tmp := k
			ret = &tmp
		}
	}
	return ret
}

func (pm *PUKMinder) PrivateKeysForHighestRole(m MetaContext) (SharedKeySequence, error) {
	rk := pm.highestRole()
	if rk == nil {
		return nil, core.KeyNotFoundError{Which: "highest role"}
	}
	return pm.PrivateKeysForRole(m, rk.Export())
}

type SharedKeySequence interface {
	At(g proto.Generation) core.SharedPrivateSuiter
	Current() core.SharedPrivateSuiter
}

type SharedKeyManager interface {
	PrivateKeysForRole(m MetaContext, rk proto.Role) (SharedKeySequence, error)
	PrivateKeysForHighestRole(m MetaContext) (SharedKeySequence, error)
}

var _ SharedKeySequence = PUKSet{}
var _ SharedKeyManager = (*PUKMinder)(nil)
