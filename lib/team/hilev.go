// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"golang.org/x/exp/slices"
)

type VerifyKeyIndex struct {
	VerifyKey proto.FixedEntityID
	Host      proto.HostID
}

type MemberKeysSet struct {
	Members map[MemberID]*proto.TeamMemberKeys
	Vki     map[VerifyKeyIndex]MemberID
}

func (a *MemberKeysSet) Clone() *MemberKeysSet {
	if a == nil {
		return nil
	}
	ret := NewMemberKeysSet()
	for k, v := range a.Members {
		ret.Members[k] = v
	}
	for k, v := range a.Vki {
		ret.Vki[k] = v
	}
	return ret
}

func (a *MemberKeysSet) CloneAndOverwriteWith(b *MemberKeysSet) *MemberKeysSet {
	if a == nil {
		return b
	}
	ret := a.Clone()
	for k, v := range b.Members {

		// It could be are overwriting an existing entry on a group role change;
		// we retain the original removal key, so we propagate it forward here.
		existing, found := a.Members[k]
		if v != nil && found && existing != nil && existing.Trkc != nil && v.Trkc == nil {
			tmp := *v
			tmp.Trkc = existing.Trkc
			v = &tmp
		}
		ret.Members[k] = v
	}
	for k, v := range b.Vki {
		ret.Vki[k] = v
	}
	return ret
}

func NewMemberKeysSet() *MemberKeysSet {
	return &MemberKeysSet{
		Members: make(map[MemberID]*proto.TeamMemberKeys),
		Vki:     make(map[VerifyKeyIndex]MemberID),
	}
}

func verifyKeyToIndex(v proto.EntityID, host proto.HostID) (*VerifyKeyIndex, error) {
	vk, err := v.ToRollingEntityID()
	if err != nil {
		return nil, err
	}
	vkf, err := vk.Fixed()
	if err != nil {
		return nil, err
	}
	ret := VerifyKeyIndex{
		VerifyKey: vkf,
		Host:      host,
	}
	return &ret, nil
}

func (a *MemberKeysSet) AddTeamMemberKeys(m MemberID, d *proto.TeamMemberKeys) error {
	prev, found := a.Members[m]
	a.Members[m] = d

	if d != nil {
		vkidx, err := verifyKeyToIndex(d.VerifyKey, m.Fqe.Host)
		if err != nil {
			return err
		}
		a.Vki[*vkidx] = m
	} else if found {
		vkix, err := verifyKeyToIndex(prev.VerifyKey, m.Fqe.Host)
		if err != nil {
			return err
		}
		delete(a.Vki, *vkix)
	}
	return nil
}

func MakeChange(mrq proto.MemberRoleSeqno, mh proto.HostID) (*Change, *proto.TeamMemberKeys, error) {
	mr := mrq.Mr
	dstRole, err := core.ImportRole(mr.DstRole)
	if err != nil {
		return nil, nil, err
	}
	if mr.Member.Id.Host != nil && mr.Member.Id.Host.Eq(mh) {
		return nil, nil, core.LinkError("for teams, can only specify hostID if different from home host")
	}

	fqef, err := mr.Member.Id.WithHost(mh).Fixed()
	if err != nil {
		return nil, nil, err
	}
	keys := mr.Member.Keys
	typ, err := keys.GetT()
	if err != nil {
		return nil, nil, err
	}
	srcRole, err := core.ImportRole(mr.Member.SrcRole)
	if err != nil {
		return nil, nil, err
	}
	if srcRole.IsNone() {
		return nil, nil, core.TeamNoSrcRoleError{}
	}

	chng := &Change{
		Member: MemberID{
			Fqe:     *fqef,
			SrcRole: *srcRole,
		},
		Info: MemberInfo{
			Role:  *dstRole,
			Seqno: mrq.Seqno,
			Time:  mrq.Time,
		},
	}

	if dstRole.Typ == proto.RoleType_NONE {
		if typ != proto.MemberKeysType_None {
			return nil, nil, core.TeamError("cannot add keys to NONE role")
		}
		return chng, nil, nil
	}

	if typ != proto.MemberKeysType_Team {
		return nil, nil, core.TeamError("need member keys type")
	}

	tk := keys.Team()
	chng.Info.Gen = tk.Gen
	return chng, &tk, nil
}

func MakeChangeSet(v []proto.MemberRoleSeqno, mh proto.HostID) (ChangeSet, *MemberKeysSet, error) {
	ret := make(ChangeSet, len(v))
	ads := NewMemberKeysSet()
	for i, mr := range v {
		chng, auxData, err := MakeChange(mr, mh)
		if err != nil {
			return nil, nil, err
		}
		err = ads.AddTeamMemberKeys(chng.Member, auxData)
		if err != nil {
			return nil, nil, err
		}
		ret[i] = *chng
	}
	return ret, ads, nil
}

type Roster struct {
	sync.Mutex
	*RosterCore
	KeyGens KeyGens
	Mks     *MemberKeysSet
}

func NewRoster(r *RosterCore, kg KeyGens, a *MemberKeysSet) *Roster {
	return &Roster{
		RosterCore: r,
		KeyGens:    kg,
		Mks:        a,
	}
}

func NewEmptyRoster() *Roster {
	return &Roster{}
}

func NewRosterWithKeyGens(kg KeyGens) *Roster {
	return &Roster{
		KeyGens: kg,
	}
}

func (r *Roster) Clone() *Roster {
	r.Lock()
	defer r.Unlock()
	return &Roster{
		RosterCore: r.RosterCore.Clone(),
		KeyGens:    r.KeyGens.Clone(),
		Mks:        r.Mks.Clone(),
	}
}

func (r *Roster) Load(
	mr []proto.MemberRoleSeqno,
	host proto.HostID,
) error {
	changes, ad, err := MakeChangeSet(mr, host)
	if err != nil {
		return err
	}
	r.RosterCore = NewRosterCoreFromChanges(changes)
	r.Mks = ad
	return nil
}

type GameplanOpts struct {
	TestingNoCheck bool
}

func (r *Roster) Gameplan(
	doerKO proto.KeyOwner,
	host proto.HostID,
	v []proto.MemberRoleSeqno,
	verifyKey proto.EntityID,
	opts *GameplanOpts,
) (
	*Roster,
	*KeySchedule,
	error,
) {

	changes, mks, err := MakeChangeSet(v, host)
	if err != nil {
		return nil, nil, err
	}

	return r.GameplanWithChanges(doerKO, host, changes, mks, verifyKey, opts)
}

func (r *Roster) GameplanWithChanges(
	doerKO proto.KeyOwner,
	host proto.HostID,
	changes ChangeSet,
	mks *MemberKeysSet,
	verifyKey proto.EntityID,
	opts *GameplanOpts,
) (
	*Roster,
	*KeySchedule,
	error,
) {

	// It's OK to pass a NIL roster, we just make its fields empty.
	if r == nil {
		r = &Roster{}
	}

	doer, err := (proto.FQEntity{
		Entity: doerKO.Party.EntityID(),
		Host:   host,
	}).Fixed()

	if err != nil {
		return nil, nil, err
	}

	doerSrcRole, err := core.ImportRole(doerKO.SrcRole)
	if err != nil {
		return nil, nil, err
	}

	membID := MemberID{
		Fqe:     *doer,
		SrcRole: *doerSrcRole,
	}

	r.Lock()
	defer r.Unlock()

	err = r.Mks.matchSigningKey(membID, verifyKey)
	if err != nil {
		return nil, nil, err
	}

	rPost, sched, keysPost, err := changes.Gameplan(membID, r.RosterCore, r.KeyGens, opts)
	if err != nil {
		return nil, nil, err
	}

	return &Roster{
		RosterCore: rPost,
		Mks:        r.Mks.CloneAndOverwriteWith(mks),
		KeyGens:    keysPost,
	}, sched, nil
}

func (m *MemberKeysSet) matchSigningKey(
	membID MemberID,
	vk proto.EntityID,
) error {
	if (m != nil) && (vk == nil) {
		return core.TeamError("need to check verify key for an update")
	}
	if m == nil {
		return nil
	}
	memb, ok := m.Members[membID]
	if !ok {
		return core.TeamError("member not found")
	}
	if !vk.Eq(memb.VerifyKey) {
		return core.TeamError("member verify key mismatch")
	}
	return nil
}

func (m *MemberKeysSet) LookupMemberByVerifyKey(
	vk proto.EntityID,
	h proto.HostID,
) (
	*MemberID,
	*proto.TeamMemberKeys,
	error,
) {
	rvk, err := vk.ToRollingEntityID()
	if err != nil {
		return nil, nil, err
	}
	fei, err := rvk.Fixed()
	if err != nil {
		return nil, nil, err
	}
	vkidx := VerifyKeyIndex{
		VerifyKey: fei,
		Host:      h,
	}
	memb, ok := m.Vki[vkidx]
	if !ok {
		return nil, nil, core.TeamRosterError("member not found")
	}
	keys, ok := m.Members[memb]
	if !ok {
		return nil, nil, core.TeamRosterError("member keys not found")
	}
	return &memb, keys, nil
}

func (r *Roster) LookupMemberByVerifyKey(
	vk proto.EntityID,
	h proto.HostID,
) (
	*MemberID,
	*proto.TeamMemberKeys,
	error,
) {
	r.Lock()
	defer r.Unlock()
	return r.Mks.LookupMemberByVerifyKey(vk, h)
}

func (r *Roster) Export(host proto.HostID) []proto.MemberRoleSeqno {
	r.Lock()
	defer r.Unlock()
	type tmpMember struct {
		id  MemberID
		mi  MemberInfo
		tmk *proto.TeamMemberKeys
	}
	var tmpV []tmpMember
	for k, v := range r.members {
		tmp := tmpMember{id: k, mi: v}
		if r.Mks != nil {
			tmk, ok := r.Mks.Members[k]
			if ok {
				tmp.tmk = tmk
			}
		}
		tmpV = append(tmpV, tmp)
	}

	slices.SortFunc(tmpV, func(a, b tmpMember) int {
		rcmp := a.mi.Role.Cmp(b.mi.Role)
		if rcmp != 0 {
			return rcmp
		}
		return a.id.Cmp(b.id)
	})

	ret := make([]proto.MemberRoleSeqno, len(tmpV))
	for i, v := range tmpV {
		id := proto.FQEntityInHostScope{
			Entity: v.id.Fqe.Entity.Unfix(),
		}

		if !v.id.Fqe.Host.Eq(host) {
			// Annoying -- make a copy of this value, since
			// it will update as we iterate through the loop
			tmp := v.id.Fqe.Host
			id.Host = &tmp
		}
		mr := proto.MemberRole{
			Member: proto.Member{
				Id:      id,
				SrcRole: v.id.SrcRole.Export(),
			},
			DstRole: v.mi.Role.Export(),
		}
		if v.tmk != nil {
			mr.Member.Keys = proto.NewMemberKeysWithTeam(*v.tmk)
		}
		mrq := proto.MemberRoleSeqno{
			Mr:    mr,
			Seqno: v.mi.Seqno,
			Time:  v.mi.Time,
		}
		ret[i] = mrq
	}
	return ret
}

func (i *MemberID) ImportFromMember(m proto.Member, h proto.HostID) error {
	fqe, err := m.Id.Fixed(h)
	if err != nil {
		return err
	}
	i.Fqe = *fqe
	srcRole, err := core.ImportRole(m.SrcRole)
	if err != nil {
		return err
	}
	i.SrcRole = *srcRole
	return nil
}

func (i *MemberID) ImportFromFQPartyAndRole(p proto.FQParty, r proto.Role) error {
	fqe, err := p.FQEntity().Fixed()
	if err != nil {
		return err
	}
	i.Fqe = *fqe
	srcRole, err := core.ImportRole(r)
	if err != nil {
		return err
	}
	i.SrcRole = *srcRole
	return nil
}

func (r *Roster) LookupRoleForMember(p proto.FQParty, idRole proto.Role) (*core.RoleKey, error) {
	fqef, err := p.FQEntity().Fixed()
	if err != nil {
		return nil, err
	}
	rk, err := core.ImportRole(idRole)
	if err != nil {
		return nil, err
	}
	memb := MemberID{
		Fqe:     *fqef,
		SrcRole: *rk,
	}

	r.Lock()
	defer r.Unlock()
	mi, ok := r.RosterCore.members[memb]
	if !ok {
		return nil, nil
	}
	return &mi.Role, nil
}

func MemberRoleToMemberID(mr *proto.MemberRole, host proto.HostID) (*MemberID, error) {
	mem, err := mr.Member.Id.WithHost(host).Fixed()
	if err != nil {
		return nil, err
	}
	rk, err := core.ImportRole(mr.Member.SrcRole)
	if err != nil {
		return nil, err
	}
	return &MemberID{
		Fqe:     *mem,
		SrcRole: *rk,
	}, nil
}
