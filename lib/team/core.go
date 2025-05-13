// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"fmt"
	"maps"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"golang.org/x/exp/slices"
)

type MemberID struct {
	Fqe     proto.FQEntityFixed
	SrcRole core.RoleKey
}

func (m MemberID) Eq(m2 MemberID) bool {
	return proto.FQEntityFixed(m.Fqe).Eq(proto.FQEntityFixed(m2.Fqe)) && m.SrcRole.Eq(m2.SrcRole)
}

func (m MemberID) Cmp(m2 MemberID) int {
	c := proto.FQEntityFixed(m.Fqe).Cmp(proto.FQEntityFixed(m2.Fqe))
	if c != 0 {
		return c
	}
	return m.SrcRole.Cmp(m2.SrcRole)
}

type MemberInfo struct {
	Role  core.RoleKey
	Gen   proto.Generation // PUK Generation for the src key (I think)
	Seqno proto.Seqno      // Seqno this addition happened
	Time  proto.Time       // Time this addition happened
}

func (i MemberInfo) Eq(i2 MemberInfo) bool {
	return i.Role.Eq(i2.Role) && i.Gen == i2.Gen && i.Seqno == i2.Seqno
}

type MemberSet map[MemberID]bool

func (m MemberSet) Copy() MemberSet {
	ret := make(MemberSet)
	maps.Copy(ret, m)
	return ret
}

func NewMemberSet() MemberSet {
	return make(MemberSet)
}

type RosterCore struct {
	sync.Mutex
	members   map[MemberID]MemberInfo
	roleIndex map[core.RoleKey]MemberSet
}

func (r *RosterCore) BorrowMembers() (map[MemberID]MemberInfo, func()) {
	r.Lock()
	return r.members, r.Unlock
}

func (r *RosterCore) Len() int {
	r.Lock()
	defer r.Unlock()
	return len(r.members)
}

func (r *RosterCore) Add(m MemberID, k core.RoleKey, g proto.Generation, q proto.Seqno, t proto.Time) {
	r.Lock()
	defer r.Unlock()

	r.members[m] = MemberInfo{Role: k, Gen: g, Seqno: q, Time: t}
	ind, found := r.roleIndex[k]
	if !found {
		ind = NewMemberSet()
		r.roleIndex[k] = ind
	}
	ind[m] = true
}

// For each role, which generation the shared key is at.
// No entry means no key yet. Generations start at seqno=0
type KeyGens map[core.RoleKey]proto.Generation

func (k KeyGens) Clone() KeyGens {
	ret := make(KeyGens)
	for r, g := range k {
		ret[r] = g
	}
	return ret
}

func NewKeyGens() KeyGens {
	return make(KeyGens)
}

type Change struct {
	Member MemberID
	Info   MemberInfo
}

type ChangeSet []Change

type roleMemberIdx struct {
	r core.RoleKey
	m MemberID
}

type workingSchedule struct {
	incrs    map[core.RoleKey]bool
	includes map[core.RoleKey]bool
	rekeys   map[roleMemberIdx]bool
	newMembs map[MemberID]bool
	delMembs map[MemberID]bool
}

func newWorkingSchedule() *workingSchedule {
	return &workingSchedule{
		incrs:    make(map[core.RoleKey]bool),
		includes: make(map[core.RoleKey]bool),
		rekeys:   make(map[roleMemberIdx]bool),
		newMembs: make(map[MemberID]bool),
		delMembs: make(map[MemberID]bool),
	}
}

func (w *workingSchedule) export(
	keyGensPre KeyGens,
) (
	*KeySchedule,
	KeyGens,
) {

	newKeys := make(map[core.RoleKey]bool)
	keyGensPost := keyGensPre.Clone()
	for role := range w.includes {

		pre, ok := keyGensPre[role]
		post := proto.FirstGeneration
		if ok {
			post = pre
			if w.incrs[role] {
				newKeys[role] = true
				post++
			}
		} else {
			newKeys[role] = true
		}
		keyGensPost[role] = post
	}

	buckets := make(map[core.RoleKey]KeyScheduleItem)
	for x := range w.rekeys {
		ksr, ok := buckets[x.r]
		if !ok {
			nk := newKeys[x.r]
			ksr = KeyScheduleItem{Role: x.r, Gen: keyGensPost[x.r], NewKeyGen: nk}
		}
		ksr.Members = append(ksr.Members, x.m)
		buckets[x.r] = ksr
	}

	// Sort inside the individual buckets
	for _, ksr := range buckets {
		slices.SortFunc(ksr.Members, func(x, y MemberID) int { return x.Cmp(y) })
	}

	ret := KeySchedule{
		Items:     make([]KeyScheduleItem, 0, len(buckets)),
		Additions: make([]MemberID, 0, len(w.newMembs)),
		Removals:  make([]MemberID, 0, len(w.delMembs)),
	}

	for _, ksr := range buckets {
		ret.Items = append(ret.Items, ksr)
	}
	for m := range w.newMembs {
		ret.Additions = append(ret.Additions, m)
	}
	for m := range w.delMembs {
		ret.Removals = append(ret.Removals, m)
	}

	// Sort the buckets
	slices.SortFunc(ret.Items, func(x, y KeyScheduleItem) int { return x.Role.Cmp(y.Role) })
	slices.SortFunc(ret.Additions, func(x, y MemberID) int { return x.Cmp(y) })
	slices.SortFunc(ret.Removals, func(x, y MemberID) int { return x.Cmp(y) })

	return &ret, keyGensPost
}

func (r *RosterCore) planChangesLocked(
	changes ChangeSet,
	keyGensPre KeyGens,
	newRoster *RosterCore,
	forceNewKeyGens []core.RoleKey,
) (
	*KeySchedule,
	KeyGens,
) {

	ws := newWorkingSchedule()

	allKeyRoles := make(map[core.RoleKey]bool)
	for r := range keyGensPre {
		allKeyRoles[r] = true
	}
	for _, r := range forceNewKeyGens {
		allKeyRoles[r] = true
	}

	keyAtLevel := func(k core.RoleKey) {
		ws.includes[k] = true
		for m, i := range newRoster.members {
			if k.LessThanOrEqual(i.Role) {
				ws.rekeys[roleMemberIdx{r: k, m: m}] = true
			}
		}
	}
	keyFlood := func(k core.RoleKey, floor *core.RoleKey) {
		for m, i := range newRoster.members {
			for role := range allKeyRoles {
				if role.LessThanOrEqual(i.Role) && role.LessThanOrEqual(k) &&
					(floor == nil || floor.LessThan(role)) {
					ws.incrs[role] = true
					ws.includes[role] = true
					ws.rekeys[roleMemberIdx{r: role, m: m}] = true
				}
			}
		}
	}

	keySingle := func(m MemberID, k core.RoleKey, prev *core.RoleKey) {
		for role := range allKeyRoles {
			if role.LessThanOrEqual(k) && (prev == nil || prev.LessThan(role)) {
				ws.includes[role] = true
				ws.rekeys[roleMemberIdx{r: role, m: m}] = true
			}
		}
	}

	for _, chng := range changes {

		existing, ok := r.members[chng.Member]
		var cmp int
		if ok {
			cmp = existing.Role.Cmp(chng.Info.Role)
		}

		rm := chng.Info.Role.Typ == proto.RoleType_NONE

		// If the role didn't prevoiusly exist, then we need to "rotate" it
		// for all users, i.e., initialize at gen=0. But no need to rotate
		// lower roles.
		if _, foundRole := keyGensPre[chng.Info.Role]; !foundRole && !rm {
			keyAtLevel(chng.Info.Role)
		}

		// If someone from a role was downgraded, then we need to rotate the
		// existing roles they can no longer see. Note that removal counts
		// as a downgrade, since RoleType_NONE is less than all other roles.
		if ok && (cmp > 0 || (cmp == 0 && existing.Gen < chng.Info.Gen)) {
			var floor *core.RoleKey
			if existing.Gen == chng.Info.Gen {
				floor = &chng.Info.Role
			}
			keyFlood(existing.Role, floor)
		}

		// If the user didn't previously exist here, or the user got *upgraded*, then
		// the key needs to be included for the new user. For all roles less than or equal the new role
		// and greater than the old role if the old role exists.
		if !ok || cmp < 0 {
			var prev *core.RoleKey
			if ok {
				prev = &existing.Role
			}
			// Ok to take this chng.Info.Role at face-value here, since we are not allowing
			// multiple updates for the same member.
			keySingle(chng.Member, chng.Info.Role, prev)
		}

		// Also keep track of new members in the team
		if !ok {
			ws.newMembs[chng.Member] = true
		}

		// Also keep track of deleted members, so admin knows to update their removals.
		if rm {
			ws.delMembs[chng.Member] = true
		}
	}

	return ws.export(keyGensPre)
}

func find(changes ChangeSet, m MemberID, r core.RoleKey) *MemberInfo {
	for _, chng := range changes {
		if chng.Member.Eq(m) && chng.Info.Role.Eq(r) {
			return &chng.Info
		}
	}
	return nil
}

// Checks that the given changes can be applied by the doer
// to the given roster.
func (r *RosterCore) checkChangesLocked(doer MemberID, changes ChangeSet, create bool) error {

	// First pass - make sure that every user only shows up once
	found := make(map[MemberID]bool)
	for _, chng := range changes {
		if found[chng.Member] {
			return core.TeamRosterError("duplicate member in change set")
		}
		found[chng.Member] = true
	}

	var doerInfo MemberInfo
	var ok bool

	// First case is if this team is being created.
	if create {

		if r.Len() != 0 {
			return core.TeamRosterError("can't create roster with existing members")
		}
		tmp := find(changes, doer, core.OwnerRole)
		if tmp == nil {
			return core.TeamRosterError("doer must be included as an owner")
		}
		doerInfo = *tmp

	} else {
		// Else the doer must already be in the groupo

		// Second check -- that the DOER is in the original roster
		// as an owner or an admin
		doerInfo, ok = r.members[doer]
		doerRole := doerInfo.Role.Typ
		if !ok {
			return core.TeamRosterError("doer not in roster")
		}
		if doerRole != proto.RoleType_ADMIN &&
			doerRole != proto.RoleType_OWNER {
			return core.TeamRosterError("doer doesn't have privileged role")
		}
	}

	// Doer can't grant owner perms if admin. Also can't demote
	// existing owners if admin
	for _, chng := range changes {
		if doerInfo.Role.LessThan(chng.Info.Role) {
			return core.TeamRosterError("doer role insufficient for change")
		}
		existing, ok := r.members[chng.Member]
		if ok && doerInfo.Role.LessThan(existing.Role) {
			return core.TeamRosterError("doer role insufficient for change")
		}
	}

	for _, chng := range changes {
		if chng.Info.Role.Typ.IsAdminOrAbove() && !doer.Fqe.Host.FastEq(chng.Member.Fqe.Host) {
			return core.TeamRosterError("only local members can be admins or above")
		}
	}

	// Check that we're subtracting existing members or if keeping
	// roles the same, that we're changing the generation of members.
	// Also that generations don't go backwards.
	for _, chng := range changes {
		existing, ok := r.members[chng.Member]
		rm := chng.Info.Role.Typ == proto.RoleType_NONE
		if !ok && rm {
			return core.TeamRosterError("can't remove non-existent member")
		}
		if rm && !chng.Info.Gen.IsVoid() {
			return core.TeamRosterError("must supply 0-generation for removal")
		}
		if ok && existing.Eq(chng.Info) {
			return core.TeamRosterError("no change to member")
		}
		if ok && !rm && existing.Gen > chng.Info.Gen {
			return core.TeamRosterError("can't decrease generation")
		}
		if ok && !rm && !chng.Info.Gen.IsValid() {
			return core.TeamRosterError("must supply valid key generation (>= 1)")
		}
	}

	// Note that there's no notion of ordering in the changes, so the
	// admin is allowed to demote themselves. It's just considered
	// to be the last change in the set.

	return nil
}

func NewRosterCore() *RosterCore {
	return &RosterCore{
		members:   make(map[MemberID]MemberInfo),
		roleIndex: make(map[core.RoleKey]MemberSet),
	}
}

func (r *RosterCore) Clone() *RosterCore {
	if r == nil {
		return NewRosterCore()
	}
	r.Lock()
	defer r.Unlock()

	ret := NewRosterCore()
	for k, v := range r.members {
		ret.members[k] = v
	}
	for k, v := range r.roleIndex {
		ret.roleIndex[k] = v.Copy()
	}
	return ret
}

func NewRosterCoreFromChanges(changes ChangeSet) *RosterCore {
	ret := NewRosterCore()
	ret.Apply(changes)
	return ret
}

func (r *RosterCore) Apply(changes ChangeSet) *RosterCore {
	for _, chng := range changes {
		if existing, found := r.members[chng.Member]; found {
			ind, found := r.roleIndex[existing.Role]
			if found {
				delete(ind, chng.Member)
			}
		}
		if chng.Info.Role.Typ == proto.RoleType_NONE {
			delete(r.members, chng.Member)
		} else {
			r.members[chng.Member] = chng.Info
			ind, found := r.roleIndex[chng.Info.Role]
			if !found {
				ind = NewMemberSet()
				r.roleIndex[chng.Info.Role] = ind
			}
			ind[chng.Member] = true
		}
	}
	return r
}

type KeyScheduleItem struct {
	Role      core.RoleKey
	NewKeyGen bool
	Gen       proto.Generation
	Members   []MemberID
}

type KeySchedule struct {
	Items     []KeyScheduleItem
	Additions []MemberID
	Removals  []MemberID
}

func (k KeySchedule) HasNewAdminKey() bool {
	for _, item := range k.Items {
		if item.NewKeyGen && item.Role.Eq(core.AdminRole) {
			return true
		}
	}
	return false
}

// Let's say we start at the roster rPre, keyed at the given gens, and apply the given delta
// We output:
//   - the new roster
//   - the rekey schedule
//   - and also an error if the changeset is invalid
func (d ChangeSet) Gameplan(
	doer MemberID,
	rPre *RosterCore,
	keysPre KeyGens,
	opts *GameplanOpts,
) (
	rPost *RosterCore,
	sched *KeySchedule,
	keysPost KeyGens,
	err error,
) {

	var create bool
	if (rPre == nil) != (keysPre == nil) {
		return nil, nil, nil, core.TeamRosterError("must supply both roster and keys, or both nil for create ")
	}

	var forcedNewKeyGens []core.RoleKey

	if rPre == nil {
		create = true
		// Make sure we always get an admin and reader key, even if there are no
		// admins or readers to admin
		forcedNewKeyGens = []core.RoleKey{
			core.AdminRole,
			core.MemberRole,
			core.KVMinRole,
		}
		keysPre = make(KeyGens)
		rPre = NewRosterCore()
	}

	if opts == nil || !opts.TestingNoCheck {
		err = rPre.checkChangesLocked(doer, d, create)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	rPost = rPre.Clone().Apply(d)

	sched, keysPost = rPre.planChangesLocked(d, keysPre, rPost, forcedNewKeyGens)

	if len(keysPost) > core.MaxRolesPerTeam {
		return nil, nil, nil, core.TeamRosterError(
			fmt.Sprintf("too many roles in team (current max=%d)",
				core.MaxRolesPerTeam,
			),
		)
	}

	return rPost, sched, keysPost, nil
}

func Gameplan(
	doer MemberID,
	rPre *RosterCore,
	keysPre KeyGens,
	d ChangeSet,
) (
	rPost *RosterCore,
	sched *KeySchedule,
	err error,
) {
	rPost, sched, _, err = d.Gameplan(doer, rPre, keysPre, nil)
	return rPost, sched, err
}
