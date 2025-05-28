// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type RoleKey struct {
	Typ proto.RoleType
	Lev proto.VizLevel
}

var OwnerRole = RoleKey{Typ: proto.RoleType_OWNER}
var AdminRole = RoleKey{Typ: proto.RoleType_ADMIN}
var MemberRole = RoleKey{Typ: proto.RoleType_MEMBER}
var KVMinRole = RoleKey{Typ: proto.RoleType_MEMBER, Lev: proto.VizLevelKvMin}

func ImportRole(p proto.Role) (*RoleKey, error) {
	rt, err := p.GetT()
	if err != nil {
		return nil, err
	}
	var viz proto.VizLevel
	if rt == proto.RoleType_MEMBER {
		viz = p.Member()
	}
	ret := &RoleKey{Typ: rt, Lev: viz}
	err = ret.validate()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (r RoleKey) validate() error {
	switch r.Typ {
	case proto.RoleType_MEMBER:
		iviz := int(r.Lev)
		if iviz < -32768 || iviz >= 32768 {
			return ValidationError("invalid viz level")
		}
	case proto.RoleType_ADMIN, proto.RoleType_OWNER, proto.RoleType_NONE:
		if r.Lev != 0 {
			return ValidationError("invalid viz level")
		}
	default:
		return ValidationError("invalid role type")
	}
	return nil
}

func ImportRoleKeyFromDB(rt int, vl int) (*RoleKey, error) {
	ret := &RoleKey{Typ: proto.RoleType(rt), Lev: proto.VizLevel(vl)}
	err := ret.validate()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (r RoleKey) Export() proto.Role {
	switch r.Typ {
	case proto.RoleType_MEMBER:
		return proto.NewRoleWithMember(r.Lev)
	default:
		return proto.NewRoleDefault(r.Typ)
	}
}

func (r RoleKey) LessThan(r2 RoleKey) bool {
	if r.Typ < r2.Typ {
		return true
	}
	if r.Typ > r2.Typ {
		return false
	}
	return r.Lev < r2.Lev
}

func (r RoleKey) LessThanOrEqual(r2 RoleKey) bool {
	if r.Typ < r2.Typ {
		return true
	}
	if r.Typ > r2.Typ {
		return false
	}
	return r.Lev <= r2.Lev
}

func (r RoleKey) Eq(r2 RoleKey) bool {
	return r.Typ == r2.Typ && r.Lev == r2.Lev
}

func (r RoleKey) Cmp(r2 RoleKey) int {
	if r.Typ < r2.Typ {
		return -1
	}
	if r.Typ > r2.Typ {
		return 1
	}
	if r.Lev < r2.Lev {
		return -1
	}
	if r.Lev > r2.Lev {
		return 1
	}
	return 0
}

func (r RoleKey) IsOwner() bool {
	return r.Typ == proto.RoleType_OWNER
}

func (r RoleKey) IsAdminOrAbove() bool {
	return r.Typ.IsAdminOrAbove()
}

type RoleKeyAndGen struct {
	RoleKey
	Gen proto.Generation
}

func ImportRoleKeyAndGen(sk *SharedPublicSuite) (*RoleKeyAndGen, error) {
	rk, err := ImportRole(sk.Role)
	if err != nil {
		return nil, err
	}
	return &RoleKeyAndGen{RoleKey: *rk, Gen: sk.Gen}, nil
}

type RoleDBKey proto.Role

func (r RoleDBKey) DbKey() (proto.DbKey, error) {
	tmp := proto.Role(r)
	b, err := EncodeToBytes(&tmp)
	if err != nil {
		return nil, err
	}
	return proto.DbKey(b), nil
}

var _ DbKeyer = RoleDBKey{}

type LocalUserIndex struct {
	Fqu  proto.FQUser
	Fxid proto.FixedEntityID
}

func (f LocalUserIndex) Eq(f2 LocalUserIndex) bool {
	return f.Fqu.Eq(f2.Fqu) && f.Fxid.Eq(f2.Fxid)
}

func ImportLocalUserIndexFromInfo(o proto.UserInfo) (*LocalUserIndex, error) {
	return NewLocalUserIndex(o.Fqu, o.Key)
}

func NewLocalUserIndex(
	fqu proto.FQUser,
	id proto.EntityID,
) (
	*LocalUserIndex,
	error,
) {
	tmp, err := id.Fixed()
	if err != nil {
		return nil, err
	}
	return &LocalUserIndex{Fqu: fqu, Fxid: tmp}, nil
}

func ImportSharedKeyGens(skg []proto.SharedKeyGen) (map[RoleKey]proto.Generation, error) {
	ret := make(map[RoleKey]proto.Generation)
	for _, v := range skg {
		rk, err := ImportRole(v.Role)
		if err != nil {
			return nil, err
		}
		ret[*rk] = v.Gen
	}
	return ret, nil
}

func (r RoleKey) IsNone() bool {
	return r.Typ == proto.RoleType_NONE
}

func (k LocalUserIndex) Export() proto.LocalUserIndex {
	return proto.LocalUserIndex{
		Host: k.Fqu.HostID,
		Rest: proto.LocalUserIndexAtHost{
			Uid:   k.Fqu.Uid,
			Keyid: k.Fxid.Unfix(),
		},
	}
}
