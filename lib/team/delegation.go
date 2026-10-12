// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// A team's roster delegation floor is a role stored in the team chain as
// link metadata (ChangeType_RosterDelegationFloor). When it is set to a
// member role, members at or above it may sign a restricted class of roster
// changes for the team. When it is NONE, or was never set, roster changes
// require an admin or owner, which is the pre-existing rule.
//
// CheckRosterDelegationFloor says which values may be written to the chain:
// a MEMBER role at viz level 1 or higher (so that the floor is never a role
// ordinary members already hold), or NONE to turn delegation off. Everything
// else -- m/0, negative viz levels, ADMIN, OWNER -- is refused at link-open
// time, by the server when it accepts the link and by every client that
// replays it.
func CheckRosterDelegationFloor(r proto.Role) error {
	rk, err := core.ImportRole(r)
	if err != nil {
		return err
	}
	switch {
	case rk.Typ == proto.RoleType_NONE:
		return nil
	case rk.Typ == proto.RoleType_MEMBER && rk.Lev >= 1:
		return nil
	default:
		return core.LinkError(
			"roster delegation floor must be a member role at viz level >= 1, or none to turn delegation off",
		)
	}
}

// RosterDelegationFloorActive turns a stored floor into the RoleKey at which
// delegation operates. It returns nil when the floor is absent or NONE, i.e.
// when delegation is off.
func RosterDelegationFloorActive(r *proto.Role) (*core.RoleKey, error) {
	if r == nil {
		return nil, nil
	}
	rk, err := core.ImportRole(*r)
	if err != nil {
		return nil, err
	}
	if rk.Typ == proto.RoleType_NONE {
		return nil, nil
	}
	return rk, nil
}
