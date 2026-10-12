// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestCheckRosterDelegationFloor(t *testing.T) {
	member := func(v proto.VizLevel) proto.Role { return proto.NewRoleWithMember(v) }
	tests := []struct {
		name   string
		role   proto.Role
		ok     bool
		active bool
	}{
		{"none turns delegation off", proto.NewRoleDefault(proto.RoleType_NONE), true, false},
		{"m/1 is the lowest legal floor", member(1), true, true},
		{"m/100", member(100), true, true},
		{"m/32767 is the highest viz level", member(32767), true, true},
		{"m/0 is what ordinary members hold", member(0), false, false},
		{"negative viz levels are below ordinary members", member(-10), false, false},
		{"admin already manages the roster", proto.NewRoleDefault(proto.RoleType_ADMIN), false, false},
		{"owner already manages the roster", proto.NewRoleDefault(proto.RoleType_OWNER), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckRosterDelegationFloor(tc.role)
			if !tc.ok {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			rk, err := RosterDelegationFloorActive(&tc.role)
			require.NoError(t, err)
			if tc.active {
				require.NotNil(t, rk)
			} else {
				require.Nil(t, rk)
			}
		})
	}

	// No floor at all means delegation off.
	rk, err := RosterDelegationFloorActive(nil)
	require.NoError(t, err)
	require.Nil(t, rk)
}
