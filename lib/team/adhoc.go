package team

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func MashUIDsIntoAdHocTeamID(
	users []proto.UID,
	hostID proto.HostID,
) (
	*proto.AdHocTeamMashedID,
	error,
) {
	slices.SortFunc(users, func(a, b proto.UID) int {
		return a.EntityID().Cmp(b.EntityID())
	})
	fqu := core.Map(users, func(u proto.UID) proto.FQUser {
		return proto.FQUser{
			Uid:    u,
			HostID: hostID,
		}
	})
	inputs := proto.NewAdHocTeamMashInputsWithUserownersonly(fqu)
	return doMash(inputs)
}

func doMash(inputs proto.AdHocTeamMashInputs) (
	*proto.AdHocTeamMashedID,
	error,
) {
	var output proto.AdHocTeamMashedID
	err := core.PrefixedHashInto(&inputs, output[:])
	if err != nil {
		return nil, err
	}
	return &output, nil
}

func MashFQUsersIntoAdHocTeamID(
	users []proto.FQUser,
	hostID proto.HostID,
) (
	*proto.AdHocTeamMashedID,
	error,
) {
	slices.SortFunc(users, func(a, b proto.FQUser) int {
		return a.ToFQParty().Cmp(b.ToFQParty())
	})
	inputs := proto.NewAdHocTeamMashInputsWithUserownersonly(users)
	return doMash(inputs)
}
