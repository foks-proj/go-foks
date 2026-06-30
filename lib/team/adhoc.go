package team

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
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
	err := core.PrefixedHashInto(&inputs, output[1:])
	if err != nil {
		return nil, err
	}
	output[0] = byte(proto.EntityType_AdHocTeamMashed)
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

func WrapNamed(team proto.FQTeamParsed) lcl.ConfigTeam {
	return lcl.NewConfigTeamWithNamed(team)
}

func WrapNamedPtr(team *proto.FQTeamParsed) lcl.ConfigTeam {
	if team == nil {
		return lcl.NewConfigTeamWithNone()
	}
	return WrapNamed(*team)
}

func UnwrapNamed(team lcl.ConfigTeam) (*proto.FQTeamParsed, error) {
	typ, err := team.GetT()
	if err != nil {
		return nil, err
	}
	switch typ {
	case lcl.ConfigTeamType_Named:
		tmp := team.Named()
		return &tmp, nil
	case lcl.ConfigTeamType_None:
		return nil, nil
	default:
		return nil, core.InternalError("unexpected team type in UnwrapNamed")
	}
}
