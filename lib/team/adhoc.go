package team

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func MashAdHocTeamID(
	parties []proto.FQParty,
) (
	*proto.AdHocTeamMashedID,
	error,
) {
	slices.SortFunc(parties, func(a, b proto.FQParty) int {
		return a.Cmp(b)
	})
	inputs := proto.AdHocTeamNameInputs{
		Parties: parties,
	}
	var output proto.AdHocTeamMashedID
	err := core.PrefixedHashInto(&inputs, output[:])
	if err != nil {
		return nil, err
	}
	return &output, nil
}
