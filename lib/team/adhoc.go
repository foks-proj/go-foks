package team

import (
	"slices"
	"strings"

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

func NamesToAdhHocCanonicalString(
	names []proto.NameUtf8,
	username proto.NameUtf8,
) (
	proto.AdHocTeamString,
	error,
) {
	if !username.IsZero() {
		names = append(names, username)
	}
	nmap := make(map[proto.Name]struct{})
	for _, n := range names {
		n, err := core.NormalizeName(n)
		if err != nil {
			return "", err
		}
		nmap[n] = struct{}{}
	}
	tmp := make([]proto.Name, 0, len(nmap))
	for n := range nmap {
		tmp = append(tmp, n)
	}
	slices.SortFunc(tmp, func(a, b proto.Name) int {
		return a.Cmp(b)
	})
	return proto.AdHocTeamString(
		strings.Join(
			core.Map(
				tmp,
				func(n proto.Name) string {
					return string(n)
				},
			),
			","),
	), nil
}

// StripSelfFromAdHocName drops the viewer's own username from a canonical
// ad-hoc member-name list ("alice,bob,charlie" -> "bob,charlie" for alice),
// for DM-style display of ad-hoc teams. A name that doesn't parse, or a list
// that would strip to nothing (a solo team), is returned unchanged.
func StripSelfFromAdHocName(
	nm proto.NameUtf8,
	self proto.NameUtf8,
) (
	proto.NameUtf8,
	error,
) {
	selfNorm, err := core.NormalizeName(self)
	if err != nil {
		return "", err
	}
	parts := strings.Split(nm.String(), ",")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		// Canonical lists hold normalized names, so direct comparison works.
		if !proto.Name(p).Eq(selfNorm) {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 || len(kept) == len(parts) {
		return nm, nil
	}
	return proto.NameUtf8(strings.Join(kept, ",")), nil
}

func UIDsToAdhHocCanonicalString(
	uids []proto.UID,
	uid proto.UID,
) (
	proto.AdHocTeamString,
	error,
) {
	if !uid.IsZero() {
		uids = append(uids, uid)
	}
	umap := make(map[proto.UID]struct{})
	for _, u := range uids {
		umap[u] = struct{}{}
	}
	tmp := make([]proto.UID, 0, len(umap))
	for u := range umap {
		tmp = append(tmp, u)
	}
	slices.SortFunc(tmp, func(a, b proto.UID) int {
		return a.EntityID().Cmp(b.EntityID())
	})
	var err error
	ret := proto.AdHocTeamString(
		strings.Join(
			core.Map(
				tmp,
				func(u proto.UID) string {
					tmp, e2 := u.EntityID().StringErr()
					if e2 != nil {
						err = e2
					}
					return tmp
				},
			),
			",",
		),
	)
	if err != nil {
		return "", err
	}
	return ret, nil
}
