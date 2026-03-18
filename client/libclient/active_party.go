// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func ActivePartyNamed(
	m MetaContext,
	actingAs *proto.FQTeamParsed,
) (
	*proto.FQPartyParsed,
	error,
) {
	au := m.g.ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}

	if actingAs == nil {
		hn, err := au.HomeServer().HostnameWithOptionalPort()
		if err != nil {
			return nil, err
		}
		host := proto.NewParsedHostnameWithTrue(hn)
		ret := proto.FQPartyParsed{
			Party: proto.NewParsedPartyWithTrue(
				proto.PartyName{
					Name:   au.UserInfo().Username.NameUtf8,
					IsTeam: false,
				},
			),
			Host: &host,
		}
		return &ret, nil
	}
	tm := au.TeamMinder()
	fqt, err := tm.ResolveAndReindex(m, *actingAs, nil)
	if err != nil {
		return nil, err
	}
	team := tm.GetTeam(*fqt)
	if team == nil {
		return nil, core.TeamNotFoundError{}
	}
	tw := team.Tw()
	hostname := tw.Hostname()
	name := tw.Name()
	host := proto.NewParsedHostnameWithTrue(proto.NewTCPAddrPortOpt(hostname, nil))
	ret := proto.FQPartyParsed{
		Party: proto.NewParsedPartyWithTrue(
			proto.PartyName{
				Name:   name,
				IsTeam: true,
			},
		),
		Host: &host,
	}

	return &ret, nil
}
