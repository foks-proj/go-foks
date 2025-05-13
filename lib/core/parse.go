package core

import (
	"regexp"
	"strings"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func ParseFQUser(s proto.FQUserString) (*proto.FQUserParsed, error) {
	return s.Parse(NormalizeName)
}

func ParseFQTeam(s proto.FQTeamString) (*proto.FQTeamParsed, error) {
	return s.Parse(NormalizeName)
}

func ParseFQTeamSimple(s proto.FQTeamString) (*proto.FQTeam, error) {
	tmp, err := s.Parse(NormalizeName)
	if err != nil {
		return nil, err
	}
	if tmp.Host == nil {
		return nil, ValidationError("host is required")
	}
	isName, err := tmp.Host.GetS()
	if err != nil {
		return nil, err
	}
	if isName {
		return nil, ValidationError("host must be an ID")
	}
	isName, err = tmp.Team.GetS()
	if err != nil {
		return nil, err
	}
	if isName {
		return nil, ValidationError("team must be an ID")
	}
	return &proto.FQTeam{
		Host: tmp.Host.False(),
		Team: tmp.Team.False(),
	}, nil
}

func ParseFQParty(s proto.FQPartyString) (*proto.FQPartyParsed, error) {
	return s.Parse(NormalizeName)
}

func CheckDeviceLabelAndName(dln proto.DeviceLabelAndName) error {
	dnn, err := NormalizeDeviceName(dln.Name)
	if err != nil {
		return err
	}
	if dnn != dln.Label.Name {
		return ValidationError("normalized device name didn't match")
	}
	return nil
}

func ParseFQPartyAndRole(s lcl.FQPartyAndRoleString) (*lcl.FQPartyParsedAndRole, error) {
	tmp := strings.TrimSpace(string(s))
	parts := strings.Split(tmp, proto.RoleSep)
	if len(parts) > 3 {
		return nil, ValidationError("too many commas")
	}
	fqp, err := ParseFQParty(proto.FQPartyString(parts[0]))
	if err != nil {
		return nil, err
	}
	ret := lcl.FQPartyParsedAndRole{
		Fqp: *fqp,
	}

	// Role strings are of the form: /o for owners (and admins) or /m/-40 for members
	if len(parts) >= 2 {
		roleStr := proto.RoleString(strings.Join(parts[1:], proto.RoleSep))
		role, err := roleStr.Parse()
		if err != nil {
			return nil, err
		}
		ret.Role = role
	}
	return &ret, nil
}

func ParseRoleChangeString(s lcl.RoleChangeString) (*lcl.RoleChange, error) {
	tmp := strings.TrimSpace(string(s))
	regex := regexp.MustCompile(`(->|→)`)
	parts := regex.Split(tmp, -1)
	if len(parts) != 2 {
		return nil, ValidationError("too many rolechange separators")
	}
	mem, err := ParseFQPartyAndRole(lcl.FQPartyAndRoleString(parts[0]))
	if err != nil {
		return nil, err
	}
	role, err := proto.RoleString(parts[1]).Parse()
	if err != nil {
		return nil, err
	}
	ret := lcl.RoleChange{
		Member:  *mem,
		NewRole: *role,
	}
	return &ret, nil
}
