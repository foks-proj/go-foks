// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type ArgsError string

func (a ArgsError) Error() string {
	return "error parsing arguments: " + string(a)
}

type BadSubCommandError string

func (s BadSubCommandError) Error() string {
	return "bad subcommand: " + string(s)
}

func parseRole(s string, def *proto.Role) (*proto.Role, error) {
	if len(s) == 0 {
		return def, nil
	}
	return proto.RoleString(s).Parse()
}

func parseFqu(s string) (*proto.FQUserParsed, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return core.ParseFQUser(proto.FQUserString(s))
}
