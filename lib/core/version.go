// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"encoding/json"
	"strconv"
	"strings"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

// CompatibilityVersion is the current compatibility version of the prototocol,
// in terms of FOKS clients talking to FOKS servers.
const CurrentCompatibilityVersion proto.CompatibilityVersion = 1

var CurrentClientVersion = proto.SemVer{
	Major: 0,
	Minor: 0,
	Patch: 18,
}

type ParsedSemVer struct {
	proto.SemVer
}

func (s *ParsedSemVer) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parts := strings.Split(str, ".")
	if len(parts) != 3 {
		return BadArgsError("invalid semver format")
	}
	conv := func(part string, res *uint64) error {
		val, err := strconv.ParseUint(part, 0, 64)
		if err != nil {
			return err
		}
		*res = val
		return nil
	}
	if err := conv(parts[0], &s.Major); err != nil {
		return err
	}
	if err := conv(parts[1], &s.Minor); err != nil {
		return err
	}
	if err := conv(parts[2], &s.Patch); err != nil {
		return err
	}
	return nil
}
