// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// CompatibilityVersion is the current compatibility version of the prototocol,
// in terms of FOKS clients talking to FOKS servers.
const CurrentCompatibilityVersion proto.CompatibilityVersion = 1

var CurrentClientVersion = lcl.SemVer{
	Major: 0,
	Minor: 0,
	Patch: 16,
}
