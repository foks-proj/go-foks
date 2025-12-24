// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
)

func EmulateLetsEncrypt(
	m shared.MetaContext,
	hosts []proto.Hostname,
	aliases []proto.Hostname,
	ca X509CA,
	typ proto.CKSAssetType,
) (
	*shared.AutocertDoneResult,
	error,
) {
	return shared.EmulateLetsEncrypt(m, hosts, aliases, ca.Cert, ca.Key, typ, true)
}
