// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/keybase/saltpack/encoding/basex"
)

const SingleUsePrefix = "s."

func B62Encode(b []byte) string {
	return basex.Base62StdEncodingStrict.EncodeToString(b)
}

func ExportInviteCode(c rem.InviteCode) (string, error) {
	typ, err := c.GetT()
	if err != nil {
		return "", err
	}
	var ret string
	switch typ {
	case rem.InviteCodeType_MultiUse:
		ret = c.Multiuse().String()
	case rem.InviteCodeType_Standard:
		base := c.Standard()
		s := basex.Base62StdEncodingStrict.EncodeToString(base)
		ret = SingleUsePrefix + s
	default:
		return "", VersionNotSupportedError("cannot support invitation code type")
	}
	return ret, nil
}

func ImportInviteCode(s string) (rem.InviteCode, error) {
	var ret rem.InviteCode
	switch {
	case strings.HasPrefix(s, SingleUsePrefix):
		s = s[2:]
		b, err := basex.Base62StdEncoding.DecodeString(s)
		if err != nil {
			return ret, err
		}
		ret = rem.NewInviteCodeWithStandard(b)
	default:
		s = strings.ToLower(s)
		ret = rem.NewInviteCodeWithMultiuse(rem.MultiUseInviteCode(s))
	}
	err := ValidateInviteCode(ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func B62Decode(s string) ([]byte, error) {
	return basex.Base62StdEncodingStrict.DecodeString(s)
}

func ExportShortID(id proto.ShortID) (string, error) {
	b, err := EncodeToBytes(&id)
	if err != nil {
		return "", err
	}
	return basex.Base62StdEncoding.EncodeToString(b), nil
}

const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"

// 14 chars of base-36 can encode just over 9 bytes of data.
var Base36Encoding = basex.NewEncoding(base36, 14, "")

func B36Encode(b []byte) string {
	return Base36Encoding.EncodeToString(b)
}

type Base int

const (
	Base10 Base = 10
	Base16 Base = 16
	Base36 Base = 36
	Base62 Base = 62
	Base64 Base = 64
)

func (b Base) Encode(byt []byte) (string, error) {
	switch b {
	case Base10:
		i := new(big.Int).SetBytes(byt)
		return i.Text(10), nil
	case Base16:
		return hex.EncodeToString(byt), nil
	case Base36:
		return B36Encode(byt), nil
	case Base62:
		return B62Encode(byt), nil
	case Base64:
		return base64.URLEncoding.EncodeToString(byt), nil
	default:
		return "", VersionNotSupportedError("base not supported")
	}
}
