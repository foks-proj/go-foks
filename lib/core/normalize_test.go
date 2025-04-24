// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestFlatten(t *testing.T) {

	var tests = []struct {
		in  string
		out string
	}{
		{"hello", "hello"},
		{"sans ambiguïté", "sans ambiguite"},
		{"Zimne mieszkania: 16-17 stopni musi wystarczyć. Wkładam kurtkę, czapkę i jakoś się żyje",
			"Zimne mieszkania: 16-17 stopni musi wystarczyc. Wkladam kurtke, czapke i jakos sie zyje"},
		{"ąćęłńóśżź", "acelnoszz"},
	}

	for _, v := range tests {
		res, err := UTF8Flatten(v.in)
		require.NoError(t, err)
		require.Equal(t, v.out, res)
	}

}

func TestUsernameCheck(t *testing.T) {

	errBadChar := NameError("found invalid character in name")
	var tests = []struct {
		in  proto.NameUtf8
		out proto.Name
		err error
	}{
		{"max", "max", nil},
		{"m_a.x", "m_a_x", nil},
		{"Wkładam-Kurtkę", "wkladam_kurtke", nil},
		{"m+a+x", "", errBadChar},
		{"m__a_x", "", errBadChar},
		{"_max", "", errBadChar},
		{"max_", "", errBadChar},
		{"ma", "", NameError("name too short; must be 3 or more characters")},
		{"这是书", "", errBadChar},
		{"yoyo这是书", "", errBadChar},
		{"h\u2c66e\u026bl\u0247l\u0110o\u0248\u1d75", "", errBadChar},
		{"aабвгдийфхщщещюяѐaa", "", errBadChar},
		{"yаyа", "", errBadChar},
		{"yоyо", "", errBadChar},
		{"für_Ihre_Beiträge", "fur_ihre_beitrage", nil},
		{"nå_mål", "na_mal", nil},
		{"ifølge", "ifolge", nil},
		{"væk", "vak", nil},
		{"Æok", "aok", nil},
		{"ßßs", "sss", nil},
		{"Vláda_zvyšuje", "vlada_zvysuje", nil},
		{"Celý_článek_členy", "cely_clanek_cleny", nil},
	}
	for _, v := range tests {
		res, err := NormalizeName(v.in)
		require.Equal(t, v.err, err, v.in)
		require.Equal(t, v.out, res, v.in)
	}
}

func TestDeviceNameCheck(t *testing.T) {

	var tests = []struct {
		in  proto.DeviceName
		out proto.DeviceNameNormalized
		err error
	}{
		{"max's iPhone", "max's iphone", nil},
		{"M_A.X 7.4+ Bizzle-", "m_a.x 7.4+ bizzle-", nil},
		{"Wkładam_Kurtkę-", "wkladam_kurtke-", nil},
		{"maa__a", "", proto.NormalizationError("device name, token check")},
		{"maaa ", "", proto.NormalizationError("device name, full check")},
		{"maa  a", "", proto.NormalizationError("device name, full check")},
		{"maa a", "maa a", nil},
		{"a-t-il réagi ça ne", "a-t-il reagi ca ne", nil},
		{"La journée du chef de l'Etat", "la journee du chef de l'etat", nil},
		{"a'b'c", "a'b'c", nil},
		{"a’b’c’", "", proto.NormalizationError("device name, full check")},
	}

	for _, v := range tests {
		res, err := NormalizeDeviceName(v.in)
		require.Equal(t, v.out, res, v.in)
		require.Equal(t, v.err, err, v.in)
	}
}

func TestParserFQUser(t *testing.T) {

	hn := func(s string) *proto.ParsedHostname {
		tmp := proto.NewParsedHostnameWithTrue(
			proto.NewTCPAddrPortOpt(proto.Hostname(s), nil),
		)
		return &tmp
	}
	un := func(s string) proto.ParsedUser {
		tmp := proto.NewParsedUserWithTrue(proto.NameUtf8(s))
		return tmp
	}
	fqup := func(u proto.ParsedUser, h *proto.ParsedHostname) *proto.FQUserParsed {
		return &proto.FQUserParsed{User: u, Host: h}
	}
	fqupSS := func(u string, h string) *proto.FQUserParsed {
		return fqup(un(u), hn(h))
	}

	uidString := ".19p0YuOr4eummvMjN0kHa4Z1pmzyYbyNYkF4lwoFbvNl"
	hostIdString := ".2Qjl0GWP2a5rQk7sCtofl8Tbgi2IuW2tvyYbARRNR3Aq"
	eid, err := proto.ImportEntityIDFromString(uidString)
	require.NoError(t, err)
	uid, err := eid.ToUID()
	require.NoError(t, err)
	eid, err = proto.ImportEntityIDFromString(hostIdString)
	require.NoError(t, err)
	hostId, err := eid.ToHostID()
	require.NoError(t, err)
	pHostId := proto.NewParsedHostnameWithFalse(hostId)

	var tests = []struct {
		in  proto.FQUserString
		out *proto.FQUserParsed
		err error
	}{
		{"max@localhost", fqupSS("max", "localhost"), nil},
		{"Wkładam-Kurtkę@zoo.a.b.co", fqupSS("Wkładam-Kurtkę", "zoo.a.b.co"), nil},
		{"Vláda_zvyšuje@foks.pub", fqupSS("Vláda_zvyšuje", "foks.pub"), nil},
		{"max@e.e", nil, proto.NormalizationError("invalid TLD in hostname")},
		{"max@192.168.1.2", fqupSS("max", "192.168.1.2"), nil},
		{
			proto.FQUserString(uidString + "@foks.pub"),
			fqup(
				proto.NewParsedUserWithFalse(uid),
				hn("foks.pub"),
			),
			nil,
		},
		{
			proto.FQUserString(uidString + "@" + hostIdString),
			fqup(
				proto.NewParsedUserWithFalse(uid),
				&pHostId,
			),
			nil,
		},
		{
			proto.FQUserString("max@" + hostIdString),
			fqup(
				un("max"),
				&pHostId,
			),
			nil,
		},
		{
			proto.FQUserString("max@" + hostIdString + "Xeo"),
			nil,
			proto.EntityError("input raw was wrong size"),
		},
	}

	for i, v := range tests {
		res, err := ParseFQUser(v.in)
		require.Equal(t, v.out, res, i)
		require.Equal(t, v.err, err, i)
	}
}
