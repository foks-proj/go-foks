// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFixUnfix(t *testing.T) {
	devid := DeviceID(make([]byte, 33))
	// hack a random devid
	devid[0] = byte(EntityType_Device)
	_, err := rand.Read(devid[1:])
	require.NoError(t, err)
	fix, err := EntityID(devid).Fixed()
	require.NoError(t, err)
	devid2 := DeviceID(fix.Unfix())
	require.Equal(t, devid, devid2)

	yubi := YubiID(make([]byte, 34))
	yubi[0] = byte(EntityType_Yubi)
	_, err = rand.Read(yubi[1:])
	require.NoError(t, err)
	fix, err = EntityID(yubi).Fixed()
	require.NoError(t, err)
	yubi2 := YubiID(fix.Unfix())
	require.Equal(t, yubi, yubi2)
}

func TestEntityEncoding(t *testing.T) {
	buf := make([]byte, 33)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	eid, err := EntityType_Yubi.MakeEntityID(buf)
	require.NoError(t, err)
	s, err := eid.StringErr()
	require.NoError(t, err)
	eid2, err := ImportEntityIDFromString(s)
	require.NoError(t, err)
	require.Equal(t, eid, eid2)

	badEids := []string{
		s[0:30],
		s[1:] + "x",
		"",
		".1123",
		".112345abc",
		".2" + s[2:],
		".X" + s[4:],
	}
	for _, bad := range badEids {
		_, err := ImportEntityIDFromString(bad)
		require.Error(t, err)
	}
}

func TestBase62Vectors(t *testing.T) {
	res := make([][]string, 0)
	for i := 0; i < 20; i++ {
		buf := make([]byte, i+10)
		_, err := rand.Read(buf)
		require.NoError(t, err)
		b62 := B62Encode(buf)
		hx := hex.EncodeToString(buf)
		res = append(res, []string{hx, b62})
	}
	_, err := json.MarshalIndent(res, "", "  ")
	require.NoError(t, err)
}

func TestParseRole(t *testing.T) {

	role := func(t RoleType, l int) *Role {
		var tmp Role
		if t == RoleType_MEMBER {
			tmp = NewRoleWithMember(VizLevel(l))
		} else {
			tmp = NewRoleDefault(t)
		}
		return &tmp
	}

	var tests = []struct {
		in  RoleString
		out *Role
		err error
	}{
		{"", nil, DataError("cannot parse a len=0 role")},
		{"o", role(RoleType_OWNER, 0), nil},
		{"admin", role(RoleType_ADMIN, 0), nil},
		{"m/4", role(RoleType_MEMBER, 4), nil},
		{"member/-8", role(RoleType_MEMBER, -8), nil},
		{"m", nil, DataError("invalid RoleType prefix")},
		{"m/", nil, DataError("bad vizlevel for member")},
		{"m/100000", nil, DataError("vizlevel out of range for member")},
		{"m/-100000", nil, DataError("vizlevel out of range for member")},
	}

	for i, v := range tests {
		out, err := v.in.Parse()
		require.Equal(t, v.out, out, "test %d", i)
		require.Equal(t, v.err, err, "test %d", i)
	}

}

func TestParseFQUserAndRole(t *testing.T) {
	randBuf := func() []byte {
		buf := make([]byte, 32)
		_, err := rand.Read(buf)
		require.NoError(t, err)
		return buf
	}
	eid, err := EntityType_User.MakeEntityID(randBuf())
	require.NoError(t, err)
	uid, err := eid.ToUID()
	require.NoError(t, err)
	eid, err = EntityType_Host.MakeEntityID(randBuf())
	require.NoError(t, err)
	hostid, err := eid.ToHostID()
	require.NoError(t, err)
	vizlev := VizLevel(-34)
	role := NewRoleWithMember(vizlev)

	fqur := FQUserAndRole{
		Fqu: FQUser{
			Uid:    uid,
			HostID: hostid,
		},
		Role: role,
	}
	s, err := fqur.StringErr()
	require.NoError(t, err)

	fqur2, err := FQUserAndRoleString(s).Parse()
	require.NoError(t, err)
	eq, err := fqur.Role.Eq(fqur2.Role)
	require.NoError(t, err)
	require.True(t, eq)

	s2 := ".1SkrZ7ZptD0Tzo52fTLNnJ4i0w5Ijt7MhQ32RBBhEcny/m/-47@.2wEj5vnBaStrMWqitmS0LwXlc226LgCjF8F3YSQd5ikB"
	fqur3, err := FQUserAndRoleString(s2).Parse()
	require.NoError(t, err)
	role3 := NewRoleWithMember(VizLevel(-47))
	eq, err = fqur3.Role.Eq(role3)
	require.NoError(t, err)
	require.True(t, eq)

}

func TestParseGitURL(t *testing.T) {

	ne43pub := NewParsedHostnameWithTrue("ne43.pub")

	var tests = []struct {
		in  GitURLString
		out *GitURL
		err error
	}{
		{"", nil, DataError("empty git url")},
		{"https://mama.com", nil, DataError("bad git url; doesn't start with foks://")},

		{
			"foks://ne43.pub/t:iTurf/abc.git",
			&GitURL{
				Proto: GitProtoType_Foks,
				Repo:  GitRepo("abc"),
				Fqp: FQPartyParsed{
					Party: NewParsedPartyWithTrue(PartyName{
						IsTeam: true,
						Name:   "iTurf",
					}),
					Host: &ne43pub,
				},
			},
			nil,
		},
		{
			"foks://ne43.pub/max/fOO/bAr.git",
			&GitURL{
				Proto: GitProtoType_Foks,
				Repo:  GitRepo("foo/bar"),
				Fqp: FQPartyParsed{
					Party: NewParsedPartyWithTrue(PartyName{
						IsTeam: false,
						Name:   "max",
					}),
					Host: &ne43pub,
				},
			},
			nil,
		},
		{
			"foks://ne43.pub/max",
			nil,
			DataError("bad git url; not enough parts"),
		},
	}
	for i, v := range tests {
		out, err := v.in.Parse()
		require.Equal(t, v.out, out, "test %d", i)
		require.Equal(t, v.err, err, "test %d", i)
	}

}

func TestGetPort(t *testing.T) {
	var tests = []struct {
		in  string
		out Port
		err error
	}{
		{"ne43.pub:1234", 1234, nil},
		{"ne43.pub", 0, nil},
		{"ne43.pub:aa", 0, nil},
		{"[::1]:1234", 1234, nil},
	}
	for i, v := range tests {
		port, err := TCPAddr(v.in).GetPort()
		require.Equal(t, v.out, port, "test %d", i)
		require.Equal(t, v.err, err, "test %d", i)
	}
}

func TestDeviceIDMarshalJSON(t *testing.T) {

	// Check device ID marshals with PrefixedB62Encoding
	var d DeviceID
	buf := make([]byte, 33)
	buf[0] = byte(EntityType_Device)
	_, err := rand.Read(buf[1:])
	require.NoError(t, err)
	d = DeviceID(buf)
	b, err := json.Marshal(d)
	require.NoError(t, err)
	require.Equal(t, []byte{'"', '.', '4'}, b[0:3])

	// Same thing for UID
	var u UID
	buf = make([]byte, 33)
	buf[0] = byte(EntityType_User)
	_, err = rand.Read(buf[1:])
	require.NoError(t, err)
	u = UID(buf)
	p := u.ToPartyID()
	b, err = json.Marshal(p)
	require.NoError(t, err)
	require.Equal(t, []byte{'"', '.', '1'}, b[0:3])

	tok, err := RandomID16er[PermissionToken]()
	require.NoError(t, err)
	b, err = json.Marshal(tok)
	require.NoError(t, err)
	require.Equal(t, []byte{'"', '.', 's'}, b[0:3])
	var tmp PermissionToken
	err = json.Unmarshal(b, &tmp)
	require.NoError(t, err)
	require.Equal(t, *tok, tmp)
}
