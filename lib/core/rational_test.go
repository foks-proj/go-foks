// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestRationalString(t *testing.T) {

	for _, tt := range []struct {
		r Rational
		s string
	}{
		{Rational{proto.Rational{Infinity: true}}, "∞"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{1}, Exp: 0}}, "01"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: 0}}, "abcd"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: 2}}, "abcd0000"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: -1}}, "ab.cd"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: -5}}, ".000000abcd"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0x00}, Exp: 0}}, "00"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0x00, 0x00, 0x00, 0x01}, Exp: 0}}, "01"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0x00}, Exp: 5}}, "00"},
		{Rational{proto.Rational{Infinity: false, Base: []byte{0x1, 0x00, 0x00}, Exp: -2}}, "01"},
	} {
		if got := tt.r.String(); got != tt.s {
			t.Errorf("rational.String() = %q; want %q", got, tt.s)
		}
	}
}

func TestRationalParse(t *testing.T) {
	bfe := BadFormatError("rational must have an even number of digits")

	for i, tt := range []struct {
		s   string
		r   *Rational
		err error
	}{
		{"∞", &Rational{proto.Rational{Infinity: true}}, nil},
		{"01", &Rational{proto.Rational{Infinity: false, Base: []byte{1}, Exp: 0}}, nil},
		{"abcd", &Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: 0}}, nil},
		{"abcd0000", &Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: 2}}, nil},
		{"ab.cd", &Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: -1}}, nil},
		{".000000abcd", &Rational{proto.Rational{Infinity: false, Base: []byte{0xab, 0xcd}, Exp: -5}}, nil},
		{"00", &Rational{proto.Rational{Infinity: false, Base: []byte{}, Exp: 0}}, nil},
		{"01", &Rational{proto.Rational{Infinity: false, Base: []byte{0x01}, Exp: 0}}, nil},
		{"aabb.", &Rational{proto.Rational{Infinity: false, Base: []byte{0xaa, 0xbb}, Exp: 0}}, nil},
		{"aabb.e", nil, bfe},
	} {
		got, err := ParseRational(tt.s)
		if tt.err != nil {
			require.Equal(t, tt.err, err, "%q ; vec %d", tt.s, i)
		} else {
			require.Equal(t, *tt.r, *got, "%q ; vec %d", tt.s, i)
		}
	}
}

func TestRationalCompare(t *testing.T) {

	for i, tt := range []struct {
		s1  string
		s2  string
		val int
	}{
		{"01", "01", 0},
		{"01", "02", -1},
		{"01", "0100", -1},
		{"01", "02.00", -1},
		{"01", "02.01", -1},
		{"01", ".01", 1},
		{"0100", "01", 1},
		{"00.00", "00", 0},
		{"aabbccdd", "aabbccdd.0000000002", -1},
		{"aabbccdd.000002", "aabbccdd.0000000002", 1},
		{"ee", "22", 1},
		{"∞", "01", 1},
		{"∞", "∞", 0},
		{"01", "∞", -1},
	} {
		r1, err := ParseRational(tt.s1)
		require.NoError(t, err, "vec %d", i)
		r2, err := ParseRational(tt.s2)
		require.NoError(t, err, "vec %d", i)
		require.Equal(t, tt.val, r1.Cmp(*r2), "vec %d", i)
	}
}

func TestRationalValidate(t *testing.T) {
	r0 := proto.Rational{Infinity: true, Base: []byte{0x01}, Exp: 0}
	err := r0.Validate()
	require.Error(t, err)
	require.Equal(t, proto.DataError("bad rational"), err)
}

func TestRationalRanges(t *testing.T) {

	_, err := ParseRationalRange("(01,01.01)")
	require.NoError(t, err)

	_, err = ParseRationalRange("02-01.01")
	require.Error(t, err)
	require.Equal(t, BadRangeError{}, err)

	rng := func(s string) RationalRange {
		r, err := ParseRationalRange(s)
		require.NoError(t, err)
		return *r
	}

	require.True(t, rng("01-01").Eq(rng("01-01")))
	require.True(t, rng("01-01").Eq(rng("01-01.00")))
	require.True(t, rng("01-").Eq(rng("01-")))
	require.True(t, rng("01-").Eq(rng("01-∞")))
	require.True(t, rng("01-").Includes(rng("01-ff")))
	require.True(t, rng("01-").Includes(rng("(10,ff)")))
	require.False(t, rng("01-").Includes(rng(".01-ff")))
	require.False(t, rng("01-ff").LessThan(rng("01-")))
	require.False(t, rng("01-").LessThan(rng("02-")))
	require.True(t, rng("01-10").LessThan(rng("11-")))
	require.False(t, rng("01-10").LessThan(rng("10-")))

}

func TestShifts(t *testing.T) {
	mk := func(s string) Rational {
		r, err := ParseRational(s)
		require.NoError(t, err)
		return *r
	}
	lsh := func(r Rational) Rational {
		ret, err := r.Lsh()
		require.NoError(t, err)
		return *ret
	}
	rsh := func(r Rational) Rational {
		ret, err := r.Rsh()
		require.NoError(t, err)
		return *ret
	}
	inf := mk("∞")
	require.Equal(t, rsh(mk("01")).Cmp(mk(".80")), 0)
	require.Equal(t, rsh(mk("0100")).Cmp(mk("80")), 0)

	_, err := inf.Rsh()
	require.Error(t, err)
	require.Equal(t, BadArgsError("∞ cannot be shifted"), err)

	one := mk("01")
	require.Equal(t, lsh(rsh(one)).Cmp(one), 0)
	yoyo := mk("abcdef")
	require.Equal(t, lsh(rsh(yoyo)).Cmp(yoyo), 0)
}
