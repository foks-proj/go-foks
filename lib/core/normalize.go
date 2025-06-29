// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"errors"
	"regexp"
	"strings"
	"unicode"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// We're going to keep this list small and slowly add to it
// as we go.
var nonNFDChars = map[rune]byte{

	// Polish
	'ą': 'a',
	'ć': 'c',
	'ę': 'e',
	'ł': 'l',
	'ń': 'n',
	'ó': 'o',
	'ś': 's',
	'ż': 'z',
	'ź': 'z',

	// Norwegian, Danish, Swedish, German
	'ø': 'o',
	'æ': 'a',
	'ß': 's',
}

func AllNFDChars() []rune {
	var res []rune
	for k := range nonNFDChars {
		res = append(res, k)
	}
	return res
}

func convertNonNKFD(s string) string {
	var res []rune
	for _, r := range s {
		b, found := nonNFDChars[r]
		if found {
			res = append(res, rune(b))
		} else {
			res = append(res, r)
		}
	}
	return string(res)
}

func UTF8Flatten(str string) (string, error) {
	str = convertNonNKFD(str)
	result, _, err := transform.String(
		transform.Chain(
			norm.NFD,
			runes.Remove(runes.In(unicode.Mn))),
		str)
	if err != nil {
		return "", err
	}
	return result, nil
}

func SuperToLower(s string) (string, error) {
	s, err := UTF8Flatten(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(s), nil
}

const UsernameMaxLen = 25

func checkNameLength(s proto.Name) error {
	if len(s) < 3 {
		return NameError("name too short; must be 3 or more characters")
	}
	if len(s) > UsernameMaxLen {
		return NameError("name too long; must be less than 25 characters")
	}
	return nil

}

var rrxx = regexp.MustCompile(`[.-]`)

func NormalizeName(inp proto.NameUtf8) (proto.Name, error) {
	s := string(inp)
	s = rrxx.ReplaceAllString(s, "_")
	s = strings.ToLower(s)
	s, err := UTF8Flatten(s)
	if err != nil {
		return "", err
	}
	ret := proto.Name(s)

	err = CheckUsername(ret)
	if err != nil {
		return "", err
	}
	return ret, nil
}

func NormalizedNameEq(a, b proto.NameUtf8) (bool, error) {
	an, err := NormalizeName(a)
	if err != nil {
		return false, err
	}
	bn, err := NormalizeName(b)
	if err != nil {
		return false, err
	}
	return an.Eq(bn), nil
}

func CheckUsername(u proto.Name) error {

	// Make sure we match the protocol version of normalized name
	err := u.AssertNormalized()
	if errors.Is(err, proto.NormalizationError("name")) {
		return NameError("found invalid character in name")
	}

	if err != nil {
		return err
	}

	err = checkNameLength(u)
	if err != nil {
		return err
	}
	return nil
}

var spaceRxx = regexp.MustCompile(`\s+`)

func IsDeviceNameFixed(d proto.DeviceName) bool {
	return d == FixDeviceName(string(d))
}

// FixDeviceName makes it so that this device can be more successfully normalized,
// but it doesn't normalize it. Nor does it guarantee that it can be normalized.
func FixDeviceName(s string) proto.DeviceName {
	s = strings.TrimSpace(s)
	s = spaceRxx.ReplaceAllString(s, " ")

	// Convert strings that might be inserted by the OS for fancy device names
	s = strings.ReplaceAll(s, "—", "-") // em dash
	s = strings.ReplaceAll(s, "–", "-") // en dash
	s = strings.ReplaceAll(s, "‘", "'") // curly quote #1
	s = strings.ReplaceAll(s, "’", "'") // curly quote #2

	return proto.DeviceName(s)
}

func NormalizeDeviceName(d proto.DeviceName) (proto.DeviceNameNormalized, error) {
	s := string(d)
	s, err := SuperToLower(s)
	if err != nil {
		return "", err
	}
	ret := proto.DeviceNameNormalized(s)

	err = ret.AssertNormalized()
	if err != nil {
		return "", err
	}
	return ret, nil
}

// checks if a given input an be coerced into a device name, but throws away the result.
func CheckDeviceName(s string) error {
	d := FixDeviceName(s)
	_, err := NormalizeDeviceName(d)
	return err
}

func FixAndNormalizeDeviceName(s string) (proto.DeviceName, proto.DeviceNameNormalized, error) {
	d := FixDeviceName(s)
	n, err := NormalizeDeviceName(d)
	if err != nil {
		return "", "", err
	}
	return d, n, nil
}

func NewNameBundle(u proto.NameUtf8) (proto.NameBundle, error) {
	n, err := NormalizeName(u)
	if err != nil {
		return proto.NameBundle{}, err
	}
	return proto.NameBundle{
		Name:     n,
		NameUtf8: u,
	}, nil
}
