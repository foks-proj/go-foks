// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kv

import (
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func CheckName(k proto.KVNamePlaintext) error {
	for _, c := range []byte(k) {
		switch c {
		case '/':
			return core.NameError("bad character in name (/)")
		case 0:
			return core.NameError("bad character in name (0)")
		}
	}
	return nil
}

func pathSplit(p proto.KVPath) []string {
	return strings.Split(string(p), "/")
}

// Prunes paths of repeated ////
//
//	Prunes ///a -> /a,
//	And also /a///b -> /a/b
//	But leaves trailing slashes, so :/a/ -> /a/
func pathPrune(s []string) []string {
	ret := make([]string, 0, len(s))
	prevLen := -1
	for _, c := range s {
		if len(c) > 0 || prevLen != 0 {
			ret = append(ret, c)
		}
		prevLen = len(c)
	}
	return ret

}

type ParsedPath struct {
	Components    []proto.KVPathComponent
	TrailingSlash bool
	LeadingSlash  bool
}

func (p ParsedPath) Base() proto.KVPathComponent {
	if len(p.Components) == 0 {
		return ""
	}
	return core.Last(p.Components)
}

func ParseAbsPath(p proto.KVPath) (*ParsedPath, error) {

	pp, err := ParsePath(p)
	if err != nil {
		return nil, err
	}
	if !pp.LeadingSlash {
		return nil, core.KVAbsPathError{Path: p}
	}
	return pp, nil
}

func ParsePath(p proto.KVPath) (*ParsedPath, error) {
	if len(p) == 0 {
		return nil, core.KVPathError("empty path")
	}

	parts := pathSplit(p)
	parts = pathPrune(parts)

	if len(parts) == 0 {
		return &ParsedPath{
			Components:    make([]proto.KVPathComponent, 0),
			TrailingSlash: false,
			LeadingSlash:  false,
		}, nil
	}

	var ls bool

	if len(parts[0]) == 0 {
		ls = true
		parts = parts[1:]
	}

	trailingSlash := false
	components := make([]proto.KVPathComponent, 0, len(parts))
	for _, s := range parts {
		trailingSlash = (len(s) == 0)
		if !trailingSlash {
			components = append(components, proto.KVPathComponent(s))
		}
	}
	return &ParsedPath{
		Components:    components,
		TrailingSlash: trailingSlash,
		LeadingSlash:  ls,
	}, nil
}

func (p ParsedPath) Split() (*ParsedPath, proto.KVPathComponent, error) {
	if len(p.Components) == 0 {
		return nil, "", core.KVPathError("empty path")
	}
	l1 := len(p.Components) - 1
	return &ParsedPath{
		Components:    p.Components[:l1],
		TrailingSlash: false,
	}, p.Components[l1], nil
}

func (p ParsedPath) Parent() ParsedPath {
	if len(p.Components) == 0 {
		return p
	}
	return ParsedPath{
		Components:    p.Components[:len(p.Components)-1],
		TrailingSlash: true,
		LeadingSlash:  p.LeadingSlash,
	}
}

func (p ParsedPath) Export() proto.KVPath {
	if len(p.Components) == 0 {
		if p.LeadingSlash {
			return "/"
		}
		return ""
	}
	var ret strings.Builder
	if p.LeadingSlash {
		ret.WriteByte('/')
	}
	for i, c := range p.Components {
		if i > 0 {
			ret.WriteByte('/')
		}
		ret.WriteString(string(c))
	}
	if p.TrailingSlash {
		ret.WriteByte('/')
	}
	return proto.KVPath(ret.String())
}

func (p ParsedPath) AsDir() ParsedPath {
	ret := p
	ret.TrailingSlash = true
	return ret
}

func IsForbiddenDirentName(p proto.KVPathComponent) bool {
	return p == "." || p == ".." || p == "/" || p == ""
}
