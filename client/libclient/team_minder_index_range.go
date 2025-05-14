// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (t *TeamMinder) GetIndexRange(
	m MetaContext,
	fqp proto.FQTeamParsed,
) (
	*core.RationalRange,
	error,
) {
	var ret *core.RationalRange
	err := t.withLoadedTeam(
		m, fqp,
		LoadTeamOpts{Refresh: true},
		func(m MetaContext, tm *TeamRecord) error {
			tmp := tm.IndexRange()
			ret = &tmp
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (t *TeamMinder) SetIndexRangeHigh(
	m MetaContext,
	arg lcl.TeamIndexRangeSetHighArg,
) (
	*core.RationalRange,
	error,
) {
	return t.setIndexRangeCommon(m, arg.Team, func(r core.RationalRange) (*core.RationalRange, error) {
		high := core.Rational{Rational: arg.High}
		cmp := high.Cmp(r.GetHigh())
		if cmp == 0 {
			return nil, core.TeamIndexRangeError("index high already set")
		}
		if cmp > 0 {
			return nil, core.TeamIndexRangeError("index high must be less than current high")
		}
		ret := r.SetHigh(high)
		return &ret, nil
	},
	)
}

func (t *TeamMinder) SetIndexRange(
	m MetaContext,
	arg lcl.TeamIndexRangeSetArg,
) (
	*core.RationalRange,
	error,
) {
	return t.setIndexRangeCommon(m, arg.Team, func(r core.RationalRange) (*core.RationalRange, error) {
		newRange := core.NewRationalRange(arg.Range)
		if newRange.Eq(r) {
			return nil, core.TeamIndexRangeError("index range already set")
		}
		if !r.Includes(newRange) {
			return nil, core.TeamIndexRangeError("old range does not include new range")
		}
		return &newRange, nil
	},
	)
}

func (t *TeamMinder) SetIndexRangeLow(
	m MetaContext,
	arg lcl.TeamIndexRangeSetLowArg,
) (
	*core.RationalRange,
	error,
) {
	return t.setIndexRangeCommon(m, arg.Team, func(r core.RationalRange) (*core.RationalRange, error) {
		low := core.Rational{Rational: arg.Low}
		cmp := low.Cmp(r.GetLow())
		if cmp == 0 {
			return nil, core.TeamIndexRangeError("index low already set")
		}
		if cmp < 0 {
			return nil, core.TeamIndexRangeError("index low must be greater than current high")
		}
		ret := r.SetLow(low)
		return &ret, nil
	},
	)
}

func (t *TeamMinder) setIndexRangeCommon(
	m MetaContext,
	arg proto.FQTeamParsed,
	f func(core.RationalRange) (*core.RationalRange, error),
) (
	*core.RationalRange,
	error,
) {

	fqt, err := t.ResolveAndReindex(m, arg)
	if err != nil {
		return nil, err
	}
	if fqt == nil {
		return nil, core.TeamNotFoundError{}
	}
	tok, cli, tr, err := t.adminTokenAndClient(m, *fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return nil, err
	}
	cfg, err := t.loadConfig(m, cli)
	if err != nil {
		return nil, err
	}

	tr.Lock()
	defer tr.Unlock()

	idx := tr.tw.IndexRange()

	newIdx, err := f(idx)
	if err != nil {
		return nil, err
	}

	editor := TeamEditor{
		cfg: cfg,
		tl:  tr.ldr,
		tw:  tr.tw,
		id:  tr.ldr.TeamID(),
		tok: tok,
		cp:  tr.member,
		cmd: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithTeamindexrange(newIdx.Export()),
		},
	}

	err = editor.RunMetadataOnly(m)
	if err != nil {
		return nil, err
	}
	return newIdx, nil
}

func (t *TeamMinder) LowerIndexRange(
	m MetaContext,
	fqt proto.FQTeamParsed,
) (
	*core.RationalRange,
	error,
) {
	return t.setIndexRangeCommon(m, fqt, func(r core.RationalRange) (*core.RationalRange, error) {
		if r.Eq(core.NewDefaultRange()) {
			ret := core.NewRationalRange(
				proto.RationalRange{
					Low:  r.Low,
					High: proto.Rational{Base: []byte{0x20}, Exp: 0},
				},
			)
			return &ret, nil
		}
		tmp, err := r.Rsh()
		if err != nil {
			return nil, err
		}
		return tmp, nil
	},
	)
}

func (t *TeamMinder) RaiseIndexRange(
	m MetaContext,
	fqt proto.FQTeamParsed,
) (
	*core.RationalRange,
	error,
) {
	return t.setIndexRangeCommon(m, fqt, func(r core.RationalRange) (*core.RationalRange, error) {
		if r.Eq(core.NewDefaultRange()) {
			ret := core.NewRationalRange(
				proto.RationalRange{
					Low:  proto.Rational{Base: []byte{0x80}, Exp: 0},
					High: r.High,
				},
			)
			return &ret, nil
		}
		tmp, err := r.Lsh()
		if err != nil {
			return nil, err
		}
		return tmp, nil
	},
	)
}
