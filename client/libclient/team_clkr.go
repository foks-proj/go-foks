// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type CLKROpts struct {

	// To be called between every team operation
	WaitFn func(ctx context.Context) error

	// If > 0, and if WaitFn is not set, the time to wait.
	WaitTimeout time.Duration

	// After editting the team, we load it right away to check if we broke anything.
	// In test, we need to wait for a poke.
	WaitForMerkleRefresh func(ctx context.Context) error
}

// CLKR stands for "Cascading Lazy Key Rotation". In the background, team clients iterate
// over all teams, over all members of those teams, to ensure each member's more up-to-date
// PUK or PTK is reflected in the team, and if not, rotates the team's key.
type CLKR struct {
	// input fields
	tm   *TeamMinder
	opts CLKROpts

	// collection of teams that have been rekeyed
	rekeys []proto.FQTeam
	estate *ExploreState
	order  []proto.FQTeam
}

func NewCLKR(
	tm *TeamMinder,
	opts CLKROpts,
) *CLKR {
	return &CLKR{
		tm:   tm,
		opts: opts,
	}
}

func (c *CLKR) explore(m MetaContext) error {
	var err error
	c.estate, err = c.tm.Explore(m)
	if err != nil {
		return err
	}
	return nil
}

func (c *CLKR) loadOrder(m MetaContext) error {
	var err error
	c.order, err = c.estate.SortedTeams()
	if err != nil {
		return err
	}
	return nil
}

func (c *CLKR) Rekeys() []proto.FQTeam {
	return c.rekeys
}

func (c *CLKR) visitAllTeams(m MetaContext) error {
	first := true

	for _, fqteam := range c.order {

		if first {
			first = false
		} else {
			m.Infow("clkr", "delay", "start")
			err := c.delay(m)
			if err != nil {
				return err
			}
			m.Infow("clkr", "delay", "end")
		}

		single := CLKROneTeam{
			parent: c,
			fqt:    fqteam,
		}
		m := m.WithLogTag("clkrOne")
		m.Infow("clkr", "team", fqteam, "action", "start")
		err := single.run(m)
		m.Infow("clkr", "team", fqteam, "action", "end", "err", err)
		if err != nil {
			return err
		}

		// Keep track of all the rekeys we did
		if single.rekey {
			c.rekeys = append(c.rekeys, fqteam)
		}
	}
	return nil
}

func (c *CLKR) delay(m MetaContext) error {

	if c.opts.WaitFn != nil {
		return c.opts.WaitFn(m.Ctx())
	}

	if c.opts.WaitTimeout > 0 {
		m.Infow("clkr", "action", "delay", "time", c.opts.WaitTimeout)
		select {
		case <-time.After(c.opts.WaitTimeout):
			m.Infow("clkr", "action ", "-delay")
			return nil
		case <-m.Ctx().Done():
			return m.Ctx().Err()
		}
	}

	return nil
}

func (c *CLKR) Run(m MetaContext) error {

	c.tm.clkrMu.Lock()
	defer c.tm.clkrMu.Unlock()

	m = m.WithLogTag("clkr")

	err := c.explore(m)
	if err != nil {
		return err
	}

	err = c.loadOrder(m)
	if err != nil {
		return err
	}

	err = c.visitAllTeams(m)
	if err != nil {
		return err
	}

	return nil
}

type CLKROneTeam struct {
	// input fields
	parent *CLKR
	fqt    proto.FQTeam

	// internal state fields that are updated as we go
	changes []proto.MemberRole
	dstRole *proto.Role
	roster  *team.Roster
	tw      *TeamWrapper
	hepks   *core.HEPKSet
	ldr     *TeamLoader
	rekey   bool
	member  CryptoPartier
}

func (c *CLKROneTeam) run(
	m MetaContext,
) error {

	m = m.WithLogTag("clkrOne")

	err := c.loadTeam(m)
	if err != nil {
		return err
	}

	doIt, err := c.checkAdmin(m)
	if err != nil {
		return err
	}

	if !doIt {
		m.Infow("clkr", "team", c.tw.FQTeam(), "role", *c.dstRole,
			"why", "not admin or above", "action", "skip")
		return nil
	}

	err = c.checkMembers(m)
	if err != nil {
		return err
	}

	if len(c.changes) == 0 {
		m.Infow("clkr", "team", c.tw.FQTeam(),
			"why", "no changes", "action", "skip")
		return nil
	}

	err = c.runEdit(m)
	if err != nil {
		return err
	}
	err = c.refreshTeam(m)
	if err != nil {
		return err
	}
	c.rekey = true
	return nil
}

func (c *CLKROneTeam) runEdit(m MetaContext) error {

	m.Infow("clkr", "action", "edit")

	fqt := c.tw.FQTeam()

	tok, cli, tr, err := c.parent.tm.adminTokenAndClient(m, fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return err
	}

	cfg, err := c.parent.tm.loadConfig(m, cli)
	if err != nil {
		return err
	}

	tr.Lock()
	defer tr.Unlock()

	mem := c.member

	mem, err = mem.Refresh(m, c.parent.tm)
	if err != nil {
		return err
	}

	editor := TeamEditor{
		cfg:     cfg,
		tl:      c.ldr,
		tw:      c.tw,
		id:      fqt.Team,
		tok:     tok,
		pre:     c.roster,
		changes: c.changes,
		cp:      mem,
		hepks:   c.hepks,
	}
	err = editor.Run(m)
	if err != nil {
		return err
	}

	return nil
}

func (c *CLKROneTeam) refreshTeam(m MetaContext) error {

	fqt := c.tw.FQTeam()

	if wait := c.parent.opts.WaitForMerkleRefresh; wait != nil {
		m.Infow("refreshTeam", "action", "wait")
		err := wait(m.Ctx())
		if err != nil {
			return err
		}
	}

	_, err := c.parent.tm.LoadTeamWithFQTeam(m, fqt, LoadTeamOpts{Refresh: true})
	m.Warnw("refreshTeam", "err", err)
	return err
}

func (c *CLKROneTeam) loadTeam(m MetaContext) error {
	tr, err := c.parent.tm.LoadTeamWithFQTeam(m, c.fqt, LoadTeamOpts{Refresh: true, LoadMembers: true})
	if err != nil {
		return err
	}
	ldr := tr.ldr
	tw := tr.tw

	tmem, err := tw.GetMember(ldr.Arg.As, ldr.Arg.SrcRole)
	if err != nil {
		return err
	}

	if tmem == nil {
		return core.TeamExploreError("load as party not found in team")
	}

	c.member = tr.member
	c.dstRole = &tmem.Mr.DstRole
	c.roster = ldr.rosterPost
	c.tw = tw
	c.ldr = ldr
	return nil
}

func (c *CLKROneTeam) checkAdmin(m MetaContext) (bool, error) {
	ok, err := c.dstRole.IsAdminOrAbove()
	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil
	}
	return true, nil
}

func (c *CLKROneTeam) checkMembers(m MetaContext) error {
	for feq, lst := range c.tw.rosterDetails {
		for _, deet := range lst {
			if deet.err != nil {
				m.Warnw("clkr",
					"team", c.tw.FQTeam(), "member", feq.Unfix(),
					"role", deet.srcRole, "err", deet.err, "action", "checkMembers")
				return deet.err
			}
			err := c.doOneMember(m, feq, deet)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CLKROneTeam) doOneMember(
	m MetaContext,
	fqe proto.FQEntityFixed,
	deet *rosterPackage,
) error {

	srcRk, err := core.ImportRole(deet.srcRole)
	if err != nil {
		return err
	}

	var gen proto.Generation
	var tmk *proto.TeamMemberKeys
	var hepk *proto.HEPK
	var pw PartyWrapper
	switch {
	case deet.uw != nil:
		pukGen, err := deet.uw.LatestPUKGenForRole(deet.srcRole)
		if err != nil {
			return err
		}
		gen = pukGen
		pw = deet.uw
	case deet.tw != nil:
		sk := deet.tw.ptks.CurrentPublicKeyAtRole(*srcRk)
		if sk == nil {
			return core.KeyNotFoundError{Which: "PTK"}
		}
		gen = sk.Sk.Gen
		pw = deet.tw
	default:
		return core.InternalError("neither uw nor tw for a team member in CLKR")
	}

	if deet.info.Gen >= gen {
		m.Infow("doOneMember", "team", c.tw.FQTeam(), "member", fqe.Unfix(), "role", deet.srcRole, "why", "up-to-date", "action", "skip")
		return nil
	}

	m.Infow("doOneMember", "team", c.tw.FQTeam(), "member", fqe.Unfix(), "role", deet.srcRole, "action", "fix",
		"oldGen", deet.info.Gen, "newGen", gen)

	tmk, hepk, err = pw.TeamMemberKeys(*srcRk)
	if err != nil {
		return err
	}

	// We previoulsy had a bug in TeamMemberKeys(), which output a stale (old) key suite,
	// which triggered this error. But keep this assertion in the case of any future bug.
	if tmk.Gen != gen {
		return core.InternalError(
			fmt.Sprintf("tmk.Gen (%d) != gen (%d)", tmk.Gen, gen))
	}

	m.Infow("doOneMember", "tmk", tmk)

	tmr := proto.MemberRole{
		DstRole: *c.dstRole,
		Member: proto.Member{
			Id:      fqe.Unfix().AtHost(c.tw.prot.Fqt.Host),
			SrcRole: deet.srcRole,
			Keys:    proto.NewMemberKeysWithTeam(*tmk),
		},
	}

	c.changes = append(c.changes, tmr)
	if c.hepks == nil {
		c.hepks = core.NewHEPKSet()
	}
	err = c.hepks.Add(*hepk)
	if err != nil {
		return err
	}

	return nil
}
