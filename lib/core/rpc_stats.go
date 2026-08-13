// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RpcStats counts and times the outbound RPCs made inside one logical
// operation. Several client paths are chatty and strictly sequential -- a
// GetFile walks the path one segment per round trip, and a team explore loads
// each team twice -- so the first question about a slow operation is how many
// server round trips it made and how much of its wall time they account for.
// The residual (wall time minus RPC time) is local work: signature
// verification, unboxing, and SQLite writes. Against a server on localhost that
// residual is the whole story, which is not something the wall time alone can
// tell you.
//
// A nil *RpcStats is valid and drops every write, so Call2 needs no nil check
// and the collector only exists for the operations that opt in.
type RpcStats struct {
	sync.Mutex
	methods map[string]*RpcMethodStat
	calls   int
	errs    int
	dur     time.Duration

	// Scopes nest: an operation that opens one may call into a function that
	// opens its own. Each call is recorded into every enclosing scope, so an
	// inner scope measures just its own work and an outer one still sees the
	// whole operation. Without this the inner scope shadows the outer in the
	// context and the outer reports zero.
	parent *RpcStats

	// busy is wall time with at least one RPC in flight -- the union of the
	// call intervals, not their sum. Local time is wall minus this, which
	// holds whether or not the calls overlapped; subtracting the sum instead
	// only works when they ran strictly one after another, and silently
	// understates local time as soon as any two overlap.
	//
	// Maintained with an in-flight count rather than a list of intervals, so
	// it stays O(1): the clock starts when the count leaves zero and stops
	// when it returns. A scope reported while calls are still running does
	// not count that tail; the scopes here all report after their work is
	// joined.
	active    int
	busyStart time.Time
	busy      time.Duration
}

// RpcMethodStat is the per-method rollup returned by ByMethod.
type RpcMethodStat struct {
	Method string
	Calls  int
	Errs   int
	Dur    time.Duration
}

type rpcStatsKey struct{}

func NewRpcStats() *RpcStats {
	return &RpcStats{methods: make(map[string]*RpcMethodStat)}
}

// WithRpcStats returns a context carrying a fresh collector, and the collector
// itself. Every RPC issued through an RpcClient with a context descended from
// this one is counted. Calls made on a Background() context deliberately fall
// outside the scope -- those belong to the connection manager, not to the
// operation being measured.
func WithRpcStats(ctx context.Context) (context.Context, *RpcStats) {
	st := NewRpcStats()
	st.parent = RpcStatsFromContext(ctx)
	return context.WithValue(ctx, rpcStatsKey{}, st), st
}

// RpcStatsFromContext returns the collector in ctx, or nil if the caller did
// not opt in. The nil is usable as a receiver.
func RpcStatsFromContext(ctx context.Context) *RpcStats {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(rpcStatsKey{}).(*RpcStats)
	return st
}

// Begin marks an RPC as started, in this scope and every enclosing one. Pair
// it with End; without the pair, busy time (and so localMs) is not tracked.
func (s *RpcStats) Begin(now time.Time) {
	for ; s != nil; s = s.parent {
		s.beginSelf(now)
	}
}

func (s *RpcStats) beginSelf(now time.Time) {
	s.Lock()
	defer s.Unlock()
	if s.active == 0 {
		s.busyStart = now
	}
	s.active++
}

// End records a finished RPC in this scope and every enclosing one.
func (s *RpcStats) End(method string, start, end time.Time, err error) {
	for ; s != nil; s = s.parent {
		s.endSelf(method, start, end, err)
	}
}

func (s *RpcStats) endSelf(method string, start, end time.Time, err error) {
	s.Lock()
	defer s.Unlock()
	if s.active > 0 {
		s.active--
		if s.active == 0 && !s.busyStart.IsZero() {
			s.busy += end.Sub(s.busyStart)
			s.busyStart = time.Time{}
		}
	}
	s.calls++
	s.dur += end.Sub(start)
	if err != nil {
		s.errs++
	}
	m := s.methods[method]
	if m == nil {
		m = &RpcMethodStat{Method: method}
		s.methods[method] = m
	}
	m.Calls++
	m.Dur += end.Sub(start)
	if err != nil {
		m.Errs++
	}
}

func (s *RpcStats) Calls() int {
	if s == nil {
		return 0
	}
	s.Lock()
	defer s.Unlock()
	return s.calls
}

// Duration is the summed time of every RPC in the scope. Concurrent calls are
// counted once each, so this can exceed the operation's wall time; where it
// falls well short, the operation is bound by local work rather than the
// server.
func (s *RpcStats) Duration() time.Duration {
	if s == nil {
		return 0
	}
	s.Lock()
	defer s.Unlock()
	return s.dur
}

// Busy is the wall time during which at least one RPC was in flight. Unlike
// Duration it never double-counts overlapping calls, so wall minus Busy is the
// operation's local work.
func (s *RpcStats) Busy() time.Duration {
	if s == nil {
		return 0
	}
	s.Lock()
	defer s.Unlock()
	return s.busy
}

// ByMethod returns the per-method rollup, costliest first.
func (s *RpcStats) ByMethod() []RpcMethodStat {
	if s == nil {
		return nil
	}
	s.Lock()
	defer s.Unlock()
	ret := make([]RpcMethodStat, 0, len(s.methods))
	for _, v := range s.methods {
		ret = append(ret, *v)
	}
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].Dur != ret[j].Dur {
			return ret[i].Dur > ret[j].Dur
		}
		return ret[i].Method < ret[j].Method
	})
	return ret
}

// LogArgs renders the scope as key/value pairs for a sugared zap logger. wall
// is the operation's total time, so a reader can take the difference against
// rpcMs without arithmetic. topN caps the per-method breakdown, which is
// collapsed into one field to keep this to a single log line on mobile.
func (s *RpcStats) LogArgs(wall time.Duration, topN int) []any {
	rpc, busy := s.Duration(), s.Busy()

	// localMs is wall minus the time any RPC was in flight, so it stays the
	// time spent on local crypto and SQLite whether or not the calls
	// overlapped. Clamped because wall and the call timestamps can come from
	// different reads of the clock.
	local := wall - busy
	if local < 0 {
		local = 0
	}
	ret := []any{
		"wallMs", wall.Milliseconds(),
		"rpcs", s.Calls(),
		"rpcMs", rpc.Milliseconds(),
		"localMs", local.Milliseconds(),
	}
	// Summed call time above the wall time they occupy is the average number
	// of calls in flight -- only worth printing when they actually overlapped.
	if busy > 0 && rpc > busy {
		ret = append(ret, "rpcOverlap",
			fmt.Sprintf("%.1fx", float64(rpc)/float64(busy)))
	}
	if errs := s.errCount(); errs > 0 {
		ret = append(ret, "rpcErrs", errs)
	}
	byMethod := s.ByMethod()
	if len(byMethod) == 0 {
		return ret
	}
	if topN > 0 && len(byMethod) > topN {
		byMethod = byMethod[:topN]
	}
	var parts []string
	for _, m := range byMethod {
		parts = append(parts, fmt.Sprintf("%s=%dx%dms", m.Method, m.Calls, m.Dur.Milliseconds()))
	}
	return append(ret, "top", strings.Join(parts, " "))
}

func (s *RpcStats) errCount() int {
	if s == nil {
		return 0
	}
	s.Lock()
	defer s.Unlock()
	return s.errs
}
