// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	if errs := s.ErrCount(); errs > 0 {
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

// ErrCount is the number of RPCs in the scope that returned an error. Read by
// LogArgs and by any registered RpcScopeReporter, for which a scope's timings
// mean something different when some of its calls failed.
func (s *RpcStats) ErrCount() int {
	if s == nil {
		return 0
	}
	s.Lock()
	defer s.Unlock()
	return s.errs
}

// ── Scope reporting ──
//
// The scopes above report through zap, which is the right answer for the CLI
// and the server and no answer at all on mobile: go-foks writes its log inside
// the iOS app container, where no device capture has ever reached it. The
// gomobile bridge already carries its own diagnostic channel out to the app
// (foks-gomobile/slowcalls.go), and it cannot open these scopes itself --
// RpcStats propagates by context value, and the bridge talks to the agent over
// a loopback RPC, across which context values do not travel. So the scope has
// to hand its numbers to whoever is embedding this library.
//
// A hook rather than a method on GlobalContext: this is measurement, not
// behaviour, there is exactly one implementation per process, and a nil
// default keeps the CLI and server paths at one atomic load per scope.

// RpcScopeReporter receives one finished WithRpcStats scope. `wall` is the
// operation's total time; everything else is read off `st`, whose accessors
// are safe to call from here.
//
// Called on whichever goroutine ran the scope -- GetFile runs inside fan-outs
// -- so an implementation must be safe for concurrent use and must not block.
type RpcScopeReporter func(name string, wall time.Duration, st *RpcStats)

var rpcScopeReporter atomic.Pointer[RpcScopeReporter]

// SetRpcScopeReporter installs the process-wide reporter, replacing any
// previous one. Pass nil to uninstall. Safe to call at any time; a scope
// already running reports to whichever reporter is installed when it finishes.
func SetRpcScopeReporter(fn RpcScopeReporter) {
	if fn == nil {
		rpcScopeReporter.Store(nil)
		return
	}
	rpcScopeReporter.Store(&fn)
}

// ReportRpcScope hands a finished scope to the installed reporter. No-op when
// none is installed, which is the default and the case for every non-mobile
// build.
//
// A panicking reporter is contained and then UNINSTALLED. Observing must not be
// able to change what it observes: the reporter is supplied by the embedding
// binary, runs on whichever goroutine closed the scope, and GetFile closes one
// inside a fan-out -- so without this, a bug in a diagnostic could unwind
// through an unrelated sibling read and fail a real operation. Measurement is
// never worth that.
//
// Uninstalled rather than merely recovered because a reporter that panics once
// will panic every time, and paying a recover per scope forever to keep
// swallowing it is worse than losing the diagnostic. A silent instrument is a
// better failure than a client that breaks only when instrumented. This mirrors
// the same decision on the JS side of this bridge (setNativeCallObserver in
// apps/mobile/src/lib/nativeTrace.ts), which disarms its sink for the same
// reason.
func ReportRpcScope(name string, wall time.Duration, st *RpcStats) {
	fn := rpcScopeReporter.Load()
	if fn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			rpcScopeReporter.CompareAndSwap(fn, nil)
		}
	}()
	(*fn)(name, wall, st)
}
