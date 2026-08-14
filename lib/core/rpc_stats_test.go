// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// t0 is an arbitrary fixed instant; these tests drive Begin/End with explicit
// timestamps so overlap is expressed rather than inferred from a real clock.
var t0 = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func rec(s *RpcStats, method string, start, end time.Time) {
	recErr(s, method, start, end, nil)
}

func recErr(s *RpcStats, method string, start, end time.Time, err error) {
	s.Begin(start)
	s.End(method, start, end, err)
}

func TestRpcStatsNilIsInert(t *testing.T) {
	var st *RpcStats
	require.NotPanics(t, func() {
		st.Begin(t0)
		st.End("Foo.bar", t0, t0.Add(time.Second), nil)
	})
	require.Equal(t, 0, st.Calls())
	require.Equal(t, time.Duration(0), st.Duration())
	require.Nil(t, st.ByMethod())
	require.Equal(t, time.Duration(0), st.Busy())

	// The nil case is what Call2 hits on every RPC outside a scope, so it has
	// to render too.
	require.NotEmpty(t, st.LogArgs(time.Second, 3))
}

func TestRpcStatsScoping(t *testing.T) {
	ctx, st := WithRpcStats(context.Background())
	require.Same(t, st, RpcStatsFromContext(ctx))

	// A scope is not visible from an unrelated context, which is what keeps
	// connection-manager traffic on Background() out of an operation's tally.
	require.Nil(t, RpcStatsFromContext(context.Background()))

	// Call2 is reached from enough places that the lookup guards against a nil
	// context rather than trusting every caller; this covers that guard.
	//nolint:staticcheck // SA1012: passing nil is the case under test
	require.Nil(t, RpcStatsFromContext(nil))

	// Descendants stay in scope.
	sub, cancel := context.WithCancel(ctx)
	defer cancel()
	require.Same(t, st, RpcStatsFromContext(sub))
}

func TestRpcStatsNesting(t *testing.T) {
	outerCtx, outer := WithRpcStats(context.Background())
	rec(outer, "Before.inner", t0, t0.Add(10*time.Millisecond))

	innerCtx, inner := WithRpcStats(outerCtx)
	rec(RpcStatsFromContext(innerCtx), "During.inner",
		t0.Add(10*time.Millisecond), t0.Add(30*time.Millisecond))

	// The inner scope measures only its own work...
	require.Equal(t, 1, inner.Calls())
	require.Equal(t, 20*time.Millisecond, inner.Duration())

	// ...while the outer still accounts for the whole operation. A caller
	// wrapping a function that opens its own scope would otherwise see zero.
	require.Equal(t, 2, outer.Calls())
	require.Equal(t, 30*time.Millisecond, outer.Duration())

	// Work after the inner scope closes lands in the outer one only.
	rec(RpcStatsFromContext(outerCtx), "After.inner",
		t0.Add(30*time.Millisecond), t0.Add(35*time.Millisecond))
	require.Equal(t, 3, outer.Calls())
	require.Equal(t, 1, inner.Calls())
}

func TestRpcStatsAccounting(t *testing.T) {
	_, st := WithRpcStats(context.Background())
	rec(st, "Team.loadTeamChain", t0, t0.Add(30*time.Millisecond))
	rec(st, "Team.loadTeamChain", t0.Add(30*time.Millisecond), t0.Add(100*time.Millisecond))
	recErr(st, "Merkle.lookup", t0.Add(100*time.Millisecond), t0.Add(110*time.Millisecond),
		errors.New("boom"))

	require.Equal(t, 3, st.Calls())
	require.Equal(t, 110*time.Millisecond, st.Duration())
	require.Equal(t, 1, st.ErrCount())

	// Costliest method first, so a truncated breakdown keeps what matters.
	byMethod := st.ByMethod()
	require.Len(t, byMethod, 2)
	require.Equal(t, "Team.loadTeamChain", byMethod[0].Method)
	require.Equal(t, 2, byMethod[0].Calls)
	require.Equal(t, 100*time.Millisecond, byMethod[0].Dur)
	require.Equal(t, 1, byMethod[1].Errs)
}

func TestRpcStatsLogArgs(t *testing.T) {
	_, st := WithRpcStats(context.Background())
	rec(st, "Team.loadTeamChain", t0, t0.Add(100*time.Millisecond))

	kv := make(map[string]any)
	args := st.LogArgs(500*time.Millisecond, 6)
	require.Zero(t, len(args)%2)
	for i := 0; i < len(args); i += 2 {
		kv[args[i].(string)] = args[i+1]
	}

	// localMs is the point of the whole exercise: wall time the RPCs do not
	// account for is local crypto and SQLite.
	require.EqualValues(t, 500, kv["wallMs"])
	require.EqualValues(t, 100, kv["rpcMs"])
	require.EqualValues(t, 400, kv["localMs"])
	require.EqualValues(t, 1, kv["rpcs"])
	require.Equal(t, "Team.loadTeamChain=1x100ms", kv["top"])
	require.NotContains(t, kv, "rpcErrs")
}

func TestRpcStatsLogArgsConcurrent(t *testing.T) {
	// Summed RPC time exceeding the wall clock is the normal case for a scope
	// that fans out; localMs would be negative and is dropped in favour of the
	// overlap factor.
	_, st := WithRpcStats(context.Background())
	// Eight calls all in flight over the same half second.
	for i := 0; i < 8; i++ {
		st.Begin(t0)
	}
	for i := 0; i < 8; i++ {
		st.End("Team.loadTeamChain", t0, t0.Add(500*time.Millisecond), nil)
	}

	kv := make(map[string]any)
	args := st.LogArgs(1000*time.Millisecond, 6)
	for i := 0; i < len(args); i += 2 {
		kv[args[i].(string)] = args[i+1]
	}
	require.EqualValues(t, 4000, kv["rpcMs"])
	// The calls occupied 500ms of wall time between them, so half the second
	// was local -- the summed 4000ms says nothing about that.
	require.EqualValues(t, 500, kv["localMs"])
	require.Equal(t, "8.0x", kv["rpcOverlap"])
}

func TestRpcStatsLogArgsTruncates(t *testing.T) {
	_, st := WithRpcStats(context.Background())
	at := t0
	for i, meth := range []string{"a", "b", "c", "d"} {
		next := at.Add(time.Duration(i+1) * time.Millisecond)
		rec(st, meth, at, next)
		at = next
	}
	kv := make(map[string]any)
	args := st.LogArgs(time.Second, 2)
	for i := 0; i < len(args); i += 2 {
		kv[args[i].(string)] = args[i+1]
	}
	require.Equal(t, "d=1x4ms c=1x3ms", kv["top"])
}

func TestRpcStatsLocalTimeWithOverlapInsideWall(t *testing.T) {
	// The case that made summed-vs-wall the wrong test: calls that overlap,
	// but with enough local work around them that the sum still fits inside
	// the wall clock. Taking wall minus the sum looks reasonable here and is
	// wrong -- the two calls only occupied 100ms between them, so 900ms of the
	// second was local, not 800ms.
	_, st := WithRpcStats(context.Background())
	st.Begin(t0)
	st.Begin(t0)
	st.End("A.one", t0, t0.Add(100*time.Millisecond), nil)
	st.End("A.two", t0, t0.Add(100*time.Millisecond), nil)

	require.Equal(t, 200*time.Millisecond, st.Duration()) // summed
	require.Equal(t, 100*time.Millisecond, st.Busy())     // occupied

	kv := make(map[string]any)
	args := st.LogArgs(time.Second, 6)
	for i := 0; i < len(args); i += 2 {
		kv[args[i].(string)] = args[i+1]
	}
	require.EqualValues(t, 900, kv["localMs"])
	require.Equal(t, "2.0x", kv["rpcOverlap"])
}

func TestRpcStatsSequentialCallsHaveNoOverlap(t *testing.T) {
	_, st := WithRpcStats(context.Background())
	rec(st, "A.one", t0, t0.Add(100*time.Millisecond))
	rec(st, "A.two", t0.Add(200*time.Millisecond), t0.Add(300*time.Millisecond))

	require.Equal(t, st.Duration(), st.Busy())

	kv := make(map[string]any)
	args := st.LogArgs(time.Second, 6)
	for i := 0; i < len(args); i += 2 {
		kv[args[i].(string)] = args[i+1]
	}
	require.EqualValues(t, 800, kv["localMs"])
	require.NotContains(t, kv, "rpcOverlap")
}

func TestReportRpcScopeNoReporter(t *testing.T) {
	SetRpcScopeReporter(nil)
	_, st := WithRpcStats(context.Background())
	rec(st, "M", t0, t0.Add(time.Second))
	// The default: no reporter installed, so a scope closing is inert.
	require.NotPanics(t, func() { ReportRpcScope("Op", time.Second, st) })
}

func TestReportRpcScopeDelivers(t *testing.T) {
	t.Cleanup(func() { SetRpcScopeReporter(nil) })

	type got struct {
		name  string
		wall  time.Duration
		calls int
		busy  time.Duration
	}
	var seen []got
	SetRpcScopeReporter(func(name string, wall time.Duration, st *RpcStats) {
		seen = append(seen, got{name, wall, st.Calls(), st.Busy()})
	})

	_, st := WithRpcStats(context.Background())
	rec(st, "A", t0, t0.Add(100*time.Millisecond))
	rec(st, "B", t0.Add(200*time.Millisecond), t0.Add(500*time.Millisecond))
	ReportRpcScope("Op", 900*time.Millisecond, st)

	require.Len(t, seen, 1)
	require.Equal(t, "Op", seen[0].name)
	require.Equal(t, 900*time.Millisecond, seen[0].wall)
	require.Equal(t, 2, seen[0].calls)
	// Busy is the union of the two non-overlapping intervals, so localMs the
	// bridge derives (wall - busy) stays honest: 900 - 400 = 500ms local.
	require.Equal(t, 400*time.Millisecond, seen[0].busy)
}

func TestSetRpcScopeReporterReplacesAndClears(t *testing.T) {
	t.Cleanup(func() { SetRpcScopeReporter(nil) })

	var first, second int
	SetRpcScopeReporter(func(string, time.Duration, *RpcStats) { first++ })
	ReportRpcScope("Op", 0, nil)
	SetRpcScopeReporter(func(string, time.Duration, *RpcStats) { second++ })
	ReportRpcScope("Op", 0, nil)
	SetRpcScopeReporter(nil)
	ReportRpcScope("Op", 0, nil)

	require.Equal(t, 1, first)
	require.Equal(t, 1, second)
}

// The reporter is name-keyed, so a newly-instrumented operation needs no
// change anywhere else — this pins that, since the KVMinder.List scope was
// added precisely because the instrument could not see the client's largest
// consumer.
func TestReportRpcScopeCarriesTheOperationName(t *testing.T) {
	t.Cleanup(func() { SetRpcScopeReporter(nil) })

	seen := map[string]int{}
	SetRpcScopeReporter(func(name string, _ time.Duration, st *RpcStats) {
		seen[name] += st.Calls()
	})

	for _, name := range []string{"KVMinder.GetFile", "KVMinder.List", "TeamMinder.ListMemberships"} {
		_, st := WithRpcStats(context.Background())
		rec(st, "M", t0, t0.Add(10*time.Millisecond))
		rec(st, "M", t0.Add(10*time.Millisecond), t0.Add(20*time.Millisecond))
		ReportRpcScope(name, 20*time.Millisecond, st)
	}

	require.Equal(t, map[string]int{
		"KVMinder.GetFile":           2,
		"KVMinder.List":              2,
		"TeamMinder.ListMemberships": 2,
	}, seen)
}
