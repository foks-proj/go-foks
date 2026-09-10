// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestTeamSnapshotVerifiedAt: the snapshot records when it was last confirmed
// against the merkle root, so "verified as of T" is a statement a caller can
// actually check. The second half is the one worth pinning: a reload that
// plays no new links is still a fresh verification, and must re-stamp -- if it
// did not, a quiet team would age as though nobody had checked it, and any
// staleness horizon built on this field would punish teams for being idle.
func TestTeamSnapshotVerifiedAt(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	mcli := tew.NewClientMetaContextWithEracer(t, bluey)
	au := mcli.G().ActiveUser()
	puks, err := au.RefreshPUKs(mcli)
	require.NoError(t, err)

	tm := libclient.NewTeamMinder(au)
	nm := proto.NameUtf8(fmt.Sprintf("vat%d", time.Now().UnixNano()%1000000))
	_, err = tm.Create(mcli, nm)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	host, err := au.HostID().StringErr()
	require.NoError(t, err)
	parsed, err := core.ParseFQTeam(proto.FQTeamString(string(nm) + "@" + host))
	require.NoError(t, err)

	before := mcli.G().Now()
	tw, err := tm.LoadTeam(mcli, team.WrapNamed(*parsed), libclient.LoadTeamOpts{Refresh: true})
	require.NoError(t, err)
	first := tw.VerifiedAt()
	require.False(t, first.IsZero(), "an online load must stamp the snapshot")
	require.False(t, first.Import().Before(before.Add(-time.Minute)),
		"stamp should date this load, not some earlier one")

	// Nothing has changed on the chain, so this reload plays no links and takes
	// the early-return path in saveState -- which must still re-stamp.
	time.Sleep(10 * time.Millisecond)
	tw2, err := tm.LoadTeam(mcli, team.WrapNamed(*parsed), libclient.LoadTeamOpts{Refresh: true})
	require.NoError(t, err)
	require.True(t, tw2.VerifiedAt().Import().After(first.Import()),
		"a reload that plays no new links is still a fresh verification")
	second := tw2.VerifiedAt()

	// The stamp must survive to disk, and an offline load must not touch it --
	// that is the whole basis for reading it as "how stale is this view". A
	// fresh loader means no preload, so this reads the persisted row rather
	// than the record the online loads left in memory.
	arg := libclient.LoadTeamArg{
		Team:    tw2.Prot().Fqt,
		As:      au.FQU().FQParty(),
		SrcRole: team.UserSrcRole,
		Keys:    puks,
	}
	cached, err := libclient.LoadTeamFromCache(mcli, au, arg)
	require.NoError(t, err)
	require.True(t, cached.VerifiedAt().Import().Equal(second.Import()),
		"the stamp must persist, and a cache load must date the verification, not the read")
}

// TestOfflineNameResolutionRejectsStaleRow: offline, the persisted name index
// is the only thing between a typed name and the PTKs a message gets sealed
// with. Rows are written through and never deleted, so one can outlive what
// made it -- harmless today, since teams cannot be renamed and dead names
// cannot be reused, but both are documented as changeable. A row the team's
// own verified snapshot contradicts must not resolve, while the name that
// snapshot does claim must keep resolving.
//
// The two contexts share a home directory on purpose: the second is a cold
// start over the first one's database, which is the only way to reach the
// persisted-index path. A context with warm in-memory state explores
// successfully even with the network dead, and never consults the index.
func TestOfflineNameResolutionRejectsStaleRow(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	home := t.TempDir()
	warmM := tew.NewClientMetaContextAtHome(t, bluey, home)
	au := warmM.G().ActiveUser()
	_, err := au.RefreshPUKs(warmM)
	require.NoError(t, err)

	host, err := au.HostID().StringErr()
	require.NoError(t, err)

	warm := libclient.NewTeamMinder(au)
	nm := proto.NameUtf8(fmt.Sprintf("stale%d", time.Now().UnixNano()%1000000))
	_, err = warm.Create(warmM, nm)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	parsed, err := core.ParseFQTeam(proto.FQTeamString(string(nm) + "@" + host))
	require.NoError(t, err)
	realFQT, err := warm.ResolveAndReindex(warmM, team.WrapNamed(*parsed), nil)
	require.NoError(t, err)
	require.NotNil(t, realFQT)
	// Load as well as resolve: the snapshot the guard corroborates against is
	// written by a load, and the offline path needs it too.
	_, err = warm.LoadTeam(warmM, team.WrapNamed(*parsed), libclient.LoadTeamOpts{})
	require.NoError(t, err)

	// Plant a row for a name this team does not bear -- what a released and
	// re-taken name would leave behind.
	scope := au.FQU()
	planted := *realFQT
	require.NoError(t, warmM.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scope,
		Typ:   lcl.DataType_TeamNameLookup,
		Key:   "n:notthisteam@" + host,
		Val:   &planted,
	}))

	// Cold start over the same database, with no network at all.
	coldM := tew.NewClientMetaContextAtHome(t, bluey, home)
	coldM.G().SetNetworkConditioner(core.CatastrophicNetworkConditions{On: true})
	defer coldM.G().SetNetworkConditioner(nil)
	offline := libclient.NewTeamMinder(coldM.G().ActiveUser())

	// Control: the name the snapshot claims still resolves, so a refusal below
	// is the guard firing rather than offline resolution being broken.
	got, err := offline.ResolveAndReindex(coldM, team.WrapNamed(*parsed), nil)
	require.NoError(t, err)
	require.True(t, got.Team.Eq(realFQT.Team))

	bogus, err := core.ParseFQTeam(proto.FQTeamString("notthisteam@" + host))
	require.NoError(t, err)
	_, err = offline.ResolveAndReindex(coldM, team.WrapNamed(*bogus), nil)
	require.Error(t, err, "a name the snapshot contradicts must not resolve offline")
}

// TestOfflineTeamMutationsFail: the offline path is read-only, and that is what
// keeps the no-unverified-writes rule true -- a mutation that could be queued
// offline would be a link committed against server state nobody verified. So
// every mutation must fail with a connect-class error rather than being held,
// and must not turn up applied once the network returns.
//
// Asserting IsTransportError rather than just "an error" is what keeps this
// honest: a mutation that failed for some unrelated reason would pass a bare
// error check while proving nothing about the offline boundary.
func TestOfflineTeamMutationsFail(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	other := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	home := t.TempDir()
	warmM := tew.NewClientMetaContextAtHome(t, bluey, home)
	au := warmM.G().ActiveUser()
	_, err := au.RefreshPUKs(warmM)
	require.NoError(t, err)
	host, err := au.HostID().StringErr()
	require.NoError(t, err)

	warm := libclient.NewTeamMinder(au)
	nm := randomTeamname(t)
	_, err = warm.Create(warmM, nm)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	parsed, err := core.ParseFQTeam(proto.FQTeamString(string(nm) + "@" + host))
	require.NoError(t, err)
	_, err = warm.LoadTeam(warmM, team.WrapNamed(*parsed), libclient.LoadTeamOpts{})
	require.NoError(t, err)

	// Cold start over the same database, with no network.
	coldM := tew.NewClientMetaContextAtHome(t, bluey, home)
	coldM.G().SetNetworkConditioner(core.CatastrophicNetworkConditions{On: true})
	defer coldM.G().SetNetworkConditioner(nil)
	offline := libclient.NewTeamMinder(coldM.G().ActiveUser())

	// Creating a team offline: refused, not held.
	blocked := randomTeamname(t)
	_, err = offline.Create(coldM, blocked)
	require.Error(t, err)
	require.True(t, core.IsTransportError(err),
		"team creation offline must fail on transport, got %v", err)

	// Editing membership offline: same.
	memb, err := core.ParseFQPartyAndRole(
		lcl.FQPartyAndRoleString(string(other.name) + "@" + host + "/m/0"))
	require.NoError(t, err)
	err = offline.Add(coldM, lcl.TeamAddArg{
		Team:    *parsed,
		Members: []lcl.FQPartyParsedAndRole{*memb},
	})
	require.Error(t, err)
	require.True(t, core.IsTransportError(err),
		"membership edit offline must fail on transport, got %v", err)

	// Back online, nothing the offline leg attempted may have landed.
	coldM.G().SetNetworkConditioner(nil)
	back := libclient.NewTeamMinder(coldM.G().ActiveUser())
	blockedParsed, err := core.ParseFQTeam(proto.FQTeamString(string(blocked) + "@" + host))
	require.NoError(t, err)
	_, err = back.ResolveAndReindex(coldM, team.WrapNamed(*blockedParsed), nil)
	require.Error(t, err, "a team 'created' offline must not appear once the network returns")
}

// TestOfflineNoSnapshotPropagatesTransportError: when there is nothing
// verified to serve, the transport error is the truthful answer and must be
// the one that comes back. The failure this guards against is quiet
// fabrication -- an offline load that returns success with nothing behind it,
// or a semantic "not found" for a team that exists and merely cannot be
// checked. Either would let a staleness bug pass as a correct answer, which is
// strictly worse than failing.
func TestOfflineNoSnapshotPropagatesTransportError(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	home := t.TempDir()
	warmM := tew.NewClientMetaContextAtHome(t, bluey, home)
	au := warmM.G().ActiveUser()
	_, err := au.RefreshPUKs(warmM)
	require.NoError(t, err)
	host, err := au.HostID().StringErr()
	require.NoError(t, err)

	// Warm enough that the user itself comes up offline; no team is loaded.
	warm := libclient.NewTeamMinder(au)
	nm := randomTeamname(t)
	_, err = warm.Create(warmM, nm)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)
	realParsed, err := core.ParseFQTeam(proto.FQTeamString(string(nm) + "@" + host))
	require.NoError(t, err)
	realFQT, err := warm.ResolveAndReindex(warmM, team.WrapNamed(*realParsed), nil)
	require.NoError(t, err)

	// A name row pointing at a team with no snapshot: what a client that
	// resolved a team but never completed a load of it would hold.
	scope := au.FQU()
	ghost := *realFQT
	ghost.Team[0] ^= 0xff // a team id nothing ever loaded
	require.NoError(t, warmM.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scope,
		Typ:   lcl.DataType_TeamNameLookup,
		Key:   "n:ghostteam@" + host,
		Val:   &ghost,
	}))

	coldM := tew.NewClientMetaContextAtHome(t, bluey, home)
	coldM.G().SetNetworkConditioner(core.CatastrophicNetworkConditions{On: true})
	defer coldM.G().SetNetworkConditioner(nil)
	offline := libclient.NewTeamMinder(coldM.G().ActiveUser())

	// A name nothing ever persisted: the transport error comes back, not a
	// fabricated "not found" -- offline, the client cannot honestly say the
	// team does not exist, only that it cannot ask.
	unknown, err := core.ParseFQTeam(proto.FQTeamString("neverheardofit@" + host))
	require.NoError(t, err)
	_, err = offline.ResolveAndReindex(coldM, team.WrapNamed(*unknown), nil)
	require.Error(t, err)
	require.True(t, core.IsTransportError(err),
		"an unresolvable name offline must surface the outage, got %v", err)

	// A resolvable name whose team has no snapshot: resolution proceeds, and
	// the load then propagates the transport error rather than succeeding
	// empty.
	ghostParsed, err := core.ParseFQTeam(proto.FQTeamString("ghostteam@" + host))
	require.NoError(t, err)
	_, err = offline.LoadTeam(coldM, team.WrapNamed(*ghostParsed), libclient.LoadTeamOpts{Refresh: true})
	require.Error(t, err)
	require.True(t, core.IsTransportError(err),
		"a snapshot-less team offline must surface the outage, got %v", err)
}

// TestGuardDeclineIsLogged: when the name guard cannot corroborate a row it
// allows the resolution -- failing open is safe, since with no snapshot there
// are no keys to seal with -- but it must say so. A guard that has quietly
// stopped guarding looks exactly like one with nothing to complain about, and
// the log line is the only thing separating those two states in the field.
// This asserts the line actually fires, because a claim that something "is
// logged" that no test can see is a claim that rots.
func TestGuardDeclineIsLogged(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	home := t.TempDir()
	warmM := tew.NewClientMetaContextAtHome(t, bluey, home)
	au := warmM.G().ActiveUser()
	_, err := au.RefreshPUKs(warmM)
	require.NoError(t, err)
	host, err := au.HostID().StringErr()
	require.NoError(t, err)

	warm := libclient.NewTeamMinder(au)
	nm := randomTeamname(t)
	_, err = warm.Create(warmM, nm)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)
	realParsed, err := core.ParseFQTeam(proto.FQTeamString(string(nm) + "@" + host))
	require.NoError(t, err)
	realFQT, err := warm.ResolveAndReindex(warmM, team.WrapNamed(*realParsed), nil)
	require.NoError(t, err)

	// A row whose team has no snapshot: corroboration is impossible.
	scope := au.FQU()
	ghost := *realFQT
	ghost.Team[0] ^= 0xff
	require.NoError(t, warmM.DbPut(libclient.DbTypeSoft, libclient.PutArg{
		Scope: &scope,
		Typ:   lcl.DataType_TeamNameLookup,
		Key:   "n:ghostteam@" + host,
		Val:   &ghost,
	}))

	coldM := tew.NewClientMetaContextAtHome(t, bluey, home)
	coldM.G().SetNetworkConditioner(core.CatastrophicNetworkConditions{On: true})
	defer coldM.G().SetNetworkConditioner(nil)
	obsCore, logs := observer.New(zapcore.WarnLevel)
	coldM.G().SetLog(zap.New(obsCore))
	offline := libclient.NewTeamMinder(coldM.G().ActiveUser())

	ghostParsed, err := core.ParseFQTeam(proto.FQTeamString("ghostteam@" + host))
	require.NoError(t, err)
	got, err := offline.ResolveAndReindex(coldM, team.WrapNamed(*ghostParsed), nil)

	// Both halves of R13: the resolution proceeds...
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.Team.Eq(ghost.Team))

	// ...and the decline is on the record.
	entries := logs.FilterMessage("cachedTeamClaimsName").All()
	require.NotEmpty(t, entries,
		"declining to corroborate must be recorded, not silent")
}

// TestUserSnapshotVerifiedAt: the account chain is where device revocation
// lives, so its verification time is the one that answers "is this device
// still supposed to be operating?". A staleness policy that can date a team
// snapshot but not the account is half a policy.
//
// Same three properties as the team stamp: an online load sets it, a reload
// that plays no new links still counts as a fresh verification, and a load
// from cache dates the verification rather than the read.
func TestUserSnapshotVerifiedAt(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.NewClientMetaContextAtHome(t, bluey, t.TempDir())
	au := m.G().ActiveUser()

	before := m.G().Now()
	uw, err := libclient.LoadMe(m, au)
	require.NoError(t, err)
	first := uw.VerifiedAt()
	require.False(t, first.IsZero(), "an online load must stamp the account snapshot")
	require.False(t, first.Import().Before(before.Add(-time.Minute)),
		"the stamp must date this load, not some earlier one")

	// Nothing has changed on the chain, so this reload plays no links and
	// takes the early-return path -- which must still re-stamp, or an account
	// that simply is not changing would age as though unchecked.
	time.Sleep(10 * time.Millisecond)
	uw2, err := libclient.LoadMe(m, au)
	require.NoError(t, err)
	second := uw2.VerifiedAt()
	require.True(t, second.Import().After(first.Import()),
		"a reload that plays no new links is still a fresh verification")

	// The stamp survives to disk, and a cache load does not advance it.
	cached, err := libclient.LoadMeFromCache(m, au)
	require.NoError(t, err)
	require.True(t, cached.VerifiedAt().Import().Equal(second.Import()),
		"the stamp must persist, and a cache load must date the verification, not the read")

	age, known := cached.VerifiedAge(m.G().Now())
	require.True(t, known)
	require.GreaterOrEqual(t, age, time.Duration(0))
}
