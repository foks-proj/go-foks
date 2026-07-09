package lib

import (
	"fmt"
	"slices"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestRTMinderMakeChannelSimple(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	coco := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	m := tew.MetaContext()
	tm.makeChanges(
		t, m, bluey,
		[]proto.MemberRole{
			coco.toMemberRole(t, proto.DefaultRole, tm.hepks),
		}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minderBluey := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	createChanWithRoles := func(
		mndr *librt.Minder,
		n proto.RTChannelName,
		d proto.RTChannelDesc,
		roles proto.RolePairOpt,
		expectedErr error,
	) {
		chid, err := mndr.MakeChannel(
			mb,
			team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			n, d,
			roles)
		if expectedErr != nil {
			require.Equal(t, expectedErr, err)
			return
		}
		require.NoError(t, err)
		chidStr, err := chid.StringErr()
		require.NoError(t, err)
		fmt.Printf("created new channel: %s", chidStr)
	}
	createChan := func(
		mndr *librt.Minder,
		n proto.RTChannelName,
		d proto.RTChannelDesc,
		expectedErr error,
	) {
		createChanWithRoles(mndr, n, d, proto.RolePairOpt{}, expectedErr)
	}
	createChan(minderBluey, "foo", "foobars and doobars", nil)
	createChan(minderBluey, "hotels", "zips and dips and blips", nil)
	createChan(minderBluey, "foo", "whooopsies", core.RTChannelExistsError{})
	createChan(minderBluey, "", "general is cool", nil)
	createChan(minderBluey, "", "general is not cool", core.RTChannelExistsError{})

	// We can create second channels for all members and it won't conflict with the admin
	// channels that we created (by default) above.
	createChanWithRoles(minderBluey, "", "general is cool", proto.RolePairOpt{Read: &proto.DefaultRole}, nil)
	createChanWithRoles(minderBluey, "hotels", "can never have too many hotels",
		proto.RolePairOpt{Read: &proto.DefaultRole}, nil)
	createChanWithRoles(minderBluey, "hotels", "or maybe you can",
		proto.RolePairOpt{Read: &proto.DefaultRole}, core.RTChannelExistsError{})
	createChanWithRoles(minderBluey, "alumni", "anyone can read alumni",
		proto.RolePairOpt{Read: &proto.DefaultRole}, nil)

	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	minderCoco := librt.NewMinder(mc.G().ActiveUser())

	// conflicts with bottom hotles channel (since coco is a member)
	createChan(minderCoco, "hotels", "or maybe you can for coco",
		core.RTChannelExistsError{})
	createChan(minderCoco, "alumni", "anyone can read alumni, but only can create it once",
		core.RTChannelExistsError{})

	lst, err := minderBluey.ListAllChannelsForTeam(
		mb,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
	)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 6)

	assertChannel := func(idx int, tier proto.RTChannelTier, name proto.RTChannelName) {
		require.Equal(t, lst.Channels[idx].Tier, tier)
		require.Equal(t, lst.Channels[idx].Name, name)
	}

	assertChannel(0, proto.RTChannelTier_Admin, "")
	assertChannel(1, proto.RTChannelTier_Admin, "foo")
	assertChannel(2, proto.RTChannelTier_Admin, "hotels")
	assertChannel(3, proto.RTChannelTier_Bottom, "")
	assertChannel(4, proto.RTChannelTier_Bottom, "alumni")
	assertChannel(5, proto.RTChannelTier_Bottom, "hotels")

	lst, err = minderCoco.ListAllChannelsForTeam(
		mc,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
	)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 3)

	assertChannel(0, proto.RTChannelTier_Bottom, "")
	assertChannel(1, proto.RTChannelTier_Bottom, "alumni")
	assertChannel(2, proto.RTChannelTier_Bottom, "hotels")

	// now we'll test the race-and-retry features
	ch1 := make(chan struct{})
	ch2 := make(chan struct{})
	ch3 := make(chan struct{})
	r1 := -1
	r2 := -1
	var e1, e2 error
	var roles proto.RolePairOpt
	bHooks := librt.MakeChannelTestHooks{
		// Wait until coco is about to post
		PrePostDelayHook: func() {
			<-ch1
		},
		HitRaceHook: func(i int) {
			r1 = i
		},
	}
	var hitSyncPoints bool
	cHooks := librt.MakeChannelTestHooks{
		PrePostDelayHook: func() {
			// Only do this the first time through, the second time, there is no
			// other thread around to gate us.
			if hitSyncPoints {
				return
			}
			hitSyncPoints = true
			ch1 <- struct{}{}
			<-ch2
		},
		HitRaceHook: func(i int) {
			r2 = i
		},
	}

	go func() {
		_, e1 = minderBluey.MakeChannelWithTestHooks(
			mb, team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat, "zc", "zc time", roles, &bHooks)
		ch2 <- struct{}{}
	}()
	go func() {
		_, e2 = minderCoco.MakeChannelWithTestHooks(mc,
			team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat, "zd", "zd time", roles, &cHooks)
		ch3 <- struct{}{}
	}()
	<-ch3

	require.NoError(t, e1)
	require.NoError(t, e2)
	require.Equal(t, r1, -1)
	require.Equal(t, r2, 0)

	lst, err = minderCoco.ListAllChannelsForTeam(
		mc,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
	)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 4)
	assertChannel(3, proto.RTChannelTier_Bottom, "zd")

	lst, err = minderBluey.ListAllChannelsForTeam(
		mb,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
	)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 8)
	assertChannel(3, proto.RTChannelTier_Admin, "zc")
	assertChannel(7, proto.RTChannelTier_Bottom, "zd")
}

// TestRTMinderGeneralNameReserved checks the minder reserves the "general"
// name for the default (empty-name) channel: an explicit "general" is rejected
// case-insensitively, while the empty name (which *is* "#general") still works.
func TestRTMinderGeneralNameReserved(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	// An explicit "general" is rejected, and the check normalizes case, so
	// "General"/"GENERAL" are too.
	reserved := core.RTGenericError("cannot make channel named #general")
	for _, nm := range []proto.RTChannelName{"general", "General", "GENERAL"} {
		_, err := minder.MakeChannel(
			mb,
			team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			nm, "",
			proto.RolePairOpt{},
		)
		require.Equal(t, reserved, err, "name %q", nm)
	}

	// The default channel (empty name) -- the real "#general" -- is still fine.
	_, err := minder.MakeChannel(
		mb,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
		"",
		"the real general",
		proto.RolePairOpt{},
	)
	require.NoError(t, err)

	// None of the rejected attempts created anything; only the default exists.
	lst, err := minder.ListAllChannelsForTeam(
		mb,
		team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
	)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 1)
	require.Equal(t, proto.RTChannelName(""), lst.Channels[0].Name)
}

// TestRTMinderMakeChannelWarmCacheNoRace guards against a regression in the
// channel-set caching path. When the client's cached version already matches
// the server's, the server returns an empty delta; if it (or the client) lets
// the set version collapse to 0, the next MakeChannel computes a stale
// SetVers and spuriously loses the optimistic-concurrency check, forcing a
// retry. With no contention there should be exactly zero races. We run the
// scenario across all cache modalities (no cache, disk-only, mem+disk), since
// the disk and mem layers exercise different Get/Put round-trips.
func TestRTMinderMakeChannelWarmCacheNoRace(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	fqt := tew.makeTeamForOwner(t, bluey).ToFQTeamParsed(t)
	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))

	test := func(cs libclient.CacheSettings) {
		// A fresh channel name per modality so the three runs don't collide.
		nm, err := core.RandomDomain()
		require.NoError(t, err)
		first := proto.RTChannelName(nm + "-first")
		second := proto.RTChannelName(nm + "-second")

		minder := librt.NewMinderWithCacheSettings(mb.G().ActiveUser(), cs)

		// Create one channel, then list -- this warms the cache to the current
		// server version, so the next list takes the "already fresh" path.
		_, err = minder.MakeChannel(mb,
			team.WrapNamedPtr(fqt), proto.RTAppID_Chat, first, "first channel", proto.RolePairOpt{})
		require.NoError(t, err)
		_, err = minder.ListAllChannelsForTeam(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat)
		require.NoError(t, err)

		// A second create with a warm, current cache must succeed without ever
		// hitting the race-retry path. HitRaceHook fires once per retry; with
		// the version bug it fired (i == 0) before succeeding on the retry.
		raced := false
		hooks := librt.MakeChannelTestHooks{
			HitRaceHook: func(i int) { raced = true },
		}
		_, err = minder.MakeChannelWithTestHooks(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, second, "second channel", proto.RolePairOpt{}, &hooks)
		require.NoError(t, err)
		require.False(t, raced, "warm-cache create should not hit the race-retry path (cs=%+v)", cs)
	}

	test(libclient.CacheSettings{})
	test(libclient.CacheSettings{UseMem: false, UseDisk: true})
	test(libclient.CacheSettings{UseMem: true, UseDisk: true})
}

// TestRTMinderChannelNameCaseFoldCollision checks the minder's collision
// detection normalizes case: "bar" and "Bar" are the same name within the same
// tier, so the second create collides. (Companion to the same-case collisions
// in TestRTMinderMakeChannelSimple.)
func TestRTMinderChannelNameCaseFoldCollision(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "bar", "the bar channel", proto.RolePairOpt{})
	require.NoError(t, err)

	// "Bar" normalizes to "bar" -- same name, same (admin) tier -> collision.
	_, err = minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "Bar", "the BAR channel", proto.RolePairOpt{})
	require.Equal(t, core.RTChannelExistsError{}, err)

	// Only the first channel exists, stored as it was passed.
	lst, err := minder.ListAllChannelsForTeam(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 1)
	require.Equal(t, proto.RTChannelName("bar"), lst.Channels[0].Name)
}

func makeChannelSpecifier(nm proto.RTChannelName) lcl.RTChannelSpecifier {
	return lcl.NewRTChannelSpecifierWithName(
		lcl.RTChannelNameAndTier{
			Name: nm,
		},
	)
}

func makeChannelSpecifierWithString(s string) lcl.RTChannelSpecifier {
	return makeChannelSpecifier(proto.RTChannelName(s))
}

func makeChannelSpecifierWithTier(s string, kls proto.RTChannelTier) lcl.RTChannelSpecifier {
	return lcl.NewRTChannelSpecifierWithName(
		lcl.RTChannelNameAndTier{
			Name: proto.RTChannelName(s),
			Tier: kls,
		},
	)
}

func TestRTMinderSendAndGetThread(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "foo", "the foo channel", proto.RolePairOpt{})
	require.NoError(t, err)

	// Send a handful of messages in order.
	bodies := []string{"hello world", "second message", "a third one"}
	var lastSeq proto.RTMsgSeq
	for _, b := range bodies {
		res, err := minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"), []byte(b))
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, lastSeq+1, res.Seq)
		lastSeq = res.Seq
	}

	// Read them all back; they should decrypt and come in seq order. We reached
	// the far edge (end == lastSeq) exactly, so this is not a "final" short read.
	msgs, final, err := minder.GetThreadBookended(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 1, lastSeq)
	require.NoError(t, err)
	require.False(t, final)
	require.Len(t, msgs, len(bodies))
	for i, b := range bodies {
		require.Equal(t, proto.RTMsgSeq(i+1), msgs[i].Seq)
		require.Equal(t, proto.RTMsgType_Basic, msgs[i].Typ)
		require.Equal(t, b, string(msgs[i].Body))
		require.NotNil(t, msgs[i].Sender)
		require.Equal(t, bluey.uid.ToPartyID(), *msgs[i].Sender)
	}

	// Reading a later sub-range should yield only the tail (served from cache,
	// since the read above populated it).
	msgs, final, err = minder.GetThreadBookended(mb, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 2, lastSeq)
	require.NoError(t, err)
	require.False(t, final)
	require.Len(t, msgs, 2)
	require.Equal(t, proto.RTMsgSeq(2), msgs[0].Seq)
	require.Equal(t, "second message", string(msgs[0].Body))

	// Sending to a non-existent channel fails.
	_, err = minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("nosuchchannel"),
		[]byte("hi"))
	require.Error(t, err)
}

// TestRTMinderGetMsgsBySeq exercises rtGetMsgs: fetching an arbitrary,
// non-contiguous set of messages by seq, the way a client fills holes between
// its local cache and a paged fetch. Seqs that don't exist are silently
// dropped, so the result is found-only and not necessarily in request order.
func TestRTMinderGetMsgsBySeq(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "foo", "the foo channel", proto.RolePairOpt{})
	require.NoError(t, err)

	bodies := []string{"one", "two", "three", "four", "five"}
	for _, b := range bodies {
		_, err := minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"),
			[]byte(b))
		require.NoError(t, err)
	}

	// Ask for a non-contiguous subset (2 and 4) plus a seq that doesn't exist
	// (99). We should get exactly seqs 2 and 4 back, each decrypting correctly;
	// the missing seq is simply absent.
	msgs, err := minder.GetMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"),
		[]proto.RTMsgSeq{2, 4, 99})
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	bySeq := make(map[proto.RTMsgSeq]string, len(msgs))
	for _, msg := range msgs {
		require.Equal(t, proto.RTMsgType_Basic, msg.Typ)
		require.NotNil(t, msg.Sender)
		require.Equal(t, bluey.uid.ToPartyID(), *msg.Sender)
		bySeq[msg.Seq] = string(msg.Body)
	}
	require.Equal(t, "two", bySeq[2])
	require.Equal(t, "four", bySeq[4])

	// An empty request yields nothing, not an error.
	msgs, err = minder.GetMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), nil)
	require.NoError(t, err)
	require.Len(t, msgs, 0)

	// Requesting only missing seqs yields an empty result.
	msgs, err = minder.GetMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"),
		[]proto.RTMsgSeq{100, 101})
	require.NoError(t, err)
	require.Len(t, msgs, 0)
}

// TestRTMinderGetThreadBookendedHoleFilling exercises the partial-cache path of
// GetThreadBookended: the local cache holds a sparse, non-contiguous subset, so
// a bookended read must fetch the leading range, the trailing range, and the
// interior hole(s) from the server and merge them back with the cached run into
// one ordered thread. The empty-cache and full-cache-hit branches are covered
// too (first vs. second read). Both paging directions are checked, since the
// merge / bookend / sort math differs by direction.
func TestRTMinderGetThreadBookendedHoleFilling(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // sender / team owner
	coco := tew.NewTestUser(t)  // receiver / ordinary member
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	tm.makeChanges(
		t, tew.MetaContext(), bluey,
		[]proto.MemberRole{coco.toMemberRole(t, proto.DefaultRole, tm.hepks)}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	sender := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	receiver := librt.NewMinder(mc.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	const n = 7

	// setup: bluey creates a member-readable channel and sends n messages (seqs
	// 1..n). coco is a *separate* client with her own local cache; she primes it
	// with a non-contiguous subset {3,5}, leaving an interior hole at 4 and
	// nothing cached outside [3,5]. Because the sender and receiver are different
	// users, any sender-side caching never touches coco's cache, so the holes the
	// bookended read must fill are exactly the ones set up here.
	setup := func(ch proto.RTChannelName) {
		_, err := sender.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch, "hole-filling",
			proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
		require.NoError(t, err)
		for i := 1; i <= n; i++ {
			res, err := sender.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
				makeChannelSpecifier(ch),
				[]byte(fmt.Sprintf("msg-%d", i)))
			require.NoError(t, err)
			require.Equal(t, proto.RTMsgSeq(i), res.Seq)
		}
		primed, err := receiver.GetMsgs(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifier(ch),
			[]proto.RTMsgSeq{3, 5})
		require.NoError(t, err)
		require.Len(t, primed, 2)
	}

	check := func(t *testing.T, msgs []librt.ThreadMessage, wantSeqs ...int) {
		require.Len(t, msgs, len(wantSeqs))
		for i, s := range wantSeqs {
			require.Equal(t, proto.RTMsgSeq(s), msgs[i].Seq)
			require.Equal(t, fmt.Sprintf("msg-%d", s), string(msgs[i].Body))
		}
	}

	t.Run("ascending", func(t *testing.T) {
		setup("asc")

		// coco's cache holds {3,5}. The server must supply leading [1,2], trailing
		// [6,7], and the hole at 4; all of it merges into one ascending run.
		msgs, final, err := receiver.GetThreadBookended(mc, team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			makeChannelSpecifierWithString("asc"), 1, n)
		require.NoError(t, err)
		require.False(t, final) // reached end (== n) exactly
		check(t, msgs, 1, 2, 3, 4, 5, 6, 7)

		// The read above cached everything, so the second read is a pure cache
		// hit (no holes, no bookends).
		msgs, _, err = receiver.GetThreadBookended(mc, team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			makeChannelSpecifierWithString("asc"),
			1, n)
		require.NoError(t, err)
		check(t, msgs, 1, 2, 3, 4, 5, 6, 7)
	})

	t.Run("descending", func(t *testing.T) {
		setup("desc")

		// Same sparse cache {3,5}, but walk 7..1: leading bookend [7,6], trailing
		// [2,1], hole 4, merged newest-first.
		msgs, final, err := receiver.GetThreadBookended(mc, team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			makeChannelSpecifierWithString("desc"),
			n, 1)
		require.NoError(t, err)
		require.False(t, final) // reached end (== 1) exactly
		check(t, msgs, 7, 6, 5, 4, 3, 2, 1)
	})
}

// TestRTMinderSenderReadsAreCacheHits confirms that because Send populates the
// sender's own read cache, the sender reading back exactly what it just sent is
// served entirely from cache -- no server round-trip. It uses the Minder's
// instrumentation counters to assert that (and a contrast read past the cached
// range to prove the counter actually tracks round-trips).
func TestRTMinderSenderReadsAreCacheHits(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "foo", "sender cache", proto.RolePairOpt{})
	require.NoError(t, err)

	const n = 5
	for i := 1; i <= n; i++ {
		res, err := minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"),
			[]byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err)
		require.Equal(t, proto.RTMsgSeq(i), res.Seq)
	}

	// Reading back the full range it just sent is a pure cache hit.
	before := minder.Metrics()
	msgs, final, err := minder.GetThreadBookended(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 1, n)
	require.NoError(t, err)
	require.False(t, final)
	require.Len(t, msgs, n)
	for i := 0; i < n; i++ {
		require.Equal(t, proto.RTMsgSeq(i+1), msgs[i].Seq)
		require.Equal(t, fmt.Sprintf("msg-%d", i+1), string(msgs[i].Body))
	}
	require.Equal(t, before.ServerThreadReads, minder.Metrics().ServerThreadReads,
		"fully-cached read must not issue a server RtGetThread")

	// Contrast: asking past the cached range forces a (trailing) server fetch, so
	// the counter must advance by exactly one -- proving it tracks round-trips.
	before = minder.Metrics()
	_, _, err = minder.GetThreadBookended(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 1, n+1)
	require.NoError(t, err)
	require.Equal(t, before.ServerThreadReads+1, minder.Metrics().ServerThreadReads,
		"a read past the cached range must issue exactly one server RtGetThread")
}

// TestRTMinderPrevPointers checks that a sender chains each message's
// prevSeq/prevID onto its predecessor when it has one (and leaves them zero for
// the very first message in the channel), and that a receiver fetching the
// thread from the server sees that same chain. Asserting on the receiver
// (server-decode path) and the sender (on-send cache-decode path) also confirms
// the two paths agree.
func TestRTMinderPrevPointers(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // sender / team owner
	coco := tew.NewTestUser(t)  // receiver / ordinary member
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	tm.makeChanges(
		t, tew.MetaContext(), bluey,
		[]proto.MemberRole{coco.toMemberRole(t, proto.DefaultRole, tm.hepks)}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	sender := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	receiver := librt.NewMinder(mc.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := sender.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "foo", "prev pointers",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	const n = 4
	for i := 1; i <= n; i++ {
		res, err := sender.Send(mb, team.WrapNamedPtr(fqt),
			proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"), []byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err)
		require.Equal(t, proto.RTMsgSeq(i), res.Seq)
	}

	var zeroID proto.RTMsgID
	assertChain := func(t *testing.T, who string, msgs []librt.ThreadMessage) {
		require.Len(t, msgs, n, who)
		for i, msg := range msgs {
			require.Equal(t, proto.RTMsgSeq(i+1), msg.Seq, who)
			require.NotEqual(t, zeroID, msg.MsgID, "%s: msg %d should carry a real id", who, i+1)
			if i == 0 {
				// First message in the channel: the sender had no predecessor.
				require.Equal(t, proto.RTMsgSeq(0), msg.PrevSeq, "%s: first msg prevSeq", who)
				require.Equal(t, zeroID, msg.PrevID, "%s: first msg prevID", who)
			} else {
				// Otherwise prev points at the immediately preceding message.
				require.Equal(t, msgs[i-1].Seq, msg.PrevSeq, "%s: msg %d prevSeq", who, i+1)
				require.Equal(t, msgs[i-1].MsgID, msg.PrevID, "%s: msg %d prevID", who, i+1)
			}
		}
	}

	// Receiver fetches from the server (cold cache) and must see the chain the
	// sender stamped on each message.
	got, _, err := receiver.GetThreadBookended(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 1, n)
	require.NoError(t, err)
	assertChain(t, "receiver", got)

	// The sender's own read (served from its on-send cache) agrees.
	got, _, err = sender.GetThreadBookended(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("foo"), 1, n)
	require.NoError(t, err)
	assertChain(t, "sender", got)
}

// TestRTMinderEvilServerOrdering simulates a malicious server by installing a
// Minder test hook that rewrites the server's read response in place, then
// checks the client's ingest-time verification catches the tampering. Only
// fields outside the encryption nonce can be tampered without breaking
// decryption -- in practice the server-assigned `seq` and message structure --
// so these are the realistic attacks: relabeling seqs (reordering), delivering
// one message under two seqs (equivocation), and making a prev pointer disagree
// with where its target now sits.
func TestRTMinderEvilServerOrdering(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // honest sender / team owner
	coco := tew.NewTestUser(t)  // reader, fed lies by the "evil server"
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	tm.makeChanges(
		t, tew.MetaContext(), bluey,
		[]proto.MemberRole{coco.toMemberRole(t, proto.DefaultRole, tm.hepks)}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	sender := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	fqt := tm.ToFQTeamParsed(t)

	_, err := sender.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "foo", "evil server",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	const n = 4
	for i := 1; i <= n; i++ {
		_, err := sender.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"), []byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err)
	}
	allSeqs := []proto.RTMsgSeq{1, 2, 3, 4}

	// read fetches the messages on a *fresh* receiver (empty caches) with the
	// given response-mutating hook installed.
	read := func(mut func(*rem.RTThreadPage)) ([]librt.ThreadMessage, error) {
		recv := librt.NewMinder(mc.G().ActiveUser())
		recv.SetTestHooks(&librt.MinderTestHooks{MutateReadRes: mut})
		return recv.GetMsgs(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifierWithString("foo"),
			allSeqs)
	}
	requireOrderErr := func(t *testing.T, err error) {
		require.Error(t, err)
		var oe core.RTMsgOrderError
		require.ErrorAs(t, err, &oe)
	}
	// relabel the message currently at seq `from` to seq `to`.
	setSeq := func(p *rem.RTThreadPage, from, to int) {
		for i := range p.SeqMsgs {
			if p.SeqMsgs[i].Seq == proto.RTMsgSeq(from) {
				p.SeqMsgs[i].Seq = proto.RTMsgSeq(to)
			}
		}
	}

	t.Run("seq_at_or_below_prev", func(t *testing.T) {
		// msg @2's authenticated prev is @1; relabel it @1 so seq <= prevSeq.
		_, err := read(func(p *rem.RTThreadPage) { setSeq(p, 2, 1) })
		requireOrderErr(t, err)
	})

	t.Run("same_msg_two_seqs", func(t *testing.T) {
		// Deliver msg @1 a second time under a different seq: its (authenticated)
		// id is now claimed at two sequence numbers.
		_, err := read(func(p *rem.RTThreadPage) {
			for _, msg := range p.SeqMsgs {
				if msg.Seq == 1 {
					dup := msg
					dup.Seq = 99
					p.SeqMsgs = append(p.SeqMsgs, dup)
					break
				}
			}
		})
		requireOrderErr(t, err)
	})

	t.Run("prev_pointer_disagreement", func(t *testing.T) {
		// Move msg @1 to seq @50. msg @2's prev still points at id(1)->seq 1,
		// which no longer matches where 1 sits in this page.
		_, err := read(func(p *rem.RTThreadPage) { setSeq(p, 1, 50) })
		requireOrderErr(t, err)
	})

	t.Run("benign_reorder_ok", func(t *testing.T) {
		// Reversing the (unordered) seq list changes nothing the verifier cares
		// about, so an honest-but-shuffled response must still succeed. Proves
		// the hook fires without the verifier false-positiving.
		out, err := read(func(p *rem.RTThreadPage) { slices.Reverse(p.SeqMsgs) })
		require.NoError(t, err)
		require.Len(t, out, n)
	})
}

// TestRTMinderEvilServerRecentsHoleFill drives verification through the
// recents + hole-fill path (the one that previously passed a nil session). It
// forces a hole by dropping a message from the recents response, which makes
// the client fetch a filler -- then it tampers with that filler. It also checks
// the cross-batch case the shared session enables: a filler that equivocates
// with a message from the recents batch.
func TestRTMinderEvilServerRecentsHoleFill(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // honest sender / team owner
	coco := tew.NewTestUser(t)  // reader, fed lies by the "evil server"
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	tm.makeChanges(
		t, tew.MetaContext(), bluey,
		[]proto.MemberRole{coco.toMemberRole(t, proto.DefaultRole, tm.hepks)}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	sender := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	fqt := tm.ToFQTeamParsed(t)

	const n = 4
	// populate creates a fresh channel and sends n messages into it. Each subtest
	// uses its own channel because GetThreadRecentMsgs caches the recents portion
	// even when a later filler fetch fails -- a shared channel would let one
	// subtest's cache advance `stopAt` for the next, suppressing its hole/filler.
	populate := func(ch proto.RTChannelName) {
		_, err := sender.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch, "evil recents",
			proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
		require.NoError(t, err)
		for i := 1; i <= n; i++ {
			_, err := sender.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
				makeChannelSpecifier(ch),
				[]byte(fmt.Sprintf("msg-%d", i)))
			require.NoError(t, err)
		}
	}

	requireOrderErr := func(t *testing.T, err error) {
		require.Error(t, err)
		var oe core.RTMsgOrderError
		require.ErrorAs(t, err, &oe)
	}
	// readRecents reads channel `ch` on a fresh receiver, dropping seq `dropSeq`
	// from the recents response (to force a hole + filler fetch) and applying
	// `fillerMut` to the filler response.
	readRecents := func(ch proto.RTChannelName, dropSeq int, fillerMut func(*rem.RTThreadPage)) ([]librt.ThreadMessage, error) {
		recv := librt.NewMinder(mc.G().ActiveUser())
		recv.SetTestHooks(&librt.MinderTestHooks{
			MutateRecentsRes: func(l *rem.RTMsgList) {
				l.Lst = slices.DeleteFunc(l.Lst, func(msg rem.RTMsg) bool {
					return msg.Seq == proto.RTMsgSeq(dropSeq)
				})
			},
			MutateReadRes: fillerMut,
		})
		return recv.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifier(ch), 0)
	}

	t.Run("tampered_filler", func(t *testing.T) {
		populate("foo")
		// Hole at 2 -> client fetches the filler for seq 2; relabel it seq 1 so
		// seq <= prevSeq. The filler is verified at ingest, not silently trusted.
		_, err := readRecents("foo", 2, func(p *rem.RTThreadPage) {
			for i := range p.SeqMsgs {
				if p.SeqMsgs[i].Seq == 2 {
					p.SeqMsgs[i].Seq = 1
				}
			}
		})
		requireOrderErr(t, err)
	})

	t.Run("filler_equivocates_with_recents", func(t *testing.T) {
		populate("bar")
		// Hole at 2, but the filler page *also* re-delivers msg @3 (which was in
		// the recents batch) under a bogus seq. Because the holes fetch shares the
		// recents session, the id(3)->{3,77} disagreement must be caught.
		var captured *rem.RTMsg
		recv := librt.NewMinder(mc.G().ActiveUser())
		recv.SetTestHooks(&librt.MinderTestHooks{
			MutateRecentsRes: func(l *rem.RTMsgList) {
				for i := range l.Lst {
					if l.Lst[i].Seq == 3 {
						tmp := l.Lst[i]
						captured = &tmp
					}
				}
				l.Lst = slices.DeleteFunc(l.Lst, func(msg rem.RTMsg) bool {
					return msg.Seq == 2
				})
			},
			MutateReadRes: func(p *rem.RTThreadPage) {
				if captured != nil {
					dup := *captured
					dup.Seq = 77
					p.SeqMsgs = append(p.SeqMsgs, dup)
				}
			},
		})
		_, err := recv.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
			makeChannelSpecifier("bar"), 0)
		requireOrderErr(t, err)
	})
}

// TestRTSendReadPermissions exercises the server-side authorization machinery
// for send (write role) and read (read role / channel tier), from the point of
// view of a low-privilege member who must be *denied* — the cases the
// owner-only happy-path tests never reach.
func TestRTSendReadPermissions(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // team owner
	coco := tew.NewTestUser(t)  // ordinary member
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	m := tew.MetaContext()
	tm.makeChanges(
		t, m, bluey,
		[]proto.MemberRole{
			coco.toMemberRole(t, proto.DefaultRole, tm.hepks),
		}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minderBluey := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	minderCoco := librt.NewMinder(mc.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	// "announce": a bottom channel (so coco can see it and read it) that only
	// admins+ may write to.
	chAnnounce, err := minderBluey.MakeChannel(mb, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat, "announce",
		"admins post here",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.AdminRole})
	require.NoError(t, err)

	// "watercooler": a bottom channel any member may write to (positive control).
	chWatercooler, err := minderBluey.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "watercooler",
		"anyone posts",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	// "brass": an admin-tier channel coco shouldn't even be able to see.
	chBrass, err := minderBluey.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "brass",
		"admins only",
		proto.RolePairOpt{Read: &proto.AdminRole, Write: &proto.AdminRole})
	require.NoError(t, err)

	// --- write permission ---

	// coco CAN write to the member-writable channel.
	_, err = minderCoco.Send(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("watercooler"), []byte("hi all"))
	require.NoError(t, err)

	// coco CANNOT write to the admin-writable channel, even though she can read it.
	_, err = minderCoco.Send(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), []byte("not an admin"))
	require.Equal(t, core.PermissionError("user role too low to send into channel"), err)

	// the owner CAN write to the admin-writable channel.
	_, err = minderBluey.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), []byte("official notice"))
	require.NoError(t, err)

	// --- read permission ---

	// coco CAN read the admin-writable (but member-readable) channel.
	msgs, err := minderCoco.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "official notice", string(msgs[0].Body))

	// coco can't even see the admin-tier channel, so she can't address it.
	lst, err := minderCoco.ListAllChannelsForTeam(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat)
	require.NoError(t, err)
	for _, ch := range lst.Channels {
		require.NotEqual(t, proto.RTChannelName("brass"), ch.Name)
	}

	// ...and reading its thread fails: she can't resolve a channel she can't see.
	_, err = minderCoco.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("brass"), 0)
	require.Equal(t, core.RTNotFoundError("channel 'brass'"), err)

	// --- inbox fanout ---

	// Every successful send fans out inbox-version bumps to all channel
	// members (see user_channels/user_inbox in foks_realtime.sql). Tally:
	// channel-creation fanouts hit announce {bluey, coco}, watercooler {bluey,
	// coco}, and brass {bluey} (coco is below its read role); then coco's
	// watercooler send bumps both members, coco's rejected announce send bumps
	// no one, and bluey's announce send bumps both members. Reads bump nothing.
	// So bluey has taken 5 bumps and coco 4, and each user_channels row is
	// stamped at its owner's global version as of the last delivery into that
	// channel (or its creation, for brass).
	rtdb, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer rtdb.Release()

	uiVers := func(u *TestUser) int64 {
		var v int64
		err := rtdb.QueryRow(m.Ctx(),
			`SELECT inbox_version FROM user_inbox
			 WHERE short_host_id=$1 AND uid=$2 AND app_id='chat'`,
			m.ShortHostID(), u.uid.ExportToDB()).Scan(&v)
		require.NoError(t, err)
		return v
	}
	ucVers := func(u *TestUser, ch *proto.RTChannelID) int64 {
		var v int64
		err := rtdb.QueryRow(m.Ctx(),
			`SELECT inbox_version FROM user_channels
			 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
			m.ShortHostID(), ch.Short().Int64(), u.uid.ExportToDB()).Scan(&v)
		require.NoError(t, err)
		return v
	}

	require.Equal(t, int64(5), uiVers(bluey))
	require.Equal(t, int64(4), uiVers(coco))
	require.Equal(t, int64(5), ucVers(bluey, chAnnounce))
	require.Equal(t, int64(4), ucVers(bluey, chWatercooler))
	require.Equal(t, int64(3), ucVers(bluey, chBrass))
	require.Equal(t, int64(4), ucVers(coco, chAnnounce))
	require.Equal(t, int64(3), ucVers(coco, chWatercooler))

	// --- read receipts ---

	ucRead := func(u *TestUser, ch *proto.RTChannelID) int64 {
		var v int64
		err := rtdb.QueryRow(m.Ctx(),
			`SELECT read_through FROM user_channels
			 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
			m.ShortHostID(), ch.Short().Int64(), u.uid.ExportToDB()).Scan(&v)
		require.NoError(t, err)
		return v
	}

	// coco marks announce read through its one message: her read pointer
	// advances, her global inbox version bumps, and the announce row is
	// stamped at the new version -- just like a delivery -- so her other
	// devices pick up the read state.
	err = minderCoco.ReadThrough(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), 1)
	require.NoError(t, err)
	require.Equal(t, int64(5), uiVers(coco))
	require.Equal(t, int64(5), ucVers(coco, chAnnounce))
	require.Equal(t, int64(1), ucRead(coco, chAnnounce))

	// Repeating the same mark (or any stale one) is a no-op: the pointer is
	// monotonic and nothing bumps, so racing devices can't churn each other.
	err = minderCoco.ReadThrough(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), 1)
	require.NoError(t, err)
	require.Equal(t, int64(5), uiVers(coco))
	require.Equal(t, int64(5), ucVers(coco, chAnnounce))

	// Marking past the last message is a client bug and is rejected.
	err = minderCoco.ReadThrough(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("announce"), 2)
	require.Equal(t, core.BadArgsError("read-through seq exceeds last message"), err)

	// A read receipt requires read permission, like the read itself; coco
	// can't even address brass, so resolution fails client-side.
	err = minderCoco.ReadThrough(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("brass"), 1)
	require.Error(t, err)

	// brass has no messages at all, so there's nothing to mark read.
	err = minderBluey.ReadThrough(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("brass"), 1)
	require.Equal(t, core.BadArgsError("read-through seq exceeds last message"), err)

	// The owner's receipt bumps only her own inbox, not coco's.
	err = minderBluey.ReadThrough(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString("watercooler"), 1)
	require.NoError(t, err)
	require.Equal(t, int64(6), uiVers(bluey))
	require.Equal(t, int64(6), ucVers(bluey, chWatercooler))
	require.Equal(t, int64(1), ucRead(bluey, chWatercooler))
	require.Equal(t, int64(5), uiVers(coco))

	// --- inbox sync ---

	// The heads reported over RPC match the versions we asserted in the DB.
	hv, err := minderBluey.GetInboxVersion(mb, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(6), hv)
	hv, err = minderCoco.GetInboxVersion(mc, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(5), hv)

	// One assertable summary per returned inbox channel.
	type row struct {
		id   proto.RTChannelID
		vers proto.RTInboxVersion
		read proto.RTMsgSeq
		last bool // has a last-message preview
	}
	summarize := func(d *rem.RTInboxDelta) []row {
		var out []row
		for _, ch := range d.Channels {
			require.False(t, ch.Hidden)
			require.False(t, ch.Muted)
			require.False(t, ch.Md.Unreadable)
			out = append(out, row{
				id:   ch.Md.Id,
				vers: ch.InboxVersion,
				read: ch.ReadThrough,
				last: ch.Md.LastMsg != nil,
			})
		}
		return out
	}

	// coco's full sync (since=0): both channels she's fanned into, oldest bump
	// first; brass never appears (she was never fanned in, and it's admin-tier
	// besides). Announce carries her read receipt.
	delta, err := minderCoco.GetChangedThreads(mc, proto.RTAppID_Chat, 0, 0)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(5), delta.InboxVersion)
	require.Equal(t, []row{
		{id: *chWatercooler, vers: 3, read: 0, last: true},
		{id: *chAnnounce, vers: 5, read: 1, last: true},
	}, summarize(delta))

	// Cursor pagination: advancing since past watercooler's bump leaves only
	// announce; advancing to the head leaves nothing.
	delta, err = minderCoco.GetChangedThreads(mc, proto.RTAppID_Chat, 3, 0)
	require.NoError(t, err)
	require.Equal(t, []row{
		{id: *chAnnounce, vers: 5, read: 1, last: true},
	}, summarize(delta))
	delta, err = minderCoco.GetChangedThreads(mc, proto.RTAppID_Chat, 5, 0)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(5), delta.InboxVersion)
	require.Empty(t, delta.Channels)

	// bluey's full sync: all three channels, oldest bump first. brass has no
	// messages, so no last-message preview.
	delta, err = minderBluey.GetChangedThreads(mb, proto.RTAppID_Chat, 0, 0)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(6), delta.InboxVersion)
	require.Equal(t, []row{
		{id: *chBrass, vers: 3, read: 0, last: false},
		{id: *chAnnounce, vers: 5, read: 0, last: true},
		{id: *chWatercooler, vers: 6, read: 1, last: true},
	}, summarize(delta))

	// Paged: a max of 2 returns the two oldest bumps; re-issuing with since =
	// the highest version received returns the rest. The head rides along on
	// every page so the client knows when it has caught up.
	delta, err = minderBluey.GetChangedThreads(mb, proto.RTAppID_Chat, 0, 2)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(6), delta.InboxVersion)
	require.Equal(t, []row{
		{id: *chBrass, vers: 3, read: 0, last: false},
		{id: *chAnnounce, vers: 5, read: 0, last: true},
	}, summarize(delta))
	delta, err = minderBluey.GetChangedThreads(mb, proto.RTAppID_Chat, 5, 2)
	require.NoError(t, err)
	require.Equal(t, []row{
		{id: *chWatercooler, vers: 6, read: 1, last: true},
	}, summarize(delta))

	// Stale membership rows must not leak: remove coco from the team, and her
	// lingering user_channels rows (there's no un-fanout) stop appearing in
	// her sync -- the delta re-authorizes against the current team roster. The
	// head is her own per-user counter, so it still reports.
	tm.makeChanges(t, m, bluey,
		[]proto.MemberRole{
			coco.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), nil),
		}, nil,
	)
	delta, err = minderCoco.GetChangedThreads(mc, proto.RTAppID_Chat, 0, 0)
	require.NoError(t, err)
	require.Equal(t, proto.RTInboxVersion(5), delta.InboxVersion)
	require.Empty(t, delta.Channels)
}

// TestRTSendEncryptionRole checks that the server rejects a message encrypted
// at a role other than the channel's read role, even from a user who is
// otherwise authorized to write and who legitimately holds the (wrong) key.
func TestRTSendEncryptionRole(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	// A bottom channel readable/writable by members.
	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "", "all hands",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	// Encrypting at the channel's read role (the default path) works.
	_, err = minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(""), []byte("hi"))
	require.NoError(t, err)

	// bluey (owner) holds the owner key, so she *can* encrypt at OwnerRole, but
	// the channel's read role is member, so the server must reject it.
	_, err = minder.SendWithTestHooks(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(""),
		[]byte("wrong role"),
		&librt.SendTestHooks{EncryptRoleOverride: &proto.OwnerRole})
	require.Equal(t, core.BadArgsError("message must be encrypted at the channel's read role"), err)

	// The rejected message was not persisted: only the one good message remains.
	msgs, err := minder.GetThreadRecentMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(""),
		0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "hi", string(msgs[0].Body))
}

// TestRTChannelDisambiguation covers a name shared by an admin and a bottom
// channel: addressing by name alone is ambiguous, but a channel tier resolves
// it to exactly one channel.
func TestRTChannelDisambiguation(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	// Two channels both named "general": one admin-tier, one bottom-tier.
	_, err := minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "", "for admins",
		proto.RolePairOpt{Read: &proto.AdminRole})
	require.NoError(t, err)
	_, err = minder.MakeChannel(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, "", "for everyone",
		proto.RolePairOpt{Read: &proto.DefaultRole})
	require.NoError(t, err)

	admin := proto.RTChannelTier_Admin
	bottom := proto.RTChannelTier_Bottom

	// Addressing by name alone can't choose between them.
	_, err = minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(""), []byte("hi"))
	require.Equal(t, core.RTAmbiguousChannelError{Name: ""}, err)
	_, err = minder.GetThreadRecentMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(""), 0)
	require.Equal(t, core.RTAmbiguousChannelError{Name: ""}, err)

	// A tier disambiguates, and each channel keeps its own thread.
	_, err = minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithTier("", admin),
		[]byte("admin msg"))
	require.NoError(t, err)
	_, err = minder.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithTier("", bottom),
		[]byte("bottom msg"))
	require.NoError(t, err)

	adminMsgs, err := minder.GetThreadRecentMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, makeChannelSpecifierWithTier("", admin), 0)
	require.NoError(t, err)
	require.Len(t, adminMsgs, 1)
	require.Equal(t, "admin msg", string(adminMsgs[0].Body))

	bottomMsgs, err := minder.GetThreadRecentMsgs(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, makeChannelSpecifierWithTier("", bottom), 0)
	require.NoError(t, err)
	require.Len(t, bottomMsgs, 1)
	require.Equal(t, "bottom msg", string(bottomMsgs[0].Body))
}
