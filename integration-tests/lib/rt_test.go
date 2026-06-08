package lib

import (
	"fmt"
	"testing"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
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
			mb, fqt,
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

	lst, err := minderBluey.ListAllChannelsForTeam(mb, fqt, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 6)

	assertChannel := func(idx int, klass proto.RTChannelClass, name proto.RTChannelName) {
		require.Equal(t, lst.Channels[idx].Klass, klass)
		require.Equal(t, lst.Channels[idx].Name, name)
	}

	assertChannel(0, proto.RTChannelClass_Admin, "")
	assertChannel(1, proto.RTChannelClass_Admin, "foo")
	assertChannel(2, proto.RTChannelClass_Admin, "hotels")
	assertChannel(3, proto.RTChannelClass_Bottom, "")
	assertChannel(4, proto.RTChannelClass_Bottom, "alumni")
	assertChannel(5, proto.RTChannelClass_Bottom, "hotels")

	lst, err = minderCoco.ListAllChannelsForTeam(mc, fqt, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 3)

	assertChannel(0, proto.RTChannelClass_Bottom, "")
	assertChannel(1, proto.RTChannelClass_Bottom, "alumni")
	assertChannel(2, proto.RTChannelClass_Bottom, "hotels")

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
		_, e1 = minderBluey.MakeChannelWithTestHooks(mb, fqt, proto.RTAppID_Chat, "zc", "zc time", roles, &bHooks)
		ch2 <- struct{}{}
	}()
	go func() {
		_, e2 = minderCoco.MakeChannelWithTestHooks(mc, fqt, proto.RTAppID_Chat, "zd", "zd time", roles, &cHooks)
		ch3 <- struct{}{}
	}()
	<-ch3

	require.NoError(t, e1)
	require.NoError(t, e2)
	require.Equal(t, r1, -1)
	require.Equal(t, r2, 0)

	lst, err = minderCoco.ListAllChannelsForTeam(mc, fqt, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 4)
	assertChannel(3, proto.RTChannelClass_Bottom, "zd")

	lst, err = minderBluey.ListAllChannelsForTeam(mb, fqt, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.Len(t, lst.Channels, 8)
	assertChannel(3, proto.RTChannelClass_Admin, "zc")
	assertChannel(7, proto.RTChannelClass_Bottom, "zd")
}

func TestRTMinderSendAndGetThread(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "foo", "the foo channel", proto.RolePairOpt{})
	require.NoError(t, err)

	// Send a handful of messages in order.
	bodies := []string{"hello world", "second message", "a third one"}
	var lastSeq proto.RTMsgSeq
	for _, b := range bodies {
		res, err := minder.Send(mb, fqt, proto.RTAppID_Chat, "foo", nil, []byte(b))
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, lastSeq+1, res.Seq)
		lastSeq = res.Seq
	}

	// Read them all back; they should decrypt and come in seq order. We reached
	// the far edge (end == lastSeq) exactly, so this is not a "final" short read.
	msgs, final, err := minder.GetThreadBookended(mb, fqt, proto.RTAppID_Chat, "foo",
		nil, 1, lastSeq)
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
	msgs, final, err = minder.GetThreadBookended(mb, fqt, proto.RTAppID_Chat, "foo",
		nil, 2, lastSeq)
	require.NoError(t, err)
	require.False(t, final)
	require.Len(t, msgs, 2)
	require.Equal(t, proto.RTMsgSeq(2), msgs[0].Seq)
	require.Equal(t, "second message", string(msgs[0].Body))

	// Sending to a non-existent channel fails.
	_, err = minder.Send(mb, fqt, proto.RTAppID_Chat, "nosuchchannel", nil, []byte("hi"))
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

	_, err := minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "foo", "the foo channel", proto.RolePairOpt{})
	require.NoError(t, err)

	bodies := []string{"one", "two", "three", "four", "five"}
	for _, b := range bodies {
		_, err := minder.Send(mb, fqt, proto.RTAppID_Chat, "foo", nil, []byte(b))
		require.NoError(t, err)
	}

	// Ask for a non-contiguous subset (2 and 4) plus a seq that doesn't exist
	// (99). We should get exactly seqs 2 and 4 back, each decrypting correctly;
	// the missing seq is simply absent.
	msgs, err := minder.GetMsgs(mb, fqt, proto.RTAppID_Chat, "foo", nil,
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
	msgs, err = minder.GetMsgs(mb, fqt, proto.RTAppID_Chat, "foo", nil, nil)
	require.NoError(t, err)
	require.Len(t, msgs, 0)

	// Requesting only missing seqs yields an empty result.
	msgs, err = minder.GetMsgs(mb, fqt, proto.RTAppID_Chat, "foo", nil,
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
		_, err := sender.MakeChannel(mb, fqt, proto.RTAppID_Chat, ch, "hole-filling",
			proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
		require.NoError(t, err)
		for i := 1; i <= n; i++ {
			res, err := sender.Send(mb, fqt, proto.RTAppID_Chat, ch, nil, []byte(fmt.Sprintf("msg-%d", i)))
			require.NoError(t, err)
			require.Equal(t, proto.RTMsgSeq(i), res.Seq)
		}
		primed, err := receiver.GetMsgs(mc, fqt, proto.RTAppID_Chat, ch, nil,
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
		msgs, final, err := receiver.GetThreadBookended(mc, fqt, proto.RTAppID_Chat, "asc",
			nil, 1, n)
		require.NoError(t, err)
		require.False(t, final) // reached end (== n) exactly
		check(t, msgs, 1, 2, 3, 4, 5, 6, 7)

		// The read above cached everything, so the second read is a pure cache
		// hit (no holes, no bookends).
		msgs, _, err = receiver.GetThreadBookended(mc, fqt, proto.RTAppID_Chat, "asc",
			nil, 1, n)
		require.NoError(t, err)
		check(t, msgs, 1, 2, 3, 4, 5, 6, 7)
	})

	t.Run("descending", func(t *testing.T) {
		setup("desc")

		// Same sparse cache {3,5}, but walk 7..1: leading bookend [7,6], trailing
		// [2,1], hole 4, merged newest-first.
		msgs, final, err := receiver.GetThreadBookended(mc, fqt, proto.RTAppID_Chat, "desc",
			nil, n, 1)
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

	_, err := minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "foo", "sender cache", proto.RolePairOpt{})
	require.NoError(t, err)

	const n = 5
	for i := 1; i <= n; i++ {
		res, err := minder.Send(mb, fqt, proto.RTAppID_Chat, "foo", nil, []byte(fmt.Sprintf("msg-%d", i)))
		require.NoError(t, err)
		require.Equal(t, proto.RTMsgSeq(i), res.Seq)
	}

	// Reading back the full range it just sent is a pure cache hit.
	before := minder.Metrics()
	msgs, final, err := minder.GetThreadBookended(mb, fqt, proto.RTAppID_Chat, "foo", nil, 1, n)
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
	_, _, err = minder.GetThreadBookended(mb, fqt, proto.RTAppID_Chat, "foo", nil, 1, n+1)
	require.NoError(t, err)
	require.Equal(t, before.ServerThreadReads+1, minder.Metrics().ServerThreadReads,
		"a read past the cached range must issue exactly one server RtGetThread")
}

// TestRTSendReadPermissions exercises the server-side authorization machinery
// for send (write role) and read (read role / channel class), from the point of
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
	_, err := minderBluey.MakeChannel(mb, fqt, proto.RTAppID_Chat, "announce",
		"admins post here",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.AdminRole})
	require.NoError(t, err)

	// "watercooler": a bottom channel any member may write to (positive control).
	_, err = minderBluey.MakeChannel(mb, fqt, proto.RTAppID_Chat, "watercooler",
		"anyone posts",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	// "brass": an admin-class channel coco shouldn't even be able to see.
	_, err = minderBluey.MakeChannel(mb, fqt, proto.RTAppID_Chat, "brass",
		"admins only",
		proto.RolePairOpt{Read: &proto.AdminRole, Write: &proto.AdminRole})
	require.NoError(t, err)

	// --- write permission ---

	// coco CAN write to the member-writable channel.
	_, err = minderCoco.Send(mc, fqt, proto.RTAppID_Chat, "watercooler", nil, []byte("hi all"))
	require.NoError(t, err)

	// coco CANNOT write to the admin-writable channel, even though she can read it.
	_, err = minderCoco.Send(mc, fqt, proto.RTAppID_Chat, "announce", nil, []byte("not an admin"))
	require.Equal(t, core.PermissionError("user role too low to send into channel"), err)

	// the owner CAN write to the admin-writable channel.
	_, err = minderBluey.Send(mb, fqt, proto.RTAppID_Chat, "announce", nil, []byte("official notice"))
	require.NoError(t, err)

	// --- read permission ---

	// coco CAN read the admin-writable (but member-readable) channel.
	msgs, err := minderCoco.GetThreadRecentMsgs(mc, fqt, proto.RTAppID_Chat, "announce",
		nil, 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "official notice", string(msgs[0].Body))

	// coco can't even see the admin-class channel, so she can't address it.
	lst, err := minderCoco.ListAllChannelsForTeam(mc, fqt, proto.RTAppID_Chat)
	require.NoError(t, err)
	for _, ch := range lst.Channels {
		require.NotEqual(t, proto.RTChannelName("brass"), ch.Name)
	}

	// ...and reading its thread fails: she can't resolve a channel she can't see.
	_, err = minderCoco.GetThreadRecentMsgs(mc, fqt, proto.RTAppID_Chat, "brass",
		nil, 0)
	require.Equal(t, core.RTNotFoundError("channel 'brass'"), err)
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
	_, err := minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "general", "all hands",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	// Encrypting at the channel's read role (the default path) works.
	_, err = minder.Send(mb, fqt, proto.RTAppID_Chat, "general", nil, []byte("hi"))
	require.NoError(t, err)

	// bluey (owner) holds the owner key, so she *can* encrypt at OwnerRole, but
	// the channel's read role is member, so the server must reject it.
	_, err = minder.SendWithTestHooks(mb, fqt, proto.RTAppID_Chat, "general",
		nil, []byte("wrong role"),
		&librt.SendTestHooks{EncryptRoleOverride: &proto.OwnerRole})
	require.Equal(t, core.BadArgsError("message must be encrypted at the channel's read role"), err)

	// The rejected message was not persisted: only the one good message remains.
	msgs, err := minder.GetThreadRecentMsgs(mb, fqt, proto.RTAppID_Chat, "general",
		nil, 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "hi", string(msgs[0].Body))
}

// TestRTChannelDisambiguation covers a name shared by an admin and a bottom
// channel: addressing by name alone is ambiguous, but a channel class resolves
// it to exactly one channel.
func TestRTChannelDisambiguation(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	// Two channels both named "general": one admin-class, one bottom-class.
	_, err := minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "general", "for admins",
		proto.RolePairOpt{Read: &proto.AdminRole})
	require.NoError(t, err)
	_, err = minder.MakeChannel(mb, fqt, proto.RTAppID_Chat, "general", "for everyone",
		proto.RolePairOpt{Read: &proto.DefaultRole})
	require.NoError(t, err)

	admin := proto.RTChannelClass_Admin
	bottom := proto.RTChannelClass_Bottom

	// Addressing by name alone can't choose between them.
	_, err = minder.Send(mb, fqt, proto.RTAppID_Chat, "general", nil, []byte("hi"))
	require.Equal(t, core.RTAmbiguousChannelError{Name: "general"}, err)
	_, err = minder.GetThreadRecentMsgs(mb, fqt, proto.RTAppID_Chat, "general", nil, 0)
	require.Equal(t, core.RTAmbiguousChannelError{Name: "general"}, err)

	// A class disambiguates, and each channel keeps its own thread.
	_, err = minder.Send(mb, fqt, proto.RTAppID_Chat, "general", &admin, []byte("admin msg"))
	require.NoError(t, err)
	_, err = minder.Send(mb, fqt, proto.RTAppID_Chat, "general", &bottom, []byte("bottom msg"))
	require.NoError(t, err)

	adminMsgs, err := minder.GetThreadRecentMsgs(mb, fqt, proto.RTAppID_Chat, "general", &admin, 0)
	require.NoError(t, err)
	require.Len(t, adminMsgs, 1)
	require.Equal(t, "admin msg", string(adminMsgs[0].Body))

	bottomMsgs, err := minder.GetThreadRecentMsgs(mb, fqt, proto.RTAppID_Chat, "general", &bottom, 0)
	require.NoError(t, err)
	require.Len(t, bottomMsgs, 1)
	require.Equal(t, "bottom msg", string(bottomMsgs[0].Body))
}
