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
