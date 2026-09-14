// No-push channels: a send queues no push_outbox rows, while the
// inbox-version fan-out that drives online delivery is untouched.
//
// The two halves have to be asserted separately. Suppressing the push rows is
// the feature; suppressing the inbox bump with them would make the channel
// undeliverable to members who are online, which is the opposite of what a
// control channel wants.
//
// These are also the first tests over push_outbox itself, so the ordinary
// channel case below pins the existing fan-out (one row per recipient, sender
// excluded) rather than only the new flag.
package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// noPushScene is a team with an owner and two ordinary members, plus the
// client machinery to create channels and send into them.
type noPushScene struct {
	tew               *TestEnvWrapper
	tm                *teamObj
	owner, mem1, mem2 *TestUser
	mo                librt.MetaContext
	minder            *librt.Minder
}

func setupNoPushScene(t *testing.T) *noPushScene {
	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	mem1 := tew.NewTestUser(t)
	mem2 := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, owner)
	m := tew.MetaContext()
	tm.makeChanges(t, m, owner,
		[]proto.MemberRole{
			mem1.toMemberRole(t, proto.DefaultRole, tm.hepks),
			mem2.toMemberRole(t, proto.DefaultRole, tm.hepks),
		}, nil,
	)

	mo := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, owner))
	return &noPushScene{
		tew:    tew,
		tm:     tm,
		owner:  owner,
		mem1:   mem1,
		mem2:   mem2,
		mo:     mo,
		minder: librt.NewMinder(mo.G().ActiveUser()),
	}
}

// makeChannel creates a channel with the given opts and returns its name.
func (s *noPushScene) makeChannel(
	t *testing.T, nm proto.RTChannelName, opts librt.MakeChannelOpts,
) proto.RTChannelID {
	fqt := s.tm.ToFQTeamParsed(t)
	// Explicit member roles: an empty RolePairOpt defaults the read role to
	// the creator's role in the team (owner), which would make the channel
	// admin-tier and fan in nobody else -- and then a push-row count of zero
	// would pass for the wrong reason.
	chid, err := s.minder.MakeChannelWithOpts(
		s.mo, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		nm, "a channel",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		opts, nil,
	)
	require.NoError(t, err)
	return *chid
}

func (s *noPushScene) send(t *testing.T, nm string, body string) {
	fqt := s.tm.ToFQTeamParsed(t)
	_, err := s.minder.Send(s.mo, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		makeChannelSpecifierWithString(nm), []byte(body))
	require.NoError(t, err)
}

// pushRows counts queued push rows for one user in one channel.
func (s *noPushScene) pushRows(t *testing.T, chid proto.RTChannelID, u *TestUser) int {
	m := s.tew.MetaContext()
	db, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer db.Release()
	var n int
	require.NoError(t, db.QueryRow(m.Ctx(),
		`SELECT count(*) FROM push_outbox
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3`,
		m.ShortHostID(), chid.Short().Int64(), u.uid.ExportToDB()).Scan(&n))
	return n
}

// inboxVersion is the user's global inbox version; it bumps on every delivery.
func (s *noPushScene) inboxVersion(t *testing.T, u *TestUser) int64 {
	m := s.tew.MetaContext()
	db, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer db.Release()
	var v int64
	err = db.QueryRow(m.Ctx(),
		`SELECT inbox_version FROM user_inbox
		 WHERE short_host_id=$1 AND uid=$2 AND app_id='chat'`,
		m.ShortHostID(), u.uid.ExportToDB()).Scan(&v)
	if err != nil {
		return 0
	}
	return v
}

func TestRTNoPushChannelQueuesNoPushRows(t *testing.T) {
	sc := setupNoPushScene(t)
	chid := sc.makeChannel(t, "control", librt.MakeChannelOpts{NoPush: true})

	before := map[*TestUser]int64{}
	for _, u := range []*TestUser{sc.mem1, sc.mem2} {
		before[u] = sc.inboxVersion(t, u)
	}

	sc.send(t, "control", "control traffic")

	for _, u := range []*TestUser{sc.owner, sc.mem1, sc.mem2} {
		require.Equal(t, 0, sc.pushRows(t, chid, u),
			"a no-push channel must queue no push_outbox row for anyone")
	}
	for _, u := range []*TestUser{sc.mem1, sc.mem2} {
		require.Greater(t, sc.inboxVersion(t, u), before[u],
			"no-push must not suppress the inbox-version fan-out")
	}
}

func TestRTOrdinaryChannelStillQueuesPushRows(t *testing.T) {
	sc := setupNoPushScene(t)
	chid := sc.makeChannel(t, "chat", librt.MakeChannelOpts{})

	sc.send(t, "chat", "conversation")

	require.Equal(t, 0, sc.pushRows(t, chid, sc.owner), "the sender is never pushed to")
	for _, u := range []*TestUser{sc.mem1, sc.mem2} {
		require.Equal(t, 1, sc.pushRows(t, chid, u),
			"an ordinary channel must queue one push row per recipient")
	}
}

// The flag round-trips: into the row the send path reads, and back out to a
// client through the channel listing.
func TestRTNoPushRoundTrips(t *testing.T) {
	sc := setupNoPushScene(t)
	quiet := sc.makeChannel(t, "quiet", librt.MakeChannelOpts{NoPush: true})
	loud := sc.makeChannel(t, "loud", librt.MakeChannelOpts{})

	inRow := func(chid proto.RTChannelID) bool {
		m := sc.tew.MetaContext()
		db, err := m.Db(shared.DbTypeRealTime)
		require.NoError(t, err)
		defer db.Release()
		var v bool
		require.NoError(t, db.QueryRow(m.Ctx(),
			`SELECT no_push FROM channels WHERE short_host_id=$1 AND channel_id=$2`,
			m.ShortHostID(), chid.Short().Int64()).Scan(&v))
		return v
	}
	require.True(t, inRow(quiet))
	require.False(t, inRow(loud))

	fqt := sc.tm.ToFQTeamParsed(t)
	lst, err := sc.minder.ListAllChannelsForTeam(
		sc.mo, team.WrapNamedPtr(fqt), proto.RTAppID_Chat)
	require.NoError(t, err)
	seen := 0
	for i := range lst.Channels {
		ch := &lst.Channels[i]
		switch ch.Name {
		case "quiet":
			seen++
			require.True(t, ch.NoPush, "flag lost on the way out to a client")
		case "loud":
			seen++
			require.False(t, ch.NoPush, "flag invented for an ordinary channel")
		}
	}
	require.Equal(t, 2, seen, "both channels must appear in the listing")
}

// The default channel may not be created no-push: the flag is creation-time
// only, so a team whose #general was created this way would stop notifying
// for every message in it with no way back.
func TestRTDefaultChannelCannotBeNoPush(t *testing.T) {
	sc := setupNoPushScene(t)
	fqt := sc.tm.ToFQTeamParsed(t)

	_, err := sc.minder.MakeChannelWithOpts(
		sc.mo, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		"", "", proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		librt.MakeChannelOpts{NoPush: true}, nil,
	)
	require.Error(t, err)

	_, err = sc.minder.MakeChannelWithOpts(
		sc.mo, team.WrapNamedPtr(fqt), proto.RTAppID_Chat,
		"", "", proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole},
		librt.MakeChannelOpts{}, nil,
	)
	require.NoError(t, err, "the guard must not block ordinary default-channel creation")
}
