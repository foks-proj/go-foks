// Push holds: a team admin delegates the release of the team's pushes to one
// member, the holder.
//
// dara, a team admin, is the holder throughout. What is tested:
//   - under a hold, a send into a channel the holder can read writes 'held'
//     push rows, not 'queued' ones;
//   - only the holder decides held rows (keep, drop, one push per member);
//   - when the hold ends (cleared, or the holder left the team) the held rows
//     are queued.
package lib

import (
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

type pushHoldActor struct {
	u      *TestUser
	m      librt.MetaContext
	minder *librt.Minder
}

// pushHoldScene is a team with two owners (alice, cleo), two admins (dara,
// eddie) and one member (bob), each with their own client.
type pushHoldScene struct {
	tew    *TestEnvWrapper
	tm     *teamObj
	fqt    *proto.FQTeamParsed
	teamID proto.TeamID

	alice, bob, cleo, dara, eddie *pushHoldActor
}

func setupPushHoldScene(t *testing.T) *pushHoldScene {
	tew := testEnvBeta(t)
	users := make([]*TestUser, 5)
	for i := range users {
		users[i] = tew.NewTestUser(t)
	}
	tew.DirectDoubleMerklePokeInTest(t)
	alice, bob, cleo, dara, eddie := users[0], users[1], users[2], users[3], users[4]

	tm := tew.makeTeamForOwner(t, alice)
	tm.makeChanges(t, tew.MetaContext(), alice,
		[]proto.MemberRole{
			bob.toMemberRole(t, proto.DefaultRole, tm.hepks),
			cleo.toMemberRole(t, proto.OwnerRole, tm.hepks),
			dara.toMemberRole(t, proto.AdminRole, tm.hepks),
			eddie.toMemberRole(t, proto.AdminRole, tm.hepks),
		}, nil,
	)
	teamID, err := tm.id.ToTeamID()
	require.NoError(t, err)

	// No client caches, so every read is answered by the server.
	actor := func(u *TestUser) *pushHoldActor {
		m := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, u))
		return &pushHoldActor{
			u:      u,
			m:      m,
			minder: librt.NewMinderWithCacheSettings(m.G().ActiveUser(), libclient.CacheSettings{}),
		}
	}
	return &pushHoldScene{
		tew:    tew,
		tm:     tm,
		fqt:    tm.ToFQTeamParsed(t),
		teamID: teamID,
		alice:  actor(alice),
		bob:    actor(bob),
		cleo:   actor(cleo),
		dara:   actor(dara),
		eddie:  actor(eddie),
	}
}

func (s *pushHoldScene) teamCfg() lcl.ConfigTeam { return team.WrapNamedPtr(s.fqt) }

// makeChannel creates a channel whose read and write roles are both role.
func (s *pushHoldScene) makeChannel(
	t *testing.T, by *pushHoldActor, role proto.Role, opts librt.MakeChannelOpts,
) proto.RTChannelID {
	nm, err := core.RandomDomain()
	require.NoError(t, err)
	chid, err := by.minder.MakeChannelWithOpts(
		by.m, s.teamCfg(), proto.RTAppID_Chat,
		proto.RTChannelName("ph-"+nm), "push hold test channel",
		proto.RolePairOpt{Read: &role, Write: &role},
		opts, nil,
	)
	require.NoError(t, err)
	return *chid
}

func (s *pushHoldScene) send(
	t *testing.T, by *pushHoldActor, chid proto.RTChannelID, body string,
) proto.RTMsgSeq {
	res, err := by.minder.Send(by.m, s.teamCfg(), proto.RTAppID_Chat,
		lcl.NewRTChannelSpecifierWithId(chid), []byte(body))
	require.NoError(t, err)
	return res.Seq
}

func (s *pushHoldScene) setHold(t *testing.T, by *pushHoldActor) {
	require.NoError(t, by.minder.SetPushHold(by.m, s.teamCfg(), proto.RTAppID_Chat))
}

func (s *pushHoldScene) rtdbCount(t *testing.T, q string, args ...any) int {
	m := s.tew.MetaContext()
	db, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer db.Release()
	var n int
	require.NoError(t, db.QueryRow(m.Ctx(), q, args...).Scan(&n))
	return n
}

func (s *pushHoldScene) holdCount(t *testing.T) int {
	return s.rtdbCount(t, `SELECT count(*) FROM push_holds WHERE team_id=$1`, s.teamID.ExportToDB())
}

// pushRows counts one actor's push rows in a channel, by status.
func (s *pushHoldScene) pushRows(
	t *testing.T, chid proto.RTChannelID, a *pushHoldActor,
) map[string]int {
	m := s.tew.MetaContext()
	db, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer db.Release()
	rows, err := db.Query(m.Ctx(),
		`SELECT status::text, count(*) FROM push_outbox
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3
		 GROUP BY status`,
		m.ShortHostID(), chid.Short().Int64(), a.u.uid.ExportToDB())
	require.NoError(t, err)
	defer rows.Close()
	ret := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		require.NoError(t, rows.Scan(&st, &n))
		ret[st] = n
	}
	require.NoError(t, rows.Err())
	return ret
}

// queuedSeqs lists the seqs of one actor's queued push rows in a channel.
func (s *pushHoldScene) queuedSeqs(
	t *testing.T, chid proto.RTChannelID, a *pushHoldActor,
) []int64 {
	m := s.tew.MetaContext()
	db, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer db.Release()
	rows, err := db.Query(m.Ctx(),
		`SELECT seq FROM push_outbox
		 WHERE short_host_id=$1 AND channel_id=$2 AND uid=$3 AND status='queued'
		 ORDER BY seq`,
		m.ShortHostID(), chid.Short().Int64(), a.u.uid.ExportToDB())
	require.NoError(t, err)
	defer rows.Close()
	var ret []int64
	for rows.Next() {
		var seq int64
		require.NoError(t, rows.Scan(&seq))
		ret = append(ret, seq)
	}
	require.NoError(t, rows.Err())
	return ret
}

func held(n int) map[string]int   { return map[string]int{"held": n} }
func queued(n int) map[string]int { return map[string]int{"queued": n} }

func TestRTPushHoldSetNeedsAdmin(t *testing.T) {
	sc := setupPushHoldScene(t)

	err := sc.bob.minder.SetPushHold(sc.bob.m, sc.teamCfg(), proto.RTAppID_Chat)
	require.True(t, core.IsPermissionError(err), "a plain member set a hold: %v", err)
	require.Equal(t, 0, sc.holdCount(t))

	sc.setHold(t, sc.dara)
	require.Equal(t, 1, sc.holdCount(t))
	// Setting it again, here by another admin, replaces the holder.
	sc.setHold(t, sc.eddie)
	require.Equal(t, 1, sc.holdCount(t))
}

func TestRTPushHoldMatrix(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	quiet := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{NoPush: true})
	// Read role above the holder's (admin) role.
	owners := sc.makeChannel(t, sc.alice, proto.OwnerRole, librt.MakeChannelOpts{})

	// No hold: rows are queued.
	sc.send(t, sc.bob, ch, "before any hold")
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.cleo))

	sc.setHold(t, sc.dara)

	sc.send(t, sc.bob, ch, "under the hold")
	require.Equal(t, map[string]int{"queued": 1, "held": 1}, sc.pushRows(t, ch, sc.cleo))

	// The holder's own sends are held too.
	sc.send(t, sc.dara, ch, "from the holder")
	require.Equal(t, map[string]int{"queued": 1, "held": 2}, sc.pushRows(t, ch, sc.cleo))

	// A channel the holder cannot read is not covered.
	sc.send(t, sc.alice, owners, "owners only")
	require.Equal(t, queued(1), sc.pushRows(t, owners, sc.cleo))

	// A no-push channel still writes no rows.
	sc.send(t, sc.bob, quiet, "control traffic")
	require.Empty(t, sc.pushRows(t, quiet, sc.cleo))
}

func TestRTPushReleaseKeepDropCoalesce(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)

	sc.send(t, sc.bob, ch, "one")
	s2 := sc.send(t, sc.bob, ch, "two")
	s3 := sc.send(t, sc.bob, ch, "three")

	release := func(keep []proto.UID, drop []rem.RTPushDrop) {
		require.NoError(t, sc.dara.minder.ReleasePushes(sc.dara.m, ch, s3, keep, drop))
	}
	release(
		[]proto.UID{sc.cleo.u.uid},
		[]rem.RTPushDrop{{Uid: sc.eddie.u.uid, Seq: s3}},
	)

	// alice: three held rows become one push, for the newest message.
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.alice))
	require.Equal(t, []int64{s3.Int64()}, sc.queuedSeqs(t, ch, sc.alice))
	// cleo: kept, untouched.
	require.Equal(t, held(3), sc.pushRows(t, ch, sc.cleo))
	// eddie: seq 3 dropped; of the rest, only the newest is queued.
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.eddie))
	require.Equal(t, []int64{s2.Int64()}, sc.queuedSeqs(t, ch, sc.eddie))

	// Repeating the call changes nothing.
	release(
		[]proto.UID{sc.cleo.u.uid},
		[]rem.RTPushDrop{{Uid: sc.eddie.u.uid, Seq: s3}},
	)
	require.Equal(t, held(3), sc.pushRows(t, ch, sc.cleo))
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.alice))
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.eddie))

	// Releasing cleo later: one push.
	release(nil, nil)
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.cleo))
	require.Equal(t, []int64{s3.Int64()}, sc.queuedSeqs(t, ch, sc.cleo))
}

// A release only touches rows up to throughSeq. A member kept in a call for a
// newer seq and dropped in a call for an older one ends with the older rows
// decided and the newer ones still held.
func TestRTPushReleaseThroughSeq(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)
	s1 := sc.send(t, sc.bob, ch, "one")
	s2 := sc.send(t, sc.bob, ch, "two")
	sc.send(t, sc.bob, ch, "three")
	s4 := sc.send(t, sc.bob, ch, "four")

	require.NoError(t, sc.dara.minder.ReleasePushes(sc.dara.m, ch, s4,
		[]proto.UID{sc.eddie.u.uid}, nil))
	require.NoError(t, sc.dara.minder.ReleasePushes(sc.dara.m, ch, s2,
		nil, []rem.RTPushDrop{{Uid: sc.eddie.u.uid, Seq: s1}}))

	require.Equal(t, []int64{s4.Int64()}, sc.queuedSeqs(t, ch, sc.alice))
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.alice))
	// eddie: 1 dropped, 2 queued, 3 and 4 still held.
	require.Equal(t, []int64{s2.Int64()}, sc.queuedSeqs(t, ch, sc.eddie))
	require.Equal(t, map[string]int{"queued": 1, "held": 2}, sc.pushRows(t, ch, sc.eddie))
}

func TestRTPushReleaseNonHolderDenied(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)
	s := sc.send(t, sc.bob, ch, "held")

	// alice owns the team but is not the holder.
	err := sc.alice.minder.ReleasePushes(sc.alice.m, ch, s, nil, nil)
	require.True(t, core.IsPermissionError(err), "got %v", err)
	err = sc.alice.minder.NotifyMembers(sc.alice.m, ch,
		[]rem.RTPushNotify{{Uid: sc.bob.u.uid}})
	require.True(t, core.IsPermissionError(err), "got %v", err)
	require.Equal(t, held(1), sc.pushRows(t, ch, sc.cleo))
	require.Empty(t, sc.pushRows(t, ch, sc.bob))
}

func TestRTPushNotify(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.alice, proto.AdminRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)

	// eddie was fanned into the channel as an admin; demoted, he can no
	// longer read it, though his user_channels row remains.
	sc.tm.makeChanges(t, sc.tew.MetaContext(), sc.alice.u,
		[]proto.MemberRole{
			sc.eddie.u.toMemberRole(t, proto.DefaultRole, sc.tm.hepks),
		}, nil)

	handle := []byte("0123456789abcdef")
	require.NoError(t, sc.dara.minder.NotifyMembers(sc.dara.m, ch, []rem.RTPushNotify{
		{Uid: sc.cleo.u.uid, Handle: handle},
		{Uid: sc.cleo.u.uid, Handle: []byte("again")}, // listed twice: one push
		{Uid: sc.eddie.u.uid, Handle: handle},         // role too low
		{Uid: sc.bob.u.uid, Handle: handle},           // never in the channel
	}))
	require.Equal(t, queued(1), sc.pushRows(t, ch, sc.cleo))
	require.Equal(t, 1, sc.rtdbCount(t,
		`SELECT count(*) FROM push_outbox
		 WHERE channel_id=$1 AND uid=$2 AND kind='system' AND seq IS NULL AND data=$3`,
		ch.Short().Int64(), sc.cleo.u.uid.ExportToDB(), handle))
	require.Empty(t, sc.pushRows(t, ch, sc.eddie))
	require.Empty(t, sc.pushRows(t, ch, sc.bob))

	err := sc.dara.minder.NotifyMembers(sc.dara.m, ch, []rem.RTPushNotify{
		{Uid: sc.cleo.u.uid, Handle: make([]byte, 33)},
	})
	require.Error(t, err, "a handle over 32 bytes must be refused")
}

func TestRTPushHoldClearReleases(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)
	sc.send(t, sc.bob, ch, "one")
	sc.send(t, sc.bob, ch, "two")

	err := sc.bob.minder.ClearPushHold(sc.bob.m, sc.teamCfg(), proto.RTAppID_Chat)
	require.True(t, core.IsPermissionError(err), "a plain member cleared a hold: %v", err)
	require.Equal(t, held(2), sc.pushRows(t, ch, sc.cleo))

	// Another admin clears it: every held row is queued as is.
	require.NoError(t, sc.alice.minder.ClearPushHold(sc.alice.m, sc.teamCfg(), proto.RTAppID_Chat))
	require.Equal(t, 0, sc.holdCount(t))
	require.Equal(t, queued(2), sc.pushRows(t, ch, sc.cleo))
	sc.send(t, sc.bob, ch, "after")
	require.Equal(t, queued(3), sc.pushRows(t, ch, sc.cleo))
}

func TestRTPushHoldHolderLeftEndsOnSend(t *testing.T) {
	sc := setupPushHoldScene(t)
	ch := sc.makeChannel(t, sc.bob, proto.DefaultRole, librt.MakeChannelOpts{})
	sc.setHold(t, sc.dara)
	sc.send(t, sc.bob, ch, "held")
	require.Equal(t, held(1), sc.pushRows(t, ch, sc.cleo))

	sc.tm.makeChanges(t, sc.tew.MetaContext(), sc.alice.u,
		[]proto.MemberRole{
			sc.dara.u.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), nil),
		}, nil)

	sc.send(t, sc.bob, ch, "the next send")
	require.Equal(t, queued(2), sc.pushRows(t, ch, sc.cleo),
		"the held row is queued, and so is the new one")
	require.Equal(t, 0, sc.holdCount(t))
}
