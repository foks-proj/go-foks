package lib

// Channel metadata mutation: rtUpdateChannel and rtSetChannelArchived.
//
// Three of these carry more weight than the rest, and each was checked by
// breaking the mechanism and confirming the test goes red:
//
//   - TestRTRenameResealsAtTierRole is the security test. A channel's name box
//     is sealed at a role determined by the channel's TIER, and a rename that
//     sealed at the caller's own role instead would either hand an admin-tier
//     channel's name to ordinary members or lock members out of a name they
//     could read a moment earlier. Nothing else would go red.
//   - TestRTArchivedNameStaysReserved pins the invariant archive rests on: an
//     archived channel keeps its place in the team's channel listing, so
//     nothing can take its name while it is away, so un-archiving cannot
//     collide. Names are PTK-encrypted, so a collision here is one the server
//     could never detect.
//   - TestRTArchivedLeavesTheInbox covers the half the server cannot do alone.
//     A delta of rows cannot express a removal, so an archived channel is
//     delivered once carrying the flag and the CLIENT drops it. Without that
//     handshake it would sit in every member's inbox forever.

import (
	"testing"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// mutScene is a team with one admin (ada), one ordinary member (mo), and a
// public channel to mutate, plus the default channel that a real team has.
type mutScene struct {
	tew     *TestEnvWrapper
	tm      *teamObj
	fqt     *proto.FQTeamParsed
	adaUser *TestUser
	ada     *librt.Minder
	adaM    librt.MetaContext
	mo      *librt.Minder
	moM     librt.MetaContext
	pubID   proto.RTChannelID
	pubName proto.RTChannelName
}

func setupRTMutScene(t *testing.T) *mutScene {
	tew := testEnvBeta(t)
	ada := tew.NewTestUser(t)
	mo := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, ada)
	m := tew.MetaContext()
	tm.makeChanges(t, m, ada,
		[]proto.MemberRole{mo.toMemberRole(t, proto.DefaultRole, tm.hepks)}, nil)

	adaM := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, ada))
	moM := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, mo))
	sc := &mutScene{
		tew:     tew,
		tm:      tm,
		fqt:     tm.ToFQTeamParsed(t),
		adaUser: ada,
		ada:     librt.NewMinder(adaM.G().ActiveUser()),
		adaM:    adaM,
		mo:      librt.NewMinder(moM.G().ActiveUser()),
		moM:     moM,
	}

	// The default channel first, as a real team has it: it goes in on the
	// team's first send. Without it the channel under test would be the team's
	// only one, which is not how anything else in this package behaves.
	_, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, "", "",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	sc.pubName = rtRandomChannelName(t, "pub-")
	chid, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.pubName, "a public channel",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)
	sc.pubID = *chid
	return sc
}

func rtRandomChannelName(t *testing.T, prefix string) proto.RTChannelName {
	nm, err := core.RandomDomain()
	require.NoError(t, err)
	return proto.RTChannelName(prefix + nm)
}

func (s *mutScene) teamCfg() lcl.ConfigTeam { return team.WrapNamedPtr(s.fqt) }

func (s *mutScene) spec() lcl.RTChannelSpecifier {
	return lcl.NewRTChannelSpecifierWithId(s.pubID)
}

func (s *mutScene) specFor(id proto.RTChannelID) lcl.RTChannelSpecifier {
	return lcl.NewRTChannelSpecifierWithId(id)
}

// find returns one channel from an actor's freshly-listed view, or nil when it
// is absent.
func (s *mutScene) find(
	t *testing.T, mndr *librt.Minder, m librt.MetaContext, id proto.RTChannelID,
) *lcl.RTChannelMetadataPlaintext {
	lst, err := mndr.ListAllChannelsForTeam(m, s.teamCfg(), proto.RTAppID_Chat)
	require.NoError(t, err)
	for i := range lst.Channels {
		if lst.Channels[i].Id.Eq(id) {
			return &lst.Channels[i]
		}
	}
	return nil
}

func (s *mutScene) setArchived(t *testing.T, archived bool) error {
	return s.ada.SetChannelArchived(s.adaM, s.teamCfg(), proto.RTAppID_Chat,
		s.spec(), archived)
}

// --- rename ---------------------------------------------------------------

// Only team admins may change channel metadata, and it is enforced on the
// server rather than only in the client.
func TestRTRenameRequiresAdmin(t *testing.T) {
	sc := setupRTMutScene(t)

	err := sc.mo.UpdateChannel(sc.moM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.spec(), rtRandomChannelName(t, "nope-"), "", false)
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)

	newName := rtRandomChannelName(t, "ok-")
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), newName, "renamed", false))
	require.Equal(t, newName, sc.find(t, sc.ada, sc.adaM, sc.pubID).Name)
}

// THE security test. A channel's name box is sealed at the role its TIER
// dictates -- MinRTRole for bottom, AdminRole for admin -- never at the role
// the caller happens to hold. Getting this wrong is silent: the rename
// succeeds, and either a name leaks downward or members who could read the old
// name cannot read the new one.
func TestRTRenameResealsAtTierRole(t *testing.T) {
	sc := setupRTMutScene(t)

	// Bottom tier, renamed by the team OWNER, whose own role is far above
	// MinRTRole. The box must still be sealed at the bottom tier's name role,
	// which is what lets an ordinary member read the new name.
	bottomName := rtRandomChannelName(t, "bottom-")
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), bottomName, "", false))
	fromMo := sc.find(t, sc.mo, sc.moM, sc.pubID)
	require.NotNil(t, fromMo, "an ordinary member must still see the channel")
	require.Equal(t, bottomName, fromMo.Name,
		"a bottom-tier rename must stay readable by ordinary members")

	// Admin tier: created at AdminRole, so its name is sealed at AdminRole and
	// an ordinary member must not be able to read it at all.
	adminID, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		rtRandomChannelName(t, "admin-"), "admins only",
		proto.RolePairOpt{Read: &proto.AdminRole, Write: &proto.AdminRole})
	require.NoError(t, err)

	renamed := rtRandomChannelName(t, "admin2-")
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.specFor(*adminID), renamed, "", false))
	got := sc.find(t, sc.ada, sc.adaM, *adminID)
	require.NotNil(t, got)
	require.Equal(t, renamed, got.Name)
	require.Equal(t, proto.RTChannelTier_Admin, got.Tier,
		"a rename must not move the channel between tiers")
	require.Nil(t, sc.find(t, sc.mo, sc.moM, *adminID),
		"an admin-tier channel's name must not become visible to an ordinary member")
}

// A rename has to reach OTHER members, not just the device that made it. This
// is the only test proving the channel-set version bump carries the new
// metadata across a second client; every single-actor test would pass with the
// bump missing entirely.
func TestRTRenameVisibleToOtherMembers(t *testing.T) {
	sc := setupRTMutScene(t)
	require.Equal(t, sc.pubName, sc.find(t, sc.mo, sc.moM, sc.pubID).Name)

	newName := rtRandomChannelName(t, "seen-")
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), newName, "now with a description", false))

	got := sc.find(t, sc.mo, sc.moM, sc.pubID)
	require.NotNil(t, got)
	require.Equal(t, newName, got.Name)
	require.NotNil(t, got.Desc)
	require.Equal(t, proto.RTChannelDesc("now with a description"), *got.Desc)
}

// Renaming onto a name another channel of the same tier already holds is
// refused. The server cannot compare ciphertext names, so this is the client's
// check -- but it is the only one there is.
func TestRTRenameOntoExistingNameFails(t *testing.T) {
	sc := setupRTMutScene(t)
	otherName := rtRandomChannelName(t, "other-")
	_, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		otherName, "", proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	err = sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.spec(), otherName, "", false)
	require.Error(t, err)
	require.IsType(t, core.RTChannelExistsError{}, err)

	// Renaming a channel to the name it already has is a no-op, not a clash
	// with itself.
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), sc.pubName, "", false))
}

// --- archive --------------------------------------------------------------

func TestRTArchiveRequiresAdmin(t *testing.T) {
	sc := setupRTMutScene(t)
	err := sc.mo.SetChannelArchived(sc.moM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.spec(), true)
	require.Error(t, err)
	require.IsType(t, core.PermissionError(""), err)
	require.NoError(t, sc.setArchived(t, true))
}

// An archived channel stops accepting messages, and says so rather than
// looking like a channel that does not exist.
func TestRTArchivedChannelRejectsSend(t *testing.T) {
	sc := setupRTMutScene(t)
	_, err := sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.spec(),
		[]byte("before"))
	require.NoError(t, err)

	require.NoError(t, sc.setArchived(t, true))

	_, err = sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.spec(),
		[]byte("after"))
	require.Error(t, err)
	require.IsType(t, core.RTChannelArchivedError{}, err)
}

// The invariant the archive design rests on: an archived channel stays in the
// team's channel listing carrying the flag, which is what reserves its name.
func TestRTArchivedStaysInTheListing(t *testing.T) {
	sc := setupRTMutScene(t)
	require.NoError(t, sc.setArchived(t, true))

	for _, who := range []struct {
		mndr *librt.Minder
		m    librt.MetaContext
	}{{sc.ada, sc.adaM}, {sc.mo, sc.moM}} {
		got := sc.find(t, who.mndr, who.m, sc.pubID)
		require.NotNil(t, got, "an archived channel must stay in the listing")
		require.True(t, got.Archived)
		require.Equal(t, sc.pubName, got.Name, "and keep its name, which is the point")
	}
}

// Nothing may take an archived channel's name while it is away. This is what
// makes un-archiving safe: the server cannot detect a name collision, so the
// only defence is that the collision never becomes possible.
func TestRTArchivedNameStaysReserved(t *testing.T) {
	sc := setupRTMutScene(t)
	require.NoError(t, sc.setArchived(t, true))

	_, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.pubName, "", proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.Error(t, err)
	require.IsType(t, core.RTChannelExistsError{}, err)

	require.NoError(t, sc.setArchived(t, false))
	require.False(t, sc.find(t, sc.ada, sc.adaM, sc.pubID).Archived)
}

// Renaming an archived channel is how its reserved name is released -- which
// is why the archived gate permits a rename. Without it, a name taken by a
// channel somebody archived could never be used again.
func TestRTRenamedArchivedFreesTheName(t *testing.T) {
	sc := setupRTMutScene(t)
	require.NoError(t, sc.setArchived(t, true))

	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), rtRandomChannelName(t, "retired-"), "", false))

	_, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.pubName, "reusing the freed name",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)
}

// Reading an archived channel by explicit id still works: archive hides a
// channel and closes it to new activity, it does not destroy it. In practice
// no client reaches one, because it is gone from the inbox.
func TestRTArchivedThreadStillReadableById(t *testing.T) {
	sc := setupRTMutScene(t)
	_, err := sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.spec(),
		[]byte("before the archive"))
	require.NoError(t, err)
	require.NoError(t, sc.setArchived(t, true))

	res, err := sc.ada.GetThreadRecentMsgs(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), 10)
	require.NoError(t, err, "an archived channel is hidden, not destroyed")
	require.Len(t, res.Msgs, 1)
	require.Equal(t, []byte("before the archive"), res.Msgs[0].Body)
}

// --- archive and the inbox ------------------------------------------------

// The half the server cannot do alone. A delta of rows cannot express a
// removal, so archiving re-stamps every member's delivery row and the channel
// arrives once more carrying the flag; the client is what drops it.
func TestRTArchivedLeavesTheInbox(t *testing.T) {
	sc := setupRTMutScene(t)
	_, err := sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.spec(),
		[]byte("hello"))
	require.NoError(t, err)

	_, err = sc.mo.SyncInbox(sc.moM, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.True(t, rtInboxHas(t, sc.mo, sc.moM, sc.pubID))

	require.NoError(t, sc.setArchived(t, true))

	_, err = sc.mo.SyncInbox(sc.moM, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.False(t, rtInboxHas(t, sc.mo, sc.moM, sc.pubID),
		"an archived channel must drop out of the inbox on the next sync")

	require.NoError(t, sc.setArchived(t, false))
	_, err = sc.mo.SyncInbox(sc.moM, proto.RTAppID_Chat)
	require.NoError(t, err)
	require.True(t, rtInboxHas(t, sc.mo, sc.moM, sc.pubID),
		"un-archiving must restore the channel to the inbox")
}

func rtInboxHas(
	t *testing.T, mndr *librt.Minder, m librt.MetaContext, id proto.RTChannelID,
) bool {
	view, err := mndr.LocalInbox(m, proto.RTAppID_Chat)
	require.NoError(t, err)
	for i := range view.Rows {
		if view.Rows[i].Ch.Id.Eq(id) {
			return true
		}
	}
	return false
}

// Archiving destroys nothing. After a round trip the thread is identical,
// which is the whole difference between archive and a delete.
func TestRTArchiveIsReversible(t *testing.T) {
	sc := setupRTMutScene(t)
	const n = 4
	for i := 0; i < n; i++ {
		_, err := sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
			sc.spec(), []byte{byte('a' + i)})
		require.NoError(t, err)
	}
	before, err := sc.ada.GetThreadRecentMsgs(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), n)
	require.NoError(t, err)
	require.Len(t, before.Msgs, n)

	require.NoError(t, sc.setArchived(t, true))
	require.NoError(t, sc.setArchived(t, false))

	after, err := sc.ada.GetThreadRecentMsgs(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.spec(), n)
	require.NoError(t, err)
	require.Len(t, after.Msgs, n)
	for i := range before.Msgs {
		require.Equal(t, before.Msgs[i].Seq, after.Msgs[i].Seq)
		require.Equal(t, before.Msgs[i].Body, after.Msgs[i].Body)
	}

	_, err = sc.ada.Send(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.spec(),
		[]byte("after the round trip"))
	require.NoError(t, err, "sending works again once the channel is back")
}

// The late-join fan-in must never create a delivery row for an archived
// channel. It runs on every sync whose membership marker moved, so a miss here
// would re-create the row -- and burn an inbox version -- for as long as the
// account exists.
func TestRTArchivedNotFannedInOnJoin(t *testing.T) {
	sc := setupRTMutScene(t)
	require.NoError(t, sc.setArchived(t, true))

	newbie := sc.tew.NewTestUser(t)
	sc.tm.makeChanges(t, sc.tew.MetaContext(), sc.adaUser,
		[]proto.MemberRole{newbie.toMemberRole(t, proto.DefaultRole, sc.tm.hepks)}, nil)
	nm := librt.NewMetaContext(sc.tew.NewClientMetaContextWithEracer(t, newbie))
	nMinder := librt.NewMinder(nm.G().ActiveUser())

	rows := func() int {
		m := sc.tew.MetaContext()
		db, err := m.Db(shared.DbTypeRealTime)
		require.NoError(t, err)
		defer db.Release()
		var n int
		require.NoError(t, db.QueryRow(m.Ctx(),
			`SELECT count(*) FROM user_channels
			 WHERE short_host_id=$1 AND channel_id=$2`,
			m.ShortHostID(), sc.pubID.Short().Int64()).Scan(&n))
		return n
	}
	// Baseline BEFORE the first sync: taking it afterwards would fold a
	// first-sync fan-in bug into the baseline itself.
	before := rows()
	for i := 0; i < 3; i++ {
		_, err := nMinder.SyncInbox(nm, proto.RTAppID_Chat)
		require.NoError(t, err)
		require.False(t, rtInboxHas(t, nMinder, nm, sc.pubID))
		require.Equal(t, before, rows(),
			"the fan-in must not create a delivery row for an archived channel")
	}
}

// --- duplicate names ---------------------------------------------------------

// AllowDuplicateName is for a caller that identifies channels by id: a name
// another channel has, and "general", become allowed on create and rename.
// The empty name never does -- it would make a second default channel.
func TestRTAllowDuplicateName(t *testing.T) {
	sc := setupRTMutScene(t)
	roles := proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole}
	dup := librt.MakeChannelOpts{AllowDuplicateName: true}

	// Without the flag: refused, as before.
	_, err := sc.ada.MakeChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat, sc.pubName, "", roles)
	require.IsType(t, core.RTChannelExistsError{}, err)

	// With it: a second channel of the same name.
	second, err := sc.ada.MakeChannelWithOpts(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.pubName, "", roles, dup, nil)
	require.NoError(t, err)
	require.False(t, second.Eq(sc.pubID))

	// "general" too, on create and on rename.
	gen, err := sc.ada.MakeChannelWithOpts(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		proto.RTGeneralChannel, "", roles, dup, nil)
	require.NoError(t, err)
	require.Error(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.specFor(*second), proto.RTGeneralChannel, "", false))
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.specFor(*second), proto.RTGeneralChannel, "", true))

	// Renaming onto a live name: refused without the flag, allowed with it.
	require.IsType(t, core.RTChannelExistsError{}, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(),
		proto.RTAppID_Chat, sc.specFor(*gen), sc.pubName, "", false))
	require.NoError(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.specFor(*gen), sc.pubName, "", true))

	// The empty name stays refused either way: on rename, and on create,
	// where the scene's default channel already holds it.
	require.Error(t, sc.ada.UpdateChannel(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		sc.specFor(*gen), "", "", true))
	_, err = sc.ada.MakeChannelWithOpts(sc.adaM, sc.teamCfg(), proto.RTAppID_Chat,
		"", "", roles, dup, nil)
	require.IsType(t, core.RTChannelExistsError{}, err)
}
