package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// adHocTeamFixture holds the pieces a test needs to operate on a freshly
// created ad-hoc team.
type adHocTeamFixture struct {
	tew    *TestEnvWrapper
	vhost  *core.HostIDAndName
	alice  *TestUser
	others []*TestUser
	ma     libclient.MetaContext
	tma    *libclient.TeamMinder
	fqtp   proto.FQTeamParsed
	tid    proto.TeamID
}

// createAdHocTeamForTest builds an ad-hoc team on a fresh open vhost, owned by
// alice with nOthers additional founding owners.
func createAdHocTeamForTest(t *testing.T, nOthers int) *adHocTeamFixture {
	tew := testEnvBeta(t)
	vhost := tew.openVHost(t)

	alice := tew.NewTestUserAtVHost(t, vhost)
	others := make([]*TestUser, nOthers)
	othersFqpp := make([]lcl.FQPartyParsedAndRole, nOthers)
	for i := range nOthers {
		others[i] = tew.NewTestUserAtVHost(t, vhost)
		othersFqpp[i] = toFQParsedPartyAndRole(others[i])
		othersFqpp[i].Role = &proto.OwnerRole
	}

	// since we're writing to a secondary chain (in create), we need to poke merkle
	// so that the signing key is fully provisioned.
	tew.DirectDoubleMerklePokeInTest(t)

	ma := tew.NewClientMetaContext(t, alice)
	alice.addPUKsToMetaContext(t, ma)

	tma, err := ma.G().TeamMinder()
	require.NoError(t, err)

	tid, err := tma.CreateAdHoc(ma, othersFqpp)
	require.NoError(t, err)

	// Now watch the team get committed to the tree, so subsequent loads can
	// verify the eldest link's merkle inclusion path.
	tew.DirectDoubleMerklePokeInTest(t)

	hn := proto.NewParsedHostnameWithFalse(vhost.HostID.Id)
	return &adHocTeamFixture{
		tew:    tew,
		vhost:  vhost,
		alice:  alice,
		others: others,
		ma:     ma,
		tma:    tma,
		fqtp: proto.FQTeamParsed{
			Team: proto.NewParsedTeamWithFalse(*tid),
			Host: &hn,
		},
		tid: *tid,
	}
}

func (f *adHocTeamFixture) loadTeamViaUsernames(t *testing.T, specifyAlice bool) {
	usernames := []proto.NameUtf8{}
	if specifyAlice {
		usernames = append(usernames, f.alice.name)
	}
	for _, other := range f.others {
		usernames = append(usernames, other.name)
	}
	tma, err := f.ma.TeamMinder()
	require.NoError(t, err)
	tm, err := tma.LoadTeam(
		f.ma,
		lcl.NewConfigTeamWithAdhoc(
			proto.FQAdHocTeamParsed{
				Team: proto.NewAdHocTeamParsedWithNames(usernames),
			},
		),
		libclient.LoadTeamOpts{},
	)
	require.NoError(t, err)
	require.True(t, tm.FQTeam().Team.Eq(f.tid))
}

func (f *adHocTeamFixture) loadTeamViaUIDs(t *testing.T, specifyAlice bool) *proto.AdHocTeamMashedID {
	var uids []proto.UID
	if specifyAlice {
		uids = append(uids, f.alice.uid)
	}
	for _, other := range f.others {
		uids = append(uids, other.uid)
	}
	tma, err := f.ma.TeamMinder()
	require.NoError(t, err)
	tm, err := tma.LoadTeam(
		f.ma,
		lcl.NewConfigTeamWithAdhoc(
			proto.FQAdHocTeamParsed{
				Team: proto.NewAdHocTeamParsedWithIds(uids),
			},
		),
		libclient.LoadTeamOpts{},
	)
	require.NoError(t, err)
	require.True(t, tm.FQTeam().Team.Eq(f.tid))
	ret, err := team.MashUIDsIntoAdHocTeamID(uids, f.alice.host)
	require.NoError(t, err)
	return ret
}

func (f *adHocTeamFixture) loadTeamViaMashedID(t *testing.T, mashedID proto.AdHocTeamMashedID) {
	tma, err := f.ma.TeamMinder()
	require.NoError(t, err)
	tm, err := tma.LoadTeam(
		f.ma,
		lcl.NewConfigTeamWithAdhoc(
			proto.FQAdHocTeamParsed{
				Team: proto.NewAdHocTeamParsedWithId(mashedID.EntityID()),
			},
		),
		libclient.LoadTeamOpts{},
	)
	require.NoError(t, err)
	require.True(t, tm.FQTeam().Team.Eq(f.tid))
}

func TestSimpleCreateTeamAdHoc(t *testing.T) {
	defer common.DebugEntryAndExit()()

	f := createAdHocTeamForTest(t, 3)

	// Assert that alice can load the team
	_, _, err := libclient.LoadTeamReturnLoader(f.ma, libclient.LoadTeamArg{
		Team: proto.FQTeam{
			Team: f.tid,
			Host: f.ma.G().ActiveUser().HostID(),
		},
		As:      f.alice.FQUser().FQParty(),
		Keys:    f.alice.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)

	f.loadTeamViaUsernames(t, true)
	f.loadTeamViaUsernames(t, false)
	mashed := f.loadTeamViaUIDs(t, true)
	f.loadTeamViaUIDs(t, false)
	f.loadTeamViaMashedID(t, *mashed)
}

// TestAdHocTeamRejectsRemoteMemberOnServer confirms the server's team player
// only accepts ad-hoc teams whose membership is local users. The client refuses
// to build such a team on its own, so we use a test hook to rewrite a founder
// as remote just before the eldest link is signed, then assert the server fails
// the creation.
func TestAdHocTeamRejectsRemoteMemberOnServer(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	vhost := tew.openVHost(t)

	alice := tew.NewTestUserAtVHost(t, vhost)
	bob := tew.NewTestUserAtVHost(t, vhost)
	tew.DirectDoubleMerklePokeInTest(t)

	ma := tew.NewClientMetaContext(t, alice)
	alice.addPUKsToMetaContext(t, ma)
	tma, err := ma.G().TeamMinder()
	require.NoError(t, err)

	// Rewrite bob's membership to claim a different (remote) host. The signature
	// is computed after this mutation, so the link is well-formed; the server's
	// team player must still reject the cross-host member for an ad-hoc team.
	remoteHost := proto.HostID{0xbb}
	tma.TestHooks = &libclient.TeamMinderTestHooks{
		AdHocMutateFoundingMembers: func(mrs []proto.MemberRole) {
			require.Len(t, mrs, 1)
			mrs[0].Member.Id.Host = &remoteHost
		},
	}

	bobFqpp := toFQParsedPartyAndRole(bob)
	bobFqpp.Role = &proto.OwnerRole
	_, err = tma.CreateAdHoc(ma, []lcl.FQPartyParsedAndRole{bobFqpp})
	require.Equal(t,
		core.LinkError("ad-hoc team members must be local (same-host) users"), err)
}

// TestAdHocTeamRejectsMemberEdits checks that ad-hoc teams are immutable: both
// adding and removing members are rejected. The client refuses on its own; and
// with the client guard disabled via a test hook, the server independently
// rejects the edit too.
func TestAdHocTeamRejectsMemberEdits(t *testing.T) {
	defer common.DebugEntryAndExit()()

	f := createAdHocTeamForTest(t, 3)
	expErr := core.TeamError(team.AdHocTeamImmutableMsg)

	// A fresh user we'll attempt to add.
	dave := f.tew.NewTestUserAtVHost(t, f.vhost)
	f.tew.DirectDoubleMerklePokeInTest(t)

	addNewMember := func() error {
		return f.tma.Add(f.ma, lcl.TeamAddArg{
			Team:    f.fqtp,
			Members: []lcl.FQPartyParsedAndRole{toFQParsedPartyAndRole(dave)},
			DstRole: &proto.DefaultRole,
		})
	}

	// Attempt a remove by changing a member's role to NONE. We target the owner
	// (alice) since her wrapper is always loaded; the lookup of an arbitrary
	// founder is a separate concern, and the guard fires regardless of who the
	// target is.
	removeMember := func() error {
		victim := toFQParsedPartyAndRole(f.alice)
		victim.Role = &proto.OwnerRole
		return f.tma.TeamChangeRoles(f.ma, lcl.TeamChangeRolesArg{
			Team: f.fqtp,
			Changes: []lcl.RoleChange{{
				Member:  victim,
				NewRole: proto.NewRoleDefault(proto.RoleType_NONE),
			}},
		})
	}

	// With the guard on (production default), the client refuses both an add and
	// a remove before anything hits the wire.
	require.Equal(t, expErr, addNewMember())
	require.Equal(t, expErr, removeMember())

	// Disable the client-side guard and confirm the server rejects on its own.
	// We drive this with an add: a remove would fail client-side fetching the
	// (nonexistent) removal key before ever reaching the server.
	f.tma.TestHooks = &libclient.TeamMinderTestHooks{AllowAdHocTeamEdits: true}
	require.Equal(t, expErr, addNewMember())
}
