// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestSimpleCreateTeam(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()

	// since we're writing to a secondary chain (in create), we need to poke merkle
	// so that the signing key is fully provisioned.
	tew.DirectDoubleMerklePokeInTest(t)

	team := tew.makeTeamForOwner(t, u)

	// now watch the team get committed to the tree
	tew.DirectDoubleMerklePokeInTest(t)

	// Check merkle data is updated on commiting of team links to tree
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	var cnt int
	err = db.QueryRow(m.Ctx(),
		`SELECT COUNT(*) FROM team_members 
		WHERE short_host_id=$1 AND team_id=$2 AND tree_epno IS NOT NULL`,
		m.ShortHostID().ExportToDB(),
		team.id.ExportToDB(),
	).Scan(&cnt)
	require.NoError(t, err)
	require.Equal(t, 1, cnt)

}

func TestCreateTeamEvil(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)

	pukSs := core.RandomSecretSeed32()
	puk, err := core.NewSharedPrivateSuite25519(
		proto.EntityType_User,
		proto.OwnerRole,
		pukSs,
		proto.Generation(0),
		u.host,
	)
	require.NoError(t, err)
	tew.DirectDoubleMerklePokeInTest(t)

	// Test bad PUK
	_, err = tew.makeTeamForOwnerEvil(t, u, makeTeamForOwnerEvilOpts{
		puker: func() core.SharedPrivateSuiter {
			return puk
		},
	})
	require.Error(t, err)
	require.Equal(t, core.LinkError("bad signing key for signer"), err)

	_, err = tew.makeTeamForOwnerEvil(t, u, makeTeamForOwnerEvilOpts{wrongRemovalKey: true})
	require.Error(t, err)
	require.Equal(t, core.TeamError("removal key commitment doesn't match"), err)

	_, err = tew.makeTeamForOwnerEvil(t, u, makeTeamForOwnerEvilOpts{missingRemovalKeyBox: true})
	require.Error(t, err)
	require.Equal(t, core.TeamError("wrong number of removal keys; should equal number of new members"), err)

	// Test it actually works if we are not evil
	_, err = tew.makeTeamForOwnerEvil(t, u, makeTeamForOwnerEvilOpts{})
	require.NoError(t, err)
}

func TestTeamSigningKeyStress(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	a := tew.NewTestUserFakeRoot(t)
	b := tew.NewTestUserFakeRoot(t)

	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, u)
	tew.DirectDoubleMerklePokeInTest(t)
	m := tew.MetaContext()

	// add a as an admin
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			a.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_ADMIN), tm.hepks),
		},
		nil,
	)

	// now a tries to sign with a key that shouldn't work
	_, err := tm.makeChangesFull(t,
		m,
		a,
		[]proto.MemberRole{
			b.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_ADMIN), tm.hepks),
		},
		nil,
		makeChangesKnobs{
			teamSigPuker: func() core.SharedPrivateSuiter {
				pukSs := core.RandomSecretSeed32()
				puk, err := core.NewSharedPrivateSuite25519(
					proto.EntityType_User,
					proto.OwnerRole,
					pukSs,
					proto.FirstGeneration,
					u.host,
				)
				require.NoError(t, err)
				return puk
			},
		},
	)
	require.Error(t, err)
	require.Equal(t, core.TeamError("member verify key mismatch"), err)

	oldPuk := a.puks[core.OwnerRole]
	beta := a.ProvisionNewDevice(t, a.eldest, "beta 2.2b", proto.DeviceType_Computer, proto.OwnerRole)
	tew.DirectMerklePokeForLeafCheck(t)

	tr := getCurrentTreeRoot(t, m)
	// Force a rotation via revoke
	a.RevokeDeviceWithTreeRoot(t, a.eldest, beta, &tr)
	tew.DirectMerklePokeForLeafCheck(t)

	// now a does an actual rotation that should work
	_, err = tm.makeChangesFull(t,
		m,
		a,
		[]proto.MemberRole{
			a.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_ADMIN), tm.hepks),
		},
		nil,
		makeChangesKnobs{
			teamSigPuker: func() core.SharedPrivateSuiter {
				return &oldPuk
			},
			gamePlanPuker: func() core.SharedPrivateSuiter {
				return &oldPuk
			},
		},
	)
	require.NoError(t, err)

	// Admin cannot demote an owner
	var didRpc bool
	_, err = tm.makeChangesFull(t,
		m,
		a,
		[]proto.MemberRole{
			u.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_ADMIN), tm.hepks),
		},
		nil,
		makeChangesKnobs{
			gameplanOpts: &team.GameplanOpts{
				TestingNoCheck: true,
			},
			rpcCompleteHook: func() {
				didRpc = true
			},
		},
	)
	require.Error(t, err)
	require.Equal(t, core.TeamRosterError("doer role insufficient for change"), err)
	require.True(t, didRpc)

	// a gets a demotion, poor a!
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			a.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks),
		},
		nil,
	)

	// a is now impotent
	_, err = tm.makeChangesFull(t,
		m,
		a,
		[]proto.MemberRole{
			b.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks),
		},
		nil,
		makeChangesKnobs{},
	)
	require.Error(t, err)
	require.Equal(t, core.TeamRosterError("doer doesn't have privileged role"), err)
}

func verifyDeleted(t *testing.T, m shared.MetaContext, u *TestUser, team *teamObj) {
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	var cnt int
	err = db.QueryRow(m.Ctx(),
		`SELECT COUNT(*) FROM team_members 
		WHERE short_host_id=$1 AND team_id=$2 AND member_id=$3 AND member_host_id=$4 AND active=TRUE`,
		m.ShortHostID().ExportToDB(),
		team.id.ExportToDB(),
		u.uid.EntityID().ExportToDB(),
		shared.ExportHostInScope(m, u.host),
	).Scan(&cnt)
	require.NoError(t, err)
	require.Equal(t, 0, cnt)
}

func TestCreateTeamAddLocalMembers(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	v := tew.NewTestUserFakeRoot(t)
	w := tew.NewTestUserFakeRoot(t)
	x := tew.NewTestUserFakeRoot(t)

	m := tew.MetaContext()

	doublePoke(t, m)
	team := tew.makeTeamForOwner(t, u)

	// add v as admin, and w as reader
	team.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			v.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_ADMIN), team.hepks),
			w.toMemberRole(t, proto.NewRoleWithMember(0), team.hepks),
		},
		nil,
	)

	// add x as owner, and downgrade v to reader
	team.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			x.toMemberRole(t, proto.OwnerRole, team.hepks),
			v.toMemberRole(t, proto.NewRoleWithMember(-10), team.hepks),
		},
		nil,
	)

	// Remove w from the team
	team.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			w.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), nil),
		},
		nil,
	)

	verifyDeleted(t, m, w, team)
}

func TestTeamMaxRoles(t *testing.T) {
	defer common.DebugEntryAndExit()()
	tew := testEnvBeta(t)

	cfgJson, ok := tew.G.Config().(*shared.ConfigJSonnet)
	require.True(t, ok)
	tmOrig := cfgJson.Data.Team
	defer func() {
		cfgJson.Data.Team = tmOrig
	}()
	cfgJson.Data.Team = &shared.TeamConfigJSON{
		MaxRoles_: 5,
	}

	u := tew.NewTestUser(t)
	x := tew.NewTestUser(t)
	y := tew.NewTestUser(t)
	z := tew.NewTestUser(t)
	m := tew.MetaContext()

	doublePoke(t, m)
	team := tew.makeTeamForOwner(t, u)
	_, err := team.makeChangesFull(t,
		m,
		u,
		[]proto.MemberRole{
			x.toMemberRole(t, proto.NewRoleWithMember(-1), team.hepks),
			y.toMemberRole(t, proto.NewRoleWithMember(-2), team.hepks),
			z.toMemberRole(t, proto.NewRoleWithMember(-3), team.hepks),
		},
		nil,
		makeChangesKnobs{},
	)
	require.Error(t, err)
	require.Equal(t,
		core.TeamRosterError("too many roles (7); max is 5"),
		err,
	)
}

func TestCreateTeamAddRemoteMember(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	v := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()

	doublePoke(t, m)
	team := tew.makeTeamForOwner(t, u)

	rdr := v.toMemberRole(t, proto.NewRoleWithMember(0), team.hepks)
	randomHost := core.RandomHostID()
	rdr.Member.Id.Host = &randomHost

	// make a new user at a random host
	team.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{rdr},
		nil,
	)

	// remove that user too
	rdr.DstRole = proto.NewRoleDefault(proto.RoleType_NONE)
	rdr.Member.Keys = proto.NewMemberKeysWithNone()
	team.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{rdr},
		nil,
	)
}

func TestTeamBearerTokenHappyPath(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, u)
	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	defer closer()
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)

	gen := proto.FirstGeneration

	tok, err := tcli.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: tid,
		Role: proto.OwnerRole,
		Gen:  gen,
	})
	require.NoError(t, err)
	ptk := tm.ptks[core.OwnerRole]
	require.NotNil(t, ptk)

	sig, obj, err := team.SignBearerTokenChallenge(
		u.FQUser(), tid, proto.OwnerRole, gen, tok, ptk)
	require.NoError(t, err)

	err = tcli.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	require.NoError(t, err)

	hid := m.HostID()
	mTmp := m.WithUserHost(
		shared.UserHostContext{
			HostID: &hid,
			Uid:    u.uid,
		},
	)

	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	tidp, rolep, err := shared.LoadBearerToken(mTmp, db, tok, 0)
	require.NoError(t, err)
	require.Equal(t, tid, *tidp)
	require.Equal(t, proto.OwnerRole, *rolep)

	tid2, err := tcli.CheckTeamBearerToken(m.Ctx(), tok)
	require.NoError(t, err)
	require.Equal(t, tid, tid2)

}

func TestTeamBearerTokenSadPaths(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	v := tew.NewTestUserFakeRoot(t)
	o2 := tew.NewTestUserFakeRoot(t)
	z := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, u)
	tm2 := tew.makeTeamForOwner(t, z)
	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	tcli2, closer2 := z.newTeamAdminClient(t, m.Ctx())
	defer closer()
	defer closer2()
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)

	// have a second owner up in so we can do a ptk rotation later.
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_OWNER), tm.hepks),
		},
		nil,
	)

	gen := proto.FirstGeneration

	tok, err := tcli.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: tid,
		Role: proto.OwnerRole,
		Gen:  gen,
	})
	require.NoError(t, err)
	ptk := tm.ptks[core.OwnerRole]
	require.NotNil(t, ptk)

	// inert bearer tokens can't pass a check...
	_, err = tcli.CheckTeamBearerToken(m.Ctx(), tok)
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "state"}, err)

	// can't lie about which UID is doing the work
	sig, obj, err := team.SignBearerTokenChallenge(
		v.FQUser(), tid, proto.OwnerRole, gen, tok, ptk)
	require.NoError(t, err)
	err = tcli.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, core.PermissionError("wrong UID"), err)

	// bad signatures fail
	sig, obj, err = team.SignBearerTokenChallenge(
		u.FQUser(), tid, proto.OwnerRole, gen, tok, ptk)
	require.NoError(t, err)
	sig.F_0__[3] ^= 0x1
	err = tcli.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, core.VerifyError("signature verification failed"), err)

	// z is the legit owner of team tm2, but he tries to make a bearer token for team tm.
	// It should fail in the sig stage.
	tok2, err := tcli2.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: tid,
		Role: proto.OwnerRole,
		Gen:  gen,
	})
	require.NoError(t, err)
	ptk2 := tm2.ptks[core.OwnerRole]
	require.NotNil(t, ptk2)
	sig, obj, err = team.SignBearerTokenChallenge(
		z.FQUser(), tid, proto.OwnerRole, gen, tok2, ptk2)
	require.NoError(t, err)
	err = tcli2.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  obj,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, core.VerifyError("signature verification failed"), err)

	// Can't request a bearer token for a team that doesn't exist.
	badTeam := tid
	badTeam[3] ^= 0x1
	_, err = tcli.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: badTeam,
		Role: proto.OwnerRole,
		Gen:  gen,
	})
	require.Error(t, err)
	require.Equal(t, core.TeamNotFoundError{}, err)

	// Can't sign a bearer token with a stale timestamp.
	tok, err = tcli.MakeInertTeamBearerToken(m.Ctx(), rem.MakeInertTeamBearerTokenArg{
		Team: tid,
		Role: proto.OwnerRole,
		Gen:  gen,
	})
	require.NoError(t, err)
	ptk = tm.ptks[core.OwnerRole]
	require.NotNil(t, ptk)
	p := rem.TeamBearerTokenChallengePayload{
		User: u.FQUser(),
		Team: tid,
		Role: proto.OwnerRole,
		Tok:  tok,
		Tm:   proto.Now() - 24*60*60*1000,
		Gen:  gen,
	}
	sig, o, err := core.Sign2(ptk, &p)
	require.NoError(t, err)
	err = tcli.ActivateTeamBearerToken(m.Ctx(), rem.ActivateTeamBearerTokenArg{
		Bl:  *o,
		Sig: *sig,
	})
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "time"}, err)

	// OK now get the token for reals, Force a team rotation,
	// and check it expires.
	tok = makeTeamBearerToken(t, u, tm, core.OwnerRole)
	tm.makeChanges(t,
		m,
		u,
		[]proto.MemberRole{
			o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), tm.hepks),
		},
		nil,
	)
	_, err = tcli.CheckTeamBearerToken(m.Ctx(), tok)
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "gen"}, err)

	// Make sure it expires -- not this plan could possible race if time travel
	// is on for a concurrent test.
	tok = makeTeamBearerToken(t, u, tm, core.OwnerRole)
	tew.UserSrv().SetTestTimeTravel(24 * time.Hour)
	_, err = tcli.CheckTeamBearerToken(m.Ctx(), tok)
	require.Error(t, err)
	require.Equal(t, core.TeamBearerTokenStaleError{Which: "age"}, err)
	tew.UserSrv().SetTestTimeTravel(0)

	// Ok, time traveling back should allow the token to work again.
	_, err = tcli.CheckTeamBearerToken(m.Ctx(), tok)
	require.NoError(t, err)

	// A different user can't use this bearer token.
	_, err = tcli2.CheckTeamBearerToken(m.Ctx(), tok)
	require.Error(t, core.WrongUserError{}, err)
}

func TestTeamCertHappyPath(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	o2 := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, u)

	ptk0 := tm.ptks[core.AdminRole]

	cert, err := team.MakeTeamCert(
		tm.FQTeam(t),
		ptk0,
		ptk0,
		tm.nm,
	)
	require.NoError(t, err)
	b0, err := core.EncodeToBytes(cert)
	require.NoError(t, err)

	_, err = team.OpenTeamCert(*cert)
	require.NoError(t, err)

	// have a second owner, then force a rotation.
	tm.makeChanges(t, m, u, []proto.MemberRole{
		o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_OWNER), tm.hepks),
	}, nil)
	tm.makeChanges(t, m, u, []proto.MemberRole{
		o2.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), tm.hepks),
	}, nil)

	pkt := tm.ptks[core.AdminRole]
	cert, err = team.MakeTeamCert(
		tm.FQTeam(t),
		ptk0,
		pkt,
		tm.nm,
	)
	require.NoError(t, err)
	b1, err := core.EncodeToBytes(cert)
	require.NoError(t, err)

	_, err = team.OpenTeamCert(*cert)
	require.NoError(t, err)

	require.Greater(t, len(b1), len(b0))
}

func (tm *teamObj) countRemoteJoinReqs(t *testing.T, m shared.MetaContext, nPending int, nActive int) {
	db, err := m.Db(shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	rows, err := db.Query(m.Ctx(),
		`SELECT COUNT(*), state FROM remote_joinreqs
		WHERE short_host_id=$1 AND team_id=$2
		GROUP BY state`,
		m.ShortHostID().ExportToDB(),
		tm.id.ExportToDB(),
	)
	require.NoError(t, err)
	defer rows.Close()
	var cnt int
	var s string
	for rows.Next() {
		err = rows.Scan(&cnt, &s)
		require.NoError(t, err)
		switch shared.JoinReqState(s) {
		case shared.JoinReqStatePending:
			require.Equal(t, nPending, cnt)
		case shared.JoinReqStateApproved:
			require.Equal(t, nActive, cnt)
		default:
			require.Fail(t, "bad state")
		}
	}
}

func TestTeamRemoteTeamInviteSequence(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, u)
	ptk := tm.ptks[core.AdminRole]
	require.NotNil(t, ptk)

	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	teamBearerTok := makeTeamBearerToken(t, u, tm, core.OwnerRole)

	tcli, closer := u.newTeamAdminClient(t, m.Ctx())
	defer closer()
	err = tcli.PutTeamCert(m.Ctx(), rem.PutTeamCertArg{
		Tok:  teamBearerTok,
		Cert: *cert,
	})
	require.NoError(t, err)
	var hsh proto.TeamCertHash

	// This hash is now something we can post into groups, etc
	err = core.PrefixedHashInto(cert, hsh[:])
	require.NoError(t, err)

	i1 := proto.TeamInviteV1{
		Hsh:  hsh,
		Host: u.host,
	}
	invite := proto.NewTeamInviteWithV1(i1)
	ib, err := core.EncodeToBytes(&invite)
	require.NoError(t, err)
	fmt.Printf("Invite: %s\n", core.B62Encode(ib))

	tgcli, tgcloser := u.newTeamGuestClient(t, m.Ctx())
	defer tgcloser()

	cert2, err := tgcli.LookupTeamCertByHash(m.Ctx(), invite)
	require.NoError(t, err)
	require.Equal(t, *cert, cert2.Cert)
	var hsh2 proto.TeamCertHash
	err = core.PrefixedHashInto(&cert2.Cert, hsh2[:])
	require.NoError(t, err)
	require.Equal(t, hsh2, i1.Hsh)

	vHostID := tew.VHostMakeI(t, 0)
	x := tew.NewTestUserAtVHost(t, vHostID)
	xcli, xcloser := x.newUserCertAndClient(t, m.Ctx())
	defer xcloser()
	v, err := cert2.Cert.GetV()
	require.NoError(t, err)
	require.Equal(t, rem.TeamCertVersion_V1, v)
	tmp := cert2.Cert.V1().Payload
	certPayload, err := tmp.AllocAndDecode(core.DecoderFactory{})
	require.NoError(t, err)

	vtok, err := xcli.GrantRemoteViewPermissionForUser(m.Ctx(),
		rem.GrantRemoteViewPermissionPayload{
			Viewee: x.uid.ToPartyID(),
			Viewer: certPayload.Team.FQParty(),
			Tm:     proto.Now(),
		},
	)
	require.NoError(t, err)

	rjrp := rem.TeamRemoteJoinReqPayload{
		Joiner:  x.FQUser().FQParty(),
		Tok:     vtok,
		Tm:      proto.Now(),
		SrcRole: proto.OwnerRole,
	}

	ptkPub, err := core.ImportSPSBoxerFromTeamCert(certPayload)
	require.NoError(t, err)

	xpuk, ok := x.puks[core.OwnerRole]
	require.True(t, ok)
	box, err := xpuk.BoxFor(&rjrp, ptkPub, core.BoxOpts{IncludePublicKey: true})
	require.NoError(t, err)

	jr := rem.TeamRemoteJoinReq{
		Box:    *box,
		HepkFp: ptkPub.HepkFp,
	}

	jrtok, err := tgcli.AcceptInviteRemote(m.Ctx(), rem.AcceptInviteRemoteArg{
		Jr: jr,
		I:  invite,
	})
	require.NoError(t, err)
	fmt.Printf("JRToken %s\n", core.B62Encode(jrtok[:]))

	// ok now user u processes this
	jr2, err := tcli.LoadTeamRemoteJoinReq(m.Ctx(), rem.LoadTeamRemoteJoinReqArg{
		Tok: teamBearerTok,
		Jrt: jrtok,
	})
	require.NoError(t, err)
	require.Equal(t, jr, jr2)

	var rjrp2 rem.TeamRemoteJoinReqPayload
	dhpub, err := ptk.UnboxFor(&rjrp2, jr.Box, nil)
	require.NoError(t, err)

	// Should assert this in the client code
	hepk, err := ptk.ExportHEPK()
	require.NoError(t, err)
	fp, err := core.HEPK(hepk).Fingerprint()
	require.NoError(t, err)
	require.Equal(t, jr.HepkFp, *fp)

	// X now can do a user load of the new team member
	mu := tew.NewClientMetaContext(t, u)
	joinerFqu := rjrp2.Joiner.FQUser()
	require.NotNil(t, joinerFqu)
	lures, err := libclient.LoadUser(mu,
		(libclient.LoadUserArg{LoadMode: libclient.LoadModeOthers}).SetFQU(*joinerFqu, vtok),
	)
	require.NoError(t, err)
	require.NotNil(t, lures)
	lopuk, err := lures.LatestOwnerPUK()
	require.NoError(t, err)

	// Require that the box came from the user we just loaded.
	require.NotNil(t, lopuk)
	raw := dhpub.Curve25519()
	require.NotNil(t, raw)
	require.Equal(t, *raw, *lopuk.Hepk.F_1__.Classical.F_0__)

	// box up the view token so that future rotatooors of the team can lookup the user
	vtbp := proto.TeamRemoteMemberViewTokenBoxPayload{
		Tok:   vtok,
		Tm:    proto.Now(),
		Party: rjrp2.Joiner,
	}
	skey := ptk.SecretBoxKey()
	sbox, err := core.SealIntoSecretBox(&vtbp, &skey)
	require.NoError(t, err)
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	trmvt := proto.TeamRemoteMemberViewToken{
		Team: tid,
		Inner: proto.TeamRemoteMemberViewTokenInner{
			Member:    rjrp2.Joiner,
			PtkGen:    ptk.Metadata().Gen,
			SecretBox: *sbox,
		},
		Jrt: jrtok,
	}
	hepkw, ok := lures.Hepks.Lookup(&lopuk.Sk.HepkFp)
	require.True(t, ok)
	xsps := core.SPSBoxer{
		SharedPublicSuite: core.SharedPublicSuite{
			SharedKey: lopuk.Sk,
			HEPK:      *hepkw.Obj(),
		},
		Parent: rjrp2.Joiner,
	}
	xmem, hepk, err := xsps.ExportToMember(u.host)
	require.NoError(t, err)
	xmem.SrcRole = proto.OwnerRole

	err = tm.hepks.Add(*hepk)
	require.NoError(t, err)

	tm.makeChanges(
		t,
		m,
		u,
		[]proto.MemberRole{
			{
				DstRole: proto.NewRoleWithMember(0),
				Member:  *xmem,
			},
		},
		[]proto.TeamRemoteMemberViewToken{trmvt},
	)

	tm.countRemoteJoinReqs(t, m, 0, 1)
}

func TestTeamFailureNoSrcRole(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	u := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, u)

	mr := u.toMemberRole(t, proto.NewRoleWithMember(0), tm.hepks)
	mr.Member.SrcRole = proto.NewRoleDefault(proto.RoleType_NONE)

	_, err := tm.makeChangesFull(t,
		m,
		u,
		[]proto.MemberRole{mr},
		nil,
		makeChangesKnobs{},
	)
	require.Error(t, err)
	require.Equal(t, core.TeamNoSrcRoleError{}, err)

}

func TestTeamMembershipUpdateHappyPath(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	sam := tew.NewTestUserFakeRoot(t)
	ilya := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tmMsft := tew.makeTeamForOwner(t, sam)
	tmMsft.makeChanges(t, m, sam, []proto.MemberRole{ilya.toMemberRole(t, proto.AdminRole, tmMsft.hepks)}, nil)
	doublePoke(t, m)

	tmOpenAI := tew.makeTeamForOwner(t, ilya)
	tmOpenAI.absorb(tmMsft.hepks)

	tmOpenAI.setIndexRange(t, m, ilya, index3)
	tmMsft.setIndexRange(t, m, sam, index0)

	tmOpenAI.makeChanges(t, m, ilya,
		[]proto.MemberRole{
			tmMsft.toMemberRole(t, proto.OwnerRole, proto.AdminRole),
		}, nil)

	admin0ptk := tmMsft.ptks[core.AdminRole]
	require.NotNil(t, admin0ptk)

	iltok := makeTeamBearerToken(t, ilya, tmMsft, core.AdminRole)
	require.NotNil(t, iltok)

	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    tmOpenAI.FQTeam(t),
			SrcRole: proto.OwnerRole,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst: proto.RoleAndSeqno{
						Seqno: proto.Seqno(1),
						Role:  proto.AdminRole,
					},
				},
			),
		},
	)

	tr := getCurrentTreeRoot(t, m)
	glink, err := core.MakeGenericLink(
		tmMsft.id,
		tmMsft.host,
		admin0ptk,
		glp,
		proto.ChainEldestSeqno,
		nil,
		tr,
	)

	require.NoError(t, err)
	require.NotNil(t, glink)
	doublePoke(t, m)

	tcli, tcloser := ilya.newTeamAdminClient(t, m.Ctx())
	defer tcloser()

	err = tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok: iltok,
		Link: rem.PostGenericLinkArg{
			Link:             *glink.Link,
			NextTreeLocation: *glink.NextTreeLocation,
		},
	})
	require.NoError(t, err)
}

func TestTeamMembershipChainRaces(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	sam := tew.NewTestUserFakeRoot(t)
	ilya := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tmMsft := tew.makeTeamForOwner(t, sam)
	tmMsft.makeChanges(t, m, sam,
		[]proto.MemberRole{ilya.toMemberRole(t, proto.AdminRole, tmMsft.hepks)},
		nil,
	)
	doublePoke(t, m)

	tmOai := tew.makeTeamForOwner(t, ilya)

	tmOai.setIndexRange(t, m, ilya, index3)
	tmMsft.setIndexRange(t, m, sam, index0)

	tmOai.absorb(tmMsft.hepks)
	tmOai.makeChanges(t, m, ilya,
		[]proto.MemberRole{
			tmMsft.toMemberRole(t, proto.OwnerRole, proto.AdminRole),
		}, nil)

	admin0ptk := tmMsft.ptks[core.AdminRole]
	require.NotNil(t, admin0ptk)

	// This is a little bit of a cheat -- ilya is going to use sam's owner bearer token
	// so that way we don't fail the bearer token check that will happen immediately
	// after the rotation.
	iltok := makeTeamBearerToken(t, ilya, tmMsft, core.AdminRole)
	require.NotNil(t, iltok)

	// At the same time Sam is making the change to the roster of Microsoft, Ilya
	// is trying to add a link to the team membership chain of OpenAI. This should fail.
	makeTeamMembershipLink := func(ptk core.SharedPrivateSuiter) *core.MakeLinkRes {
		return makeTeamMembershipLinkFull(
			t, m, tmMsft, tmOai, ptk, proto.ChainEldestSeqno, nil,
			proto.OwnerRole,
			proto.TeamMembershipApprovedDetails{
				Dst: proto.RoleAndSeqno{
					Seqno: proto.Seqno(1),
					Role:  proto.AdminRole,
				},
			},
		)
	}

	glink := makeTeamMembershipLink(admin0ptk)

	tcli, tcloser := ilya.newTeamAdminClient(t, m.Ctx())
	defer tcloser()

	stop := tew.UserSrv().TestStopPostMembershipLink.Init()
	none := proto.NewRoleDefault(proto.RoleType_NONE)

	revokeThread := func() {
		ch := <-stop
		// Force a rotation of the admin link. It will only happen after PostMembershipLink
		// authenticates.
		tmMsft.makeChanges(t, m, sam, []proto.MemberRole{ilya.toMemberRole(t, none, nil)}, nil)
		ch <- struct{}{}
	}

	go revokeThread()

	err := tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok: iltok,
		Link: rem.PostGenericLinkArg{
			Link:             *glink.Link,
			NextTreeLocation: *glink.NextTreeLocation,
		},
	})
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "key locked"}, err)

	// sam adds ilya back in
	doublePoke(t, m)
	tmMsft.makeChanges(t, m, sam,
		[]proto.MemberRole{ilya.toMemberRole(t, proto.AdminRole, tmMsft.hepks)},
		nil)
	doublePoke(t, m)

	// new admin PTK
	admin1ptk := tmMsft.ptks[core.AdminRole]
	require.NotNil(t, admin1ptk)
	iltok = makeTeamBearerToken(t, ilya, tmMsft, core.AdminRole)

	// Now we're going to try the races in the other directions. Meaning, the change is going to be made
	// but the revoke is going to fail since the change is still in flight and hasn't hit the tree yet.
	glink = makeTeamMembershipLink(admin1ptk)
	err = tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
		Tok: iltok,
		Link: rem.PostGenericLinkArg{
			Link:             *glink.Link,
			NextTreeLocation: *glink.NextTreeLocation,
		},
	})
	require.NoError(t, err)

	_, err = tmMsft.makeChangesFull(t, m, sam,
		[]proto.MemberRole{ilya.toMemberRole(t, none, nil)}, nil, makeChangesKnobs{})
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "work inflight"}, err)

	ctx := m.Ctx()
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBuilderSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)

	// Even though the revoke is happening after the provision, it is still based on a tree
	// that is old, since it doesn't contain the provision link.  This is because,
	// in this test, the revoker process never got to sign the link.
	tr := getCurrentSignedTreeRoot(t, m)
	_, err = tmMsft.makeChangesFull(t, m, sam,
		[]proto.MemberRole{ilya.toMemberRole(t, none, nil)}, nil,
		makeChangesKnobs{treeRoot: &tr},
	)
	require.Error(t, err)
	require.Equal(t, core.RevokeRaceError{Which: "too old"}, err)

	// Now, finally when the merkle leaf for the team membership update is in the main tree,
	// the revoke should work.
	err = tew.MerkleSignerSrv().Poke(ctx)
	require.NoError(t, err)
	tmMsft.makeChanges(t, m, sam, []proto.MemberRole{ilya.toMemberRole(t, none, nil)}, nil)

	// See Issue #23.
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBuilderSrv().Poke(ctx)
	require.NoError(t, err)
	err = tew.MerkleBatcherSrv().Poke(ctx)
	require.NoError(t, err)
}

func TestTeamKeyTooNew(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	o := tew.NewTestUserFakeRoot(t)
	m := tew.MetaContext()
	doublePoke(t, m)
	tm := tew.makeTeamForOwner(t, o)
	tm2 := tew.makeTeamForOwner(t, o)

	tok := makeTeamBearerToken(t, o, tm, core.OwnerRole)
	require.NotNil(t, tok)

	owner0ptk := tm.ptks[core.AdminRole]
	require.NotNil(t, owner0ptk)

	// At the same time Sam is making the change to the roster of Microsoft, Ilya
	// is trying to add a link to the team membership chain of OpenAI. This should fail.
	makeTeamMembershipLink := func(ptk core.SharedPrivateSuiter) *core.MakeLinkRes {
		return makeTeamMembershipLinkFull(
			t, m, tm, tm2, ptk, proto.ChainEldestSeqno, nil,
			proto.OwnerRole,
			proto.TeamMembershipApprovedDetails{
				Dst: proto.RoleAndSeqno{
					Seqno: proto.Seqno(1),
					Role:  proto.AdminRole,
				},
			},
		)
	}

	glink := makeTeamMembershipLink(owner0ptk)

	tcli, tcloser := o.newTeamAdminClient(t, m.Ctx())
	defer tcloser()

	post := func() error {
		return tcli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
			Tok: tok,
			Link: rem.PostGenericLinkArg{
				Link:             *glink.Link,
				NextTreeLocation: *glink.NextTreeLocation,
			},
		})
	}
	err := post()
	require.Error(t, err)
	require.Equal(t, core.SigningKeyNotFullyProvisionedError{}, err)
	doublePoke(t, m)
	err = post()
	require.Error(t, err)

	verr, ok := err.(core.VerifyError)
	require.True(t, ok)
	require.Equal(t, strings.Index(string(verr), "signing key too new to sign for this link"), 0)

	glink = makeTeamMembershipLink(owner0ptk)
	err = post()
	require.NoError(t, err)
}

func TestTeamLocalInviteSequence(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, owner)
	require.NotNil(t, tm)
	membRole := proto.NewRoleWithMember(0)
	carole := tew.NewTestUser(t)
	require.NotNil(t, carole)
	require.NotNil(t, membRole)
	m := tew.MetaContext()

	ptk := tm.ptks[core.AdminRole]
	require.NotNil(t, ptk)

	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	require.NotNil(t, cert)

	teamBearerTok := makeTeamBearerToken(t, owner, tm, core.OwnerRole)

	tcli, closer := owner.newTeamAdminClient(t, m.Ctx())
	defer closer()
	err = tcli.PutTeamCert(m.Ctx(), rem.PutTeamCertArg{
		Tok:  teamBearerTok,
		Cert: *cert,
	})
	require.NoError(t, err)
	var hsh proto.TeamCertHash

	// This hash is now something we can post into groups, etc
	err = core.PrefixedHashInto(cert, hsh[:])
	require.NoError(t, err)

	i1 := proto.TeamInviteV1{
		Hsh:  hsh,
		Host: owner.host,
	}
	invite := proto.NewTeamInviteWithV1(i1)
	ib, err := core.EncodeToBytes(&invite)
	require.NoError(t, err)
	fmt.Printf("Invite: %s\n", core.B62Encode(ib))

	ccli, ccloser := carole.newTeamMemberClient(t, m.Ctx())
	defer ccloser()

	_, err = ccli.AcceptInviteLocal(m.Ctx(), rem.AcceptInviteLocalArg{
		I:       invite,
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)

	// owner now adds Carole
	res, err := tm.makeChangesFull(
		t,
		m,
		owner,
		[]proto.MemberRole{
			carole.toMemberRole(t, proto.AdminRole, tm.hepks),
		},
		nil,
		makeChangesKnobs{},
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, 1, len(res.LocalInvitees))

	// Check that the local_joinreq table got the right update.
	require.Equal(t, rem.LocalPartyRole{
		Party: carole.uid.ToPartyID(),
		Role:  proto.OwnerRole,
	}, res.LocalInvitees[0])

	tew.DirectMerklePoke(t)
	mc := tew.NewClientMetaContext(t, carole)
	wrp, err := libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:    tm.FQTeam(t),
		As:      carole.FQUser().FQParty(),
		Keys:    carole.KeySeq(t, proto.OwnerRole),
		SrcRole: proto.OwnerRole,
	})
	require.NoError(t, err)
	require.NotNil(t, wrp)
	require.NotNil(t, wrp.RemovalKey())

	// Next prove out that alice can post links to her team
	// membership chain. Most the work is already done since
	// we got the removal key with the team loader.
	kc, err := core.ComputeKeyCommitment(wrp.RemovalKey())
	require.NoError(t, err)

	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    tm.FQTeam(t),
			SrcRole: proto.OwnerRole,
			State: proto.NewTeamMembershipDetailsWithApproved(
				proto.TeamMembershipApprovedDetails{
					Dst: proto.RoleAndSeqno{
						Seqno: proto.Seqno(1),
						Role:  proto.NewRoleWithMember(0),
					},
					KeyComm: *kc,
				},
			),
		},
	)
	tr := getCurrentTreeRoot(t, m)
	glink, err := core.MakeGenericLink(
		carole.uid.EntityID(), carole.host,
		carole.devices[0], glp, carole.teamMembSeqno, carole.teamMembPrev, tr)
	require.NoError(t, err)
	ucli, ucloser := carole.newUserCertAndClient(t, m.Ctx())
	defer ucloser()
	err = ucli.PostGenericLink(m.Ctx(), rem.PostGenericLinkArg{
		Link:             *glink.Link,
		NextTreeLocation: *glink.NextTreeLocation,
	})
	require.NoError(t, err)
}

func TestSimpleLocalJoinSequences(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	t0 := tew.makeTeamForOwner(t, bluey)
	t1 := tew.makeTeamForOwner(t, bingo)
	m := tew.MetaContext()
	runLocalJoinSequenceForUser(t, m, t0, bluey, bingo, proto.AdminRole, nil)
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, bluey)

	// Do a team load primarily to get t0's VO bearer token.
	tl, _, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
		Team:    t0.FQTeam(t),
		As:      bluey.FQUser().FQParty(),
		SrcRole: proto.OwnerRole,
		Keys:    bluey.KeySeq(t, proto.OwnerRole),
	})
	require.NoError(t, err)
	tok := tl.Tok()

	// Test that we can load a user with the TeamVOBearerToken for the team
	// that the user just joined.
	_, err = libclient.LoadUser(mc,
		libclient.LoadUserArg{
			Uid:               bingo.uid,
			LoadMode:          libclient.LoadModeOthers,
			TeamVOBearerToken: tok,
		},
	)
	require.NoError(t, err)

	memrole := proto.NewRoleWithMember(0)

	// Now team t0 joins t1
	t0.setIndexRange(t, m, bluey, index3)
	t1.setIndexRange(t, m, bingo, index0)
	tew.DirectMerklePokeInTest(t)
	runLocalJoinSequenceForTeam(t, m, t0, t1, bluey, bingo, proto.AdminRole, memrole)

	// Team t1 can load t0 by using a team VO-bearer token for t0.
	_, err = libclient.LoadTeam(mc, libclient.LoadTeamArg{
		Team:               t1.FQTeam(t),
		As:                 t0.FQTeam(t).FQParty(),
		LocalParentTeamTok: tok,
	})
	require.NoError(t, err)
}

func TestTeamRemoval(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	mario := tew.NewTestUser(t)
	luigi := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	bowser := tew.NewTestUserAtVHost(t, vHostID)

	m := tew.MetaContext()
	tew.DirectMerklePokeForLeafCheck(t)

	// t0 is a local team on mario bros host
	t0 := tew.makeTeamForOwner(t, mario)
	t0.makeChanges(
		t,
		m,
		mario,
		[]proto.MemberRole{
			luigi.toMemberRole(t, proto.AdminRole, t0.hepks),
		},
		nil,
	)

	t2 := tew.makeTeamForOwner(t, bowser)

	t2.setIndexRange(t, m, bowser, index3)
	t0.setIndexRange(t, m, mario, index0)

	mem := proto.NewRoleWithMember(0)
	t2.absorb(t0.hepks)
	t2.makeChanges(
		t,
		m,
		bowser,
		[]proto.MemberRole{
			t0.toMemberRoleRemote(t, proto.AdminRole, mem),
		},
		nil,
	)
	tew.DirectDoubleMerklePokeInTest(t)

	// First off, make sure luigi can load t2
	mc := tew.NewClientMetaContext(t, luigi)

	doLoad := func() (*libclient.TeamLoader, error) {
		ldr, _, err := libclient.LoadTeamReturnLoader(mc, libclient.LoadTeamArg{
			Team:    t2.FQTeam(t),
			As:      t0.FQTeam(t).FQParty(),
			Keys:    t0.KeySeq(t, proto.AdminRole),
			SrcRole: proto.AdminRole,
		})
		return ldr, err

	}
	_, err := doLoad()
	require.NoError(t, err)

	none := proto.NewRoleDefault(proto.RoleType_NONE)
	t2.makeChanges(
		t,
		m,
		bowser,
		[]proto.MemberRole{
			t0.toMemberRoleRemote(t, proto.AdminRole, none),
		},
		nil,
	)

	ldr, err := doLoad()
	require.Error(t, err)
	require.Equal(t, core.PermissionError("team member permission failed (vo bearer token)"), err)

	err = ldr.VerifyRemoval(mc, nil)
	require.NoError(t, err)
}

// Bingo makes a team and adds Coco and Snickers to it, all locally. New Snickers cam load
// Coco's user. But muffin is just a *member* so therefore, he fails to load Coco's user
// via the team.
func TestUserLoadAsTeam(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	bingo := tew.NewTestUser(t)
	coco := tew.NewTestUser(t)
	snickers := tew.NewTestUser(t)
	muffin := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bingo)
	m := tew.MetaContext()

	ptk := tm.ptks[core.AdminRole]
	require.NotNil(t, ptk)
	cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
	require.NoError(t, err)
	require.NotNil(t, cert)

	invite := makeTeamInvite(t, tm, bingo)
	for _, u := range []*TestUser{coco, snickers} {
		cli, closer := u.newTeamMemberClient(t, m.Ctx())
		defer closer()
		_, err = cli.AcceptInviteLocal(tew.MetaContext().Ctx(), rem.AcceptInviteLocalArg{
			I:       invite,
			SrcRole: proto.OwnerRole,
		})
		require.NoError(t, err)
	}

	// owner adds two members as Admins (needed to allow for user loading via the team)
	mem := proto.AdminRole
	tm.makeChanges(
		t,
		m,
		bingo,
		[]proto.MemberRole{
			coco.toMemberRole(t, mem, tm.hepks),
			snickers.toMemberRole(t, mem, tm.hepks),
			muffin.toMemberRole(t, proto.DefaultRole, tm.hepks),
		},
		nil,
	)

	memPtk := tm.ptks[core.MemberRole]
	require.NotNil(t, memPtk)
	tok := makeVOBearerTokenForUser(t, tm, snickers, nil)
	require.NotNil(t, tok)

	mSnickers := tew.NewClientMetaContext(t, snickers)
	_, err = libclient.LoadUser(mSnickers,
		libclient.LoadUserArg{
			Uid:               coco.uid,
			LoadMode:          libclient.LoadModeOthers,
			TeamVOBearerToken: &tok,
		},
	)
	require.NoError(t, err)

	// muffin fails to load coco since muffin is lowly member/0 in the team.
	// need admin privs or higher.
	tok = makeVOBearerTokenForUser(t, tm, muffin, nil)
	require.NotNil(t, tok)
	mMuffin := tew.NewClientMetaContext(t, muffin)
	_, err = libclient.LoadUser(mMuffin,
		libclient.LoadUserArg{
			Uid:               coco.uid,
			LoadMode:          libclient.LoadModeOthers,
			TeamVOBearerToken: &tok,
		},
	)
	require.Error(t, err)
	require.Equal(t,
		core.ChainLoaderError{
			Err:  core.PermissionError("no view permission"),
			Race: true,
		},
		err,
	)
}

func TestTeamCertPutGet(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	bingo := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	m := tew.MetaContext()
	tm.makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			bingo.toMemberRole(t, proto.AdminRole, tm.hepks),
		},
		nil,
	)

	putCert := func() {
		ptk := tm.ptks[core.AdminRole]
		cert, err := team.MakeTeamCert(tm.FQTeam(t), tm.ptk0Admin, ptk, tm.nm)
		require.NoError(t, err)
		teamBearerTok := makeTeamBearerToken(t, bluey, tm, core.OwnerRole)
		tcli, closer := bluey.newTeamAdminClient(t, m.Ctx())
		defer closer()
		err = tcli.PutTeamCert(m.Ctx(), rem.PutTeamCertArg{
			Tok:  teamBearerTok,
			Cert: *cert,
		})
		require.NoError(t, err)
	}

	getCerts := func() []rem.TeamCert {
		teamBearerTok := makeTeamBearerToken(t, bluey, tm, core.OwnerRole)
		tcli, closer := bluey.newTeamAdminClient(t, m.Ctx())
		defer closer()
		certs, err := tcli.GetCurrentTeamCerts(m.Ctx(), teamBearerTok)
		require.NoError(t, err)
		return certs
	}

	putCert()
	certs := getCerts()
	require.Equal(t, 1, len(certs))
	putCert()
	certs = getCerts()
	require.Equal(t, 2, len(certs))

	tew.DirectMerklePokeInTest(t)

	tm.makeChanges(
		t,
		m,
		bluey,
		[]proto.MemberRole{
			bingo.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), nil),
		},
		nil,
	)
	certs = getCerts()
	require.Equal(t, 0, len(certs))

	putCert()
	certs = getCerts()
	require.Equal(t, 1, len(certs))
}

func TestTeamListMemberships(t *testing.T) {
	defer common.DebugEntryAndExit()()

	tew := testEnvBeta(t)
	tew.DirectMerklePoke(t)
	bluey := tew.NewTestUser(t)
	vHostID := tew.VHostMakeI(t, 0)
	coco := tew.NewTestUserAtVHost(t, vHostID)
	tew.DirectDoubleMerklePokeInTest(t)

	t1 := tew.makeTeamForOwner(t, bluey)
	t2 := tew.makeTeamForOwner(t, coco)

	tew.DirectDoubleMerklePokeInTest(t)

	m := tew.MetaContext()

	t1.setIndexRange(t, m, bluey, index0)
	t2.setIndexRange(t, m, coco, index3)

	t2.absorb(t1.hepks)
	mem := proto.NewRoleWithMember(0)
	t2.makeChanges(
		t,
		m,
		coco,
		[]proto.MemberRole{
			t1.toMemberRoleRemote(t, proto.AdminRole, mem),
		},
		nil,
	)

	// Bluey posts that t1's chain shows that t1 is a member of t2
	postTeamMembmershipLinkForTeam(t,
		bluey,
		m,
		t1, t2, t1.ptks[core.AdminRole],
		proto.ChainEldestSeqno,
		nil,
		proto.AdminRole,
		proto.TeamMembershipApprovedDetails{
			Dst: proto.RoleAndSeqno{
				Role:  mem,
				Seqno: proto.ChainEldestSeqno + 1,
			},
			KeyComm: t2.getRemovalKeyCommitment(t, t1.FQTeam(t).FQParty(), core.AdminRole),
		},
	)
	tew.DirectDoubleMerklePokeInTest(t)

	mc := tew.NewClientMetaContext(t, bluey)
	tmm, err := mc.G().TeamMinder()
	require.NoError(t, err)

	lst, err := tmm.ListMemberships(mc)
	require.NoError(t, err)
	require.Equal(t, 2, len(lst.Teams))

	// Sort order is for direct-membership teams first,
	// and then team-via-team membership next.
	require.Nil(t, lst.Teams[0].Via)
	require.NotNil(t, lst.Teams[1].Via)

	require.Equal(t, t1.FQTeam(t), *lst.Teams[0].Team.Fqp.FQTeam())
	require.Equal(t, t1.FQTeam(t), *lst.Teams[1].Via.Fqp.FQTeam())
	require.Equal(t, t2.FQTeam(t), *lst.Teams[1].Team.Fqp.FQTeam())
	require.Equal(t, t1.nm, lst.Teams[0].Team.Name)
	require.Equal(t, t1.nm, lst.Teams[1].Via.Name)
	require.Equal(t, t2.nm, lst.Teams[1].Team.Name)

}
