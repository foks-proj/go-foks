// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

func (c *UserClientConn) ReserveTeamname(
	ctx context.Context,
	nm proto.Name,
) (
	rem.ReserveNameRes,
	error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.ReserveName(m, nm, rem.NameType_Team, 0)
}

type teamEditor struct {
	*UserClientConn
	vtab      teamEditInterface
	tx        pgx.Tx
	arg       rem.EditTeamArg
	openres   *team.OpenTeamLinkRes
	signer    proto.EntityID
	teamID    proto.TeamID
	name      proto.Name
	seqno     proto.Seqno
	prev      *proto.BaseChainer
	res       rem.EditTeamRes
	tokTeamID *proto.TeamID
}

type teamCreator struct {
	*teamEditor
	openEldestRes *team.OpenEldestRes
	arg           rem.CreateTeamArg
}

type teamEditInterface interface {
	insertCreateTeam(m shared.MetaContext) error
	openLink(m shared.MetaContext) (*team.OpenTeamLinkRes, error)
}

func (e *teamEditor) insertCreateTeam(m shared.MetaContext) error { return nil }

func (c *teamCreator) openLink(m shared.MetaContext) (*team.OpenTeamLinkRes, error) {
	return &c.openEldestRes.OpenTeamLinkRes, nil
}

var _ teamEditInterface = (*teamCreator)(nil)
var _ teamEditInterface = (*teamEditor)(nil)

func (c *UserClientConn) CreateTeam(
	ctx context.Context,
	arg rem.CreateTeamArg,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	return shared.RetryTx(m, db, "signup", func(m shared.MetaContext, tx pgx.Tx) error {
		obj := &teamCreator{
			arg: arg,
			teamEditor: &teamEditor{
				UserClientConn: c,
				arg:            arg.Eta,
				tx:             tx,
			},
		}
		obj.teamEditor.vtab = obj
		return obj.run(m)
	})
}

func (c *teamCreator) handleNameReservation(
	m shared.MetaContext,
) (
	proto.Name,
	error,
) {
	expectedName, err := core.NormalizeName(proto.NameUtf8(c.arg.NameUtf8))
	if err != nil {
		return "", err
	}
	err = shared.ClaimReservation(m, c.tx, m.HostID(), expectedName, c.arg.Rnr, rem.NameType_Team)
	if err != nil {
		return "", err
	}
	return expectedName, nil
}

func (c *teamEditor) insertIntoTeams(
	m shared.MetaContext,
) error {
	tag, err := c.tx.Exec(
		m.Ctx(),
		`INSERT INTO teams(short_host_id,team_id,name_ascii,ctime)
		VALUES($1, $2, $3, NOW())`,
		m.ShortHostID().ExportToDB(),
		c.teamID.ExportToDB(),
		string(c.name),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("teams")
	}
	return err
}

func (c *teamEditor) readRotatedKeys(
	m shared.MetaContext,
) (
	[]proto.EntityID,
	error,
) {
	return shared.ReadRotatedPTKs(m, c.tx, c.teamID, c.openres.Sched)
}

func (c *teamEditor) insertLink(
	m shared.MetaContext,
) error {

	// On a downgrade, we wind up rotating keys. Each of those keys needs to be locked
	// via the revoke_key_locks table, so that we don't have a concurrent attempt to use that
	// key elsewhere. Say, for instance, when signing a link on a different chain like the
	// team membership chain. Thus, we load a list of all keys that are rotated away from
	// here, and pass them to InsertLink, which will lock them.
	rot, err := c.readRotatedKeys(m)
	if err != nil {
		return err
	}

	// For teams, it doesn't matter when the PTK verify key was introduced, since we'll
	// never wind up reusing them. So it's safe to say they are all at seqno=0 in the sigchain.
	// For device keys, we have to be more careful, since yubikeys can be reused, so we need
	// to disambiguate them with the seqno they appeared in the chain with.
	conv := func(e proto.EntityID) core.SignerPair {
		return core.SignerPair{Eid: e}
	}

	rotConv := make([]core.SignerPair, len(rot))
	for i, p := range rot {
		rotConv[i] = conv(p)
	}

	return shared.InsertLink(
		m,
		c.tx,
		proto.ChainType_Team,
		c.teamID.ToPartyID(),
		conv(c.signer),
		c.prev,
		c.openres.Gc.Chainer.Base,
		c.arg.Link,
		shared.TeamChangeInsertTrigger(m, c.teamID, c.seqno, c.openres.Gc.Changes, c.openres.Gc.SharedKeys),
		rotConv,
	)
}

func (c *teamEditor) editMembers(
	m shared.MetaContext,
) error {
	return shared.EditMembers(
		m,
		c.tx,
		c.teamID.EntityID(),
		c.openres.Gc.Chainer.Base.Seqno,
		c.openres.Gc.Chainer.Base.Root.Epno,
		c.openres.Gc.Changes,
		c.arg.Obd.Hepks,
	)
}

func (c *teamCreator) insertCreateTeam(
	m shared.MetaContext,
) error {
	err := shared.InsertName(
		m,
		c.tx,
		c.teamID.EntityID(),
		c.signer,
		m.HostID(),
		c.name,
		c.arg.NameUtf8,
		&c.arg.TeamnameCommitmentKey,
		c.openEldestRes.Tnc,
		c.arg.Rnr.Seq,
		rem.NameType_Team,
	)
	if err != nil {
		return err
	}
	err = c.insertIntoTeams(m)
	if err != nil {
		return err
	}

	err = shared.InsertSubchainTreeLocationSeed(m, c.tx, c.teamID.ToPartyID(),
		c.arg.SubchainTreeLocationSeed, c.openEldestRes.Stltc)
	if err != nil {
		return err
	}

	err = shared.InsertMemberLoadFloor(
		m,
		c.tx,
		c.teamID,
		c.openEldestRes.MemberLoadFloorOrDefault(),
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *teamEditor) findNewKeyInChanges() error {
	nkor := c.arg.Obd.NewKeyOnRotate
	if nkor == nil {
		return nil
	}
	chng := team.FindChangeForMember(c.openres.Gc.Changes, *c.openres.Gc.Signer.KeyOwner)
	if chng == nil {
		return core.BadArgsError("cannot find key owner among changes")
	}
	typ, err := chng.Member.Keys.GetT()
	if err != nil {
		return err
	}
	if typ != proto.MemberKeysType_Team {
		return core.BadArgsError("bad non-team member keys type")
	}
	tmk := chng.Member.Keys.Team()
	if !tmk.VerifyKey.Eq(nkor) {
		return core.BadArgsError("bad new key on rotate")
	}
	return nil
}

func (c *teamEditor) insertLocalViewPermission(
	m shared.MetaContext,
) error {

	// BulkInsertLocalViewPermissions assumes open-viewership mode for
	// any additions. For open viewership, it makes sense to insert a low
	// role here. Maybe should be even lower than m/0. This is temporary
	// BTW, we should revisit this in subqeuent PRs.
	viewerRole := proto.DefaultRole

	err := shared.BulkInsertLocalViewPermissions(
		m,
		c.tx,
		c.teamID.ToPartyID(),
		viewerRole,
		c.arg.InsLocalPermsFor,
		c.openres.Gc.Changes,
	)
	return err
}

func (c *teamEditor) insertPTKs(
	m shared.MetaContext,
) error {

	key := c.signer
	if c.arg.Obd.NewKeyOnRotate != nil {
		err := c.findNewKeyInChanges()
		if err != nil {
			return err
		}
		key = c.arg.Obd.NewKeyOnRotate
	}

	return shared.InsertPTKs(
		m,
		c.tx,
		c.teamID.EntityID(),
		key,
		*c.openres,
		c.arg.Obd,
	)
}

func (c *teamEditor) checkAndInsertRemovalKeys(
	m shared.MetaContext,
) error {
	return shared.CheckAndInsertRemovalKeys(
		m,
		c.tx,
		c.openres.Gc.Chainer.Base.Seqno,
		c.teamID,
		c.openres.Sched,
		c.arg.Obd.RemovalKeys,
		c.openres.Gc.Changes,
	)
}

func (c *teamEditor) checkAndInsertRemovals(
	m shared.MetaContext,
) error {
	return shared.CheckAndInsertRemovals(
		m,
		c.tx,
		c.teamID,
		c.openres.Sched,
		c.arg.Obd.Removals,
	)
}

func (c *teamEditor) checkMemberIndexRangesAgainstTeam(
	m shared.MetaContext,
) error {
	return shared.CheckMemberIndexRangesAgainstTeam(
		m,
		c.tx,
		c.teamID,
		c.openres.Gc.Changes,
	)
}

func (c *teamEditor) insertTeamIndexRange(
	m shared.MetaContext,
) error {
	rng := c.openres.Range
	if rng == nil {
		return nil
	}
	return shared.InsertTeamIndexRange(
		m,
		c.tx,
		c.teamID,
		c.openres.Gc.Chainer.Base.Seqno,
		*rng,
	)
}

func (c *teamEditor) insertRemoteMemberViewTokens(
	m shared.MetaContext,
) error {
	return shared.InsertRemoteMemberViewTokens(
		m,
		c.tx,
		c.teamID,
		c.arg.Obd.RemoteMemberViewTokens,
	)
}

func (c *teamEditor) updateLocalJoinReqs(
	m shared.MetaContext,
) error {
	invitees, err := shared.UpdateLocalJoinReqs(
		m,
		c.tx,
		c.teamID,
		c.openres.Sched.Additions,
	)
	if err != nil {
		return err
	}
	c.res.LocalInvitees = invitees
	return nil
}

func (c *teamEditor) checkLocalMembers(
	m shared.MetaContext,
) error {

	err := shared.CheckLocalMembers(m, c.tx, c.openres.Gc.Changes)
	if err != nil {
		return err
	}
	return nil

}

func (c *teamCreator) checkSigner(
	m shared.MetaContext,
) error {
	lsk, err := shared.ReadLatestSharedKey(m, c.tx, m.UID().EntityID(), proto.OwnerRole)
	if err != nil {
		return err
	}
	if !c.openres.Gc.Signer.Key.RollingEq(lsk.VerifyKey) {
		return core.LinkError("bad signing key for signer")
	}
	return nil
}

func (c *teamCreator) run(
	m shared.MetaContext,
) error {
	m = m.WithLogTag("TEAM.CREATE")

	var err error

	c.name, err = c.handleNameReservation(m)
	if err != nil {
		return err
	}
	hepks, err := core.ImportHEPKSet(&c.arg.Eta.Obd.Hepks)
	if err != nil {
		return err
	}
	openRes, err := team.OpenEldestLink(&c.arg.Eta.Link, hepks, m.HostID().Id)
	if err != nil {
		return err
	}

	c.openEldestRes = openRes
	c.teamEditor.openres = &openRes.OpenTeamLinkRes
	c.teamID, err = openRes.Gc.Entity.Entity.ToTeamID()
	if err != nil {
		return err
	}
	c.seqno = openRes.Gc.Chainer.Base.Seqno

	// Usually the signer is already in the chain, but for the first link,
	// we need to check the signer against database.
	err = c.checkSigner(m)
	if err != nil {
		return err
	}

	err = c.runEditCommon(m)
	if err != nil {
		return err
	}

	err = shared.InsertTeamMembershipLink(m, c.tx, c.arg.TeamMembershipLink)
	if err != nil {
		return err
	}

	viewerPermRole := c.openEldestRes.MemberLoadFloorOrDefault()

	// Owner gives permission to *future* members to load him, once they are allowed
	// into the group. Otherwise, they can't.
	_, err = shared.InsertLocalViewPermission(m, c.tx, c.teamID.ToPartyID(), viewerPermRole, m.UID().ToPartyID())
	if err != nil {
		return err
	}

	err = shared.ShortPartyIns(m, c.tx, c.teamID.ToPartyID())
	if err != nil {
		return err
	}

	return nil
}

func (e *teamEditor) runEdit(m shared.MetaContext) error {

	teamid, seqno, err := team.ExtractTeamAndSeqno(&e.arg.Link)
	if err != nil {
		return err
	}
	e.teamID = *teamid
	e.seqno = seqno
	return e.runEditCommon(m)
}

func (c *teamEditor) openLink(m shared.MetaContext) (*team.OpenTeamLinkRes, error) {
	roster, prev, err := shared.LoadRoster(m, c.tx, c.teamID)
	if err != nil {
		return nil, err
	}
	if roster == nil {
		return nil, core.InternalError("need a roster or cannot continue")
	}
	c.prev = prev

	hepks, err := core.ImportHEPKSet(&c.arg.Obd.Hepks)
	if err != nil {
		return nil, err
	}

	res, err := team.OpenTeamLink(&c.arg.Link, hepks, &c.teamID, m.HostID().Id, roster)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *teamEditor) checkAgainstCurrentParty(m shared.MetaContext) error {

	if c.openres.Gc.Signer.KeyOwner.Party.EntityID().Eq(m.UID().EntityID()) {
		return nil
	}
	if c.tokTeamID != nil && c.tokTeamID.Eq(c.teamID) {
		return nil
	}
	return core.PermissionError("poster must be logged in or authorized to act on behalf of the team")
}

func (c *teamEditor) loadBearerToken(m shared.MetaContext) error {
	if c.arg.Tok == nil {
		return nil
	}
	tid, role, err := shared.LoadBearerToken(m, c.tx, *c.arg.Tok, 0)
	if err != nil {
		return err
	}
	ok, err := role.IsAdminOrAbove()
	if err != nil {
		return err
	}
	if !ok {
		return core.PermissionError("bearer token must be admin or above")
	}
	c.tokTeamID = tid
	return nil
}

func (c *teamEditor) checkTeamLimits(m shared.MetaContext) error {
	if c.openres.RosterPost == nil {
		return nil
	}
	nKeys := c.openres.RosterPost.KeyGens.Num()
	cfg, err := m.G().Config().TeamConfig(m.Ctx())
	if err != nil {
		return err
	}
	max := cfg.MaxRoles()
	if nKeys > int(max) {
		return core.TeamRosterError(
			fmt.Sprintf("too many roles (%d); max is %d", nKeys, max),
		)
	}

	return nil
}

func (c *teamEditor) runEditCommon(m shared.MetaContext) error {

	// Locking the chain means we can go ahead and make SELECTs against team
	// data without fear of races. Other threads who lost the race to acquire
	// this lock will be blocked until we commit or rollback. On rollback, they
	// can go forward. On commit, they will error out here with a primary key
	// violation and then rollback.
	err := shared.LockEntity(m, c.tx, c.teamID.EntityID(), proto.ChainType_Team, c.seqno)
	if err != nil {
		return err
	}

	openres, err := c.vtab.openLink(m)
	if err != nil {
		return err
	}

	c.openres = openres
	c.signer = c.openres.Gc.Signer.Key

	err = c.checkTeamLimits(m)
	if err != nil {
		return err
	}

	err = c.loadBearerToken(m)
	if err != nil {
		return err
	}

	err = c.checkAgainstCurrentParty(m)
	if err != nil {
		return err
	}

	// need to insert name before we can insert into teams to satisfy the
	// foreign key constraints.
	err = c.vtab.insertCreateTeam(m)
	if err != nil {
		return err
	}

	// in OpenEldestLink we opened the team roster as a result of the specified
	// changes. Therefore, we know that local users have their hostID=nil set
	// on changes. We here check that these users (or teams) are specified with the
	// corect keys and generations, and aren't behind a rotation due to a race.
	err = c.checkLocalMembers(m)
	if err != nil {
		return err
	}

	err = c.insertLink(m)
	if err != nil {
		return err
	}

	err = c.editMembers(m)
	if err != nil {
		return err
	}

	err = c.insertPTKs(m)
	if err != nil {
		return err
	}

	err = c.insertLocalViewPermission(m)
	if err != nil {
		return err
	}

	err = c.insertTeamIndexRange(m)
	if err != nil {
		return err
	}

	err = c.checkMemberIndexRangesAgainstTeam(m)
	if err != nil {
		return err
	}

	err = c.insertRemoteMemberViewTokens(m)
	if err != nil {
		return err
	}

	err = c.updateLocalJoinReqs(m)
	if err != nil {
		return err
	}

	err = c.checkAndInsertRemovalKeys(m)
	if err != nil {
		return err
	}

	err = c.checkAndInsertRemovals(m)
	if err != nil {
		return err
	}

	err = shared.InsertTreeLocationMachinery(m,
		c.tx,
		proto.ChainType_Team,
		c.teamID.EntityID(),
		c.openres.Gc.Chainer.Base.Seqno,
		c.openres.Gc.LocationVRFID,
		c.arg.NextTreeLocation,
		c.openres.Gc.Chainer.NextLocationCommitment,
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *UserClientConn) EditTeam(
	ctx context.Context,
	arg rem.EditTeamArg,
) (
	rem.EditTeamRes,
	error,
) {
	var zed rem.EditTeamRes
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return zed, err
	}
	defer db.Release()

	var ret rem.EditTeamRes
	err = shared.RetryTx(m, db, "edit", func(m shared.MetaContext, tx pgx.Tx) error {
		obj := &teamEditor{
			UserClientConn: c,
			arg:            arg,
			tx:             tx,
		}
		obj.vtab = obj
		err := obj.runEdit(m)
		if err != nil {
			return err
		}
		ret = obj.res
		return nil
	})
	if err != nil {
		return zed, err
	}
	return ret, nil
}

func (c *UserClientConn) MakeInertTeamBearerToken(
	ctx context.Context,
	arg rem.MakeInertTeamBearerTokenArg,
) (
	rem.TeamBearerToken,
	error,
) {
	var tok rem.TeamBearerToken
	m := shared.NewMetaContextConn(ctx, c)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return tok, err
	}
	defer db.Release()
	err = shared.RetryTx(m, db, "MakeInertTeamBearerToken", func(m shared.MetaContext, tx pgx.Tx) error {
		err := core.RandomFill(tok[:])
		if err != nil {
			return err
		}
		return shared.InsertInertTeamBearerToken(m, tx, tok, arg, nil)
	})
	if err != nil {
		return tok, err
	}
	return tok, nil
}

func (u *UserClientConn) ActivateTeamBearerToken(
	ctx context.Context,
	arg rem.ActivateTeamBearerTokenArg,
) error {
	m := shared.NewMetaContextConn(ctx, u)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return shared.RetryTx(m, db, "ActivateTeamBearerToken", func(m shared.MetaContext, tx pgx.Tx) error {
		return shared.ActivateTeamBearerToken(m, tx, arg, false)
	})
}

func inTeamRoleContext(
	ctx context.Context,
	u *UserClientConn,
	tok rem.TeamBearerToken,
	f func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error,
) error {
	m := shared.NewMetaContextConn(ctx, u)
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	tt := u.srv.TestTimeTravel()
	tid, role, err := shared.LoadBearerToken(m, db, tok, tt)
	if err != nil {
		return err
	}
	return f(m, *tid, *role)
}

func (u *UserClientConn) CheckTeamBearerToken(
	ctx context.Context,
	arg rem.TeamBearerToken,
) (
	proto.TeamID,
	error,
) {
	var ret proto.TeamID
	err := inTeamRoleContext(ctx, u, arg,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			ret = tid
			return nil
		},
	)
	return ret, err
}

func (u *UserClientConn) PutTeamCert(
	ctx context.Context,
	arg rem.PutTeamCertArg,
) error {
	err := inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can put a cert"))
			if err != nil {
				return err
			}
			return shared.RetryTxUserDB(m, "StoreTeamCert",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return shared.StoreTeamCert(m, tx, tid, arg.Cert)
				},
			)
		},
	)
	return err
}

func (u *UserClientConn) LoadTeamRemoteJoinReq(
	ctx context.Context,
	arg rem.LoadTeamRemoteJoinReqArg,
) (
	rem.TeamRemoteJoinReq,
	error,
) {
	var ret rem.TeamRemoteJoinReq
	err := inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can get the cert"))
			if err != nil {
				return err
			}
			tmp, err := shared.LoadRemoteJoinReq(m, tid, arg.Jrt)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		},
	)
	return ret, err
}

func (u *UserClientConn) PostTeamMembershipLink(
	ctx context.Context,
	arg rem.PostTeamMembershipLinkArg,
) error {
	return inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can post to membership chain"))
			if err != nil {
				return err
			}
			return shared.RetryTxUserDB(m, "PostTeamMembershipLink",
				func(m shared.MetaContext, tx pgx.Tx) error {

					return shared.PostGenericLinkTryTx(
						m, tx, arg.Link, tid.ToPartyID(),
						&u.srv.TestStopPostMembershipLink,
					)
				},
			)
		},
	)
}

func (u *UserClientConn) LoadRemovalKeyBoxForTeamAdmin(
	ctx context.Context,
	arg rem.LoadRemovalKeyBoxForTeamAdminArg,
) (
	proto.TeamRemovalKeyBox,
	error,
) {
	var ret proto.TeamRemovalKeyBox
	err := inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can get the removal key box"))
			if err != nil {
				return err
			}
			return shared.RetryTxUserDB(m, "PostTeamMembershipLink",
				func(m shared.MetaContext, tx pgx.Tx) error {
					tmp, err := shared.LoadRemovalKeyBoxForTeamAdmin(m, tx, tid, arg.Member, arg.SrcRole)
					if err != nil {
						return err
					}
					ret = *tmp
					return nil
				},
			)
		},
	)
	return ret, err
}

func (u *UserClientConn) PostTeamRemoval(
	ctx context.Context,
	arg rem.PostTeamRemovalArg,
) error {
	return inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can post removals"))
			if err != nil {
				return err
			}
			return shared.RetryTxUserDB(m, "PostTeamRemoval",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return shared.PostTeamRemoval(m, tx, tid, arg.Rm)
				},
			)
		},
	)
}

func (u *UserClientConn) GetCurrentTeamCerts(
	ctx context.Context,
	arg rem.TeamBearerToken,
) (
	[]rem.TeamCert,
	error,
) {
	var ret []rem.TeamCert
	err := inTeamRoleContext(ctx, u, arg,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can put a cert"))
			if err != nil {
				return err
			}
			tmp, err := shared.GetCurrentTeamCerts(m, tid)
			if err != nil {
				return err
			}
			ret = tmp
			return nil
		},
	)
	return ret, err
}

func (u *UserClientConn) LoadTeamRawInbox(
	ctx context.Context,
	arg rem.LoadTeamRawInboxArg,
) (
	rem.TeamRawInbox,
	error,
) {
	var ret rem.TeamRawInbox
	err := inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can load the inbox"))
			if err != nil {
				return err
			}
			tmp, err := shared.LoadTeamInbox(m, tid, arg.Pagination)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		},
	)
	return ret, err
}

func (u *UserClientConn) RejectJoinReq(
	ctx context.Context,
	arg rem.RejectJoinReqArg,
) error {
	return inTeamRoleContext(ctx, u, arg.Tok,
		func(m shared.MetaContext, tid proto.TeamID, r proto.Role) error {
			err := r.AssertAdminOrAbove(core.PermissionError("only admins can reject join requests"))
			if err != nil {
				return err
			}
			return shared.RetryTxUserDB(m, "RejectJoinReq",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return shared.RejectJoinReq(m, tx, tid, arg.Req)
				},
			)
		},
	)
}

func (u *UserClientConn) GetTeamConfig(ctx context.Context) (rem.TeamConfig, error) {
	m := shared.NewMetaContextConn(ctx, u)
	var ret rem.TeamConfig
	tcfg, err := m.G().Config().TeamConfig(ctx)
	if err != nil {
		return ret, err
	}
	ret.MaxRoles = uint64(tcfg.MaxRoles())
	return ret, nil
}

var _ rem.TeamAdminInterface = (*UserClientConn)(nil)
