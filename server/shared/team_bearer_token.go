// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type lookupTeamMemberVerifyKeyRes struct {
	key  core.EntityPublic
	seq  proto.Seqno
	role proto.Role
}

type maskableError struct {
	err  error
	mask bool
}

func lookupTeamMemberVerifyKey(
	m MetaContext,
	rq Querier,
	req rem.TeamVOBearerTokenReq,
) (
	*lookupTeamMemberVerifyKeyRes,
	*proto.TeamID,
	*maskableError,
) {
	team := req.Team
	member := req.Member
	gen := req.Gen
	srk, err := core.ImportRole(req.SrcRole)
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: false}
	}
	if !m.HostID().Id.Eq(team.Host) {
		return nil, nil, &maskableError{err: core.HostMismatchError{}, mask: false}
	}

	isId, err := req.Team.IdOrName.GetId()
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: false}
	}
	var teamID proto.TeamID
	if isId {
		teamID = req.Team.IdOrName.True()
	} else {
		name := req.Team.IdOrName.False()
		err := name.AssertNormalized()
		if err != nil {
			return nil, nil, &maskableError{err: err, mask: false}
		}
		var tmp []byte
		err = rq.QueryRow(m.Ctx(),
			`SELECT team_id
			 FROM teams
			 WHERE short_host_id=$1 AND name_ascii=$2`,
			m.ShortHostID().ExportToDB(),
			name,
		).Scan(&tmp)
		if errors.Is(err, pgx.ErrNoRows) {
			// For timing purposes, if there is no such name, we fill in a
			// random team ID that will fail the query below. This way a
			// team-name-not-found condition won't leak (too much) timing info.
			err = core.RandomFill(teamID[:])
			if err != nil {
				return nil, nil, &maskableError{err: err, mask: true}
			}
			m.Warnw("lookupTeamMemberVerifyKey", "err", "TeamNameNotFound", "name", name, "randomTeamID", teamID)
		}
		if err != nil {
			return nil, nil, &maskableError{err: err, mask: true}
		}
		err = teamID.ImportFromDB(tmp)
		if err != nil {
			return nil, nil, &maskableError{err: err, mask: true}
		}
	}

	var vk []byte
	var dstRoleType, dstVizLevel, q int
	err = rq.QueryRow(m.Ctx(),
		`SELECT verify_key, seqno, dst_role_type, dst_viz_level
		 FROM team_members
		 WHERE short_host_id=$1 AND team_id=$2 
		 AND member_id=$3 AND member_host_id=$4
		 AND key_gen=$5 AND active=TRUE
		 AND src_role_type=$6 AND src_viz_level=$7`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
		member.Party.ExportToDB(),
		ExportHostInScope(m, member.Host),
		int(gen),
		int(srk.Typ),
		int(srk.Lev),
	).Scan(&vk, &q, &dstRoleType, &dstVizLevel)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, &maskableError{err: core.TeamNotFoundError{}, mask: true}
	}
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: true}
	}
	eid, err := proto.ImportEntityIDFromBytes(vk)
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: true}
	}
	ep, err := core.ImportEntityPublic(eid)
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: true}
	}
	rk, err := core.ImportRoleKeyFromDB(dstRoleType, dstVizLevel)
	if err != nil {
		return nil, nil, &maskableError{err: err, mask: true}
	}
	ret := lookupTeamMemberVerifyKeyRes{
		role: rk.Export(),
		key:  ep,
		seq:  proto.Seqno(q),
	}
	return &ret, &teamID, nil
}

func GetTeamVOBearerTokenChallenge(
	m MetaContext,
	req rem.TeamVOBearerTokenReq,
) (
	*rem.TeamVOBearerTokenChallenge,
	error,
) {
	m, err := m.WithProtoHostID(&req.Team.Host)
	if err != nil {
		return nil, err
	}

	if !req.Gen.IsValid() {
		return nil, core.BadArgsError("invalid generation for signing key")
	}

	if req.Member.Host.Eq(m.HostID().Id) && m.UID().IsZero() {
		return nil, core.NeedLoginError{}
	}

	srt, err := req.SrcRole.GetT()
	if err != nil {
		return nil, err
	}
	if srt == proto.RoleType_NONE {
		return nil, core.TeamNoSrcRoleError{}
	}

	id, key, err := LookupLatestChallengeKey(m, HmacKeyTypeTeamVOBearerToken)
	if err != nil {
		return nil, err
	}

	// NOTE -- We don't assertTeamMember here since that would leak
	// membership info to a potentially remote user who has no login credentials.
	//
	// ALSO NOTE: We don't write anything to the DB in this path for the reason
	// as above.
	payload := rem.TeamVOBearerTokenChallengePayload{
		Req: req,
		Tm:  proto.ExportTime(m.Now()),
		Id:  *id,
	}
	err = core.RandomFill(payload.Tok[:])
	if err != nil {
		return nil, err
	}

	mac, err := core.Hmac(&payload, key)
	if err != nil {
		return nil, err
	}

	ret := rem.TeamVOBearerTokenChallenge{
		Payload: payload,
		Mac:     *mac,
	}

	return &ret, nil
}

func insertTeamVOBearerToken(
	m MetaContext,
	tx pgx.Tx,
	pl rem.TeamVOBearerTokenChallengePayload,
	seqno proto.Seqno,
	teamID proto.TeamID,
) error {
	srcRk, err := core.ImportRole(pl.Req.SrcRole)
	if err != nil {
		return err
	}
	if srcRk.IsNone() {
		return core.ValidationError("cannot create a token for NONE role")
	}
	tm := pl.Tm.Import()
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO team_vo_bearer_tokens
		  (short_host_id, team_id, token, state, member_id, member_host_id, 
			src_role_type, src_viz_level, seqno, ctime)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
		pl.Tok.ExportToDB(),
		team.BearerTokenStateActive,
		pl.Req.Member.Party.ExportToDB(),
		ExportHostInScope(m, pl.Req.Member.Host),
		int(srcRk.Typ),
		int(srcRk.Lev),
		int(seqno),
		tm,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("team vo bearer token")
	}
	return nil
}

func ActivateTeamVOBearerToken(
	m MetaContext,
	arg rem.ActivateTeamVOBearerTokenArg,
) (
	*rem.ActivatedVOBearerToken,
	error,
) {
	m, err := m.WithProtoHostID(&arg.Ch.Payload.Req.Team.Host)
	if err != nil {
		return nil, err
	}
	if arg.Ch.Payload.Req.Member.Host.Eq(m.HostID().Id) && m.UID().IsZero() {
		return nil, core.NeedLoginError{}
	}
	var ret *rem.ActivatedVOBearerToken
	err = RetryTxUserDB(m, "activeTeamVOBearerToken", func(m MetaContext, tx pgx.Tx) error {

		key, err := LookupHMACKeyByID(m, tx, arg.Ch.Payload.Id, HmacKeyTypeTeamVOBearerToken)
		if err != nil {
			return err
		}
		computed, err := core.Hmac(&arg.Ch.Payload, key)
		if err != nil {
			return err
		}
		if !computed.Eq(arg.Ch.Mac) {
			return core.ValidationError("hmac failed")
		}
		if arg.Ch.Payload.Tm.IsStale(m.Now()) {
			return core.TimeoutError{}
		}

		// Can fail if it's a replay attack. Do this first.
		err = MarkChallengeUsed(m, tx, arg.Ch.Payload.Tok.ExportToDB())
		if err != nil {
			return err
		}

		// Do this either way to not leak timing.
		rvk, err := core.RandomPUKVerifyKey()
		if err != nil {
			return err
		}

		// CRUCIAL -- don't leak data as to whether the team exists, or whether the
		// user is a member or not.
		var vk core.EntityPublic
		lRes, teamID, lookupErr := lookupTeamMemberVerifyKey(
			m, tx,
			arg.Ch.Payload.Req,
		)

		// Some errors are ok to return to the caller, since they don't reveal information about
		// the team or the team's makeup.
		if lookupErr == nil {
			vk = lRes.key
		} else if !lookupErr.mask {
			return lookupErr.err
		} else {
			m.Warnw("ActivateTeamVOBearerToken", "err", lookupErr.err, "stage", "lookup")
			// For timing reasons, go ahead and verify the signature with a dummy public
			// key that will always fail.
			vk = rvk
		}

		err = vk.Verify(arg.Sig, &arg.Ch)
		if err != nil || lookupErr != nil {
			m.Warnw("ActivateTeamVOBearerToken", "err", err, "stage", "sig verify")
			return core.PermissionError("team member permission failed (vo bearer token)")
		}

		err = insertTeamVOBearerToken(m, tx, arg.Ch.Payload, lRes.seq, *teamID)
		if err != nil {
			return err
		}
		ret = &rem.ActivatedVOBearerToken{
			Tok: arg.Ch.Payload.Tok,
			Id:  *teamID,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func CheckTeamVOBearerToken(
	m MetaContext,
	rq Querier,
	tok rem.TeamVOBearerToken,
	testTimeTravel time.Duration,
) (
	*rem.TeamVOBearerTokenReqAndRole,
	error,
) {
	var active bool
	var tm time.Time
	var rawTeam, rawMember, rawMemberHost []byte
	var dstRoleType, dstVizLevel, g int
	var srcRoleType, srcVizLevel int

	err := rq.QueryRow(m.Ctx(),
		`SELECT team_id, active, T.ctime, dst_role_type, dst_viz_level, 
		   key_gen, member_id, member_host_id, src_role_type, src_viz_level
		 FROM team_vo_bearer_tokens AS T
		 JOIN team_members 
		 USING (short_host_id, team_id, member_id, member_host_id, 
			 src_role_type, src_viz_level, seqno)
		 WHERE short_host_id=$1 AND token=$2 AND T.state='active'`,
		m.ShortHostID().ExportToDB(),
		tok.ExportToDB(),
	).Scan(&rawTeam, &active, &tm, &dstRoleType, &dstVizLevel, &g, &rawMember, &rawMemberHost,
		&srcRoleType, &srcVizLevel)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("team vo bearer token")
	}
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, core.TeamBearerTokenStaleError{Which: "stale member"}
	}
	err = assertTokenNotExpired(m, tm, testTimeTravel)
	if err != nil {
		return nil, err
	}
	var teamID proto.TeamID
	err = teamID.ImportFromDB(rawTeam)
	if err != nil {
		return nil, err
	}

	host, err := ImportHost(m, rawMemberHost)
	if err != nil {
		return nil, err
	}
	dstRk, err := core.ImportRoleKeyFromDB(dstRoleType, dstVizLevel)
	if err != nil {
		return nil, err
	}
	srcRk, err := core.ImportRoleKeyFromDB(srcRoleType, srcVizLevel)
	if err != nil {
		return nil, err
	}
	ret := rem.TeamVOBearerTokenReqAndRole{
		Req: rem.TeamVOBearerTokenReq{
			Team: proto.FQTeamIDOrName{
				Host:     m.HostID().Id,
				IdOrName: proto.NewTeamIDOrNameWithTrue(teamID),
			},
			Gen: proto.Generation(g),
			Member: proto.FQParty{
				Host: host,
			},
			SrcRole: srcRk.Export(),
		},
		Role: dstRk.Export(),
	}
	err = ret.Req.Member.Party.ImportFromDB(rawMember)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func assertTokenNotExpired(
	m MetaContext,
	ctime time.Time,
	testTimeTravel time.Duration,
) error {
	// For testing, we might bump now off into the future, but for the sake of combatting future
	// security bugs, never allow a time travel value to be negative.
	if testTimeTravel < 0 {
		return core.InternalError("negative time travel is dangerous and not allowed")
	}
	now := m.Now()
	if testTimeTravel > 0 {
		now = now.Add(testTimeTravel)
	}
	age := now.Sub(ctime)
	settings, err := m.G().Config().Settings(m.Ctx())
	if err != nil {
		return err
	}
	if age > settings.TeamBearerTokenLifespan() {
		return core.TeamBearerTokenStaleError{Which: "age"}
	}
	return nil
}

func LoadBearerToken(
	m MetaContext,
	q Querier,
	tok rem.TeamBearerToken,
	testTimeTravel time.Duration,
) (
	*proto.TeamID,
	*proto.Role,
	error,
) {
	var teamidRaw, uidRaw []byte
	var typ, lev, gen int
	var ctime time.Time
	err := q.QueryRow(m.Ctx(),
		`SELECT team_id, role_type, viz_level, gen, holder_uid, ctime
		 FROM team_bearer_tokens
		 WHERE short_host_id=$1 AND token=$2 AND state=$3`,
		m.ShortHostID().ExportToDB(),
		tok.ExportToDB(),
		team.BearerTokenStateActive,
	).Scan(&teamidRaw, &typ, &lev, &gen, &uidRaw, &ctime)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, core.TeamBearerTokenStaleError{Which: "state"}
	}
	if err != nil {
		return nil, nil, err
	}

	err = assertTokenNotExpired(m, ctime, testTimeTravel)
	if err != nil {
		return nil, nil, err
	}

	var uid proto.UID
	err = uid.ImportFromDB(uidRaw)
	if err != nil {
		return nil, nil, err
	}

	rk, err := core.ImportRoleKeyFromDB(typ, lev)
	if err != nil {
		return nil, nil, err
	}

	role := rk.Export()

	if m.UID().IsZero() {
		err = role.AssertBelowAdmin(core.PermissionError("no admin tokens allowed for remote users"))
		if err != nil {
			return nil, nil, err
		}
	} else {
		if !m.UID().Eq(proto.UID(uid)) {
			return nil, nil, core.WrongUserError{}
		}
	}

	var teamID proto.TeamID
	err = teamID.ImportFromDB(teamidRaw)
	if err != nil {
		return nil, nil, err
	}

	sps, err := LoadLatestPTKForRole(m, q, teamID, role)
	if err != nil {
		return nil, nil, err
	}
	if sps.Gen != proto.Generation(gen) {
		return nil, nil, core.TeamBearerTokenStaleError{Which: "gen"}
	}
	return &teamID, &role, nil
}

func ActivateTeamBearerToken(
	m MetaContext,
	tx pgx.Tx,
	arg rem.ActivateTeamBearerTokenArg,
	guest bool,
) error {
	obj, err := arg.Bl.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return err
	}
	sps, err := LoadLatestPTKForRole(m, tx, obj.Team, obj.Role)
	if err != nil {
		return err
	}
	if sps.Gen != obj.Gen {
		return core.TeamBearerTokenStaleError{Which: "gen"}
	}
	if !obj.Tm.IsNowish() {
		return core.TeamBearerTokenStaleError{Which: "time"}
	}

	var uid proto.UID
	var hostIDRaw []byte

	if m.HostID().Id.Eq(obj.User.HostID) {
		if guest {
			return core.PermissionError("cannot be a guest for a local token")
		}
		if !m.UID().Eq(obj.User.Uid) {
			return core.PermissionError("wrong UID")
		}
		uid = m.UID()
		hostIDRaw = LocalHost
	} else {
		if !guest {
			return core.PermissionError("cannot use a remote token for a local user")
		}
		uid = obj.User.Uid
		hostIDRaw = obj.User.HostID.ExportToDB()
		err = obj.Role.AssertBelowAdmin(
			core.PermissionError("no admin tokens allowed for remote users"),
		)
		if err != nil {
			return err
		}
	}

	err = sps.Verify(arg.Sig, &arg.Bl)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE team_bearer_tokens
		 SET state=$1
		 WHERE short_host_id=$2 AND team_id=$3 AND token=$4 
		 AND state=$5 AND holder_uid=$6 AND holder_host_id=$7`,
		team.BearerTokenStateActive,
		m.ShortHostID().ExportToDB(),
		obj.Team.ExportToDB(),
		obj.Tok.ExportToDB(),
		team.BearerTokenStateInert,
		uid.ExportToDB(),
		hostIDRaw,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("team_bearer_tokens")
	}
	return nil
}

func InsertInertTeamBearerToken(
	m MetaContext,
	tx pgx.Tx,
	tok rem.TeamBearerToken,
	arg rem.MakeInertTeamBearerTokenArg,
	fqu *proto.FQUser,
) error {
	// We don't check that this is a valid Tean/Gen
	// combo, since it would leak information that we don't
	// know that the caller has access to. This means we might
	// wind up with "junk" insert tokens, but that's OK for now.
	rk, err := core.ImportRole(arg.Role)
	if err != nil {
		return err
	}

	if rk.Typ.IsAdminOrAbove() != (fqu == nil) {
		return core.PermissionError("admin bearer tokens only can work for logged in users")
	}

	var uid proto.UID
	var hostIDRaw []byte
	if fqu != nil {
		uid = fqu.Uid
		hostIDRaw = fqu.HostID.ExportToDB()
	} else {
		uid = m.UID()
		hostIDRaw = LocalHost
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO team_bearer_tokens(short_host_id, team_id, token, state,
			 role_type, viz_level,
			 gen, holder_uid, holder_host_id, ctime)
		 VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
		m.ShortHostID().ExportToDB(),
		arg.Team.ExportToDB(),
		tok.ExportToDB(),
		team.BearerTokenStateInert,
		int(rk.Typ),
		int(rk.Lev),
		int(arg.Gen),
		uid.ExportToDB(),
		hostIDRaw,
	)

	if pgErr, ok := err.(*pgconn.PgError); ok &&
		pgErr.Code == "23503" &&
		pgErr.ConstraintName == "team_bearer_tokens_short_host_id_team_id_fkey" {
		return core.TeamNotFoundError{}
	}

	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("team_bearer_tokens")
	}
	return nil
}
