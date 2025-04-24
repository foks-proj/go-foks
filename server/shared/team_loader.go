// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TeamLoader struct {
	Arg  rem.LoadTeamChainArg
	Res  rem.TeamChain
	Locs map[int]proto.TreeLocation

	creds  *rem.TeamVOBearerTokenReqAndRole
	viewer *proto.FQParty // If we passed a permission token, creds=nil, and this is nonnil
	name   proto.NameAndSeqnoBundle
	cl     *ChainLoader
	db     *pgxpool.Conn
}

func NewTeamLoader(arg rem.LoadTeamChainArg) *TeamLoader {
	return &TeamLoader{
		Arg: arg,
	}
}

func (l *TeamLoader) init(m MetaContext) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	l.db = db
	l.cl = NewChainLoader(l.Arg.Team.Team.EntityID(), proto.ChainType_Team, l.Arg.Start, db)
	return nil
}

func (t *TeamLoader) cleanup(m MetaContext) {
	if t.db != nil {
		t.db.Release()
	}
}

// These various conditions are tested in: TestTeamLoaderPermissions in team_perms_test.go
func (l *TeamLoader) checkPerms(m MetaContext) error {
	typ, err := l.Arg.Tok.GetT()
	if err != nil {
		return err
	}

	switch typ {
	case rem.TokenType_TeamVOBearer:
		creds, err := checkTeamVOBearerTokenForTeam(m, l.db, l.Arg.Tok.Teamvobearer(), l.Arg.Team)
		if err != nil {
			return err
		}
		l.creds = creds
	case rem.TokenType_Permission:
		viewer, err := checkTeamPermissionToken(m, l.db, l.Arg.Tok.Permission(), l.Arg.Team)
		if err != nil {
			return err
		}
		l.viewer = viewer
	case rem.TokenType_LocalParentTeam:
		teamID, err := checkTeamVOBearerTokenForLocalParentTeam(m, l.db, l.Arg.Tok.Localparentteam())
		if err != nil {
			return err
		}
		err = checkLocalViewPermission(m, l.db, teamID.ToPartyID(), l.Arg.Team)
		if err != nil {
			return err
		}
		l.viewer = &proto.FQParty{
			Party: teamID.ToPartyID(),
			Host:  m.HostID().Id,
		}
	default:
		return core.PermissionError("no view token")
	}
	return nil
}

func checkLocalViewPermission(
	m MetaContext,
	db *pgxpool.Conn,
	viewer proto.PartyID,
	target proto.FQTeam,
) error {
	var dummy int
	err := db.QueryRow(m.Ctx(),
		`SELECT 1 FROM local_view_permissions
		 WHERE short_host_id=$1
		 AND viewer_eid=$2
		 AND target_eid=$3
		 AND state='valid'`,
		m.ShortHostID(),
		viewer.ExportToDB(),
		target.Team.ExportToDB(),
	).Scan(&dummy)
	if !m.HostID().Id.Eq(target.Host) {
		return core.HostMismatchError{}
	}
	if errors.Is(err, pgx.ErrNoRows) || dummy != 1 {
		return core.PermissionError("no view permission")
	}
	if err != nil {
		return err
	}
	return nil
}

func checkTeamPermissionToken(
	m MetaContext,
	rq Querier,
	tok proto.PermissionToken,
	team proto.FQTeam,
) (
	*proto.FQParty,
	error,
) {
	if !team.Host.Eq(m.HostID().Id) {
		return nil, core.HostMismatchError{}
	}

	var viewerEID, viewerHost []byte

	err := rq.QueryRow(
		m.Ctx(),
		`SELECT viewer_eid, viewer_host_id
		 FROM remote_view_permissions
		 WHERE short_host_id=$1 AND target_eid=$2 AND token=$3
		 AND state='valid'`,
		int(m.ShortHostID()),
		team.Team.ExportToDB(),
		tok.ExportToDB(),
	).Scan(&viewerEID, &viewerHost)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.PermissionError("permission token not valid for team")
	}
	if err != nil {
		return nil, err
	}
	var viewer proto.FQParty
	err = viewer.Party.ImportFromDB(viewerEID)
	if err != nil {
		return nil, err
	}
	viewer.Host, err = ImportHost(m, viewerHost)
	if err != nil {
		return nil, err
	}
	return &viewer, nil
}

func checkTeamVOBearerTokenForLocalParentTeam(
	m MetaContext,
	db *pgxpool.Conn,
	tok rem.TeamVOBearerToken,
) (
	*proto.TeamID,
	error,
) {
	creds, err := CheckTeamVOBearerToken(m, db, tok, 0)
	if err != nil {
		return nil, err
	}
	isID, err := creds.Req.Team.IdOrName.GetId()
	if err != nil {
		return nil, err
	}
	if !isID {
		return nil, core.InternalError("expected a teamID from CheckTeamVOBearerToken")
	}
	if !creds.Req.Team.Host.Eq(m.HostID().Id) {
		return nil, core.HostMismatchError{}
	}
	id := creds.Req.Team.IdOrName.True()
	return &id, nil
}

func checkTeamVOBearerTokenForTeam(
	m MetaContext,
	db *pgxpool.Conn,
	tok rem.TeamVOBearerToken,
	team proto.FQTeam,
) (
	*rem.TeamVOBearerTokenReqAndRole,
	error,
) {
	creds, err := CheckTeamVOBearerToken(m, db, tok, 0)
	if err != nil {
		return nil, err
	}
	isID, err := creds.Req.Team.IdOrName.GetId()
	if err != nil {
		return nil, err
	}
	if !isID {
		return nil, core.InternalError("expected a teamID from CheckTeamVOBearerToken")
	}
	teamID := creds.Req.Team.IdOrName.True()
	if !teamID.Eq(team.Team) || !creds.Req.Team.Host.Eq(m.HostID().Id) {
		return nil, core.PermissionError("wrong token for team load")
	}
	if creds.Req.Member.Host.Eq(m.HostID().Id) && m.UID().IsZero() {
		return nil, core.NeedLoginError{}
	}
	return creds, nil
}

func (l *TeamLoader) loadCommittedData(m MetaContext) error {
	return iterateOverChangeMetadata(l.Res.Links, func(c proto.ChangeMetadata) error {
		t, err := c.GetT()
		if err != nil {
			return err
		}
		switch t {
		case proto.ChangeType_Teamname:
			comm := c.Teamname()
			var res rem.NameCommitmentAndKey
			res.Key, err = LoadCommitment(m.Ctx(), l.db, m.ShortHostID(), comm, &res.Unc, nil)
			if err != nil {
				return err
			}
			l.Res.Teamnames = append(l.Res.Teamnames, res)
		}
		return nil
	})
}

func (l *TeamLoader) loadKeyBoxes(m MetaContext) error {
	// If we didn't get a VOBearerToken, we'll have nil creds, and we can't load key boxes
	if l.creds == nil {
		return nil
	}
	myRk, err := core.ImportRole(l.creds.Role)
	if err != nil {
		return err
	}
	mp, err := core.ImportSharedKeyGens(l.Arg.HavePtkGens)
	if err != nil {
		return err
	}

	// First figure out which (role,gen)s we need to load.
	rows, err := l.db.Query(m.Ctx(),
		`SELECT role_type, viz_level, gen
		 FROM shared_key_generations
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type >= $3`,
		m.ShortHostID(), l.Arg.Team.Team.ExportToDB(), myRk.Lev,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	toFetch := make(map[core.RoleKey]int)

	for rows.Next() {
		var r, v, g int
		err = rows.Scan(&r, &v, &g)
		if err != nil {
			return err
		}
		rk, err := core.ImportRoleKeyFromDB(r, v)
		if err != nil {
			return err
		}

		// Only consider keys that we can see
		if !rk.LessThanOrEqual(*myRk) {
			continue
		}

		gen, ok := mp[*rk]
		if !ok || int(gen) < g {
			toFetch[*rk] = g
		}
	}

	srcRk, err := core.ImportRole(l.creds.Req.SrcRole)
	if err != nil {
		return err
	}

	// Now fetch all of the needed boxes
	for rk, g := range toFetch {
		var box, dh, sndr, bs []byte
		var tg, trt, tvl int
		host := ExportHostInScope(m, l.creds.Req.Member.Host)
		err := l.db.QueryRow(m.Ctx(),
			`SELECT box, ephemeral_dh_key, signer_id, box_set_id, 
  			    target_gen, target_role_type, target_viz_level
		 	 FROM shared_key_boxes
		 	 JOIN shared_key_box_metadata USING (short_host_id, box_set_id)
		 	 WHERE short_host_id=$1 AND entity_id=$2 
			 AND target_entity_id=$3 AND target_host_id=$4
			 AND target_role_type=$5 AND target_viz_level=$6
		     AND role_type=$7 AND viz_level=$8 AND gen=$9`,
			m.ShortHostID(),
			l.Arg.Team.Team.ExportToDB(),
			l.creds.Req.Member.Party.ExportToDB(),
			host,
			srcRk.Typ,
			srcRk.Lev,
			rk.Typ,
			rk.Lev,
			g,
		).Scan(&box, &dh, &sndr, &bs, &tg, &trt, &tvl)
		if err != nil {
			return err
		}
		hosIdp, err := ImportHostInScope(host)
		if err != nil {
			return err
		}
		trk, err := core.ImportRoleKeyFromDB(trt, tvl)
		if err != nil {
			return err
		}
		skp := proto.SharedKeyParcel{
			Box: proto.SharedKeyBox{
				Gen:  proto.Generation(g),
				Role: rk.Export(),
				Targ: proto.SharedKeyBoxTarget{
					Eid:  l.creds.Req.Member.Party.EntityID(),
					Host: hosIdp,
					Gen:  proto.Generation(tg),
					Role: trk.Export(),
				},
			},
		}
		err = core.DecodeFromBytes(&skp.Box.Box, box)
		if err != nil {
			return err
		}
		if len(dh) > 0 {
			var tmp proto.TempDHKeySigned
			err = core.DecodeFromBytes(&tmp, dh)
			if err != nil {
				return err
			}
			skp.TempDHKeySigned = &tmp
		}
		err = skp.BoxId.ImportFromBytes(bs)
		if err != nil {
			return err
		}
		skp.Sender, err = proto.ImportEntityIDFromBytes(sndr)
		if err != nil {
			return err
		}

		nextGen, ok := mp[rk]
		if ok {
			nextGen++
		}

		rows, err := l.db.Query(m.Ctx(),
			`SELECT gen, secret_box
			 FROM shared_key_seed_chain
			 WHERE short_host_id=$1 AND entity_id=$2 
			 AND role_type=$3 AND viz_level=$4
			 AND gen >= $5
			 ORDER BY gen ASC`,
			m.ShortHostID(),
			l.Arg.Team.Team.ExportToDB(),
			rk.Typ,
			rk.Lev,
			nextGen,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g int
			var sb []byte
			err = rows.Scan(&g, &sb)
			if err != nil {
				return err
			}
			scb := proto.SeedChainBox{
				Gen:  proto.Generation(g),
				Role: rk.Export(),
			}
			err = core.DecodeFromBytes(&scb.Box, sb)
			if err != nil {
				return err
			}
			skp.SeedChain = append(skp.SeedChain, scb)
		}

		l.Res.Boxes = append(l.Res.Boxes, skp)
	}

	return nil
}

func (l *TeamLoader) checkArgs(m MetaContext) error {
	if !l.Arg.Start.IsValid() {
		return core.BadArgsError("invalid start seqno")
	}
	return nil
}

func (l *TeamLoader) Run(m MetaContext) error {
	defer l.cleanup(m)

	// Set scope relative to the host ID specified in the fully-qualified team name
	// (important if this server is servicing multiple vhosts).
	m, err := m.WithProtoHostID(&l.Arg.Team.Host)
	if err != nil {
		return err
	}

	err = l.init(m)
	if err != nil {
		return err
	}

	err = l.checkArgs(m)
	if err != nil {
		return err
	}

	err = l.checkPerms(m)
	if err != nil {
		return err
	}

	err = l.loadName(m)
	if err != nil {
		return err
	}

	l.Locs, l.Res.Locations, err = l.cl.LoadTreeLocations(m)
	if err != nil {
		return err
	}

	l.Res.Links, err = l.cl.LoadChain(m)
	if err != nil {
		return err
	}

	err = l.loadCommittedData(m)
	if err != nil {
		return err
	}

	err = l.loadKeyBoxes(m)
	if err != nil {
		return err
	}

	err = l.loadMerkle(m)
	if err != nil {
		return err
	}

	err = l.loadRemovalKey(m)
	if err != nil {
		return err
	}

	err = l.loadRemoteViewTokens(m)
	if err != nil {
		return err
	}

	err = l.loadHEPKs(m)
	if err != nil {
		return err
	}

	return nil
}

func (l *TeamLoader) loadHEPKs(m MetaContext) error {
	set, err := l.cl.LoadHEPKs(m, l.Res.Links)
	if err != nil {
		return err
	}
	l.Res.Hepks = *set
	return nil
}

func scanTeamRemoteViewToks(
	m MetaContext,
	rows pgx.Rows,

) (
	[]proto.TeamRemoteMemberViewTokenInner,
	error,
) {
	var ret []proto.TeamRemoteMemberViewTokenInner
	for rows.Next() {
		var pidRaw, hidRaw, box []byte
		var gen int
		err := rows.Scan(&pidRaw, &hidRaw, &gen, &box)
		if err != nil {
			return nil, err
		}
		var pid proto.PartyID
		err = pid.ImportFromDB(pidRaw)
		if err != nil {
			return nil, err
		}
		hid, err := ImportHost(m, hidRaw)
		if err != nil {
			return nil, err
		}
		var sb proto.SecretBox
		err = core.DecodeFromBytes(&sb, box)
		if err != nil {
			return nil, err
		}
		row := proto.TeamRemoteMemberViewTokenInner{
			Member: proto.FQParty{
				Party: pid,
				Host:  hid,
			},
			PtkGen:    proto.Generation(gen),
			SecretBox: sb,
		}
		ret = append(ret, row)
	}
	return ret, nil
}

func (l *TeamLoader) loadRemoteViewTokens(m MetaContext) error {
	if !l.Arg.LoadRemoteViewTokens {
		return nil
	}
	if l.creds == nil {
		return core.BadArgsError("cannot load remote view tokens without a VO bearer token")
	}
	rows, err := l.db.Query(m.Ctx(),
		`SELECT member_id, member_host_id, ptk_gen, secret_box
		 FROM team_remote_member_view_tokens
		 WHERE short_host_id=$1 AND team_id=$2`,
		m.ShortHostID(),
		l.Arg.Team.Team.ExportToDB(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	l.Res.RemoteViewTokens, err = scanTeamRemoteViewToks(m, rows)
	if err != nil {
		return err
	}
	return nil
}

func (l *TeamLoader) loadRemovalKey(m MetaContext) error {
	if !l.Arg.LoadRemovalKey {
		return nil
	}
	if l.creds == nil {
		return core.PermissionError("cannot load removal key without a VO bearer token")
	}
	srcRk, err := core.ImportRole(l.creds.Req.SrcRole)
	if err != nil {
		return err
	}
	host := ExportHostInScope(m, l.creds.Req.Member.Host)
	var rkRaw []byte
	err = l.db.QueryRow(m.Ctx(),
		`SELECT rk_member
		 FROM team_removal_keys
		 WHERE short_host_id=$1 AND team_id=$2
		 AND member_id=$3 AND member_host_id=$4
		 AND src_role_type=$5 AND src_viz_level=$6
		 ORDER BY create_seqno DESC LIMIT 1`,
		m.ShortHostID(),
		l.Arg.Team.Team.ExportToDB(),
		l.creds.Req.Member.Party.ExportToDB(),
		host,
		srcRk.Typ,
		srcRk.Lev,
	).Scan(&rkRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.KeyNotFoundError{Which: "removal"}
	}
	if err != nil {
		return err
	}
	var rk proto.TeamRemovalKeyBox
	err = core.DecodeFromBytes(&rk, rkRaw)
	if err != nil {
		return err
	}
	l.Res.RemovalKey = &rk
	return nil
}

func (l *TeamLoader) loadMerkle(m MetaContext) error {
	keys, err := nameMerkleKeys(l.Arg.Team.Host, l.Arg.Name, rem.NameSeqnoPair{
		S: l.name.S,
		N: l.name.B.Name,
	})
	if err != nil {
		return err
	}
	l.Res.NumTeamnameLinks = uint64(len(keys))

	tmp, err := l.cl.MakeMerkleKeys(m, l.Locs, l.Res.Links)
	if err != nil {
		return err
	}
	keys = append(keys, tmp...)

	res, err := l.cl.LoadMerkle(m, keys)
	if err != nil {
		return err
	}
	l.Res.Merkle = *res
	return nil
}

func (l *TeamLoader) loadName(m MetaContext) error {
	nm, err := l.cl.LoadName(m, l.Arg.Team.Team.ToPartyID())
	if err != nil {
		return err
	}
	l.name = *nm
	l.Res.TeamnameUtf8 = nm.B.NameUtf8
	return nil
}

func LoadTeamChain(
	m MetaContext,
	arg rem.LoadTeamChainArg,
) (
	rem.TeamChain,
	error,
) {
	var ret rem.TeamChain
	l := NewTeamLoader(arg)
	err := l.Run(m)
	if err != nil {
		return ret, err
	}
	return l.Res, nil
}

func withTeamAndTok(
	m MetaContext,
	t proto.FQTeam,
	tok rem.TeamVOBearerToken,
	f func(m MetaContext, db *pgxpool.Conn, role proto.Role) error,
) error {
	// Set scope relative to the host ID specified in the fully-qualified team name
	// (important if this server is servicing multiple vhosts).
	m, err := m.WithProtoHostID(&t.Host)
	if err != nil {
		return err
	}
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	perms, err := checkTeamVOBearerTokenForTeam(m, db, tok, t)
	if err != nil {
		return err
	}
	err = f(m, db, perms.Role)
	if err != nil {
		return err
	}
	return nil
}

func LoadTeamMembershipChain(
	m MetaContext,
	arg rem.LoadTeamMembershipChainArg,
) (
	rem.GenericChain,
	error,
) {
	var ret rem.GenericChain
	err := withTeamAndTok(m, arg.Team, arg.Tok, func(m MetaContext, db *pgxpool.Conn, _ proto.Role) error {
		tmp, err := LoadGenericChain(m, proto.ChainType_TeamMembership, arg.Team.Team.EntityID(), arg.Start)
		if err != nil {
			return err
		}
		ret = *tmp
		return nil

	})
	return ret, err
}

func LoadTeamRemoteViewTokens(
	m MetaContext,
	arg rem.LoadTeamRemoteViewTokensArg,
) (
	rem.TeamRemoteViewTokenSet,
	error,
) {
	var ret rem.TeamRemoteViewTokenSet
	err := withTeamAndTok(m, arg.Team, arg.Tok, func(m MetaContext, db *pgxpool.Conn, r proto.Role) error {
		ok, err := r.IsAdminOrAbove()
		if err != nil {
			return err
		}
		if !ok {
			return core.PermissionError("must be admin to load remote view tokens")
		}
		parties := make([][]byte, len(arg.Members))
		hosts := make([][]byte, len(arg.Members))
		for i, mem := range arg.Members {
			parties[i] = mem.Party.ExportToDB()
			hosts[i] = ExportHostInScope(m, mem.Host)
		}
		rows, err := db.Query(m.Ctx(),
			`SELECT t.member_id, t.member_host_id, t.ptk_gen, t.secret_box
 			FROM unnest($1::bytea[], $2::bytea[]) AS m(member_id, member_host_id)
			JOIN team_remote_member_view_tokens AS t USING (member_id, member_host_id)
			WHERE t.short_host_id=$3 AND t.team_id=$4`,
			parties,
			hosts,
			m.ShortHostID(),
			arg.Team.Team.ExportToDB(),
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		toks, err := scanTeamRemoteViewToks(m, rows)
		if err != nil {
			return err
		}
		ret.Tokens = toks
		return nil
	})
	return ret, err

}
