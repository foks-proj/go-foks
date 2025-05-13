// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func TeamChangeInsertTrigger(
	m MetaContext,
	team proto.TeamID,
	seqno proto.Seqno,
	changes []proto.MemberRole,
	newKeys []proto.SharedKey,
) proto.UpdateTrigger {

	return proto.NewUpdateTriggerWithTeamchange(
		proto.UpdateTriggerTeamChange{
			Team:    team,
			Seqno:   seqno,
			Changes: changes,
			NewKeys: newKeys,
		},
	)
}

func EditMembers(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	seqno proto.Seqno,
	epno proto.MerkleEpno,
	changes []proto.MemberRole,
	hepks proto.HEPKSet,
) error {
	hepkm, err := core.ImportHEPKSet(&hepks)
	if err != nil {
		return err
	}
	for _, chng := range changes {
		err := EditMember(m, tx, team, seqno, epno, chng, hepkm)
		if err != nil {
			return err
		}
	}
	return nil
}

func EditMember(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	seqno proto.Seqno,
	epno proto.MerkleEpno,
	mr proto.MemberRole,
	hepks *core.HEPKSet,
) error {

	rk, err := core.ImportRole(mr.DstRole)
	if err != nil {
		return err
	}
	srk, err := core.ImportRole(mr.Member.SrcRole)
	if err != nil {
		return err
	}

	if rk.Typ == proto.RoleType_NONE {

		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE team_members SET removal_seqno=$1, active=false
			 WHERE short_host_id=$2 AND team_id=$3 AND member_id=$4
			 AND member_host_id=$5 AND src_role_type=$6 AND src_viz_level=$7
			 AND removal_seqno IS NULL`,
			int(seqno),
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			mr.Member.Id.Entity.ExportToDB(),
			ExportHostP(mr.Member.Id.Host),
			int(srk.Typ),
			int(srk.Lev),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() < 1 {
			return core.UpdateError("team_members set removal_seqno")
		}

	} else {

		keys := mr.Member.Keys

		typ, err := keys.GetT()
		if err != nil {
			return err
		}
		if typ != proto.MemberKeysType_Team {
			return core.InsertError("need member keys type")
		}
		tmk := keys.Team()

		var tir []byte
		if tmk.Tir != nil {
			var err error
			tir, err = core.EncodeToBytes(tmk.Tir)
			if err != nil {
				return err
			}
		}

		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO team_members(short_host_id, team_id, member_id, member_host_id, 
			  src_role_type, src_viz_level,
			  seqno, active, create_header_epno,
			  key_gen, verify_key, hepk_fp, dst_role_type, dst_viz_level, tir, ctime)
			VALUES($1, $2, $3, $4, 
			  $5, $6, 
			  $7, $8, $9, 
			  $10, $11, $12, $13, $14, $15, NOW())`,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			mr.Member.Id.Entity.ExportToDB(),
			ExportHostP(mr.Member.Id.Host),
			int(srk.Typ),
			int(srk.Lev),
			int(seqno),
			true,
			int(epno),
			int(tmk.Gen),
			tmk.VerifyKey.ExportToDB(),
			tmk.HepkFp.ExportToDB(),
			int(rk.Typ),
			int(rk.Lev),
			tir,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("team_members")
		}

		// If we are inserting remote team members, we need to copy their full HEPK
		// into our database. If they are local members, we should already have it.
		if mr.Member.Id.Host != nil {
			err = InsertHEPK(m, tx, tmk.HepkFp, hepks)
			if err != nil {
				return err
			}
		}
	}

	// Mark earlier rows no longer active
	_, err = tx.Exec(
		m.Ctx(),
		`UPDATE team_members SET active=false 
		 WHERE short_host_id=$1 AND team_id=$2 AND member_id=$3 
		 AND member_host_id=$4 AND seqno<$5
		 AND src_role_type=$6 AND src_viz_level=$7`,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		mr.Member.Id.Entity.ExportToDB(),
		ExportHostP(mr.Member.Id.Host),
		int(seqno),
		int(srk.Typ),
		int(srk.Lev),
	)
	if err != nil {
		return err
	}

	return nil
}

func StoreTeamCert(
	m MetaContext,
	tx pgx.Tx,
	team proto.TeamID,
	cert rem.TeamCert,
) error {
	v, err := cert.GetV()
	if err != nil {
		return err
	}
	if v != rem.TeamCertVersion_V1 {
		return core.VersionNotSupportedError("team cert")
	}
	v1 := cert.V1()
	payload, err := v1.Payload.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return err
	}
	gen := payload.Ptk.Gen

	b, err := core.EncodeToBytes(&cert)
	if err != nil {
		return err
	}
	hsh, err := core.PrefixedHash(&cert)
	if err != nil {
		return err
	}
	if !payload.Team.Host.Eq(m.HostID().Id) {
		return core.HostMismatchError{}
	}
	if !payload.Team.Team.Eq(team) {
		return core.TeamError("team mismatch")
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO team_certs(short_host_id, team_id, gen, hsh, cert, ctime, mtime)
		 VALUES($1, $2, $3, $4, $5, NOW(), NOW())`,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		int(gen),
		hsh.ExportToDB(),
		b,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("team_certs")
	}
	return nil

}

func InsertPTKs(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	doer proto.EntityID,
	openres team.OpeanTeamLinkRes,
	obd rem.OffchainBoxData,
) error {

	sched := openres.Sched
	memberHost := m.HostID().Id

	err := sched.MatchBoxes(obd.PtkBoxes, memberHost)
	if err != nil {
		return err
	}

	err = sched.MatchPublicKeys(openres.Gc.SharedKeys)
	if err != nil {
		return err
	}

	err = sched.MatchSeedChain(obd.SeedChain)
	if err != nil {
		return err
	}

	if len(obd.PtkBoxes.Boxes) == 0 {
		return nil
	}

	err = insertGenerations(m, tx, team, sched)
	if err != nil {
		return err
	}

	err = insertSharedKeys(m, tx, team, doer, openres.Gc.SharedKeys, obd.Hepks)
	if err != nil {
		return err
	}

	err = insertSeedChain(m, tx, team, obd.SeedChain)
	if err != nil {
		return err
	}

	err = insertMetadata(m, tx, team, doer, obd.PtkBoxes)
	if err != nil {
		return err
	}

	err = insertBoxes(m, tx, team, obd.PtkBoxes, openres.RosterPost.Mks)
	if err != nil {
		return err
	}

	return nil
}

func insertBoxes(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	sbs proto.SharedKeyBoxSet,
	mks *team.MemberKeysSet,
) error {

	for _, box := range sbs.Boxes {
		rk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		b, err := core.EncodeToBytes(&box.Box)
		if err != nil {
			return err
		}
		trk, err := core.ImportRole(box.Targ.Role)
		if err != nil {
			return err
		}

		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_boxes(short_host_id, entity_id, 
				target_entity_id, target_host_id, 
			    gen, role_type, viz_level, box_set_id, box, ctime,
				target_gen, target_role_type, target_viz_level)
		     VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12)`,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			box.Targ.Eid.ExportToDB(),
			ExportHostP(box.Targ.Host),
			box.Gen,
			rk.Typ,
			rk.Lev,
			sbs.Id.ExportToDB(),
			b,
			box.Targ.Gen,
			trk.Typ,
			trk.Lev,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert shared_key_boxes")
		}
	}
	return nil
}

func insertMetadata(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	doer proto.EntityID,
	sbs proto.SharedKeyBoxSet,
) error {

	dh, err := ExportTmpDHKeySignedToDB(sbs.TempDHKeySigned)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO shared_key_box_metadata (short_host_id, box_set_id, signer_id, ephemeral_dh_key)
         VALUES($1,$2,$3,$4)`,
		m.ShortHostID().ExportToDB(),
		sbs.Id.ExportToDB(),
		doer.ExportToDB(),
		dh,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert shared key box metadata")
	}
	return nil
}

func insertSeedChain(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	ch []proto.SeedChainBox,
) error {

	for _, box := range ch {
		rk, err := core.ImportRole(box.Role)
		if err != nil {
			return err
		}
		b, err := core.EncodeToBytes(&box.Box)
		if err != nil {
			return err
		}
		tags, err := tx.Exec(m.Ctx(),
			`INSERT INTO shared_key_seed_chain(short_host_id, entity_id, gen, role_type, viz_level, ctime, secret_box)
	         VALUES($1, $2, $3, $4, $5, NOW(), $6)`,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			box.Gen,
			rk.Typ,
			rk.Lev,
			b,
		)
		if err != nil {
			return err
		}
		if tags.RowsAffected() != 1 {
			return core.InsertError("failed to insert into shared_key_seed_chain")
		}
	}
	return nil

}

func insertSharedKeys(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	doer proto.EntityID,
	sks []proto.SharedKey,
	hepkVec proto.HEPKSet,
) error {
	hepks, err := core.ImportHEPKSet(&hepkVec)
	if err != nil {
		return err
	}
	for _, sk := range sks {
		err := InsertSharedKey(m, tx, proto.EntityType_PTKVerify, team, doer, sk, hepks)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertGenerations(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	sched team.KeySchedule,
) error {

	for _, item := range sched.Items {
		if !item.NewKeyGen {
			continue
		}

		args := []any{
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			int(item.Role.Typ),
			int(item.Role.Lev),
			int(item.Gen),
		}
		var q string

		switch {
		case item.Gen.IsFirst():
			q = `INSERT INTO shared_key_generations(short_host_id, entity_id, role_type, viz_level, gen)
				 VALUES($1, $2, $3, $4, $5)`
		case !item.Gen.IsValid():
			return core.BadArgsError("invalid generation; PTK gens must be >= 1")
		default:
			q = `UPDATE shared_key_generations
				 SET gen=$5
				 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 AND viz_level=$4`
		}
		tag, err := tx.Exec(m.Ctx(), q, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("shared_key_generations")
		}
	}
	return nil
}

// XXXX - this is wrong and doesn't take into the account the role of the shared key relative to
// the member. For PUKs, this will probably always be Owners, but for teams, it seems like we can add
// and role of PTK as a PTK into the team. A PTK at R can be a member of another team at T, for any
// R or T.
func ReadLatestSharedKey(
	m MetaContext,
	tx pgx.Tx,
	eid proto.EntityID,
	role proto.Role,
) (
	*proto.SharedKey,
	error,
) {
	var gen int
	var hpekFpRaw, vk []byte

	rk, err := core.ImportRole(role)
	if err != nil {
		return nil, err
	}

	err = tx.QueryRow(m.Ctx(),
		`SELECT gen, hepk_fp, verify_key
		 FROM shared_keys
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 AND viz_level=$4
		 ORDER BY gen DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(),
		int(rk.Typ),
		int(rk.Lev),
	).Scan(&gen, &hpekFpRaw, &vk)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.KeyNotFoundError{Which: "shared key"}
	}

	if err != nil {
		return nil, err
	}

	vke, err := proto.ImportEntityIDFromBytes(vk)
	if err != nil {
		return nil, err
	}

	var hepkFp proto.HEPKFingerprint
	err = hepkFp.ImportFromDB(hpekFpRaw)
	if err != nil {
		return nil, err
	}

	ret := proto.SharedKey{
		Gen:       proto.Generation(gen),
		Role:      role,
		VerifyKey: vke,
		HepkFp:    hepkFp,
	}

	return &ret, nil
}

func forAllTeamChanges(
	changes []proto.MemberRole,
	f func(proto.MemberRole, proto.TeamMemberKeys) error,
) error {
	for _, chng := range changes {
		rtyp, err := chng.DstRole.GetT()
		if err != nil {
			return err
		}
		if rtyp == proto.RoleType_NONE {
			continue
		}
		typ, err := chng.Member.Keys.GetT()
		if err != nil {
			return err
		}
		if typ != proto.MemberKeysType_Team {
			return core.LinkError("bad member keys type")
		}
		err = f(chng, chng.Member.Keys.Team())
		if err != nil {
			return err
		}
	}
	return nil
}

func CheckLocalMembers(
	m MetaContext,
	tx pgx.Tx,
	changes []proto.MemberRole,
) error {

	checkTeamIndexRange := func(chng proto.MemberRole, keys proto.TeamMemberKeys) error {
		if chng.Member.Id.Entity.Type() != proto.EntityType_Team {
			return nil
		}
		tid, err := chng.Member.Id.Entity.ToTeamID()
		if err != nil {
			return err
		}
		tir, _, err := GetLatestTeamIndexRange(m, tx, tid)
		if err != nil {
			return err
		}
		if keys.Tir == nil {
			return core.LinkError("no team index range for added team")
		}
		tmp := core.NewRationalRange(*keys.Tir)
		if !tir.Eq(tmp) {
			return core.TeamRaceError("bad team index range for member")
		}
		return nil

	}

	return forAllTeamChanges(changes, func(chng proto.MemberRole, keys proto.TeamMemberKeys) error {
		if chng.Member.Id.Host != nil {
			return nil
		}
		ktyp, err := chng.Member.Keys.GetT()
		if err != nil {
			return err
		}
		if ktyp != proto.MemberKeysType_Team {
			return core.LinkError("bad member keys type")
		}
		lsk, err := ReadLatestSharedKey(m, tx, chng.Member.Id.Entity, chng.Member.SrcRole)
		if err != nil {
			return err
		}
		if lsk.Gen != keys.Gen {
			return core.TeamRaceError("bad/stale generation for member")
		}
		if !lsk.VerifyKey.Eq(keys.VerifyKey) {
			return core.TeamRaceError("bad verify key for member")
		}
		if !lsk.HepkFp.Eq(&keys.HepkFp) {
			return core.TeamRaceError("bad dh key for member")
		}
		err = checkTeamIndexRange(chng, keys)
		if err != nil {
			return err
		}
		return nil
	})
}

func LoadTeamMembersFromDB(
	m MetaContext,
	tx pgx.Tx,
	teamid proto.TeamID,
) (
	[]proto.MemberRoleSeqno,
	error,
) {
	rows, err := tx.Query(m.Ctx(),
		`SELECT member_id, member_host_id, key_gen, verify_key, hepk_fp, 
		  src_role_type, src_viz_level, dst_role_type, dst_viz_level, seqno
	     FROM team_members
		 WHERE short_host_id=$1 AND team_id=$2 AND active=true`,
		m.ShortHostID().ExportToDB(),
		teamid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []proto.MemberRoleSeqno
	for rows.Next() {
		var mid, mhost []byte
		var gen, dstRol, dstViz, srcRol, srcViz, seqno int
		var vk, hepkFpRaw []byte
		err = rows.Scan(&mid, &mhost, &gen, &vk, &hepkFpRaw,
			&srcRol, &srcViz, &dstRol, &dstViz, &seqno)
		if err != nil {
			return nil, err
		}
		var tmk proto.TeamMemberKeys
		var fqe proto.FQEntityInHostScope

		fqe.Host, err = ImportHostInScope(mhost)
		if err != nil {
			return nil, err
		}
		fqe.Entity, err = proto.ImportEntityIDFromBytes(mid)
		if err != nil {
			return nil, err
		}
		drk, err := core.ImportRoleKeyFromDB(dstRol, dstViz)
		if err != nil {
			return nil, err
		}
		srk, err := core.ImportRoleKeyFromDB(srcRol, srcViz)
		if err != nil {
			return nil, err
		}

		tmk.VerifyKey, err = proto.ImportEntityIDFromBytes(vk)
		if err != nil {
			return nil, err
		}
		err = tmk.HepkFp.ImportFromDB(hepkFpRaw)
		if err != nil {
			return nil, err
		}
		tmk.Gen = proto.Generation(gen)

		mrq := proto.MemberRoleSeqno{
			Mr: proto.MemberRole{
				DstRole: drk.Export(),
				Member: proto.Member{
					Id:      fqe,
					SrcRole: srk.Export(),
					Keys:    proto.NewMemberKeysWithTeam(tmk),
				},
			},
			Seqno: proto.Seqno(seqno),
		}
		ret = append(ret, mrq)
	}
	return ret, nil
}

func LoadKeyGenerationsFromDB(
	m MetaContext,
	tx pgx.Tx,
	eid proto.EntityID,
) (
	team.KeyGens,
	error,
) {
	rows, err := tx.Query(m.Ctx(),
		`SELECT role_type, viz_level, gen
		 FROM shared_key_generations
		 WHERE short_host_id=$1 AND entity_id=$2`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret := make(map[core.RoleKey]proto.Generation)
	for rows.Next() {
		var typ, lev, gen int
		err = rows.Scan(&typ, &lev, &gen)
		if err != nil {
			return nil, err
		}
		rk, err := core.ImportRoleKeyFromDB(typ, lev)
		if err != nil {
			return nil, err
		}
		ret[*rk] = proto.Generation(gen)
	}
	return ret, nil
}

func LoadRoster(
	m MetaContext,
	tx pgx.Tx,
	teamid proto.TeamID,
) (
	*team.Roster,
	*proto.BaseChainer,
	error,
) {
	kg, err := LoadKeyGenerationsFromDB(m, tx, teamid.EntityID())
	if err != nil {
		return nil, nil, err
	}
	mr, err := LoadTeamMembersFromDB(m, tx, teamid)
	if err != nil {
		return nil, nil, err
	}
	ct, err := ReadChainTail(m, tx, proto.ChainType_Team, teamid.EntityID())
	if err != nil {
		return nil, nil, err
	}
	ret := team.NewRosterWithKeyGens(kg)
	err = ret.Load(mr, m.HostID().Id)
	if err != nil {
		return nil, nil, err
	}
	return ret, ct, nil
}

func LoadLatestPTKForRole(
	m MetaContext,
	rq Querier,
	teamid proto.TeamID,
	role proto.Role,
) (
	*core.SharedPublicSuite,
	error,
) {
	rk, err := core.ImportRole(role)
	if err != nil {
		return nil, err
	}
	var gen int
	var vkRaw, hepkFpRaw, hepkRaw []byte
	err = rq.QueryRow(m.Ctx(),
		`SELECT gen, hepk_fp, hepk, verify_key
		 FROM shared_keys
		 JOIN hepks USING(short_host_id, hepk_fp)
		 WHERE short_host_id=$1 AND entity_id=$2 AND role_type=$3 AND viz_level=$4
		 ORDER BY gen DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		teamid.ExportToDB(),
		int(rk.Typ),
		int(rk.Lev),
	).Scan(&gen, &hepkFpRaw, &hepkRaw, &vkRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.KeyNotFoundError{Which: "PTK"}
	}
	if err != nil {
		return nil, err
	}
	sps, err := core.ImportSharedPublicSuiteFromDB(vkRaw, hepkFpRaw, hepkRaw, role, gen)
	if err != nil {
		return nil, err
	}
	return sps, nil
}

func LoadTeamCertByHash(
	m MetaContext,
	hsh proto.TeamCertHash,
) (
	*rem.TeamCertAndMetadata,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	return loadTeamCertByHashWithDB(m, db, hsh)
}

func loadTeamCertByHashWithDB(
	m MetaContext,
	db Querier,
	hsh proto.TeamCertHash,
) (
	*rem.TeamCertAndMetadata,
	error,
) {
	var certRaw []byte
	var temaIdRaw []byte
	err := db.QueryRow(m.Ctx(),
		`SELECT cert, team_id
		 FROM team_certs
		 WHERE short_host_id=$1 AND hsh=$2`,
		m.ShortHostID().ExportToDB(),
		hsh.ExportToDB(),
	).Scan(&certRaw, &temaIdRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("team cert")
	}
	if err != nil {
		return nil, err
	}
	var teamID proto.TeamID
	err = teamID.ImportFromDB(temaIdRaw)
	if err != nil {
		return nil, err
	}
	var cert rem.TeamCert
	err = core.DecodeFromBytes(&cert, certRaw)
	if err != nil {
		return nil, err
	}
	var lowRaw, highRaw []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT low, high FROM team_index_ranges
		 WHERE short_host_id=$1 AND team_id=$2
		 ORDER BY seqno DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
	).Scan(&lowRaw, &highRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("team index range")
	}
	if err != nil {
		return nil, err
	}
	var rng proto.RationalRange
	err = core.DecodeFromBytes(&rng.Low, lowRaw)
	if err != nil {
		return nil, err
	}
	err = core.DecodeFromBytes(&rng.High, highRaw)
	if err != nil {
		return nil, err
	}
	ret := rem.TeamCertAndMetadata{
		Cert: cert,
		Tir:  rng,
	}
	return &ret, nil
}

func InsertRemoteMemberViewTokens(
	m MetaContext,
	tx pgx.Tx,
	team proto.EntityID,
	toks []proto.TeamRemoteMemberViewToken,
) error {
	for _, tok := range toks {
		if tok.Inner.Member.Host.Eq(m.HostID().Id) {
			return core.TeamError("cannot insert local member view token")
		}
		if !tok.Team.EntityID().Eq(team) {
			return core.TeamError("wrong team for token")
		}
		b, err := core.EncodeToBytes(&tok.Inner.SecretBox)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(m.Ctx(),
			`INSERT INTO team_remote_member_view_tokens(
				 short_host_id, team_id, member_id, member_host_id,
				 ptk_gen, secret_box, ctime, mtime)
			VAlUES($1, $2, $3, $4, $5, $6, NOW(), NOW())
			ON CONFLICT (short_host_id, team_id, member_id, member_host_id)
			DO UPDATE SET secret_box=$6, mtime=NOW()`,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			tok.Inner.Member.Party.ExportToDB(),
			tok.Inner.Member.Host.ExportToDB(),
			int(tok.Inner.PtkGen),
			b,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("team_remote_member_view_tokens")
		}
		_, err = tx.Exec(m.Ctx(),
			`UPDATE remote_joinreqs SET state=$1
			 WHERE short_host_id=$2 AND team_id=$3 AND state=$4 AND token=$5`,
			JoinReqStateApproved,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			JoinReqStatePending,
			tok.Jrt.ExportToDB(),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

type JoinReqState string

const (
	JoinReqStatePending  JoinReqState = "pending"
	JoinReqStateApproved JoinReqState = "approved"
)

func RemoteAcceptInvite(
	m MetaContext,
	tx pgx.Tx,
	hsh proto.TeamCertHash,
	crt rem.TeamCert,
	rjr rem.TeamRemoteJoinReq,
) (
	*proto.TeamRSVPRemote,
	error,
) {
	v, err := crt.GetV()
	if err != nil {
		return nil, err
	}
	if v != rem.TeamCertVersion_V1 {
		return nil, core.VersionNotSupportedError("team cert")
	}
	c1 := crt.V1()
	payload, err := c1.Payload.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return nil, err
	}
	var c int
	err = tx.QueryRow(
		m.Ctx(),
		`SELECT 1 
		 FROM shared_keys
		 WHERE short_host_id=$1 AND entity_id=$2 AND gen=$3
		 AND role_type=$4 AND viz_level=$5 AND hepk_fp=$6`,
		m.ShortHostID().ExportToDB(),
		payload.Team.Team.ExportToDB(),
		int(payload.Ptk.Gen),
		int(proto.RoleType_ADMIN),
		0,
		rjr.HepkFp.ExportToDB(),
	).Scan(&c)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && c != 1) {
		return nil, core.KeyNotFoundError{Which: "hepk"}
	}
	if err != nil {
		return nil, err
	}
	payloadFp, err := core.HEPK(&payload.Hepk).Fingerprint()
	if err != nil {
		return nil, err
	}
	if !rjr.HepkFp.Eq(payloadFp) {
		return nil, core.KeyMismatchError{}
	}
	ret, err := proto.RandomID16er[proto.TeamRSVPRemote]()
	if err != nil {
		return nil, err
	}
	b, err := core.EncodeToBytes(&rjr)
	if err != nil {
		return nil, err
	}

	// if the user is supplying a source index range, make sure it is less than the
	// index range of the target team.
	if rjr.Vd.Tir != nil {
		high, _, err := GetLatestTeamIndexRange(m, tx, payload.Team.Team)
		if err != nil {
			return nil, err
		}
		if high == nil {
			return nil, core.TeamError("no index range for target team")
		}
		low := core.NewRationalRange(*rjr.Vd.Tir)
		if !low.LessThan(*high) {
			return nil, core.NewTeamCycleError(low, *high)
		}
	}

	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO remote_joinreqs(short_host_id, team_id,
		  state, token, req, cert_hsh, ctime)
		 VALUES($1, $2, $3, $4, $5, $6, NOW())`,
		m.ShortHostID().ExportToDB(),
		payload.Team.Team.ExportToDB(),
		JoinReqStatePending,
		ret.ExportToDB(),
		b,
		hsh.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, core.InsertError("remote_joinreqs")
	}
	return ret, nil
}

func LoadRemoteJoinReq(
	m MetaContext,
	tm proto.TeamID,
	jrt proto.TeamRSVPRemote,
) (
	*rem.TeamRemoteJoinReq,
	error,
) {
	var reqRaw []byte
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	err = db.QueryRow(
		m.Ctx(),
		`SELECT req FROM remote_joinreqs
		 WHERE short_host_id=$1 AND team_id=$2 AND token=$3 
		 AND state=$4`,
		m.ShortHostID().ExportToDB(),
		tm.ExportToDB(),
		jrt.ExportToDB(),
		JoinReqStatePending,
	).Scan(&reqRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NotFoundError("remote join req")
	}
	if err != nil {
		return nil, err
	}
	var ret rem.TeamRemoteJoinReq
	err = core.DecodeFromBytes(&ret, reqRaw)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func InsertTeamMembershipLink(
	m MetaContext,
	tx pgx.Tx,
	pga rem.PostGenericLinkArg,
) error {
	return PostGenericLinkTryTx(
		m, tx, pga, m.UID().ToPartyID(), nil,
	)
}

func ReadRotatedPTKs(
	m MetaContext,
	rq Querier,
	team proto.TeamID,
	sched team.KeySchedule,
) (
	[]proto.EntityID,
	error,
) {
	var ret []proto.EntityID
	for _, item := range sched.Items {
		if !item.NewKeyGen || item.Gen.IsFirst() {
			continue
		}
		var raw []byte
		err := rq.QueryRow(m.Ctx(),
			`SELECT verify_key FROM shared_keys
			 WHERE short_host_id=$1 AND entity_id=$2 
			 AND role_type=$3 AND viz_level=$4 AND gen=$5`,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			int(item.Role.Typ),
			int(item.Role.Lev),
			int(item.Gen-1),
		).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.KeyNotFoundError{Which: "shared key"}
		}
		if err != nil {
			return nil, err
		}
		eid, err := proto.ImportEntityIDFromBytes(raw)
		if err != nil {
			return nil, err
		}
		ret = append(ret, eid)
	}
	return ret, nil
}

func ReadTeamAdminKeys(
	m MetaContext,
	tx pgx.Tx,
	team proto.TeamID,
) (
	map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
	error,
) {
	rows, err := tx.Query(m.Ctx(),
		`SELECT verify_key, hepk_fp, hepk, role_type, viz_level, COALESCE(provision_epno, -1), 0
		 FROM shared_keys
	     JOIN shared_key_generations USING (short_host_id, entity_id, role_type, viz_level, gen)
		 JOIN hepks USING (short_host_id, hepk_fp)
		WHERE short_host_id=$1 AND entity_id=$2 AND key_state='valid'
		 AND (role_type=$3 OR role_type=$4)`,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		int(proto.RoleType_ADMIN),
		int(proto.RoleType_OWNER),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return readPublicSuitersFromDB(m.HostID(), rows)
}

func insertRemovalKey(
	m MetaContext,
	tx pgx.Tx,
	seqno proto.Seqno,
	team proto.TeamID,
	rk rem.TeamRemovalBoxData,
) error {
	q := `INSERT INTO team_removal_keys
			(short_host_id, team_id, member_id, member_host_id, create_seqno,
				src_role_type, src_viz_level,
				rk_comm, rk_member, rk_team, ctime)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`

	mbox, err := core.EncodeToBytes(&rk.Member)
	if err != nil {
		return err
	}
	tbox, err := core.EncodeToBytes(&rk.Team)
	if err != nil {
		return err
	}
	srk, err := core.ImportRole(rk.Md.SrcRole)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		q,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		rk.Md.Member.Party.ExportToDB(),
		ExportHostInScope(m, rk.Md.Member.Host),
		int(seqno),
		int(srk.Typ),
		int(srk.Lev),
		rk.Comm.ExportToDB(),
		mbox,
		tbox,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("team_removal_keys")
	}
	return nil
}

func CheckAndInsertRemovalKeys(
	m MetaContext,
	tx pgx.Tx,
	seqno proto.Seqno,
	teamID proto.TeamID,
	sched team.KeySchedule,
	rks []rem.TeamRemovalBoxData,
	changes []proto.MemberRole,
) error {

	if len(rks) != len(sched.Additions) {
		return core.TeamError("wrong number of removal keys; should equal number of new members")
	}

	eq := func(md rem.TeamRemovalKeyMetadata, mr team.MemberID) (bool, error) {
		ok, err := md.SrcRole.Eq(mr.SrcRole.Export())
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		if !md.Tm.Eq(proto.FQTeam{Team: teamID, Host: m.HostID().Id}) {
			return false, nil
		}
		fqp, err := mr.Fqe.Unfix().FQParty()
		if err != nil {
			return false, err
		}
		if !md.Member.Eq(*fqp) {
			return false, nil
		}
		return true, nil
	}

	cmap := make(map[team.MemberID]int)
	for i, chng := range changes {
		key, err := team.MemberRoleToMemberID(&chng, m.HostID().Id)
		if err != nil {
			return err
		}
		_, found := cmap[*key]
		if found {
			return core.TeamError("duplicate member in changes")
		}
		cmap[*key] = i
	}

	checkRemovalKeyCommitment := func(id team.MemberID, expected proto.KeyCommitment) error {
		i, ok := cmap[id]
		if !ok {
			return core.TeamError("addition wasn't found in changes")
		}
		chng := changes[i]
		typ, err := chng.Member.Keys.GetT()
		if err != nil {
			return err
		}
		if typ != proto.MemberKeysType_Team {
			return core.TeamError("bad member keys type")
		}
		keys := chng.Member.Keys.Team()
		if keys.Trkc == nil {
			return core.TeamError("missing removal key commitment in change")
		}
		if !keys.Trkc.Eq(expected) {
			return core.TeamError("removal key commitment doesn't match")
		}
		return nil
	}

	for i, rk := range rks {
		ok, err := eq(rk.Md, sched.Additions[i])
		if err != nil {
			return err
		}
		if !ok {
			return core.TeamError("removal key doesn't match member")
		}
		err = checkRemovalKeyCommitment(sched.Additions[i], rk.Comm)
		if err != nil {
			return err
		}
	}

	for _, rk := range rks {
		err := insertRemovalKey(m, tx, seqno, teamID, rk)
		if err != nil {
			return err
		}
	}
	return nil
}

func LoadRemovalKeyBoxForTeamAdmin(
	m MetaContext,
	rq Querier,
	tid proto.TeamID,
	party proto.FQParty,
	srcRole proto.Role,
) (
	*proto.TeamRemovalKeyBox,
	error,
) {

	rk, err := core.ImportRole(srcRole)
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = rq.QueryRow(m.Ctx(),
		`SELECT rk_team 
		 FROM team_removal_keys
		 WHERE short_host_id=$1 AND team_id=$2 
		 AND member_id=$3 AND member_host_id=$4
		 AND src_role_type=$5 AND src_viz_level=$6
		 ORDER BY create_seqno DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		tid.ExportToDB(),
		party.Party.ExportToDB(),
		ExportHostInScope(m, party.Host),
		int(rk.Typ),
		int(rk.Lev),
	).Scan(&raw)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.KeyNotFoundError{Which: "team removal key"}
	}
	if err != nil {
		return nil, err
	}
	var ret proto.TeamRemovalKeyBox
	err = core.DecodeFromBytes(&ret, raw)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func LoadRemovalForMember(
	m MetaContext,
	arg rem.LoadRemovalForMemberArg,
) (
	rem.TeamRemovalAndKeyBox,
	error,
) {
	var zed rem.TeamRemovalAndKeyBox
	var box, removal []byte
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return zed, err
	}
	defer db.Release()
	err = db.QueryRow(m.Ctx(),
		`SELECT rk_member, rk_removal
		 FROM team_removal_keys
		 WHERE short_host_id=$1
		 AND rk_comm=$2
		 AND team_id=$3`,
		m.ShortHostID().ExportToDB(),
		arg.Comm.ExportToDB(),
		arg.Team.Team.ExportToDB(),
	).Scan(&box, &removal)
	if errors.Is(err, pgx.ErrNoRows) {
		return zed, core.NotFoundError("removal key")
	}
	if err != nil {
		return zed, err
	}
	var ret rem.TeamRemovalAndKeyBox
	err = core.DecodeFromBytes(&ret.KeyBox, box)
	if err != nil {
		return zed, err
	}
	if len(removal) == 0 {
		return zed, core.NotFoundError("team removal key")
	}

	err = core.DecodeFromBytes(&ret.Removal, removal)
	if err != nil {
		return zed, err
	}

	return ret, nil
}

func PostTeamRemoval(
	m MetaContext,
	tx pgx.Tx,
	tid proto.TeamID,
	rm rem.TeamRemovalAndComm,
) error {
	b, err := core.EncodeToBytes(&rm.Rm)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE team_removal_keys SET rk_removal=$1 WHERE short_host_id=$2 AND rk_comm=$3`,
		b,
		m.ShortHostID().ExportToDB(),
		rm.Comm.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("team_removal_keys")
	}
	return nil
}

func checkAndInsertSingleRemoval(
	m MetaContext,
	tx pgx.Tx,
	teamID proto.TeamID,
	sched team.KeySchedule,
	r rem.TeamRemovalAndComm,
	target team.MemberID,
) error {
	var mem, host []byte
	var srcRol, srcViz int
	err := tx.QueryRow(m.Ctx(),
		`SELECT member_id, member_host_id, src_role_type, src_viz_level
		     FROM team_removal_keys
			 WHERE short_host_id=$1 AND team_id=$2 AND rk_comm=$3 AND rk_removal IS NULL`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
		r.Comm.ExportToDB(),
	).Scan(&mem, &host, &srcRol, &srcViz)

	if errors.Is(err, pgx.ErrNoRows) {
		return core.KeyNotFoundError{Which: "team removal key"}
	}
	if err != nil {
		return err
	}
	rk, err := core.ImportRoleKeyFromDB(srcRol, srcViz)
	if err != nil {
		return err
	}
	hid, err := ImportHost(m, host)
	if err != nil {
		return err
	}
	var pid proto.PartyID
	err = pid.ImportFromDB(mem)
	if err != nil {
		return err
	}
	fqp := proto.FQParty{Party: pid, Host: hid}
	fqpf, err := fqp.FQEntity().Fixed()
	if err != nil {
		return err
	}
	memID := team.MemberID{
		Fqe:     *fqpf,
		SrcRole: *rk,
	}
	if !target.Eq(memID) {
		return core.TeamError("removal doesn't match member")
	}
	err = PostTeamRemoval(m, tx, teamID, r)
	if err != nil {
		return err
	}
	return nil
}

func CheckAndInsertRemovals(
	m MetaContext,
	tx pgx.Tx,
	teamID proto.TeamID,
	sched team.KeySchedule,
	rms []rem.TeamRemovalAndComm,
) error {
	if len(rms) != len(sched.Removals) {
		return core.TeamError("wrong number of removals; should equal number of removed members")
	}
	for i, r := range rms {
		target := sched.Removals[i]
		err := checkAndInsertSingleRemoval(m, tx, teamID, sched, r, target)
		if err != nil {
			return err
		}
	}
	return nil
}

func acceptInviteLocal(
	m MetaContext,
	tx pgx.Tx,
	srcTeamID *proto.TeamID,
	invite proto.TeamInvite,
	srcRole proto.Role,
) (
	*proto.TeamRSVPLocal,
	error,
) {
	typ, err := invite.GetV()
	if err != nil {
		return nil, err
	}
	if typ != proto.TeamInviteVersion_V1 {
		return nil, core.VersionNotSupportedError("team invite")
	}
	i1 := invite.V1()
	if !m.HostID().Id.Eq(i1.Host) {
		return nil, core.HostMismatchError{}
	}
	var viewee proto.PartyID
	if srcTeamID != nil {
		viewee = srcTeamID.ToPartyID()
	} else {
		viewee = m.UID().ToPartyID()
	}
	cert, err := loadTeamCertByHashWithDB(m, tx, i1.Hsh)
	if err != nil {
		return nil, err
	}
	v, err := cert.Cert.GetV()
	if err != nil {
		return nil, err
	}
	if v != rem.TeamCertVersion_V1 {
		return nil, core.VersionNotSupportedError("team cert")
	}

	c1 := cert.Cert.V1()
	certPayload, err := c1.Payload.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return nil, err
	}
	if !certPayload.Team.Host.Eq(m.HostID().Id) {
		return nil, core.HostMismatchError{}
	}
	tok, err := InsertLocalViewPermission(m, tx, certPayload.Team.Team.ToPartyID(), viewee)
	if err != nil {
		return nil, err
	}

	if srcTeamID != nil {
		err = CheckTeamIndexRanges(m, tx, *srcTeamID, certPayload.Team.Team)
		if err != nil {
			return nil, err
		}
	}

	rk, err := core.ImportRole(srcRole)
	if err != nil {
		return nil, err
	}
	ret, err := proto.RandomID16er[proto.TeamRSVPLocal]()
	if err != nil {
		return nil, err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO local_joinreqs
		  (short_host_id, team_id, token, joiner_party_id, 
			joiner_src_role_type, joiner_src_viz_level,
			state, permission_token, ctime)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		m.ShortHostID().ExportToDB(),
		certPayload.Team.Team.ExportToDB(),
		ret.ExportToDB(),
		viewee.ExportToDB(),
		int(rk.Typ),
		int(rk.Lev),
		JoinReqStatePending,
		tok.ExportToDB(),
	)
	if IsDuplicateKeyError(err, "local_joinreq_joiner_idx") {
		return nil, core.TeamInviteAlreadyAcceptedError{}
	}
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, core.InsertError("local_joinreqs")
	}
	return ret, nil
}

func AcceptInviteLocal(
	m MetaContext,
	arg rem.AcceptInviteLocalArg,
) (
	proto.TeamRSVPLocal,
	error,
) {
	var ret proto.TeamRSVPLocal
	err := RetryTxUserDB(m, "AcceptInviteLocal",
		func(m MetaContext, tx pgx.Tx) error {
			var team *proto.TeamID
			var partyID proto.PartyID
			if arg.Tok != nil {
				var err error
				var rp *proto.Role
				team, rp, err = LoadBearerToken(m, tx, *arg.Tok, 0)
				if err != nil {
					return err
				}
				rk, err := core.ImportRole(*rp)
				if err != nil {
					return err
				}
				if !rk.Typ.IsAdminOrAbove() {
					return core.PermissionError("need admin or owner to accept a team invite for a team")
				}
				partyID = team.ToPartyID()
			} else {
				partyID = m.UID().ToPartyID()
			}
			tmp, err := acceptInviteLocal(m, tx, team, arg.I, arg.SrcRole)
			if err != nil {
				return err
			}
			ret = *tmp
			if arg.TeamMembershipLink != nil {
				err = PostGenericLinkTryTx(
					m, tx, *arg.TeamMembershipLink, partyID, nil,
				)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
	return ret, err
}

func UpdateLocalJoinReqs(
	m MetaContext,
	tx pgx.Tx,
	team proto.TeamID,
	additions []team.MemberID,
) (
	[]rem.LocalPartyRole,
	error,
) {
	var res []rem.LocalPartyRole
	for _, add := range additions {
		if !add.Fqe.Host.Eq(m.HostID().Id) {
			continue
		}
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE local_joinreqs
			 SET state=$1
			 WHERE short_host_id=$2 AND team_id=$3 AND joiner_party_id=$4
			 AND joiner_src_role_type=$5 AND joiner_src_viz_level=$6
			 AND state=$7`,
			JoinReqStateApproved,
			m.ShortHostID().ExportToDB(),
			team.ExportToDB(),
			add.Fqe.Entity.Unfix().ExportToDB(),
			int(add.SrcRole.Typ),
			int(add.SrcRole.Lev),
			JoinReqStatePending,
		)
		if err != nil {
			return nil, err
		}

		// Keep track of the additions that trigger invite updates, since we return those out to the
		// caller.
		if tag.RowsAffected() == 1 {
			party, err := add.Fqe.Entity.Unfix().ToPartyID()
			if err != nil {
				return nil, err
			}
			res = append(res, rem.LocalPartyRole{
				Role:  add.SrcRole.Export(),
				Party: party,
			})
		}
	}
	return res, nil
}

func GetCurrentTeamCerts(
	m MetaContext,
	team proto.TeamID,
) (
	[]rem.TeamCert,
	error,
) {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var ret []rem.TeamCert

	rows, err := db.Query(m.Ctx(),
		`SELECT C.cert
		 FROM team_certs AS C
		 JOIN shared_key_generations AS G
		 ON (C.short_host_id=G.short_host_id AND C.team_id=G.entity_id AND C.gen=G.gen)
		 WHERE G.short_host_id=$1
		 AND G.entity_id=$2
		 AND G.role_type=$3 AND G.viz_level=$4`,
		m.ShortHostID().ExportToDB(),
		team.ExportToDB(),
		int(proto.RoleType_ADMIN),
		0,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var certRaw []byte
		err := rows.Scan(&certRaw)
		if err != nil {
			return nil, err
		}
		var cert rem.TeamCert
		err = core.DecodeFromBytes(&cert, certRaw)
		if err != nil {
			return nil, err
		}
		ret = append(ret, cert)
	}

	return ret, nil
}

func GetLatestTeamIndexRange(
	m MetaContext,
	rq Querier,
	teamID proto.TeamID,
) (
	*core.RationalRange,
	proto.Seqno,
	error,
) {
	var low, high []byte
	var seqno int
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT low, high, seqno FROM team_index_ranges
		 WHERE short_host_id=$1 AND team_id=$2
		 ORDER BY seqno DESC
		 LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
	).Scan(&low, &high, &seqno)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var ret core.RationalRange
	err = core.DecodeFromBytes(&ret.Low, low)
	if err != nil {
		return nil, 0, err
	}
	err = core.DecodeFromBytes(&ret.High, high)
	if err != nil {
		return nil, 0, err
	}
	err = ret.Validate()
	if err != nil {
		return nil, 0, err
	}
	return &ret, proto.Seqno(seqno), nil
}

func InsertTeamIndexRange(
	m MetaContext,
	tx pgx.Tx,
	teamID proto.TeamID,
	seqno proto.Seqno,
	ir core.RationalRange,
) error {
	prev, prevSeqno, err := GetLatestTeamIndexRange(m, tx, teamID)
	if err != nil {
		return err
	}
	first := seqno.IsEldest()

	if prev == nil {
		if !first {
			return core.BadServerDataError("no previous index range")
		}
	} else {
		if first {
			return core.BadServerDataError("previous index range exists")
		}
		if prevSeqno >= seqno {
			return core.BadServerDataError("seqno not greater than previous")
		}
		if ir.Eq(*prev) {
			return core.TeamError("index range is the same as the previous")
		}
		if !prev.Includes(ir) {
			return core.TeamError("previous range does not include new range")
		}
	}

	low, err := core.EncodeToBytes(&ir.Low)
	if err != nil {
		return err
	}
	high, err := core.EncodeToBytes(&ir.High)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO team_index_ranges
		 (short_host_id, team_id, seqno, low, high, ctime)
		 VALUES($1, $2, $3, $4, $5, NOW())`,
		m.ShortHostID().ExportToDB(),
		teamID.ExportToDB(),
		int(seqno),
		low,
		high,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("team_index_ranges")
	}
	return nil
}

func CheckTeamIndexRanges(
	m MetaContext,
	rq Querier,
	joiner proto.TeamID,
	joinee proto.TeamID,
) error {
	left, _, err := GetLatestTeamIndexRange(m, rq, joiner)
	if err != nil {
		return err
	}
	if left == nil {
		return core.TeamError("no index range")
	}
	right, _, err := GetLatestTeamIndexRange(m, rq, joinee)
	if err != nil {
		return err
	}
	if right == nil {
		return core.TeamError("no index range")
	}
	if !left.LessThan(*right) {
		return core.NewTeamCycleError(*left, *right)
	}
	return nil
}

func CheckMemberIndexRangesAgainstTeam(
	m MetaContext,
	rq Querier,
	teamID proto.TeamID,
	changes []proto.MemberRole,
) error {
	high, _, err := GetLatestTeamIndexRange(m, rq, teamID)
	if err != nil {
		return err
	}

	return forAllTeamChanges(changes, func(chng proto.MemberRole, tmk proto.TeamMemberKeys) error {
		if chng.Member.Id.Entity.Type() != proto.EntityType_Team {
			return nil
		}
		if tmk.Tir == nil {
			return core.TeamError("missing team index range in addition")
		}
		tmp := core.NewRationalRange(*tmk.Tir)
		if !tmp.LessThan(*high) {
			return core.NewTeamCycleError(tmp, *high)
		}
		return nil
	})
}

func RejectJoinReq(
	m MetaContext,
	tx pgx.Tx,
	teamID proto.TeamID,
	tok proto.TeamRSVP,
) error {

	lcl, rmt, err := tok.Sel()
	switch {
	case err != nil:
		return err

	case rmt != nil:
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE remote_joinreqs
			SET state='rejected'
			WHERE short_host_id=$1 AND team_id=$2 AND token=$3`,
			m.ShortHostID().ExportToDB(),
			teamID.ExportToDB(),
			rmt.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("remote_joinreqs")
		}
	case lcl != nil:
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE local_joinreqs
			SET state='rejected'
			WHERE short_host_id=$1 AND team_id=$2 AND token=$3`,
			m.ShortHostID().ExportToDB(),
			teamID.ExportToDB(),
			lcl.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("local_joinreqs")
		}
	default:
		return core.InternalError("unreachable")
	}
	return nil
}

func scanTeamListRow(
	rows pgx.Rows,
	named bool,
) (
	*rem.NamedLocalTeamListEntry,
	error,
) {
	var sr, dr, sl, dl, seq, kg int
	var tidRaw, uidRaw []byte
	var nm string
	slots := []any{&tidRaw, &sr, &sl, &seq, &kg, &dr, &dl}
	if named {
		slots = append(slots, &nm, &uidRaw)
	}
	err := rows.Scan(slots...)
	if err != nil {
		return nil, err
	}
	var tid proto.TeamID
	err = tid.ImportFromDB(tidRaw)
	if err != nil {
		return nil, err
	}
	var srcRole, dstRole proto.Role
	err = srcRole.ImportFromDB(sr, sl)
	if err != nil {
		return nil, err
	}
	err = dstRole.ImportFromDB(dr, dl)
	if err != nil {
		return nil, err
	}
	ret := rem.NamedLocalTeamListEntry{
		Name: proto.NameUtf8(nm),
		Te: rem.LocalTeamListEntry{
			Id:      tid,
			SrcRole: srcRole,
			Seqno:   proto.Seqno(seq),
			KeyGen:  proto.Generation(kg),
			DstRole: dstRole},
	}
	if named && len(uidRaw) > 0 {
		var uid proto.UID
		err = uid.ImportFromDB(uidRaw)
		if err != nil {
			return nil, err
		}
		ret.QuotaMaster = &uid
	}
	return &ret, nil
}

func GetTeamListForUser(
	m MetaContext,
) (
	rem.LocalTeamList,
	error,
) {
	var ret rem.LocalTeamList
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT team_id, src_role_type, src_viz_level,
		   seqno, key_gen, dst_role_type, dst_viz_level
		 FROM team_members
		 WHERE short_host_id=$1 AND member_host_id=$2
		 AND member_id=$3 AND active=TRUE
		 `,
		m.ShortHostID().ExportToDB(),
		LocalHost,
		m.UID().ExportToDB(),
	)
	if err != nil {
		return ret, err
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanTeamListRow(rows, false)
		if err != nil {
			return ret, err
		}
		ret = append(ret, row.Te)
	}
	return ret, nil
}

func GetNamedTeamListForUser(
	m MetaContext,
) (
	rem.NamedLocalTeamList,
	error,
) {
	var ret rem.NamedLocalTeamList
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT team_id, src_role_type, src_viz_level,
		   seqno, key_gen, dst_role_type, dst_viz_level, name_utf8, uid
		 FROM team_members
		 JOIN teams USING(short_host_id, team_id)
		 JOIN names USING(short_host_id, name_ascii)
		 LEFT OUTER JOIN team_quota_masters USING(short_host_id, team_id)
		 WHERE short_host_id=$1 AND member_host_id=$2
		 AND member_id=$3 AND active=TRUE
		 ORDER BY name_utf8 ASC
		 `,
		m.ShortHostID().ExportToDB(),
		LocalHost,
		m.UID().ExportToDB(),
	)
	if err != nil {
		return ret, err
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanTeamListRow(rows, true)
		if err != nil {
			return ret, err
		}
		ret = append(ret, *row)
	}
	return ret, nil

}
