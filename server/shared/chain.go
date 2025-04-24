// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func ReadChainTail(
	m MetaContext,
	tx pgx.Tx,
	typ proto.ChainType,
	eid proto.EntityID,
) (
	*proto.BaseChainer,
	error,
) {
	seqno := -1
	var hash []byte
	err := tx.QueryRow(m.Ctx(),
		`SELECT seqno,hash 
		 FROM links 
		 WHERE short_host_id=$1 
		 AND chain_type=$2 
		 AND entity_id=$3 
		 ORDER BY seqno DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
		typ,
		eid.ExportToDB(),
	).Scan(&seqno, &hash)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var prev proto.LinkHash
	copy(prev[:], hash)
	return &proto.BaseChainer{
		Prev:  &prev,
		Seqno: proto.Seqno(seqno),
	}, nil
}

type InsertRevokeLinkPackage struct {
	LinkEpno proto.MerkleEpno
	Target   proto.EntityID
}

func InsertLink(
	m MetaContext,
	tx pgx.Tx,
	typ proto.ChainType,
	party proto.PartyID,
	signer core.SignerPair,
	prev *proto.BaseChainer,
	curr proto.BaseChainer,
	link proto.LinkOuter,
	trigger proto.UpdateTrigger,
	revokeIDs []core.SignerPair,
) error {

	err := InsertDeviceLock(m, tx, party, signer)
	if err != nil {
		m.Warnw("InsertLink", "stage", "InsertDeviceLock", "err", err,
			"which", "signer")
		return err
	}

	// Try to insert the locks in the same order.
	slices.SortFunc(revokeIDs, func(e1, e2 core.SignerPair) int { return e1.Cmp(e2) })

	var selfRevoke bool

	for _, revokeID := range revokeIDs {
		if revokeID.Eid.Eq(signer.Eid) {
			selfRevoke = true
			break
		}
	}

	if selfRevoke && len(revokeIDs) != 1 {
		return core.RevokeError("self-revokes can only revoke one key at a time")
	}

	for _, revokeID := range revokeIDs {
		if revokeID.Eid.Eq(signer.Eid) {
			m.Infow("InsertLink", "stage", "InsertDeviceLock", "msg", "skipping self-lock for self-revoke")
			continue
		}
		err = InsertDeviceLock(m, tx, party, revokeID)
		if err != nil {
			m.Warnw("InsertLink", "stage", "InsertDeviceLock", "err", err,
				"which", "revokee")
			return err
		}
	}

	if !curr.Seqno.IsValid() {
		return core.PrevError("invalid seqno")
	}

	if prev == nil && !curr.Seqno.IsEldest() {
		return core.PrevError("no prev link found")
	}
	if prev != nil && curr.Seqno != prev.Seqno+1 {
		return core.PrevError("wrong seqno for new link")
	}
	if prev != nil && curr.Prev == nil {
		return core.PrevError("prev link found but no prev hash")
	}
	if prev != nil && !curr.Prev.Eq(*prev.Prev) {
		return core.PrevError("wrong prev hash")
	}

	rawLink, err := core.EncodeToBytes(&link)
	if err != nil {
		return err
	}
	hash, err := core.LinkHash(&link)
	if err != nil {
		return err
	}
	_, err = tx.Exec(m.Ctx(),
		`INSERT INTO links(short_host_id, chain_type, entity_id, seqno, body, hash, ctime)
	     VALUES($1, $2, $3, $4, $5, $6, TO_TIMESTAMP($7))`,
		m.ShortHostID().ExportToDB(),
		typ,
		party.ExportToDB(),
		curr.Seqno,
		rawLink,
		hash.ExportToDB(),
		curr.Time.ToSecondsFloat(),
	)
	if err != nil {
		return err
	}

	var loc *proto.TreeLocation
	if !curr.Seqno.IsEldest() || typ.IsSubchain() {
		tmp, err := LookupTreeLocation(m, tx, typ, party.EntityID(), curr.Seqno)
		if err != nil {
			return err
		}
		loc = &tmp
	}

	if selfRevoke {
		// It's important that we do this before we queue the merkle work
		// for the revoke, since otherwise the Assert and the Queue operation
		// will conflict. The same arguments hold even if these two
		// operations are re-ordered for the self-revoke case.
		err = AssertNoRacingSigners(m, tx, party, signer, curr.Root.Epno)
		if err != nil {
			m.Warnw("InsertLink", "stage", "AssertNoRacingSigners", "err", err)
			return err
		}
	}

	err = QueueMerkleWork(
		m,
		tx,
		m.ShortHostID(),
		party.EntityID(),
		signer.Eid,
		curr.Seqno,
		typ,
		loc,
		hash.ToStdHash(),
		trigger,
	)
	if err != nil {
		return err
	}

	if selfRevoke {
		return nil
	}

	err = ReleaseDeviceLock(m, tx, party, signer)
	if err != nil {
		m.Warnw("InsertLink", "stage", "ReleaseDeviceLock", "err", err)
		return err
	}

	// On self-revokes, we need to do this assertion before we insert into the merkle
	// merkle work queue, otherwise we'll self-interfere.
	for _, revokeID := range revokeIDs {
		err = AssertNoRacingSigners(m, tx, party, revokeID, curr.Root.Epno)
		if err != nil {
			m.Warnw("InsertLink", "stage", "AssertNoRacingSigners", "err", err)
			return err
		}
	}

	return nil
}

func lookupComputeZeroethTreeLocation(
	m MetaContext,
	tx Querier,
	typ proto.ChainType,
	eid proto.EntityID,
) (
	proto.TreeLocation,
	error,
) {
	var ret proto.TreeLocation
	var seedTmp []byte
	err := tx.QueryRow(m.Ctx(),
		`SELECT seed FROM subchain_tree_location_seeds
	     WHERE short_host_id=$1 AND entity_id=$2`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(),
	).Scan(&seedTmp)
	if err != nil {
		return ret, err
	}
	var seed proto.TreeLocation
	if len(seed) != len(seedTmp) {
		return ret, core.BadServerDataError("wrong length for seed")
	}
	copy(seed[:], seedTmp)
	tmp, err := core.SubchainTreeLocation(seed, typ)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func LookupTreeLocation(
	m MetaContext,
	tx pgx.Tx,
	typ proto.ChainType,
	eid proto.EntityID,
	seqno proto.Seqno,
) (proto.TreeLocation, error) {
	var b []byte

	if typ.IsSubchain() && seqno.IsEldest() {
		return lookupComputeZeroethTreeLocation(m, tx, typ, eid)
	}

	var ret proto.TreeLocation
	err := tx.QueryRow(m.Ctx(),
		"SELECT loc FROM tree_locations WHERE short_host_id=$1 AND chain_type=$2 AND entity_id=$3 AND seqno=$4",
		m.ShortHostID().ExportToDB(),
		int(typ),
		eid.ExportToDB(),
		int(seqno),
	).Scan(&b)
	if err != nil {
		return ret, err
	}
	if len(b) != len(ret) {
		return ret, core.DbError("wrong length for tree location")
	}
	copy(ret[:], b)
	return ret, nil
}

func readPublicSuitersFromDB(
	hostId core.HostID,
	rows pgx.Rows,
) (
	map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
	error,
) {
	var verifyKey, hepkFpRaw, hepkRaw []byte
	var rt, lev, epno, seqno int

	ret := make(map[proto.FQEntityFixed]core.PublicSuiterWithSeqno)

	_, err := pgx.ForEachRow(rows, []any{&verifyKey, &hepkFpRaw, &hepkRaw, &rt, &lev, &epno, &seqno}, func() error {
		e, err := proto.ImportEntityIDFromBytes(verifyKey)
		if err != nil {
			return err
		}

		var hepk proto.HEPK
		var hepkFp proto.HEPKFingerprint
		err = core.DecodeFromBytes(&hepk, hepkRaw)
		if err != nil {
			return err
		}

		err = hepkFp.ImportFromDB(hepkFpRaw)
		if err != nil {
			return err
		}

		err = core.HEPK(&hepk).AssertFingerprint(&hepkFp)
		if err != nil {
			return err
		}

		ep, err := core.ImportEntityPublic(e)
		if err != nil {
			return err
		}
		role := proto.NewRole(proto.RoleType(rt), proto.VizLevel(lev))
		if role == nil {
			return core.DbError("got nil role for device")
		}
		var me *proto.MerkleEpno
		if epno >= 0 {
			tmp := proto.MerkleEpno(epno)
			me = &tmp
		}
		ps, err := core.ImportPublicSuiteFromDB(ep, &hepk, *role, hostId.Id, me)
		if err != nil {
			return err
		}
		fid, err := ep.GetEntityID().Fixed()
		if err != nil {
			return err
		}
		obj := core.PublicSuiterWithSeqno{Ps: ps, Seqno: proto.Seqno(seqno)}
		ret[proto.FQEntityFixed{Entity: fid, Host: hostId.Id}] = obj
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func ReadDevicesForUser(
	m MetaContext,
	tx pgx.Tx,
	uid proto.UID,
	hostId core.HostID,
) (
	map[proto.FQEntityFixed]core.PublicSuiterWithSeqno,
	error,
) {
	rows, err := tx.Query(m.Ctx(),
		`SELECT verify_key, hepk_fp, hepk, role_type, viz_level, 
		   COALESCE(provision_epno, -1), seqno
		FROM device_keys
		JOIN hepks USING(short_host_id, hepk_fp)
		WHERE key_state='valid' AND short_host_id=$1 AND uid=$2`,
		int(hostId.Short),
		uid.ExportToDB(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return readPublicSuitersFromDB(hostId, rows)
}

// See docs/revoke_locks.md
func InsertDeviceLock(
	m MetaContext,
	tx pgx.Tx,
	party proto.PartyID,
	sp core.SignerPair,
) error {

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO revoke_key_locks(short_host_id, party_id, verify_key, ctime, seqno)
		 VALUES($1,$2,$3,NOW(),$4)`,
		m.ShortHostID().ExportToDB(),
		party.ExportToDB(),
		sp.Eid.ExportToDB(),
		int(sp.Seqno),
	)
	if pgErr, ok := err.(*pgconn.PgError); ok &&
		pgErr.Code == "23505" &&
		pgErr.ConstraintName == "revoke_key_locks_pkey" {
		return core.RevokeRaceError{Which: "key locked"}
	}

	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("could not insert into device lock table")
	}
	return nil
}

func ReleaseDeviceLock(
	m MetaContext,
	tx pgx.Tx,
	eid proto.PartyID,
	sp core.SignerPair,
) error {
	tag, err := tx.Exec(m.Ctx(),
		`DELETE FROM revoke_key_locks
		 WHERE short_host_id=$1 AND party_id=$2 AND verify_key=$3 AND seqno=$4`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(),
		sp.Eid.ExportToDB(),
		int(sp.Seqno),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("could not delete from device lock table")
	}
	return nil
}

func AssertNoRacingSigners(
	m MetaContext,
	tx pgx.Tx,
	party proto.PartyID,
	sp core.SignerPair,
	linkEpno proto.MerkleEpno,
) error {
	rows, err := tx.Query(
		m.Ctx(),
		`SELECT state, COALESCE(epno, -1) FROM merkle_work_queue
		WHERE short_host_id=$1 AND id=$2 AND signer=$3`,
		m.ShortHostID().ExportToDB(),
		party.ExportToDB(),
		sp.Eid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var state string
		var epno int
		err = rows.Scan(&state, &epno)
		if err != nil {
			return err
		}
		switch MerkleWorkState(state) {
		case MerkleWorkStateCommitted:
			if epno < 0 {
				return core.RevokeRaceError{Which: "no epno"}
			}
			if proto.MerkleEpno(epno) > linkEpno {
				return core.RevokeRaceError{Which: "too old"}
			}
		default:
			return core.RevokeRaceError{Which: "work inflight"}
		}
	}
	return nil
}
