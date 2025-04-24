// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func InsertName(
	m MetaContext,
	tx pgx.Tx,
	actorID proto.EntityID,
	signerKey proto.EntityID,
	hostID core.HostID,
	name proto.Name,
	nameUtf8 proto.NameUtf8,
	nameCommitmentKey *proto.RandomCommitmentKey,
	nameCommitment *proto.Commitment,
	seq proto.NameSeqno,
	typ rem.NameType,
) error {
	var reuseIdRaw int
	var reuseId proto.NameSeqno
	var usernameState string
	err := tx.QueryRow(m.Ctx(),
		`SELECT reuse_id,state 
		FROM names 
		WHERE short_host_id=$1
		AND name_ascii=$2
		ORDER BY reuse_id DESC LIMIT 1`,
		int(hostID.Short),
		name,
	).Scan(&reuseIdRaw, &usernameState)
	if err == pgx.ErrNoRows {
		reuseId = proto.FirstNameSeqno
	} else if err == nil && usernameState != "dead" {
		return core.ReservationError("username should have been dead")
	} else if err != nil {
		return err
	} else {
		reuseId = proto.NameSeqno(reuseIdRaw)
	}

	if !reuseId.IsValid() {
		return core.ReservationError("invalid name reuse_id")
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO names(short_host_id,name_ascii,name_utf8,reuse_id,ctime,mtime,state,typ)
	     VALUES($1,$2,$3,$4,NOW(),NOW(),'in_use',$5)`,
		int(hostID.Short),
		name, nameUtf8, reuseId,
		typ.ExportToDB(),
	)
	if err != nil {
		m.Errorw("signup", "stage", "insert usernames", "err", err)
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("usernames")
	}

	pun := proto.Name(name).Normalize()

	if reuseId != seq {
		return core.ReservationError("username reuse_id mismatch")
	}

	unp := rem.NameCommitment{
		Name: pun,
		Seq:  reuseId,
	}

	err = OpenAndStoreCommitment(
		m.Ctx(), tx, &unp, nameCommitmentKey,
		nameCommitment, hostID.Short, nil,
	)
	if err != nil {
		return err
	}

	err = QueueMerkleWorkForName(m, tx, hostID, pun, reuseId, actorID, signerKey)
	if err != nil {
		return err
	}

	return nil
}

func reserveUsernameTryTx(
	m MetaContext,
	tx pgx.Tx,
	u proto.Name,
	hostID core.HostID,
	timeTravelTest time.Duration,
	retp *rem.ReserveNameRes,
	typ rem.NameType,
) error {
	var ret rem.ReserveNameRes

	// For vhosts
	err := CheckSeatLimits(m, tx)
	if err != nil {
		return err
	}

	cfg, err := m.G().Config().RegServerConfig(m.Ctx())
	if err != nil {
		return err
	}

	tmp, err := proto.RandomID16er[proto.ReservationToken]()
	if err != nil {
		return err
	}
	ret.Tok = *tmp

	timeout := cfg.UsernameReservationTimeout()

	// For now we are not allowing the reuse of dead names, but we can imagine a future
	// where we're OK if the latest reuse_id of the username is marked 'dead' and the mtime
	// on that is >1 year in the past or so. But we have a long time to figure that out.
	var reuseId int
	var state string
	err = tx.QueryRow(m.Ctx(),
		`SELECT reuse_id, state FROM names
		WHERE short_host_id=$1
		AND name_ascii=$2
		ORDER BY reuse_id DESC LIMIT 1`,
		int(hostID.Short),
		u,
	).Scan(&reuseId, &state)
	if err == nil {
		return core.NameInUseError{}
	}
	if err != pgx.ErrNoRows {
		return err
	}
	ret.Seq = proto.FirstNameSeqno
	ret.Etime = proto.ExportTime(m.Now().Add(timeout))

	_, err = tx.Exec(m.Ctx(),
		`DELETE FROM name_reservations
		 WHERE state='reserved'
		 AND short_host_id=$1
		 AND name=$2
		 AND ctime + $3 < NOW() + $4`,
		hostID.Short.ExportToDB(),
		u, timeout, timeTravelTest,
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(m.Ctx(),
		`INSERT INTO name_reservations
 		   (short_host_id, name, id, state, ctime, typ)
	     VALUES($1, $2, $3, 'reserved', NOW(), $4)`,
		hostID.Short.ExportToDB(),
		u,
		ret.Tok[:],
		typ.ExportToDB(),
	)

	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.ConstraintName == "name_reservations_pkey" {
			err = core.NameInUseError{}
		}
		return err
	}
	*retp = ret
	return nil
}

func ClaimReservation(
	m MetaContext,
	tx pgx.Tx,
	hostID core.HostID,
	expectedUsername proto.Name,
	rur rem.ReserveNameRes,
	typ rem.NameType,
) error {
	if !rur.Seq.IsValid() {
		return core.BadArgsError("invalid name reservation seqno")
	}
	var raw string
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT name
		 FROM name_reservations
		 WHERE short_host_id=$1 AND id=$2 AND typ=$3`,
		int(hostID.Short),
		rur.Tok.ExportToDB(),
		typ.ExportToDB(),
	).Scan(&raw)
	if err != nil {
		m.Warnw("signup", "stage", "select reservation", "err", err)
		return err
	}
	reservedUsername := proto.Name(raw)

	if expectedUsername != reservedUsername {
		m.Warnw("signup",
			"stage", "compare reserved usernames",
			"expected", expectedUsername,
			"reserved", reservedUsername,
		)
		return core.NameError("reserved username did not match given username")
	}
	ures, err := tx.Exec(m.Ctx(),
		`UPDATE name_reservations
		 SET state='in_use'
		 WHERE short_host_id=$1 AND id=$2
		 AND state='reserved'`,
		hostID.Short.ExportToDB(),
		rur.Tok.ExportToDB())
	if err != nil {
		return err
	}
	m.Infow("signup", "stage", "update resevations")
	if ures.RowsAffected() != 1 {
		return core.ReservationError("not found")
	}
	return nil
}

func ReserveName(
	m MetaContext,
	u proto.Name,
	t rem.NameType,
	timeTravelTest time.Duration,
) (
	rem.ReserveNameRes,
	error,
) {
	var ret rem.ReserveNameRes
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return ret, err
	}
	defer db.Release()

	err = RetryTx(m, db, "reserveUsername", func(m MetaContext, tx pgx.Tx) error {
		return reserveUsernameTryTx(m, tx, u, m.HostID(), timeTravelTest, &ret, t)
	})
	if err != nil {
		return ret, err
	}
	return ret, nil
}
