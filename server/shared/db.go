// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"errors"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DbExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func (g *GlobalContext) dbPool(ctx context.Context, which DbType) (*pgxpool.Pool, error) {
	g.Lock()
	defer g.Unlock()

	return g.dbPoolWithLock(ctx, which)
}

func (g *GlobalContext) dbPoolWithLock(ctx context.Context, which DbType) (*pgxpool.Pool, error) {

	pool := g.dbpools[which]
	if pool != nil {
		return pool, nil
	}

	opts, err := g.cfg.DbConfig(ctx, which)
	if err != nil {
		return nil, err
	}

	pool, err = pgxpool.NewWithConfig(ctx, opts)
	if err != nil {
		return nil, err
	}

	err = pool.Ping(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	g.dbpools[which] = pool

	return pool, nil
}

func (g *GlobalContext) Db(ctx context.Context, which DbType) (*pgxpool.Conn, error) {

	pool, err := g.dbPool(ctx, which)
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (g *GlobalContext) DbTx(ctx context.Context, which DbType) (pgx.Tx, func() error, error) {
	db, err := g.Db(ctx, which)
	if err != nil {
		return nil, nil, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		db.Release()
		return nil, nil, err
	}
	retFn := func() error {
		err := tx.Rollback(ctx)
		db.Release()
		if err == nil {
			return nil
		}
		if errors.Is(err, pgx.ErrTxClosed) {
			return nil
		}
		return err
	}
	return tx, retFn, nil
}

func RetryTxUserDB(m MetaContext, nm string, tryFn func(m MetaContext, tx pgx.Tx) error) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTx(m, db, nm, tryFn)
}

func RetryTxServerConfigDB(
	m MetaContext,
	nm string,
	tryFn func(m MetaContext, tx pgx.Tx) error,
) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTx(m, db, nm, tryFn)
}

func RetryTx(m MetaContext, db *pgxpool.Conn, nm string, tryFn func(m MetaContext, tx pgx.Tx) error) error {

	nTries := 5
	backoff := 1 * time.Millisecond
	m = m.WithLogTag("dbtx")

	tryOnce := func(i int) (ret bool, err error) {
		tx, err := db.Begin(m.Ctx())
		if err != nil {
			return false, err
		}
		defer func() {
			err = TxRollback(m.Ctx(), tx, err)
		}()
		err = tryFn(m, tx)
		if err != nil {
			return false, err
		}
		err = tx.Commit(m.Ctx())
		if err == nil {
			return false, nil
		}
		if !pgconn.SafeToRetry(err) {
			return false, err
		}
		m.Warnw("retryTx", "query", nm, "i", i, "err", err)
		time.Sleep(backoff)
		backoff *= 2
		return true, nil
	}

	for i := 0; i < nTries; i++ {
		if retry, err := tryOnce(i); !retry {
			return err
		}
	}
	return core.TxRetryError{}
}

func IsDuplicateKeyError(e error, k string) bool {
	if e == nil {
		return false
	}
	pgerr, ok := e.(*pgconn.PgError)
	if !ok {
		return false
	}
	return pgerr.Code == "23505" && pgerr.ConstraintName == k
}

func LockEntity(m MetaContext, tx pgx.Tx, e proto.EntityID, typ proto.ChainType, seqno proto.Seqno) error {
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO chain_locks(short_host_id, entity_id, chain_type, seqno) VALUES($1,$2,$3,$4)`,
		int(m.ShortHostID()),
		e.ExportToDB(),
		int(typ),
		seqno,
	)
	if IsDuplicateKeyError(err, "chain_locks_pkey") {
		return core.DuplicateError("chain lock")
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InternalError("could not insert into chain lock table")
	}
	return nil
}

func (g *GlobalContext) readHostIDFromDB(ctx context.Context) error {

	if g.hostID.IsZero() {
		return core.InternalError("hostID is unset")
	}

	db, err := g.dbPoolWithLock(ctx, DbTypeServerConfig)
	if err != nil {
		return err
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if g.hostID.Short != 0 {
		var hostTmp, vhostTmp []byte
		err := db.QueryRow(
			ctx,
			"SELECT host_id, vhost_id FROM hosts WHERE short_host_id=$1",
			int(g.hostID.Short),
		).Scan(&hostTmp, &vhostTmp)
		if err != nil {
			return err
		}
		var id proto.HostID
		var vid proto.VHostID
		err = id.ImportFromBytes(hostTmp)
		if err != nil {
			return err
		}
		err = vid.ImportFromDB(vhostTmp)
		if err != nil {
			return err
		}
		if !g.hostID.Id.IsZero() && !g.hostID.Id.Eq(id) {
			return core.HostMismatchError{}
		}
		g.hostID.Id = id
		g.hostID.VId = vid
		return nil
	}

	var short int
	var vhostTmp []byte
	err = db.QueryRow(
		ctx,
		"SELECT short_host_id, vhost_id FROM hosts WHERE host_id=$1",
		g.hostID.Id.ExportToDB(),
	).Scan(&short, &vhostTmp)
	if err != nil {
		return err
	}
	var vid proto.VHostID
	err = vid.ImportFromDB(vhostTmp)
	if err != nil {
		return err
	}
	g.hostID.Short = core.ShortHostID(short)
	g.hostID.VId = vid

	return nil
}

type KVKey string

const (
	KVKeyPublicZone KVKey = "publicZone"
)

func (g *GlobalContext) GetKV(ctx context.Context, o core.Codecable, key KVKey, shid core.ShortHostID) error {
	db, err := g.Db(ctx, DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	var b []byte
	err = db.QueryRow(
		ctx,
		`SELECT v FROM host_kv WHERE short_host_id=$1 AND k=$2`,
		shid.ExportToDB(),
		string(key),
	).Scan(&b)

	if err != nil && err == pgx.ErrNoRows {
		return core.NotFoundError(key)
	}

	err = core.DecodeFromBytes(o, b)
	if err != nil {
		return err
	}
	return nil
}

func (g *GlobalContext) PutKV(ctx context.Context, o core.Codecable, key KVKey, shid core.ShortHostID) error {
	db, err := g.Db(ctx, DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	b, err := core.EncodeToBytes(o)
	if err != nil {
		return err
	}

	tag, err := db.Exec(
		ctx,
		`INSERT INTO host_kv(short_host_id, k, v, ctime, mtime)
		VALUES($1,$2,$3,NOW(),NOW())
		ON CONFLICT(short_host_id, k)
		DO UPDATE SET v=$3, mtime=NOW()`,
		shid.ExportToDB(),
		string(key),
		b,
	)

	if err != nil {
		return err
	}

	if tag.RowsAffected() != 1 {
		return core.UpdateError(key)
	}

	return nil
}

func ShortPartyIns(m MetaContext, tx pgx.Tx, p proto.PartyID) error {
	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO short_party(short_host_id, short_party_id) VALUES($1, $2)`,
		m.ShortHostID().ExportToDB(),
		p.Shorten().ExportToDB(),
	)
	if IsDuplicateKeyError(err, "short_party_pkey") {
		return core.DuplicateError("short party collision")
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("short_party")
	}
	return nil
}

func TxRollback(ctx context.Context, tx pgx.Tx, err error) error {
	rberr := tx.Rollback(ctx)
	if err == nil && rberr != nil && !errors.Is(rberr, pgx.ErrTxClosed) {
		return rberr
	}
	return err
}
