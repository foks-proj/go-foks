// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	clisql "github.com/foks-proj/go-foks/client/sql"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/mattn/go-sqlite3"
)

type DbType int

type Scoper interface {
	core.Codecable
}

const (
	DbTypeHard DbType = 1
	DbTypeSoft DbType = 2
)

var schema = map[DbType]string{
	DbTypeHard: clisql.HardSQL,
	DbTypeSoft: clisql.SoftSQL,
}

type DBs struct {
	sync.Mutex
	dbs map[DbType](*DB)
}

type scopeMapKey [100]byte

type DB struct {
	sync.Mutex
	db       *sql.DB
	scopeMap map[scopeMapKey]lcl.ScopeID
	which    DbType
}

func NewDBs() *DBs {
	return &DBs{
		dbs: make(map[DbType](*DB)),
	}
}

func scopeLabelToMapKey(lab lcl.ScopeLabel) (scopeMapKey, error) {
	var ret scopeMapKey
	if len(lab) > len(ret) {
		return scopeMapKey{}, errors.New("scope label too long")
	}
	copy(ret[:], lab[:])
	return ret, nil
}

func initDB(ctx context.Context, db *sql.DB, which DbType) (err error) {

	schm, ok := schema[which]
	if !ok {
		return core.DbError("schema not found")
	}
	statements := strings.Split(schm, ";")

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		tmp := tx.Rollback()
		if err == nil && tmp != nil && !errors.Is(tmp, sql.ErrTxDone) {
			err = tmp
		}
	}()
	for _, stmt := range statements {
		_, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func (g *GlobalContext) Db(ctx context.Context, which DbType) (*DB, error) {
	file, opts, dbs, err := g.prepareDbGet(ctx, which)
	if err != nil {
		return nil, err
	}
	return dbs.Get(ctx, which, file, opts)
}

func (g *GlobalContext) DbNuke(ctx context.Context, which DbType) error {
	file, _, dbs, err := g.prepareDbGet(ctx, which)
	if err != nil {
		return err
	}
	return dbs.Nuke(ctx, which, file)

}

func (g *GlobalContext) prepareDbGet(ctx context.Context, which DbType) (string, string, *DBs, error) {
	log := g.ThinLog(ctx)
	file, err := g.cfg.DbFile(which)
	opts := g.cfg.DbOpts(log)
	dbs := g.dbs
	return file, opts, dbs, err
}

func (d *DBs) Nuke(context context.Context, which DbType, file string) error {
	d.Lock()
	defer d.Unlock()
	cached := d.dbs[which]
	if cached != nil {
		cached.db.Close()
		delete(d.dbs, which)
	}
	return os.Remove(file)
}

func (d *DBs) Get(ctx context.Context, which DbType, file string, opts string) (*DB, error) {
	d.Lock()
	defer d.Unlock()

	cached := d.dbs[which]
	if cached != nil {
		return cached, nil
	}
	err := os.MkdirAll(filepath.Dir(file), MkdirAllMode)
	if err != nil {
		return nil, err
	}
	connStr := file
	if len(opts) > 0 {
		connStr = connStr + "?" + opts
	}
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}
	err = initDB(ctx, db, which)
	if err != nil {
		return nil, err
	}
	ret := &DB{db: db, scopeMap: make(map[scopeMapKey]lcl.ScopeID), which: which}
	d.dbs[which] = ret
	return ret, err
}

func RetryTx(m MetaContext, db *sql.DB, nm string, tryFn func(m MetaContext, tx *sql.Tx) error) error {

	nTries := 5
	backoff := 1 * time.Millisecond
	m = m.WithLogTag("dbtx")

	tryOnce := func(i int) (ret bool, err error) {
		tx, err := db.BeginTx(m.Ctx(), nil)
		if err != nil {
			return false, err
		}

		defer func() {
			tmp := tx.Rollback()
			if err == nil && tmp != nil && !errors.Is(tmp, sql.ErrTxDone) {
				err = tmp
			}
		}()

		err = tryFn(m, tx)
		if err != nil {
			return false, err
		}
		err = tx.Commit()
		if err == nil {
			return false, nil
		}
		if errors.Is(err, sqlite3.ErrLocked) {
			return false, err
		}
		m.Warnw("retryTx", "query", nm, "i", i, "err", err)
		time.Sleep(backoff)
		backoff *= 2
		return true, nil
	}

	for i := range nTries {
		if retry, err := tryOnce(i); !retry {
			return err
		}
	}
	return core.TxRetryError{}
}

type PutArg struct {
	Scope   Scoper
	Typ     lcl.DataType
	Key     any
	Val     core.Codecable
	Counter *int64
	Set     bool
}

func (g *GlobalContext) DbPut(ctx context.Context, which DbType, row PutArg) error {
	return g.DbPutTx(ctx, which, []PutArg{row})
}

func (d *DB) getScopeID(ctx context.Context, scope Scoper) (lcl.ScopeID, error) {
	if scope == nil {
		return lcl.ScopeID(0), nil
	}
	scopeLabel, err := core.EncodeToBytes(scope)
	if err != nil {
		return 0, err
	}
	scopeKey, err := scopeLabelToMapKey(scopeLabel)
	if err != nil {
		return 0, err
	}
	scopeID, ok := d.scopeMap[scopeKey]

	if ok {
		return scopeID, nil
	}

	var id int
	err = d.db.QueryRow(
		`SELECT id FROM scope WHERE label=$1`,
		[]byte(scopeLabel),
	).Scan(&id)

	if err == nil {
		scopeID = lcl.ScopeID(id)
		d.scopeMap[scopeKey] = scopeID
		return scopeID, nil
	}

	if err != sql.ErrNoRows {
		return 0, err
	}

	var mx int
	err = d.db.QueryRow(
		`SELECT COALESCE(MAX(id),0) FROM scope`,
	).Scan(&mx)

	if err != nil {
		return 0, err
	}

	ret := lcl.ScopeID(mx + 1)

	tag, err := d.db.Exec(
		`INSERT INTO scope (id, label) VALUES ($1, $2)`,
		int(ret),
		[]byte(scopeLabel),
	)

	if err != nil {
		return 0, err
	}

	if n, _ := tag.RowsAffected(); n != 1 {
		return 0, core.InsertError("put scope failed")
	}

	d.scopeMap[scopeKey] = ret

	return ret, nil
}

func (g *GlobalContext) DbGetGlobalKV(
	ctx context.Context,
	out core.Codecable,
	which DbType,
	key core.KVKey,
) (proto.Time, error) {
	var zed proto.Time
	db, err := g.Db(ctx, which)
	if err != nil {
		return zed, err
	}
	return db.GetGlobalKV(ctx, out, key)
}

func (d *DB) GetGlobalKV(
	ctx context.Context,
	out core.Codecable,
	key core.KVKey,
) (proto.Time, error) {
	var zed proto.Time

	d.Lock()
	defer d.Unlock()

	q := `SELECT val,mtime FROM global_kv WHERE key=$1`
	args := []any{string(key)}
	var val []byte
	var timeRaw uint64
	err := d.db.QueryRow(q, args...).Scan(&val, &timeRaw)
	if err == sql.ErrNoRows {
		return zed, core.RowNotFoundError{}
	}
	if err != nil {
		return zed, err
	}
	ret := proto.Time(timeRaw)
	err = core.DecodeFromBytes(out, val)
	if err != nil {
		return zed, err
	}
	return ret, nil
}

type rawSetItem struct {
	val  []byte
	time proto.Time
}

func (g *GlobalContext) DbGetGlobalSet(
	ctx context.Context,
	which DbType,
	key core.KVKey,
) ([]rawSetItem, error) {
	db, err := g.Db(ctx, which)
	if err != nil {
		return nil, err
	}
	return db.GetGlobalSet(ctx, key)
}

func DbGetGlobalSetGctx[
	T any,
	PT interface {
		*T
		core.CryptoPayloader
	}](
	ctx context.Context,
	g *GlobalContext,
	which DbType,
	key core.KVKey,
) ([]T, []proto.Time, error) {
	raw, err := g.DbGetGlobalSet(ctx, which, key)
	if err != nil {
		return nil, nil, err
	}
	ret := make([]T, len(raw))
	times := make([]proto.Time, len(raw))
	for i, item := range raw {
		pt := PT(&ret[i])
		err = core.DecodeFromBytes(pt, item.val)
		if err != nil {
			return nil, nil, err
		}
		times[i] = item.time
	}
	return ret, times, nil
}

func (d *DB) GetGlobalSet(
	ctx context.Context,
	key core.KVKey,
) ([]rawSetItem, error) {
	var ret []rawSetItem

	d.Lock()
	defer d.Unlock()

	q := `SELECT val,ctime FROM global_set WHERE key=$1`
	args := []any{string(key)}
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var val []byte
		var timeRaw uint64
		err = rows.Scan(&val, &timeRaw)
		if err != nil {
			return nil, err
		}
		tm := proto.Time(timeRaw)
		ret = append(ret, rawSetItem{val, tm})
	}
	return ret, nil
}

func (g *GlobalContext) DbGetCounter(
	ctx context.Context,
	which DbType,
	scope Scoper,
	typ lcl.DataType,
) (int64, proto.Time, error) {

	var c int64
	var t proto.Time

	db, err := g.Db(ctx, which)
	if err != nil {
		return c, t, err
	}
	db.Lock()
	defer db.Unlock()

	if scope == nil {
		return c, t, core.InternalError("scope is nil")
	}
	if typ == lcl.DataType_None {
		return c, t, core.InternalError("type is none")
	}

	scopeID, err := db.getScopeID(ctx, scope)
	if err != nil {
		return c, t, err
	}

	q := `SELECT val,mtime FROM scoped_counters WHERE scope_id=$1 AND typ=$2`
	args := []any{int(scopeID), typ}

	var val int64
	var timeRaw uint64
	err = db.db.QueryRow(q, args...).Scan(&val, &timeRaw)
	if err == sql.ErrNoRows {
		return c, t, core.RowNotFoundError{}
	}
	if err != nil {
		return c, t, err
	}
	t = proto.Time(timeRaw)
	return val, t, nil
}

func (g *GlobalContext) DbGet(
	ctx context.Context,
	out core.Codecable,
	which DbType,
	scope Scoper,
	typ lcl.DataType,
	gkey any,
) (proto.Time, error) {
	var zed proto.Time
	db, err := g.Db(ctx, which)
	if err != nil {
		return zed, err
	}
	m := NewMetaContext(ctx, g)

	return db.Get(m, out, scope, typ, gkey)
}

func (d *DB) Get(
	m MetaContext,
	out core.Codecable,
	scope Scoper,
	typ lcl.DataType,
	gkey any,
) (proto.Time, error) {
	var zed proto.Time
	d.Lock()
	defer d.Unlock()

	key, err := core.NewDbKey(gkey)
	if err != nil {
		return zed, err
	}

	if scope == nil {
		return zed, core.InternalError("scope is nil")
	}
	if typ == lcl.DataType_None {
		return zed, core.InternalError("type is none")
	}

	scopeID, err := d.getScopeID(m.Ctx(), scope)
	if err != nil {
		return zed, err
	}

	q := `SELECT val,mtime FROM scoped_data WHERE scope_id=$1 AND typ=$2 AND key=$3`
	args := []any{int(scopeID), typ, key.ExportToDB()}

	var val []byte
	var timeRaw uint64
	err = d.db.QueryRow(q, args...).Scan(&val, &timeRaw)
	if err == sql.ErrNoRows {
		return zed, core.RowNotFoundError{}
	}
	if err != nil {
		return zed, err
	}
	ret := proto.Time(timeRaw)
	err = core.DecodeFromBytes(out, val)
	if err != nil {
		return zed, err
	}

	if d.which == DbTypeHard {
		return ret, nil
	}

	q = `UPDATE scoped_data SET gc_bit=1 WHERE scope_id=$1 AND typ=$2 AND key=$3`
	args = []any{int(scopeID), typ, key.ExportToDB()}

	err = RetryTx(m, d.db, "Get", func(m MetaContext, tx *sql.Tx) error {
		_, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		// Can't check rowsAffected() since it might noop if we're
		// idempotent and the row already has gc_bit=1.
		return nil
	})

	if err != nil {
		return zed, err
	}

	return ret, nil
}

func (g *GlobalContext) DbPutTx(ctx context.Context, which DbType, rows []PutArg) error {
	m := NewMetaContext(ctx, g)
	db, err := g.Db(ctx, which)
	if err != nil {
		return err
	}
	return db.PutTx(m, rows)
}

func (g *GlobalContext) DbDelete(ctx context.Context, which DbType, s Scoper, typ lcl.DataType, gkey any) error {
	m := NewMetaContext(ctx, g)
	db, err := g.Db(ctx, which)
	if err != nil {
		return err
	}
	return db.Delete(m, s, typ, gkey)
}

func (g *GlobalContext) DbDeleteFromGlobalSet(ctx context.Context, which DbType, key core.KVKey, h proto.StdHash) error {
	m := NewMetaContext(ctx, g)
	db, err := g.Db(ctx, which)
	if err != nil {
		return err
	}
	return db.DeleteFromGlobalSet(m, key, h)
}

func (g *GlobalContext) DbDeleteGlobalKV(ctx context.Context, which DbType, key core.KVKey) error {
	m := NewMetaContext(ctx, g)
	db, err := g.Db(ctx, which)
	if err != nil {
		return err
	}
	return db.DeleteGlobalKV(m, key)
}

func (d *DB) Put(m MetaContext, row PutArg) error {
	return d.PutTx(m, []PutArg{row})
}

func (d *DB) PutTx(m MetaContext, rows []PutArg) error {
	d.Lock()
	defer d.Unlock()

	ctx := m.Ctx()
	var err error

	scopeIDs := make([]lcl.ScopeID, len(rows))

	for i, row := range rows {
		if row.Scope != nil {
			scopeIDs[i], err = d.getScopeID(ctx, row.Scope)
			if err != nil {
				return err
			}

		}
	}

	err = RetryTx(m, d.db, "Put", func(m MetaContext, tx *sql.Tx) error {
		for i, row := range rows {

			var args []any
			var q string
			var valRaw []byte
			if row.Val != nil {
				valRaw, err = core.EncodeToBytes(row.Val)
				if err != nil {
					return err
				}
			}
			now := proto.Now()
			var rkey any
			checkRows := true

			switch {
			case row.Typ == lcl.DataType_None:
				if valRaw == nil {
					return core.InternalError("nil value on insert")
				}
				if scopeIDs[i] != 0 {
					return core.InternalError("scopeID is not 0")
				}

				var k core.KVKey
				k, ok := row.Key.(core.KVKey)
				if !ok {
					return core.InternalError("key is not KVKey")
				}
				rkey = k
				if row.Set {
					cp, ok := row.Val.(core.CryptoPayloader)
					if !ok {
						return core.InternalError("value in set is not CrytpoPayloader, needs a type ID")
					}
					hsh, err := core.PrefixedHash(cp)
					if err != nil {
						return err
					}
					q = `INSERT INTO global_set(key, hash, val, ctime)
					VALUES($1, $2, $3, $4)
 		 		    ON CONFLICT(key, hash) DO NOTHING`
					args = []any{string(k), (*hsh)[:], valRaw, now}
					checkRows = false

				} else {
					q = `INSERT INTO global_kv(key, val, ctime, mtime) VALUES($1, $2, $3, $3)
		 		    ON CONFLICT(key) DO UPDATE SET val=$2, mtime=$3`
					args = []any{string(k), valRaw, now}
				}

			case row.Counter != nil:
				if row.Key != nil || row.Val != nil {
					return core.InternalError("key or val is not nil for counter updated")
				}

				q = `INSERT INTO scoped_counters(scope_id, typ, val, ctime, mtime)
				     VALUES($1, $2, $3, $4, $4)
				     ON CONFLICT(scope_id, typ)
				     DO UPDATE SET val=$3
				     WHERE val<$3
				`
				args = []any{int(scopeIDs[i]), row.Typ.ExportToDB(), row.Counter, now}
				checkRows = false

			default:
				if valRaw == nil {
					return core.InternalError("nil value on insert")
				}
				key, err := core.NewDbKey(row.Key)
				if err != nil {
					return err
				}
				if scopeIDs[i] == 0 {
					return core.InternalError("scopeID is 0")
				}
				rkey = key
				q = `INSERT INTO scoped_data(scope_id, typ, key, val, ctime, mtime)
				     VALUES($1, $2, $3, $4, $5, $5)
				     ON CONFLICT(scope_id, typ, key)
					 DO UPDATE SET val=$4, mtime=$5`
				args = []any{int(scopeIDs[i]), row.Typ.ExportToDB(), key.ExportToDB(), valRaw, proto.Now()}
			}

			tag, err := tx.Exec(q, args...)
			if err != nil {
				m.Errorw("RetryTX", "err", err, "key", rkey, "scope", scopeIDs[i])
				return err
			}
			n, err := tag.RowsAffected()
			if err != nil {
				return err
			}

			// For updating counters, we might not move the needle at all
			if checkRows && n != 1 {
				return core.InsertError("dbPutTX failed")
			}
		}
		return nil
	})
	return err
}

func (d *DB) DeleteFromGlobalSet(m MetaContext, key core.KVKey, h proto.StdHash) error {
	d.Lock()
	defer d.Unlock()
	q := `DELETE FROM global_set WHERE key=$1 AND hash=$2`
	args := []any{string(key), h[:]}
	err := RetryTx(m, d.db, "DeleteGlobalFromGlobalSet", func(m MetaContext, tx *sql.Tx) error {
		_, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (d *DB) DeleteGlobalKV(m MetaContext, key core.KVKey) error {
	d.Lock()
	defer d.Unlock()
	q := `DELETE FROM global_kv WHERE key=$1`
	args := []any{string(key)}
	err := RetryTx(m, d.db, "DeleteGlobalKV", func(m MetaContext, tx *sql.Tx) error {
		_, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (d *DB) Delete(m MetaContext, scope Scoper, typ lcl.DataType, gkey any) error {
	ctx := m.Ctx()
	d.Lock()
	defer d.Unlock()

	scopeID, err := d.getScopeID(ctx, scope)
	if err != nil {
		return err
	}
	key, err := core.NewDbKey(gkey)
	if err != nil {
		return err
	}

	q := `DELETE FROM scoped_data WHERE scope_id=$1 AND typ=$2 AND key=$3`
	args := []any{int(scopeID), typ, key}

	err = RetryTx(m, d.db, "Delete", func(m MetaContext, tx *sql.Tx) error {
		_, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}
