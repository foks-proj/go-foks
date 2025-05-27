// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"regexp"
	"strings"

	"github.com/foks-proj/go-foks/server/sql"
	"github.com/jackc/pgx/v5/pgxpool"
)

type InitDB struct {
	Dbs ManageDBsConfig
}

func (i *InitDB) execAll(m MetaContext, q string) error {
	db, err := m.G().Db(m.ctx, DbTypeTemplate)
	if err != nil {
		return err
	}
	defer db.Release()
	for _, d := range i.Dbs.All() {
		_, err := db.Exec(m.Ctx(), q+" "+d.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *InitDB) CreateAll(m MetaContext) error {
	return i.execAll(m, "CREATE DATABASE")
}

func (i *InitDB) DropAll(m MetaContext) error {
	return i.execAll(m, "DROP DATABASE")
}

func (i *InitDB) DatabaseNames() []string {
	var ret []string
	for _, pair := range i.Dbs.All() {
		ret = append(ret, pair.Name)
	}
	return ret
}

func SplitSQLStatements(b string) []string {
	// Strip both /*…*/ (even across lines) and --… comments
	re := regexp.MustCompile(`(?s:/\*.*?\*/)|--[^\r\n]*`)
	clean := re.ReplaceAllString(b, "")

	// Now split on semicolons
	return strings.Split(clean, ";")
}

func (i *InitDB) readSQLFile(m MetaContext, d DbType) ([]string, error) {
	b, found := sql.SQL[d.ToString()]
	if !found {
		return nil, errors.New("no SQL found for " + d.ToString())
	}
	return SplitSQLStatements(b), nil
}

func (i *InitDB) runMakeTablesOne(m MetaContext, db *pgxpool.Conn, typ DbType, name string) (err error) {
	statements, err := i.readSQLFile(m, typ)
	if err != nil {
		return err
	}
	tx, err := db.Begin(m.Ctx())
	defer func() {
		err = TxRollback(m.Ctx(), tx, err)
	}()
	if err != nil {
		return err
	}
	for _, statement := range statements {
		_, err = tx.Exec(m.Ctx(), statement)
		if err != nil {
			return err
		}
	}
	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}
	m.Infow("created tables", "database", name)
	return nil
}

func (i *InitDB) RunMakeTablesAll(m MetaContext) error {
	for _, typ := range i.Dbs.Dbs {
		db, err := m.Db(typ)
		if err != nil {
			return err
		}
		defer db.Release()
		err = i.runMakeTablesOne(m, db, typ, typ.ToString())
		if err != nil {
			return err
		}
	}
	for _, shard := range i.Dbs.KVShards {
		db, err := m.KVShardByID(shard.Index)
		if err != nil {
			return err
		}
		defer db.Release()
		err = i.runMakeTablesOne(m, db, DbTypeKVStore, shard.Name)
		if err != nil {
			return err
		}
	}
	return nil
}
