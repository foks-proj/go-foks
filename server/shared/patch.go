package shared

import (
	"fmt"
	"slices"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type patch struct {
	id  int
	sql string
}

type patchSingleDB struct {
	which   DbType
	conn    *pgxpool.Conn
	applied map[int]bool // map of applied patch IDs
	needed  []patch      // patches that need to be applied
	shdesc  *KVShardDescriptor
}

func (p *patchSingleDB) cleanup() {
	if p.conn != nil {
		p.conn.Release()
		p.conn = nil
	}
}

type PatchDBEng struct {
	Which       DbType
	Shards      []int
	shards      []KVShardDescriptor
	dbs         []*patchSingleDB
	ConfirmHook func(m MetaContext, ps *PatchSummary) error
}

func (p *PatchDBEng) loadShards(m MetaContext) error {
	if p.Which != DbTypeKVStore {
		return nil
	}
	if len(p.Shards) == 0 {
		shards, err := AllShards(m)
		if err != nil {
			return err
		}
		p.shards = shards
		return nil
	}
	shards, err := SomeShards(m, p.Shards)
	if err != nil {
		return err
	}
	p.shards = shards
	return nil
}

func (p *PatchDBEng) getDBs(m MetaContext) error {

	if p.Which != DbTypeKVStore {
		db, err := m.Db(p.Which)
		if err != nil {
			return err
		}
		p.dbs = []*patchSingleDB{{which: p.Which, conn: db}}
	} else {
		for _, shard := range p.shards {
			db, err := m.KVShardByID(shard.Index)
			if err != nil {
				return err
			}
			p.dbs = append(p.dbs,
				&patchSingleDB{
					which:  p.Which,
					conn:   db,
					shdesc: &shard,
				})
		}
	}
	return nil
}

func (p *PatchDBEng) cleanup() {
	for _, db := range p.dbs {
		db.cleanup()
	}
	p.dbs = nil
	p.shards = nil
}

func (p *patchSingleDB) makeSchemaPatchesTable(m MetaContext) error {
	// Create the schema_patches table if it doesn't exist
	_, err := p.conn.Exec(
		m.Ctx(),
		`CREATE TABLE IF NOT EXISTS schema_patches (
			id INT PRIMARY KEY,
			ctime TIMESTAMP NOT NULL
		)`,
	)
	if err != nil {
		return err
	}
	return nil
}

func (p *patchSingleDB) loadCurrentPatchState(m MetaContext) error {
	rows, err := p.conn.Query(
		m.Ctx(),
		"SELECT id FROM schema_patches",
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	p.applied = make(map[int]bool)
	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		if err != nil {
			return err
		}
		p.applied[id] = true
	}
	return nil
}

type PatchSummary struct {
	totPatches int
	descs      []string
}

func (p *PatchSummary) Desc() []string {
	return p.descs
}

func (ps *PatchSummary) addPatches(n int, desc string) {
	if n == 0 {
		return
	}
	ps.totPatches += n
	ps.descs = append(ps.descs, desc)
}

func (p *patchSingleDB) prepare(m MetaContext, ps *PatchSummary) error {
	err := p.makeSchemaPatchesTable(m)
	if err != nil {
		return err
	}
	err = p.loadCurrentPatchState(m)
	if err != nil {
		return err
	}
	all := sql.Patches[p.which.ToString()]
	for id, sql := range all {
		if _, ok := p.applied[id]; ok {
			continue // already applied
		}
		p.needed = append(p.needed, patch{id: id, sql: sql})
	}

	// Sort the patches by ID, lowest ID first
	slices.SortFunc(p.needed, func(a, b patch) int {
		return (a.id - b.id)
	})

	ps.addPatches(len(p.needed), p.String())
	return nil
}

func (p *patchSingleDB) String() string {
	if len(p.needed) == 0 {
		return ""
	}
	var patches []string
	for _, patch := range p.needed {
		patches = append(patches, fmt.Sprintf("p%d", patch.id))
	}
	parts := []string{p.which.ToString()}
	if p.shdesc != nil {
		parts = append(parts, fmt.Sprintf("(shard %d)", p.shdesc.Index))
	}
	parts = append(parts, ": ")
	parts = append(parts, strings.Join(patches, ", "))

	return strings.Join(parts, "")
}

func (p *patchSingleDB) w() []any {
	var ret []any
	ret = append(ret, "db", p.which.ToString())
	if p.shdesc != nil {
		ret = append(ret, "shard-name", p.shdesc.Name,
			"shard-index", p.shdesc.Index)
	}
	ret = append(ret, "numPatches", len(p.needed))
	return ret
}

func trunc(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	n := 35
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (p *patchSingleDB) doSinglePatch(m MetaContext, patch patch) (err error) {
	m = m.WithLogTag("ptch")
	m.Infow("applying patch", "id", patch.id, "sql", trunc(patch.sql))

	var tx pgx.Tx
	tx, err = p.conn.Begin(m.Ctx())
	if err != nil {
		return err
	}

	stmnts := SplitSQLStatements(patch.sql)
	for _, stmnt := range stmnts {

		if strings.TrimSpace(stmnt) == "" {
			continue // skip empty statements
		}

		m.Infow("executing statement", "stmt", trunc(stmnt))

		_, err = tx.Exec(m.Ctx(), stmnt)
		if err != nil {
			m.Errorw("patch failed", "id", patch.id, "stmt", trunc(stmnt), "error", err)
			return err
		}
	}

	// insert the patch into the schema_patches table
	var tag pgconn.CommandTag
	tag, err = tx.Exec(
		m.Ctx(),
		"INSERT INTO schema_patches (id, ctime) VALUES ($1, NOW())",
		patch.id,
	)
	if err != nil {
		m.Errorw("failed to insert patch record", "id", patch.id, "error", err)
		return err
	}

	if tag.RowsAffected() != 1 {
		m.Errorw("failed to insert patch record", "id", patch.id, "rowsAffected", tag.RowsAffected())
		return core.InsertError("failed to insert patch record")
	}

	defer func() {
		if err != nil {
			rberr := tx.Rollback(m.Ctx())
			if rberr != nil {
				m.Errorw("rollback failed", "error", rberr)
			}
			m.Errorw("patch failed", "id", patch.id, "error", err)
			return
		}
		err = tx.Commit(m.Ctx())
		if err != nil {
			m.Errorw("commit failed", "id", patch.id, "error", err)
		}
		m.Infow("patch commited", "id", patch.id)
	}()

	return nil

}

func (p *patchSingleDB) doAllPatches(m MetaContext) error {
	for _, patch := range p.needed {
		err := p.doSinglePatch(m, patch)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PatchDBEng) Run(m MetaContext) error {
	err := p.loadShards(m)
	if err != nil {
		return err
	}
	err = p.getDBs(m)
	if err != nil {
		return err
	}
	defer p.cleanup()

	var ps PatchSummary
	for _, db := range p.dbs {
		err = db.prepare(m, &ps)
		if err != nil {
			return err
		}
	}

	if ps.totPatches == 0 {
		return core.NotFoundError("no patches to apply")
	}

	err = p.ConfirmHook(m, &ps)
	if err != nil {
		return err
	}

	for _, db := range p.dbs {
		whch := db.w()
		m := m.WithLogTag("db")
		m.Infow("patching DB", whch...)
		err := db.doAllPatches(m)
		if err != nil {
			return err
		}
		m.Infow("DB patched", whch...)
	}

	return nil
}
