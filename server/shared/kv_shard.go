// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type KVShardMgr struct {
	shardsMu sync.Mutex
	shards   map[proto.FixedPartyID]proto.KVShardID
	lookups  core.Locktab[proto.FixedPartyID]

	dbsMu sync.Mutex
	dbs   map[proto.KVShardID]*pgxpool.Pool

	allMu  sync.Mutex
	allIDs []proto.KVShardID
}

func NewKVShardMgr() *KVShardMgr {
	return &KVShardMgr{
		shards: make(map[proto.FixedPartyID]proto.KVShardID),
		dbs:    make(map[proto.KVShardID]*pgxpool.Pool),
	}
}

func (s *KVShardMgr) getAll(m MetaContext) ([]proto.KVShardID, error) {
	s.allMu.Lock()
	defer s.allMu.Unlock()
	if len(s.allIDs) > 0 {
		return s.allIDs, nil
	}
	cfg, err := m.G().Config().KVShardsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	s.allIDs = core.Map(cfg.All(), func(scfg KVShardConfig) proto.KVShardID { return scfg.Id() })
	return s.allIDs, nil
}

func (s *KVShardMgr) GetAllConns(m MetaContext) (*ConnIter, error) {
	ids, err := s.getAll(m)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, core.ConfigError("no kv shards")
	}
	ret := &ConnIter{mgr: s}
	ret.clusters = core.Map(ids, func(id proto.KVShardID) cluster { return cluster{id: id} })
	return ret, nil
}

func (s *KVShardMgr) GetConn(m MetaContext, p proto.PartyID) (*pgxpool.Conn, error) {
	id, err := s.getOrMakeID(m, p, true)
	if err != nil {
		return nil, err
	}
	return s.GetConnByShardID(m, id)
}

type cluster struct {
	parties []proto.PartyID
	id      proto.KVShardID
}
type ConnIter struct {
	mgr      *KVShardMgr
	clusters []cluster
}

func (s *KVShardMgr) GetSomeConns(m MetaContext, ps []proto.PartyID) (*ConnIter, error) {
	clusters := make(map[proto.KVShardID]cluster)
	for _, p := range ps {
		id, err := s.getOrMakeID(m, p, true)
		if err != nil {
			return nil, err
		}
		c, ok := clusters[id]
		if !ok {
			c = cluster{id: id}
		}
		c.parties = append(c.parties, p)
		clusters[id] = c
	}
	ret := &ConnIter{
		mgr:      s,
		clusters: make([]cluster, 0, len(clusters)),
	}
	for _, c := range clusters {
		ret.clusters = append(ret.clusters, c)
	}
	return ret, nil
}

func (c *ConnIter) Next() bool { return len(c.clusters) > 0 }

func (c *ConnIter) Conn(m MetaContext) (*pgxpool.Conn, []proto.PartyID, error) {
	if len(c.clusters) == 0 {
		return nil, nil, core.InternalError("iterator was empty")
	}
	cl := c.clusters[0]
	c.clusters = c.clusters[1:]
	conn, err := c.mgr.GetConnByShardID(m, cl.id)
	if err != nil {
		return nil, nil, err
	}
	return conn, cl.parties, nil
}

func (s *KVShardMgr) DoSome(
	m MetaContext,
	pids []proto.PartyID,
	fn func(conn *pgxpool.Conn, parties []proto.PartyID) error,
) error {
	iter, err := s.GetSomeConns(m, pids)
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.Next() {
		conn, parties, err := iter.Conn(m)
		if err != nil {
			return err
		}
		defer conn.Release()
		err = fn(conn, parties)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *KVShardMgr) DoAll(
	m MetaContext,
	fn func(conn *pgxpool.Conn) error,
) error {
	iter, err := s.GetAllConns(m)
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.Next() {
		conn, _, err := iter.Conn(m)
		if err != nil {
			return err
		}
		defer conn.Release()
		err = fn(conn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ConnIter) Close() {}

func (s *KVShardMgr) GetConnByShardID(m MetaContext, id proto.KVShardID) (*pgxpool.Conn, error) {
	pool, err := s.getDbPool(m, id)
	if err != nil {
		return nil, err
	}

	conn, err := pool.Acquire(m.Ctx())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *KVShardMgr) getDbPool(m MetaContext, id proto.KVShardID) (*pgxpool.Pool, error) {
	s.dbsMu.Lock()
	defer s.dbsMu.Unlock()

	ret, ok := s.dbs[id]
	if ok {
		return ret, nil
	}

	cfg, err := m.G().Config().KVShardsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	scfg := cfg.Get(id)
	if scfg == nil {
		return nil, core.ConfigError("no kv shard config")
	}
	dbcfg, err := scfg.DbConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(m.Ctx(), dbcfg)
	if err != nil {
		return nil, err
	}
	err = pool.Ping(m.Ctx())
	if err != nil {
		pool.Close()
		return nil, err
	}
	s.dbs[id] = pool
	return pool, nil
}

func randomSel[T any, S core.Codecable](v []T, seed S) (T, error) {
	var zed T
	if len(v) == 0 {
		return zed, core.InternalError("empty slice")
	}
	var hsh proto.StdHash
	err := core.HashInto(seed, hsh[:])
	if err != nil {
		return zed, nil
	}

	value := binary.LittleEndian.Uint32(hsh[:4])
	n := uint32(len(v))

	return v[value%n], nil
}

func (s *KVShardMgr) getOrMakeID(
	m MetaContext,
	p proto.PartyID,
	make bool,
) (proto.KVShardID, error) {
	var zed proto.KVShardID
	fpi, err := p.Fixed()
	if err != nil {
		return zed, err
	}
	s.shardsMu.Lock()
	ret, ok := s.shards[fpi]
	s.shardsMu.Unlock()
	if ok {
		return ret, nil
	}

	// Single-flight all work on the party
	lte := s.lookups.Acquire(fpi)
	defer lte.Release()

	// Check again after acquiring the single-flight lock
	s.shardsMu.Lock()
	ret, ok = s.shards[fpi]
	s.shardsMu.Unlock()
	if ok {
		return ret, nil
	}

	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return zed, err
	}
	defer db.Release()
	var tmp int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT shard_id FROM kv_shards
		 WHERE short_host_id = $1 AND party_id = $2`,
		m.ShortHostID().ExportToDB(),
		p.ExportToDB(),
	).Scan(&tmp)

	put := func() {
		s.shardsMu.Lock()
		s.shards[fpi] = ret
		s.shardsMu.Unlock()
	}

	if err == nil {
		ret = proto.KVShardID(tmp)
		put()
		return ret, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return zed, err
	}

	if !make {
		return zed, core.NotFoundError(p)
	}

	cfg, err := m.G().Config().KVShardsConfig(m.Ctx())
	if err != nil {
		return zed, err
	}
	active := cfg.Active()
	if len(active) == 0 {
		return zed, core.ConfigError("no active kv shard")
	}
	sel, err := randomSel(active, &p)
	if err != nil {
		return zed, err
	}
	ret = sel.Id()
	tag, err := db.Exec(
		m.Ctx(),
		`INSERT INTO kv_shards (short_host_id, party_id, shard_id, ctime)
		 VALUES ($1, $2, $3, NOW())`,
		m.ShortHostID().ExportToDB(),
		p.ExportToDB(),
		int(ret),
	)
	if err != nil {
		return zed, err
	}
	if tag.RowsAffected() != 1 {
		return zed, core.UpdateError("kv shard")
	}

	put()
	return ret, nil
}

func AllShards(m MetaContext) ([]KVShardDescriptor, error) {
	shcfg, err := m.G().Config().KVShardsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	all := shcfg.All()
	var ret []KVShardDescriptor
	for _, shard := range all {
		ret = append(ret, KVShardDescriptor{
			Index:  shard.Id(),
			Active: shard.IsActive(),
			Name:   shard.Name(),
		})
	}
	return ret, nil
}

func SomeShards(m MetaContext, indices []int) ([]KVShardDescriptor, error) {
	shcfg, err := m.G().Config().KVShardsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	var ret []KVShardDescriptor
	for _, id := range indices {
		shard := shcfg.Get(proto.KVShardID(id))
		if shard == nil {
			return nil, core.BadArgsError(fmt.Sprintf("no such shard: %d", id))
		}
		ret = append(ret, MakeShardDescriptor(shard))
	}
	return ret, nil
}
