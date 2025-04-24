// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"bytes"
	"context"
	"flag"
	"sort"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/pgtype"
	"github.com/jackc/pgx/v5"
)

type MerkleBatcherVHostState struct {
	shid  core.ShortHostID
	state *proto.MerkleBatcherState
}

type MerkleBatcherServer struct {
	MerklePipelineBaseServer
	vhosts map[core.ShortHostID]*MerkleBatcherVHostState
}

func NewMerkleBatcherServer() *MerkleBatcherServer {
	ret := &MerkleBatcherServer{
		vhosts: make(map[core.ShortHostID]*MerkleBatcherVHostState),
	}
	ret.serverType = proto.ServerType_MerkleBatcher
	ret.sub = ret
	return ret
}

func (b *MerkleBatcherServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (b *MerkleBatcherServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &MerkleBatcherClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

func (b *MerkleBatcherServer) Setup(m shared.MetaContext) error {
	err := b.MerklePipelineBaseServer.Setup(m)
	if err != nil {
		return err
	}
	return nil
}

func (s *MerkleBatcherServer) initBackgroundLoop(m shared.MetaContext) error {
	return nil
}

func (s *MerkleBatcherServer) writeBatchState(m shared.MetaContext, tx pgx.Tx, state proto.MerkleBatcherState) error {
	raw, err := core.EncodeToBytes(&state)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO raft_kv_store(short_host_id, k, v)
		 VALUES($1,$2,$3)
		 ON CONFLICT (short_host_id,k) DO UPDATE SET v=$3`,
		m.ShortHostID().ExportToDB(),
		BatchStateKey,
		raw,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("batchState")
	}
	return nil
}

func (v *MerkleBatcherVHostState) init(m shared.MetaContext, s *MerkleBatcherServer) error {
	err := v.initBatcherState(m, s)
	if err != nil {
		return err
	}
	return nil
}

func (v *MerkleBatcherVHostState) initBatcherState(m shared.MetaContext, s *MerkleBatcherServer) (err error) {
	db, err := m.Db(shared.DbTypeMerkleRaft)
	if err != nil {
		return err
	}
	defer db.Release()
	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = shared.TxRollback(m.Ctx(), tx, err)
	}()
	state, err := s.readBatchState(m, tx)
	if err != nil {
		return err
	}
	if state != nil {
		v.state = state
		return nil
	}

	state = &proto.MerkleBatcherState{
		Next: 1,
	}
	err = s.writeBatchState(m, tx, *state)
	if err != nil {
		return err
	}
	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}
	v.state = state
	return nil
}

func (s *MerkleBatcherServer) initVhostState(m shared.MetaContext) (*MerkleBatcherVHostState, error) {
	shid := m.ShortHostID()
	vh, ok := s.vhosts[shid]
	if ok {
		return vh, nil
	}
	vh = &MerkleBatcherVHostState{shid: shid}
	err := vh.init(m, s)
	if err != nil {
		return nil, err
	}
	s.vhosts[shid] = vh
	return vh, nil
}

func (s *MerkleBatcherServer) pollHostchain(m shared.MetaContext, batch *proto.MerkleBatch) (err error) {
	db, err := m.Db(shared.DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = shared.TxRollback(m.Ctx(), tx, err)
	}()

	rows, err := tx.Query(m.Ctx(),
		`SELECT seqno, hash, merkle_state,
		 EXTRACT(EPOCH FROM (NOW() - qtime))::int8 AS age
	     FROM hostchain_links
	     WHERE short_host_id=$1
	     AND merkle_state != $2
	     ORDER BY seqno DESC`,
		m.ShortHostID().ExportToDB(),
		string(shared.MerkleWorkStateCommitted),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	var seqno int
	var hash []byte
	var stateRaw string
	var ageSecs pgtype.Int8

	inProcess := false
	var tail *proto.HostchainTail

	_, err = pgx.ForEachRow(rows, []any{&seqno, &hash, &stateRaw, &ageSecs}, func() error {
		if tail == nil {
			lh, err := proto.ImportLinkHashFromDB(hash)
			if err != nil {
				return err
			}
			tail = &proto.HostchainTail{
				Seqno: proto.Seqno(seqno),
				Hash:  *lh,
			}
		}
		var age shared.Seconds
		if ageSecs.Status == pgtype.Present {
			age = shared.Seconds(ageSecs.Int)
		}
		state := shared.MerkleWorkState(stateRaw)
		switch state {
		case shared.MerkleWorkStateStaged:
			// noop
		case shared.MerkleWorkStateProcessing:
			if age.Duration() < s.cfg.WorkTimeout() {
				inProcess = true
			} else {
				m.Warnw("pollHostchain", "state", "work timeout", "age", age, "seqno", seqno)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Only respam a hostchain update if the previous update timed out
	if inProcess || tail == nil {
		return nil
	}

	batch.Hostchain = tail
	tag, err := tx.Exec(m.Ctx(),
		`UPDATE hostchain_links
		 SET merkle_state=$1, qtime=NOW()
		 WHERE merkle_state!=$2 AND short_host_id=$3`,
		string(shared.MerkleWorkStateProcessing),
		string(shared.MerkleWorkStateCommitted),
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.UpdateError("no row updated in pollHostchain")
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	return nil
}

func (s *MerkleBatcherServer) pollLeaves(m shared.MetaContext, b *proto.MerkleBatch) (err error) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = shared.TxRollback(m.Ctx(), tx, err)
	}()

	rows, err := tx.Query(m.Ctx(),
		`SELECT id, chain_type, seqno, key, val, state, 
		  (EXTRACT(EPOCH FROM (NOW() - qtime))*1000)::int8 AS age,
		  (EXTRACT(EPOCH FROM ctime) * 1000)::int8 AS ctime
	     FROM merkle_work_queue
		 WHERE state IN ($2, $3)
		 AND short_host_id=$1
		 AND (id, chain_type) IN 
		  (SELECT id,chain_type FROM merkle_work_queue
		   WHERE (state=$2
		     OR (state=$3 AND qtime < NOW() - $4 * INTERVAL '1 second'))
		   AND short_host_id=$5
		   ORDER by ctime ASC
		   LIMIT $6)
 		 ORDER by ctime ASC`,
		m.ShortHostID().ExportToDB(),
		string(shared.MerkleWorkStateStaged),
		string(shared.MerkleWorkStateProcessing),
		int(s.cfg.WorkTimeout().Seconds()),
		m.ShortHostID().ExportToDB(),
		s.cfg.BatchSize(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	var id, key, val []byte
	var seqno, typ, ctime int
	var state string
	var age pgtype.Int8

	type leaf struct {
		m     proto.MerkleLeaf
		id    proto.EntityID33
		typ   proto.ChainType
		seqno proto.Seqno
		state shared.MerkleWorkState
		age   shared.Milliseconds
		ctime proto.Time
	}

	type leafIdx struct {
		id  proto.EntityID33
		typ proto.ChainType
	}

	leafMap := make(map[leafIdx](*leaf))

	_, err = pgx.ForEachRow(rows, []any{&id, &typ, &seqno, &key, &val, &state, &age, &ctime}, func() error {
		var idx proto.EntityID33
		err := idx.ImportFromBytes(id)
		if err != nil {
			return err
		}
		mapkey := leafIdx{
			id:  idx,
			typ: proto.ChainType(typ),
		}
		leaf := leaf{
			seqno: proto.Seqno(seqno),
			typ:   proto.ChainType(typ),
			state: shared.MerkleWorkState(state),
			ctime: proto.Time(ctime),
			id:    idx,
		}
		if age.Status == pgtype.Present {
			leaf.age = shared.Milliseconds(age.Int)
		}
		err = leaf.m.Key.ImportFromBytes(key)
		if err != nil {
			return err
		}
		err = leaf.m.Value.ImportFromBytes(val)
		if err != nil {
			return err
		}
		existing := leafMap[mapkey]
		if existing == nil || existing.seqno > leaf.seqno {
			leafMap[mapkey] = &leaf
		}
		return nil
	})
	if err != nil {
		return err
	}

	leafVec := make([](*leaf), 0, len(leafMap))
	for _, leaf := range leafMap {
		if leaf.state == shared.MerkleWorkStateStaged ||
			(leaf.state == shared.MerkleWorkStateProcessing && leaf.age.Duration() > s.cfg.WorkTimeout()) {
			leafVec = append(leafVec, leaf)
		}
	}

	// Canonical sorting is via ctime, with tie-breaks going to the lower Key,
	// when compared lexicographically.
	sort.Slice(leafVec, func(i, j int) bool {
		return (bytes.Compare(leafVec[i].m.Key[:], leafVec[j].m.Key[:]) < 0)
	})

	b.Leaves = make([]proto.MerkleLeaf, len(leafVec))
	for i, leaf := range leafVec {
		b.Leaves[i] = leaf.m
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE merkle_work_queue
			 SET state=$1, qtime=NOW()
			 WHERE short_host_id=$2 AND id=$3 AND chain_type=$4 AND seqno=$5`,
			string(shared.MerkleWorkStateProcessing),
			m.ShortHostID().ExportToDB(),
			leaf.id[:],
			int(leaf.typ),
			int(leaf.seqno),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("now row updated in pollLeaves")
		}
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	return nil
}

func (s *MerkleBatcherServer) commitBatch(m shared.MetaContext, batch *proto.MerkleBatch) (err error) {

	vh, err := s.initVhostState(m)
	if err != nil {
		return err
	}

	if batch.IsEmpty() {
		return nil
	}

	batch.Time = proto.Now()
	batch.Batchno = vh.state.Next
	nxt := *vh.state
	nxt.Next++

	tx, cleanup, err := m.G().DbTx(m.Ctx(), shared.DbTypeMerkleRaft)
	if err != nil {
		return err
	}
	defer func() {
		tmp := cleanup()
		if err == nil && tmp != nil {
			err = tmp
		}
	}()

	batchRaw, err := core.EncodeToBytes(batch)
	if err != nil {
		return err
	}

	// We're writing up into foks_merkle_tree.sql / merkle_bookkeeping before
	// we write into merkle_raft_kv.  If we fail after the former but before
	// the latter, it's not an big problem. It will match the pipeline slightly
	// less efficient, since we'll be busy-polling this batch number but not progressing.
	// But no data will be lost or invariants violated.
	err = s.eng.UpdateBookkeepingForBatcher(m, nxt.Next)
	if err != nil {
		return err
	}

	m.Infow("commitBatch", "stage", "start", "shortHostID", m.ShortHostID(), "batch", batch.Batchno, "leaves", len(batch.Leaves), "id", s.lock.ID())

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO raft_kv_store(short_host_id, k,v) VALUES($1,$2,$3)`,
		m.ShortHostID().ExportToDB(),
		BatchKey(batch.Batchno),
		batchRaw,
	)
	if err != nil {
		m.Errorw("commitBatch", "err", err, "batch", batch.Batchno, "id", s.lock.ID())
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("k-v insert failed")
	}
	err = s.writeBatchState(m, tx, nxt)
	if err != nil {
		return err
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	m.Infow("commitBatch",
		"stage", "complete",
		"shortHostID", m.ShortHostID(),
		"batch", batch.Batchno,
		"leaves", len(batch.Leaves),
		"id", s.lock.ID())

	vh.state = &nxt
	return nil
}

func (s *MerkleBatcherServer) poll(m shared.MetaContext) (*proto.MerkleBatch, error) {
	var batch proto.MerkleBatch
	err := s.pollHostchain(m, &batch)
	if err != nil {
		return nil, err
	}
	err = s.pollLeaves(m, &batch)
	if err != nil {
		return nil, err
	}
	err = s.commitBatch(m, &batch)
	if err != nil {
		return nil, err
	}

	return &batch, nil
}

func (s *MerkleBatcherServer) checkTreeForHostchainUpdates(
	m shared.MetaContext,
) error {

	db, err := m.Db(shared.DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	var cnt int
	err = db.QueryRow(m.Ctx(),
		`SELECT COUNT(*)
  		 FROM hostchain_links
		 WHERE short_host_id=$1
		 AND merkle_state=$2`,
		m.ShortHostID().ExportToDB(),
		string(shared.MerkleWorkStateProcessing),
	).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt == 0 {
		return nil
	}
	cli, err := m.MerkleCli()
	if err != nil {
		return err
	}
	root, err := cli.GetCurrentRoot(m.Ctx(), m.HostID().IDp())
	if err != nil {
		return err
	}
	v, err := root.GetV()
	if err != nil {
		return err
	}
	if v != proto.MerkleRootVersion_V1 {
		return core.VersionNotSupportedError("merkle root version from future")
	}
	v1 := root.V1()
	seqno := v1.Hostchain.Seqno
	tag, err := db.Exec(m.Ctx(),
		`UPDATE hostchain_links
		 SET merkle_state=$1
		 WHERE short_host_id=$2
		 AND merkle_state=$3
		 AND seqno <= $4`,
		string(shared.MerkleWorkStateCommitted),
		m.ShortHostID().ExportToDB(),
		string(shared.MerkleWorkStateProcessing),
		int(seqno),
	)
	if err != nil {
		return err
	}
	n := tag.RowsAffected()
	m.Infow("checkTreeForHostchainUpdates", "shortHostID", m.ShortHostID(), "nLinksUpdated", n, "seqno", seqno)

	return nil
}

func (s *MerkleBatcherServer) checkTreeForLeafUpdates(m shared.MetaContext) (err error) {

	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}

	defer func() {
		err = shared.TxRollback(m.Ctx(), tx, err)
	}()

	cli, err := m.MerkleCli()
	if err != nil {
		return err
	}

	rows, err := tx.Query(
		m.Ctx(),
		`SELECT id,key,chain_type,seqno,update_trigger
		 FROM merkle_work_queue
		 WHERE short_host_id=$1
		 AND state=$2`,
		m.ShortHostID().ExportToDB(),
		string(shared.MerkleWorkStateProcessing),
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	type item struct {
		id       []byte
		typ      int64
		seqno    int64
		epno     int64
		newState shared.MerkleWorkState
		trig     proto.UpdateTrigger
	}
	var items []item

	for rows.Next() {
		var it item
		var key, trig []byte
		err := rows.Scan(&it.id, &key, &it.typ, &it.seqno, &trig)
		if err != nil {
			return err
		}

		var mkey proto.MerkleTreeRFOutput
		err = mkey.ImportFromBytes(key)
		if err != nil {
			return err
		}
		err = core.DecodeFromBytes(&it.trig, trig)
		if err != nil {
			return err
		}
		arg := rem.CheckKeyExistsArg{
			Key:    mkey,
			HostID: m.HostID().IDp(),
		}
		if res, foundErr := cli.CheckKeyExists(m.Ctx(), arg); foundErr == nil {
			it.epno = int64(res.Epno)
			it.newState = shared.MerkleWorkStateCommitted
			items = append(items, it)
		}
	}

	for _, it := range items {
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE merkle_work_queue
				 SET state=$1, epno=$2
				 WHERE short_host_id=$3
				 AND id=$4
				 AND chain_type=$5
				 AND seqno=$6`,
			string(it.newState),
			it.epno,
			m.ShortHostID().ExportToDB(),
			it.id,
			it.typ,
			it.seqno,
		)

		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update merkle_work_queue")
		}

		typ, err := it.trig.GetT()
		if err != nil {
			return err
		}
		switch typ {
		case proto.UpdateTriggerType_Revoke:
			rev := it.trig.Revoke()
			tag, err := tx.Exec(m.Ctx(),
				`UPDATE revoked_device_keys SET revoke_tree_epno=$1
				 WHERE short_host_id=$2 AND verify_key=$3 AND revoke_header_epno=$4`,
				it.epno,
				m.ShortHostID().ExportToDB(),
				rev.VerifyKeyID.ExportToDB(),
				int(rev.Epno),
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return core.UpdateError("failed to update revoked_device_keys")
			}
		case proto.UpdateTriggerType_Provision:
			tag, err := tx.Exec(m.Ctx(),
				`UPDATE device_keys SET provision_epno=$1
				 WHERE short_host_id=$2 AND verify_key=$3`,
				it.epno,
				m.ShortHostID().ExportToDB(),
				it.trig.Provision().Eid.ExportToDB(),
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return core.UpdateError("failed to update device_keys")
			}
		case proto.UpdateTriggerType_TeamChange:
			chng := it.trig.Teamchange()
			for _, mr := range chng.Changes {
				typ, err := mr.DstRole.GetT()
				if err != nil {
					return err
				}
				srk, err := core.ImportRole(mr.Member.SrcRole)
				if err != nil {
					return err
				}

				if typ == proto.RoleType_NONE {

					q := `UPDATE team_members SET tree_removal_epno=$1
					 WHERE short_host_id=$2 AND team_id=$3 AND member_id=$4
					 AND member_host_id=$5 AND src_role_type=$6 
					 AND src_viz_level=$7 AND tree_removal_epno IS NULL`
					args := []any{
						it.epno,
						m.ShortHostID().ExportToDB(),
						chng.Team.EntityID().ExportToDB(),
						mr.Member.Id.Entity.ExportToDB(),
						shared.ExportHostP(mr.Member.Id.Host),
						int(srk.Typ),
						int(srk.Lev),
					}
					tag, err := tx.Exec(m.Ctx(), q, args...)
					if err != nil {
						return err
					}

					// TODO -- See Issue #23
					if tag.RowsAffected() < 1 && false {
						return core.UpdateError("failed to update tree_removal_epno on team_members")
					}

				} else {

					q := `UPDATE team_members SET tree_epno=$1
					 WHERE short_host_id=$2 AND team_id=$3 AND member_id=$4
					 AND member_host_id=$5 AND seqno=$6
					 AND src_role_type=$7 AND src_viz_level=$8`

					tag, err := tx.Exec(m.Ctx(), q,
						it.epno,
						m.ShortHostID().ExportToDB(),
						chng.Team.EntityID().ExportToDB(),
						mr.Member.Id.Entity.ExportToDB(),
						shared.ExportHostP(mr.Member.Id.Host),
						int(chng.Seqno),
						int(srk.Typ),
						int(srk.Lev),
					)
					if err != nil {
						return err
					}
					if tag.RowsAffected() != 1 {
						return core.UpdateError("failed to update team_members")
					}
				}
			}
			for _, key := range chng.NewKeys {
				q := `UPDATE shared_keys SET provision_epno=$1
 					 WHERE short_host_id=$2 AND entity_id=$3 AND verify_key=$4`
				tag, err := tx.Exec(m.Ctx(), q,
					it.epno,
					m.ShortHostID().ExportToDB(),
					chng.Team.EntityID().ExportToDB(),
					key.VerifyKey.ExportToDB(),
				)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return core.UpdateError("failed to update shared_keys")
				}
			}
		}
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	return nil
}

func (s *MerkleBatcherServer) checkTreeForUpdates(m shared.MetaContext) error {

	err := s.checkTreeForHostchainUpdates(m)
	if err != nil {
		return err
	}
	err = s.checkTreeForLeafUpdates(m)
	if err != nil {
		return err
	}

	return nil
}

func (s *MerkleBatcherServer) pollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error) {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	set := make(map[core.ShortHostID]bool)

	rows, err := db.Query(m.Ctx(),
		`SELECT DISTINCT(short_host_id) FROM merkle_work_queue WHERE state != $1`,
		string(shared.MerkleWorkStateCommitted),
	)
	if err != nil {
		return nil, err
	}

	scanRows := func(rows pgx.Rows) error {
		defer rows.Close()
		for rows.Next() {
			var i int
			err = rows.Scan(&i)
			if err != nil {
				return err
			}
			shid := core.ShortHostID(i)
			set[shid] = true
		}
		return nil
	}
	err = scanRows(rows)
	if err != nil {
		return nil, err
	}

	cdb, err := m.Db(shared.DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer cdb.Release()

	rows, err = cdb.Query(m.Ctx(),
		`SELECT short_host_id FROM hostchain_links WHERE merkle_state != $1`,
		string(shared.MerkleWorkStateCommitted),
	)
	if err != nil {
		return nil, err
	}
	err = scanRows(rows)
	if err != nil {
		return nil, err
	}

	var tmp []int
	for k := range set {
		tmp = append(tmp, int(k))
	}

	mdb, err := m.Db(shared.DbTypeMerkleTree)
	if err != nil {
		return nil, err
	}
	defer mdb.Release()

	// don't race the creation of a tree! last step is to make sure that there is a root
	// in place for the given tree.
	set = make(map[core.ShortHostID]bool)
	rows, err = mdb.Query(m.Ctx(),
		`SELECT short_host_id FROM merkle_bookkeeping WHERE short_host_id=ANY($1)`,
		tmp,
	)
	if err != nil {
		return nil, err
	}
	err = scanRows(rows)

	var ret []core.ShortHostID
	for k := range set {
		ret = append(ret, k)
	}

	return ret, nil
}

func (s *MerkleBatcherServer) doOnePollForHost(m shared.MetaContext) error {

	err := s.checkTreeForUpdates(m)
	if err != nil {
		m.Errorw("checkTreeForUpdates", "err", err)
		return err
	}
	_, err = s.poll(m)
	if err != nil {
		m.Errorw("poll", "err", err)
		return err
	}
	return nil
}

type MerkleBatcherClientConn struct {
	shared.BaseClientConn
	srv *MerkleBatcherServer
	xp  rpc.Transporter
}

func (c *MerkleBatcherClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(proto.MerkleBatcherProtocol(c))
}

func (c *MerkleBatcherClientConn) Poke(ctx context.Context) error {
	return c.srv.Poke(ctx)
}

func (c *MerkleBatcherClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}
func (s *MerkleBatcherServer) ToRPCServer() shared.RPCServer { return s }

var _ proto.MerkleBatcherInterface = (*MerkleBatcherClientConn)(nil)
var _ shared.ClientConn = (*MerkleBatcherClientConn)(nil)
var _ shared.RPCServer = (*MerkleBatcherServer)(nil)
