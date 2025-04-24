// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"errors"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type SQLStorage struct {
	g      *GlobalContext
	hostID core.HostID
}

var _ merkle.StorageWriter = (*SQLStorage)(nil)
var _ merkle.MetaContext = MetaContext{}
var _ merkle.StorageReader = (*Reader)(nil)
var _ merkle.StorageTransactor = (*Tx)(nil)
var _ Querier = (*pgxpool.Conn)(nil)
var _ Querier = (pgx.Tx)(nil)

type Tx struct {
	tx     pgx.Tx
	hostID core.HostID
}

func NewSQLStorage(m MetaContext) *SQLStorage {
	return &SQLStorage{g: m.G(), hostID: m.G().HostID()}
}

func UpcastMerkleContext(m merkle.MetaContext) (MetaContext, error) {
	ret, ok := m.(MetaContext)
	if !ok {
		return ret, core.InternalError("merkle.MetaContext is not a shared.MetaContext")
	}
	return ret, nil
}

func (s *SQLStorage) RunRetryTx(
	mMerk merkle.MetaContext,
	which string,
	f func(m merkle.MetaContext, tx merkle.StorageTransactor) error,
) error {
	m, err := UpcastMerkleContext(mMerk)
	if err != nil {
		return err
	}
	db, err := m.Db(DbTypeMerkleTree)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTx(m, db, which, func(m MetaContext, tx pgx.Tx) error {
		return f(m, &Tx{tx: tx, hostID: s.hostID})
	})
}

type Reader struct {
	db     *pgxpool.Conn
	hostID core.HostID
}

func NewReader(m MetaContext, hostID core.HostID) (*Reader, error) {
	db, err := m.Db(DbTypeMerkleTree)
	if err != nil {
		return nil, err
	}
	return &Reader{db: db, hostID: hostID}, nil
}

func (s *SQLStorage) RunRead(
	m merkle.MetaContext,
	which string,
	f func(m merkle.MetaContext, tx merkle.StorageReader) error,
) error {
	db, err := s.g.Db(m.Ctx(), DbTypeMerkleTree)
	if err != nil {
		return err
	}
	defer db.Release()
	return f(m, &Reader{db: db, hostID: s.hostID})
}

func (t *Tx) InsertRoot(
	m merkle.MetaContext,
	epno proto.MerkleEpno,
	time proto.Time,
	rootHash proto.MerkleRootHash,
	body []byte,
	rootNode *merkle.PrefixedHash,
	hct *proto.HostchainTail,
) error {
	tag, err := t.tx.Exec(m.Ctx(),
		`INSERT INTO merkle_roots(short_host_id, epno, ctime, hash, body, root_node)
		 VALUES($1, $2, to_timestamp($3), $4, $5, $6)`,
		m.ShortHostID().ExportToDB(),
		epno,
		float64(time)/float64(1000),
		rootHash.ExportToDB(),
		body,
		rootNode.Hash.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert a merkle root")
	}
	if hct != nil {
		tag, err = t.tx.Exec(m.Ctx(),
			`INSERT INTO merkle_hostchain_tails(short_host_id, seqno, hash)
		     VALUES($1, $2, $3)`,
			m.ShortHostID().ExportToDB(),
			int(hct.Seqno),
			hct.Hash.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert a merkle hostchain tail")
		}
	}
	if epno.IsFirst() {
		tag, err := t.tx.Exec(m.Ctx(),
			`INSERT INTO merkle_tree_metadata(short_host_id, first_node) VALUES($1, $2)`,
			m.ShortHostID().ExportToDB(),
			false,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert merkle metadata")
		}
	} else if rootNode.Typ == proto.MerkleNodeType_Node {
		_, err := t.tx.Exec(m.Ctx(),
			`UPDATE merkle_tree_metadata SET first_node = true WHERE short_host_id = $1`,
			m.ShortHostID().ExportToDB(),
		)
		if err != nil {
			return err
		}
	}

	if epno.IsFirst() {
		tag, err = t.tx.Exec(m.Ctx(),
			`INSERT INTO merkle_bookkeeping(short_host_id, build_next_batchno, batch_next_batchno, pos, mtime)
			 VALUES($1, $2, $2, $3, NOW())`,
			m.ShortHostID().ExportToDB(),
			1,  // the next batch to build and batch on is 2
			-1, // -1 means is the state when we need to write a hostchain update
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.InsertError("failed to insert bookkeeping")
		}
	}

	return nil
}

func (t *Tx) InsertNode(
	m merkle.MetaContext,
	hash *proto.MerkleNodeHash,
	segment merkle.Segment,
	left *merkle.PrefixedHash,
	right *merkle.PrefixedHash,
) error {
	tag, err := t.tx.Exec(m.Ctx(),
		`INSERT INTO merkle_nodes(hash, bit_start, bit_count, key_segment, l, r)
		VALUES($1, $2, $3, $4, $5, $6)`,
		hash.ExportToDB(),
		segment.BitStart,
		segment.BitCount,
		segment.Bytes,
		left.Bytes(),
		right.Bytes(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InternalError("error inserting into merkle_nodes")
	}
	return nil
}

func (t *Tx) InsertLeaf(
	m merkle.MetaContext,
	hash proto.MerkleNodeHash,
	key proto.MerkleTreeRFOutput,
	val proto.StdHash,
	epno proto.MerkleEpno,
) error {
	tags, err := t.tx.Exec(m.Ctx(),
		`INSERT INTO merkle_leaves(hash, k, v, epno) VALUES($1, $2, $3, $4)`,
		hash.ExportToDB(),
		key.ExportToDB(),
		val.ExportToDB(),
		int(epno),
	)
	if pgerr, ok := err.(*pgconn.PgError); ok && pgerr.Code == "23505" && pgerr.ConstraintName == "merkle_leaves_pkey" {
		return core.MerkleLeafExistsError{}
	}
	if err != nil {
		return err
	}
	if tags.RowsAffected() != 1 {
		return core.InsertError("failed to insert leaf")
	}
	return nil
}

func (t *Tx) UpdateBookkeepingForBatcher(m merkle.MetaContext, bn proto.MerkleBatchNo) error {
	tag, err := t.tx.Exec(m.Ctx(),
		`UPDATE merkle_bookkeeping 
		SET batch_next_batchno=$2
		WHERE short_host_id=$1`,
		m.ShortHostID().ExportToDB(),
		int(bn),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		m.Warnw("UpdateBookkeepingForBatcher",
			"rows", tag.RowsAffected(),
			"host",
			m.ShortHostID(),
			"err",
			"wrong number of rows affected",
			"batchno",
			bn,
		)
		return core.InsertError("failed to insert bookkeeping for batcher")
	}
	return err
}

func (t *Tx) UpdateBookkeeping(m merkle.MetaContext, bk merkle.Bookkeeping) error {
	tag, err := t.tx.Exec(m.Ctx(),
		`UPDATE merkle_bookkeeping 
		SET build_next_batchno=$2, pos=$3, mtime=NOW()
		WHERE short_host_id = $1`,
		m.ShortHostID().ExportToDB(),
		int(bk.BatchNo),
		bk.Pos,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert bookkeeping")
	}
	return err
}

func (t *Tx) SelectBookkeeping(m merkle.MetaContext) (*merkle.Bookkeeping, error) {
	return selectBookkeping(m, t.tx)
}

func (r *Reader) SelectBookkeeping(m merkle.MetaContext) (*merkle.Bookkeeping, error) {
	return selectBookkeping(m, r.db)
}

func selectBookkeping(m merkle.MetaContext, q Querier) (*merkle.Bookkeeping, error) {
	var batchno, pos int
	err := q.QueryRow(m.Ctx(),
		`SELECT build_next_batchno, pos FROM merkle_bookkeeping WHERE short_host_id=$1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&batchno, &pos)
	if err != nil && err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &merkle.Bookkeeping{
		BatchNo: proto.MerkleBatchNo(batchno),
		Pos:     pos,
	}, nil
}

func (r *Reader) SelectRootForTraversal(m merkle.MetaContext, signed bool, epno *proto.MerkleEpno) (mr *merkle.Root, err error) {
	return selectRootForTraversal(m, r.db, signed, epno)
}

func (t *Tx) SelectRootForTraversal(m merkle.MetaContext, signed bool, epno *proto.MerkleEpno) (mr *merkle.Root, err error) {
	return selectRootForTraversal(m, t.tx, signed, nil)
}

func selectRootHashes(m merkle.MetaContext, q Querier, seq []proto.MerkleEpno) ([]proto.MerkleRootHash, error) {
	v := make([]int, len(seq))
	for i, s := range seq {
		v[i] = int(s)
	}
	rows, err := q.Query(m.Ctx(),
		`SELECT epno, hash FROM merkle_roots WHERE short_host_id=$1 AND epno = ANY($2)`,
		m.ShortHostID().ExportToDB(),
		v,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rootMap := make(map[proto.MerkleEpno](*proto.MerkleRootHash))
	var epno int
	var hash []byte
	_, err = pgx.ForEachRow(rows, []any{&epno, &hash}, func() error {
		var tmp proto.MerkleRootHash
		if len(hash) != len(tmp) {
			return core.InternalError(fmt.Sprintf("wrong hash size for epno=%d", epno))
		}
		copy(tmp[:], hash)
		rootMap[proto.MerkleEpno(epno)] = &tmp
		return nil
	})
	if err != nil {
		return nil, err
	}
	ret := make([]proto.MerkleRootHash, len(seq))
	for i, ep := range seq {
		tmp, found := rootMap[ep]
		if !found {
			return nil, core.InternalError(fmt.Sprintf("no hash found for epno=%d", ep))
		}
		ret[i] = *tmp
	}

	return ret, nil
}

func selectRoots(m merkle.MetaContext, q Querier, seq []proto.MerkleEpno) ([]proto.MerkleRoot, error) {
	v := make([]int, len(seq))
	for i, s := range seq {
		v[i] = int(s)
	}
	rows, err := q.Query(m.Ctx(),
		`SELECT epno, body FROM merkle_roots WHERE short_host_id=$1 AND epno = ANY($2)`,
		m.ShortHostID().ExportToDB(),
		v,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rootMap := make(map[proto.MerkleEpno](*proto.MerkleRoot))
	var epno int
	var body []byte
	_, err = pgx.ForEachRow(rows, []any{&epno, &body}, func() error {
		var tmp proto.MerkleRoot
		err := core.DecodeFromBytes(&tmp, body)
		if err != nil {
			return err
		}
		rootMap[proto.MerkleEpno(epno)] = &tmp
		return nil
	})
	if err != nil {
		return nil, err
	}
	ret := make([]proto.MerkleRoot, len(seq))
	for i, ep := range seq {
		tmp, found := rootMap[ep]
		if !found {
			return nil, core.InternalError(fmt.Sprintf("no body found for epno=%d", ep))
		}
		ret[i] = *tmp
	}

	return ret, nil
}

func (t *Tx) SelectRoots(m merkle.MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRoot, error) {
	return selectRoots(m, t.tx, seq)
}

func (r *Reader) SelectRoots(m merkle.MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRoot, error) {
	return selectRoots(m, r.db, seq)
}

func (t *Tx) SelectRootHashes(m merkle.MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRootHash, error) {
	return selectRootHashes(m, t.tx, seq)
}

func (r *Reader) SelectRootHashes(m merkle.MetaContext, seq []proto.MerkleEpno) ([]proto.MerkleRootHash, error) {
	return selectRootHashes(m, r.db, seq)
}

func (r *Reader) SelectCurrentRootHash(m merkle.MetaContext) (*proto.TreeRoot, error) {
	return selectCurrentRootHash(m, r.db)
}

func (t *Tx) SelectCurrentRootHash(m merkle.MetaContext) (*proto.TreeRoot, error) {
	return selectCurrentRootHash(m, t.tx)
}

func (r *Reader) SelectCurrentHostchainTail(m merkle.MetaContext) (*proto.HostchainTail, error) {
	return selectCurrentHostchainTail(m, r.db)
}
func (t *Tx) SelectCurrentHostchainTail(m merkle.MetaContext) (*proto.HostchainTail, error) {
	return selectCurrentHostchainTail(m, t.tx)
}

func selectCurrentHostchainTail(m merkle.MetaContext, rq Querier) (*proto.HostchainTail, error) {
	var seqno int
	var hash []byte

	err := rq.QueryRow(m.Ctx(),
		`SELECT seqno, hash 
		 FROM merkle_hostchain_tails
		 WHERE short_host_id = $1
		 ORDER BY seqno DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&seqno, &hash)
	if err != nil && err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ret := proto.HostchainTail{
		Seqno: proto.Seqno(seqno),
	}
	err = ret.Hash.ImportFromBytes(hash)
	if err != nil {
		return nil, err
	}
	return &ret, nil

}

func selectCurrentRootHash(m merkle.MetaContext, rq Querier) (*proto.TreeRoot, error) {
	var hshRaw []byte
	var epnoRaw int

	err := rq.QueryRow(m.Ctx(),
		`SELECT epno, hash FROM merkle_roots WHERE short_host_id=$1 ORDER BY epno DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&epnoRaw, &hshRaw)

	if err == pgx.ErrNoRows {
		return nil, core.MerkleNoRootError{}
	}

	if err != nil {
		return nil, err
	}

	retp, err := proto.ImportMerkleRootHash(hshRaw)
	if err != nil {
		return nil, err
	}

	return &proto.TreeRoot{
		Hash: *retp,
		Epno: proto.MerkleEpno(epnoRaw),
	}, nil
}

func selectRootForTraversal(m merkle.MetaContext, rq Querier, signed bool, findEpno *proto.MerkleEpno) (*merkle.Root, error) {

	var body, node []byte
	var epno int
	var rootIsNode bool

	hid := m.ShortHostID()

	var sig []byte
	queryArgs := []any{int(hid)}
	scanArgs := []any{&epno, &body, &node, &sig, &rootIsNode}

	var q string

	switch {

	case findEpno != nil:
		q = `SELECT epno, body, root_node, sig, first_node
		     FROM merkle_roots
			 JOIN merkle_tree_metadata USING(short_host_id)
			 WHERE short_host_id=$1
			 AND epno=$2`
		queryArgs = append(queryArgs, int(*findEpno))

	case signed:
		q = `SELECT epno, body, root_node, sig, first_node
		     FROM merkle_roots
			 JOIN merkle_last_sig USING(short_host_id, epno)
			 JOIN merkle_tree_metadata USING(short_host_id)
			 WHERE short_host_id=$1`

	default:
		q = `SELECT epno, body, root_node, sig, first_node
		     FROM merkle_roots
			 JOIN merkle_tree_metadata USING(short_host_id)
		     WHERE short_host_id=$1
		     ORDER BY epno DESC LIMIT 1`
	}

	err := rq.QueryRow(m.Ctx(), q, queryArgs...).Scan(scanArgs...)

	if err == pgx.ErrNoRows {
		return nil, core.MerkleNoRootError{}
	}

	if err != nil {
		return nil, err
	}
	var ret merkle.Root

	ret.Epno = proto.MerkleEpno(epno)
	ret.Body = body

	// It would be silly to waste a whole byte for every root (storing if the root node is a
	// leaf or an internal node). So say instead that only for epno=0 or epno=1 is this ever a concern.
	typ := proto.MerkleNodeType_Node
	if !rootIsNode {
		typ = proto.MerkleNodeType_Leaf
	}

	var hsh proto.MerkleNodeHash
	if len(node) != len(hsh) {
		return nil, core.InternalError("need root nodeHash to be 32 bytes")
	}
	copy(hsh[:], node)
	ret.RootNode = &merkle.PrefixedHash{Hash: &hsh, Typ: typ}
	if signed {
		var tmp proto.Signature
		err = core.DecodeFromBytes(&tmp, sig)
		if err != nil {
			return nil, err
		}
		ret.Sig = &tmp
	}

	return &ret, nil
}

func (t *Tx) SelectNode(m merkle.MetaContext, h *merkle.PrefixedHash) (*merkle.Node, error) {
	return selectNode(m, t.tx, h)
}
func (r *Reader) SelectNode(m merkle.MetaContext, h *merkle.PrefixedHash) (*merkle.Node, error) {
	return selectNode(m, r.db, h)
}
func (t *Tx) SelectLeaf(m merkle.MetaContext, h *merkle.PrefixedHash) (*proto.MerkleLeaf, error) {
	return selectLeaf(m, t.tx, h)
}
func (r *Reader) SelectLeaf(m merkle.MetaContext, h *merkle.PrefixedHash) (*proto.MerkleLeaf, error) {
	return selectLeaf(m, r.db, h)
}

func selectNode(m merkle.MetaContext, rq Querier, h *merkle.PrefixedHash) (*merkle.Node, error) {
	var start, count int
	var segment, left, right []byte
	err := rq.QueryRow(m.Ctx(),
		`SELECT bit_start, bit_count, key_segment, l, r FROM merkle_nodes WHERE hash=$1`,
		h.Hash.ExportToDB(),
	).Scan(&start, &count, &segment, &left, &right)
	if err != nil {
		return nil, err
	}
	lph, err := merkle.ImportPrefixedHashFromDB(left)
	if err != nil {
		return nil, err
	}
	rph, err := merkle.ImportPrefixedHashFromDB(right)
	if err != nil {
		return nil, err
	}
	return &merkle.Node{
		Prefix: merkle.Segment{
			Bytes:    segment,
			BitCount: count,
			BitStart: start,
		},
		Left:  lph,
		Right: rph,
	}, nil
}

func selectLeaf(m merkle.MetaContext, rq Querier, h *merkle.PrefixedHash) (*proto.MerkleLeaf, error) {
	var k, v []byte
	err := rq.QueryRow(m.Ctx(),
		`SELECT k,v FROM merkle_leaves WHERE hash=$1`,
		h.Hash.ExportToDB(),
	).Scan(&k, &v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MerkleLeafNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	var ret proto.MerkleLeaf
	if len(k) != len(ret.Key) {
		return nil, core.InternalError("wrong size for merkle leaf key")
	}
	if len(v) != len(ret.Value) {
		return nil, core.InternalError("wrong size for merkle leaf value")
	}
	copy(ret.Key[:], k)
	copy(ret.Value[:], v)
	return &ret, nil
}

func (r *Reader) CheckLeafExists(m merkle.MetaContext, h proto.MerkleTreeRFOutput) (rem.MerkleExistsRes, error) {
	return checkLeafExists(m, r.db, h)
}

func (t *Tx) CheckLeafExists(m merkle.MetaContext, h proto.MerkleTreeRFOutput) (rem.MerkleExistsRes, error) {
	return checkLeafExists(m, t.tx, h)
}

func checkLeafExists(
	m merkle.MetaContext,
	rq Querier,
	h proto.MerkleTreeRFOutput,
) (
	rem.MerkleExistsRes,
	error,
) {
	var res rem.MerkleExistsRes
	var epno, signedEpno int
	err := rq.QueryRow(m.Ctx(),
		`SELECT epno FROM merkle_leaves WHERE k=$1`,
		h.ExportToDB(),
	).Scan(&epno)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, core.MerkleLeafNotFoundError{}
	}
	if err != nil {
		return res, err
	}
	res.Epno = proto.MerkleEpno(epno)
	err = rq.QueryRow(m.Ctx(),
		`SELECT epno FROM merkle_last_sig WHERE short_host_id=$1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&signedEpno)
	if err == nil && signedEpno >= epno {
		res.Signed = true
	}
	return res, nil
}

func confirmRoot(
	m merkle.MetaContext,
	rq Querier,
	root proto.TreeRoot,
) error {
	var one int
	err := rq.QueryRow(m.Ctx(),
		`SELECT 1 FROM merkle_roots WHERE short_host_id=$1 AND epno=$2 AND hash=$3`,
		m.ShortHostID().ExportToDB(),
		int(root.Epno),
		root.Hash.ExportToDB(),
	).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.MerkleNoRootError{}
	}
	if err != nil {
		return err
	}
	if one != 1 {
		return core.MerkleNoRootError{}
	}
	return nil
}

func (t *Tx) ConfirmRoot(
	m merkle.MetaContext,
	root proto.TreeRoot,
) error {
	return confirmRoot(m, t.tx, root)
}

func (r *Reader) ConfirmRoot(
	m merkle.MetaContext,
	root proto.TreeRoot,
) error {
	return confirmRoot(m, r.db, root)
}
