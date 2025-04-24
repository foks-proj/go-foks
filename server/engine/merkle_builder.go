// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"errors"
	"flag"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
)

type MerkleBuilderServer struct {
	MerklePipelineBaseServer
}

func NewMerkleBuilderServer() *MerkleBuilderServer {
	ret := &MerkleBuilderServer{}
	ret.sub = ret
	ret.serverType = proto.ServerType_MerkleBuilder
	return ret
}

func (b *MerkleBuilderServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (b *MerkleBuilderServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &MerkleBuilderClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

type MerkleBuilderClientConn struct {
	shared.BaseClientConn
	srv *MerkleBuilderServer
	xp  rpc.Transporter
}

func (b *MerkleBuilderServer) Setup(m shared.MetaContext) error {
	err := b.MerklePipelineBaseServer.Setup(m)
	if err != nil {
		return err
	}
	return nil
}

func (c *MerkleBuilderClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(proto.MerkleBuilderProtocol(c))
}

func (c *MerkleBuilderClientConn) Poke(ctx context.Context) error {
	return c.srv.Poke(ctx)
}

func (c *MerkleBuilderClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (s *MerkleBuilderServer) initBackgroundLoop(m shared.MetaContext) error {
	return nil
}

func (s *MerkleBuilderServer) readBatch(
	m shared.MetaContext,
	batchNo proto.MerkleBatchNo,
) (
	*proto.MerkleBatch,
	error,
) {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeMerkleRaft)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var val []byte
	err = db.QueryRow(
		m.Ctx(),
		`SELECT v FROM raft_kv_store WHERE short_host_id=$1 AND k = $2`,
		m.ShortHostID().ExportToDB(),
		BatchKey(batchNo),
	).Scan(&val)
	if err != nil && err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ret proto.MerkleBatch
	err = core.DecodeFromBytes(&ret, val)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

var errNoWork = errors.New("no work")

func (s *MerkleBuilderServer) doOnePollForHost(m shared.MetaContext) error {

	for {
		err := s.doOneLeaf(m)
		if err == errNoWork {
			return nil
		}
		if err != nil {
			m.Errorw("doOneLeaf", "err", err)
			return err
		}
	}
}

func scanShortHostIDs(rows pgx.Rows) ([]core.ShortHostID, error) {
	var ret []core.ShortHostID
	for rows.Next() {
		var i int
		err := rows.Scan(&i)
		if err != nil {
			return nil, err
		}
		ret = append(ret, core.ShortHostID(i))
	}
	return ret, nil
}

func (s *MerkleBuilderServer) pollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error) {

	db, err := m.Db(shared.DbTypeMerkleTree)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT short_host_id FROM merkle_bookkeeping WHERE build_next_batchno < batch_next_batchno`,
	)
	if err != nil {
		return nil, err
	}
	ret, err := scanShortHostIDs(rows)
	m.Infow("pollReadyHosts", "shortHostID", m.ShortHostID(), "ret", ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *MerkleBuilderServer) doOneLeaf(m shared.MetaContext) error {

	// Note we need that bookkeeping is already initialized before we get going.
	// Therefore, look for it to be initialized in merkle.InitTree, which calls
	// StorageWriter.InsertRoot(epno = 0). This is important since this thread
	// and the one in merkle_batcher will be updating this same table.
	nxt, err := s.eng.SelectBookkeeping(m)
	if err != nil {
		return err
	}
	if nxt == nil {
		return core.InternalError("next is nil")
	}
	batch, err := s.readBatch(m, nxt.BatchNo)
	if err != nil {
		return err
	}

	if batch == nil {
		return errNoWork
	}

	if nxt.Pos == -1 && len(batch.Leaves) == 0 && batch.Hostchain != nil {
		nxt.Pos = 0
		m.Infow("doOneLeaf", "shortHostID", m.ShortHostID(), "batchNo", nxt.BatchNo, "stage", "store hostchain")
		err = s.eng.StoreRoot(m, batch.Time, *batch.Hostchain, *nxt)
		if err != nil {
			return err
		}
	}

	if nxt.Pos >= len(batch.Leaves) {
		nxt = nxt.Advance()
		err = s.eng.UpdateBookkeeping(m, *nxt)
		if err != nil {
			return err
		}
		m.Infow("doOneLeaf", "shortHostID", m.ShortHostID(), "batchNo", nxt.BatchNo, "stage", "no more leaves")
		return nil
	}

	var hct *proto.HostchainTail
	if nxt.Pos == -1 {
		hct = batch.Hostchain
		nxt.Pos++
	}
	leaf := batch.Leaves[nxt.Pos]
	nxt.Pos++
	arg := merkle.InsertKeyValueArg{
		Key:  leaf.Key,
		Val:  leaf.Value,
		Time: batch.Time,
		Bk:   nxt,
		Hct:  hct,
	}

	m.Infow("doOneLeaf", "shortHostID", m.ShortHostID(), "batchNo", nxt.BatchNo, "stage", "insert key-value")

	// NB: this updates Bookkeeping in the same transaction as the insertion of the
	// Key-Value (see Bk : nxt above).
	err = s.eng.InsertKeyValue(m, arg)
	if err != nil {
		return err
	}
	return nil
}

func (s *MerkleBuilderServer) ToRPCServer() shared.RPCServer { return s }

var _ proto.MerkleBuilderInterface = (*MerkleBuilderClientConn)(nil)
var _ shared.ClientConn = (*MerkleBuilderClientConn)(nil)
var _ shared.RPCServer = (*MerkleBuilderServer)(nil)
