// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

type BlobSQLStorage struct {
}

func NewBlobSQLStorage(m shared.MetaContext) (*BlobSQLStorage, error) {
	return &BlobSQLStorage{}, nil
}

func (b *BlobSQLStorage) Get(
	m shared.MetaContext,
	rq shared.Querier,
	pid proto.PartyID,
	id proto.FileID,
	offset proto.Offset,
) (
	*rem.GetEncryptedChunkRes,
	error,
) {
	var dbOff int
	var dat []byte
	var final bool
	err := rq.QueryRow(
		m.Ctx(),
		`SELECT chunk_offset, data, final
		 FROM large_file_chunk
		 WHERE short_host_id=$1 AND short_party_id=$2 AND file_id=$3 AND chunk_offset <= $4
		 ORDER BY chunk_offset DESC LIMIT 1`,
		int(m.HostID().Short),
		pid.Shorten().ExportToDB(),
		id.ExportToDB(),
		int(offset),
	).Scan(&dbOff, &dat, &final)
	if err != nil && err == pgx.ErrNoRows {
		return nil, core.NotFoundError("large_file_blob")
	}
	if err != nil {
		return nil, err
	}
	ret := rem.GetEncryptedChunkRes{
		Chunk:  dat,
		Final:  final,
		Offset: proto.Offset(dbOff),
	}
	return &ret, nil
}

func (b *BlobSQLStorage) Strategy() LargeStorageStrategy {
	return LargeStorageStrategySQL
}

func (b *BlobSQLStorage) Finalize(m shared.MetaContext, tx pgx.Tx, fid proto.FileID) error {
	// No-op for SQL blob storage
	return nil
}

var _ LargeFileStorageEngine = (*BlobSQLStorage)(nil)
