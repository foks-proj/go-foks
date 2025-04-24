// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

func OpenAndStoreCommitment(
	ctx context.Context,
	tx pgx.Tx,
	o core.Verifiable,
	key *proto.RandomCommitmentKey,
	c *proto.Commitment,
	hid core.ShortHostID,
	aux core.Codecable,
) error {
	err := core.OpenCommitment(o, key, c)
	if err != nil {
		return err
	}
	b, err := core.EncodeToBytes(o)
	if err != nil {
		return err
	}
	var auxb []byte
	if aux != nil {
		auxb, err = core.EncodeToBytes(aux)
		if err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO commitments(short_host_id, id, random_key, data, normalization_preimage)
		VALUES($1, $2, $3, $4, $5)`,
		int(hid),
		c.ExportToDB(),
		key.ExportToDB(),
		b,
		auxb,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("commitments")
	}
	return nil
}

func LoadCommitment(
	ctx context.Context,
	q Querier,
	hid core.ShortHostID,
	c proto.Commitment,
	o core.Codecable,
	aux core.Codecable,
) (proto.RandomCommitmentKey, error) {
	var rk, dat, auxb []byte
	var ret proto.RandomCommitmentKey
	err := q.QueryRow(ctx,
		`SELECT random_key, data, normalization_preimage FROM commitments WHERE short_host_id=$1 AND id=$2`,
		int(hid),
		c.ExportToDB(),
	).Scan(&rk, &dat, &auxb)
	if err == pgx.ErrNoRows {
		return ret, core.CommitmentError("not found")
	}
	if err != nil {
		return ret, err
	}
	err = core.DecodeFromBytes(o, dat)
	if err != nil {
		return ret, err
	}
	err = ret.ImportFromBytes(rk)
	if err != nil {
		return ret, err
	}
	if aux != nil && len(auxb) > 0 {
		err = core.DecodeFromBytes(aux, auxb)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}
