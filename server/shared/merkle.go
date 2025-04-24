// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func QueueMerkleWorkForName(
	m MetaContext,
	tx pgx.Tx,
	hostId core.HostID,
	name proto.Name,
	seqno proto.NameSeqno,
	eid proto.EntityID,
	signer proto.EntityID,
) error {
	key, err := merkle.NameToEntityID(name, hostId.Id)
	if err != nil {
		return err
	}
	v := rem.NewEntityIDMerkleValueWithV1(eid)
	h, err := core.PrefixedHash(&v)
	if err != nil {
		return err
	}
	return QueueMerkleWork(m, tx, hostId.Short, key, signer,
		proto.Seqno(seqno), proto.ChainType_Name, nil, *h,
		proto.NewUpdateTriggerDefault(proto.UpdateTriggerType_None),
	)
}

func QueueMerkleWork(
	m MetaContext,
	tx pgx.Tx,
	shortHostID core.ShortHostID,
	id proto.EntityID,
	signer proto.EntityID,
	seqno proto.Seqno,
	ct proto.ChainType,
	loc *proto.TreeLocation,
	val proto.StdHash,
	trig proto.UpdateTrigger,
) error {

	inp := proto.MerkleTreeRFInput{
		Entity:   id,
		Seqno:    seqno,
		Ct:       ct,
		Location: loc,
	}

	var key proto.MerkleTreeRFOutput
	err := merkle.KeyHash(&key, inp)
	if err != nil {
		return err
	}

	var locString string
	if loc != nil {
		locString = core.B62Encode(loc[:])
	}

	m.Infow("QueueMerkleWork", "key", key, "val", val, "id", id, "seqno", seqno, "loc", locString)
	trigEnc, err := core.EncodeToBytes(&trig)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO merkle_work_queue(short_host_id, id, seqno, chain_type,
			    ctime, key, val, state, signer, update_trigger)
		VALUES($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9)`,
		shortHostID.ExportToDB(),
		id.ExportToDB(),
		int(seqno),
		int(ct),
		key.ExportToDB(),
		val.ExportToDB(),
		string(MerkleWorkStateStaged),
		signer.ExportToDB(),
		trigEnc,
	)
	if err != nil {
		m.Errorw("QueueMerkleWork", "err", err)
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("merkle work queu")
	}
	return nil
}

type MerkleWorkState string

const (
	MerkleWorkStateStaged     MerkleWorkState = "staged"
	MerkleWorkStateProcessing MerkleWorkState = "processing"
	MerkleWorkStateCommitted  MerkleWorkState = "committed"
)

func PokeMerklePipeline(
	m MetaContext,
) error {

	type poker interface {
		Poke(ctx context.Context) error
	}

	doOnePoke := func(
		typ proto.ServerType,
		makePoker func(*core.RpcClient) poker,
	) error {
		bec := NewBackendClient(m.G(), typ, proto.ServerType_Tools, nil)
		defer bec.Close()
		gcli, err := bec.Cli(m.Ctx())
		if err != nil {
			return err
		}
		cli := makePoker(gcli)
		err = cli.Poke(m.Ctx())
		if err != nil {
			return err
		}
		return nil
	}

	err := doOnePoke(proto.ServerType_MerkleBatcher, func(cli *core.RpcClient) poker {
		return &proto.MerkleBatcherClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
	if err != nil {
		return err
	}
	err = doOnePoke(proto.ServerType_MerkleBuilder, func(cli *core.RpcClient) poker {
		return &proto.MerkleBuilderClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
	if err != nil {
		return err
	}
	err = doOnePoke(proto.ServerType_MerkleSigner, func(cli *core.RpcClient) poker {
		return &proto.MerkleSignerClient{Cli: cli, ErrorUnwrapper: core.StatusToError}
	})
	if err != nil {
		return err
	}
	return nil

}
