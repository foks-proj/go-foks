// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func usageInc(
	m shared.MetaContext,
	tx pgx.Tx,
	pid *proto.PartyID, // If no partyID specified then add to the vhost_table
	typ proto.KVNodeType,
	sz int,
	first bool,
) error {
	var isSmall bool
	switch typ {
	case proto.KVNodeType_SmallFile, proto.KVNodeType_Symlink:
		isSmall = true
	case proto.KVNodeType_File:
	default:
		return core.InternalError("usageInc: invalid type")
	}

	args := []any{
		m.ShortHostID().ExportToDB(),
	}

	numSmallInc := core.Sel(isSmall, 1, 0)
	numLargeInc := core.Sel(!isSmall && first, 1, 0)
	numLargeChunkInc := core.Sel(isSmall, 0, 1)
	sumSmallInc := core.Sel(isSmall, int64(sz), 0)
	sumLargeInc := core.Sel(!isSmall, int64(sz), 0)

	var q string

	if pid != nil {
		q = `INSERT INTO usage(
			short_host_id,
			party_id,
			num_small,
			num_large,
			num_large_chunks,
			sum_small,
			sum_large
		) VALUES($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT(short_host_id, party_id) 
		  DO UPDATE SET num_small = usage.num_small + $3,
				    num_large = usage.num_large + $4,
					num_large_chunks = usage.num_large_chunks + $5,
					sum_small = usage.sum_small + $6,
					sum_large = usage.sum_large + $7`
		args = append(args, pid.ExportToDB())
	} else {
		q = `INSERT INTO usage_vhost(
			short_host_id,
			num_small,
			num_large,
			num_large_chunks,
			sum_small,
			sum_large
		) VALUES($1, $2, $3, $4, $5, $6)
		 ON CONFLICT(short_host_id) 
		  DO UPDATE SET num_small = usage_vhost.num_small + $2,
				    num_large = usage_vhost.num_large + $3,
					num_large_chunks = usage_vhost.num_large_chunks + $4,
					sum_small = usage_vhost.sum_small + $5,
					sum_large = usage_vhost.sum_large + $6`
	}
	args = append(args,
		numSmallInc,
		numLargeInc,
		numLargeChunkInc,
		sumSmallInc,
		sumLargeInc,
	)

	_, err := tx.Exec(m.Ctx(), q, args...)

	if err != nil {
		return err
	}
	return nil
}

func pokeQuotaChecker(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
) error {
	_, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO quota_check(
			short_host_id,
			party_id,
			num_new_writes,
			check_time,
			in_quota)
		VALUES($1, $2, 1, NOW(), true)
		ON CONFLICT(short_host_id, party_id)
 		DO UPDATE SET num_new_writes = quota_check.num_new_writes + 1`,
		int(m.ShortHostID()),
		pid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	return nil
}

func pokeQuotaCheckerVhost(
	m shared.MetaContext,
	tx pgx.Tx,
) error {
	_, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO quota_check_vhost(
			short_host_id,
			num_new_writes,
			check_time,
			in_quota)
		VALUES($1, 1, NOW(), true)
		ON CONFLICT(short_host_id)
 		DO UPDATE SET num_new_writes = quota_check_vhost.num_new_writes + 1`,
		int(m.ShortHostID()),
	)
	if err != nil {
		return err
	}
	return nil
}

func quotaCheck(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
) error {
	var inQuota bool
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT in_quota
		 FROM quota_check
		 WHERE short_host_id = $1 AND party_id = $2`,
		int(m.ShortHostID()),
		pid.ExportToDB(),
	).Scan(&inQuota)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !inQuota {
		return core.OverQuotaError{}
	}
	return nil
}

func quotaCheckVHost(
	m shared.MetaContext,
	tx pgx.Tx,
) error {
	var inQuota bool
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT in_quota
		 FROM quota_check_vhost
		 WHERE short_host_id = $1`,
		int(m.ShortHostID()),
	).Scan(&inQuota)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !inQuota {
		return core.OverQuotaError{}
	}
	return nil
}

func quotaScope(
	m shared.MetaContext,
	tx pgx.Tx,
) (
	infra.QuotaScope,
	error,
) {
	config, err := m.G().HostIDMap().Config(m, m.ShortHostID())
	if err != nil {
		return infra.QuotaScope_None, err
	}
	if config.Metering.PerVHostDisk {
		return infra.QuotaScope_VHost, nil
	}
	return infra.QuotaScope_Teams, nil
}

func usageCheckAndInc(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	typ proto.KVNodeType,
	sz int,
	first bool,
) error {
	scope, err := quotaScope(m, tx)
	if err != nil {
		return err
	}
	switch scope {
	case infra.QuotaScope_Teams:
		return usageCheckAndIncTeams(m, tx, pid, typ, sz, first)
	case infra.QuotaScope_VHost:
		return usageCheckAndIncVHost(m, tx, typ, sz, first)
	}
	return core.InternalError("usageCheckAndInc: no scope")
}

func usageCheckAndIncVHost(
	m shared.MetaContext,
	tx pgx.Tx,
	typ proto.KVNodeType,
	sz int,
	first bool,
) error {
	err := quotaCheckVHost(m, tx)
	if err != nil {
		return err
	}
	err = usageInc(m, tx, nil, typ, sz, first)
	if err != nil {
		return err
	}
	err = pokeQuotaCheckerVhost(m, tx)
	if err != nil {
		return err
	}
	return nil
}

func usageCheckAndIncTeams(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	typ proto.KVNodeType,
	sz int,
	first bool,
) error {
	err := quotaCheck(m, tx, pid)
	if err != nil {
		return err
	}
	err = usageInc(m, tx, &pid, typ, sz, first)
	if err != nil {
		return err
	}
	err = usageInc(m, tx, nil, typ, sz, first)
	if err != nil {
		return err
	}
	err = pokeQuotaChecker(m, tx, pid)
	if err != nil {
		return err
	}
	return nil
}

func getUsage(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
) (
	*proto.KVUsage,
	error,
) {
	var numSmall, numLarge, numLargeChunks int
	var sumSmall, sumLarge int64
	err := db.QueryRow(
		m.Ctx(),
		`SELECT num_small, num_large, num_large_chunks,
		     sum_small, sum_large
		 FROM usage
		 WHERE short_host_id = $1 AND party_id = $2`,
		int(m.ShortHostID()),
		pid.ExportToDB(),
	).Scan(&numSmall, &numLarge, &numLargeChunks, &sumSmall, &sumLarge)
	if err == pgx.ErrNoRows {
		return &proto.KVUsage{}, nil
	}
	if err != nil {
		return nil, err
	}
	return &proto.KVUsage{
		Small: proto.KVUsageStats{
			Num: uint64(numSmall),
			Sum: proto.Size(sumSmall),
		},
		Large: proto.KVUsageStatsChunked{
			Base: proto.KVUsageStats{
				Num: uint64(numLarge),
				Sum: proto.Size(sumLarge),
			},
			NumChunks: uint64(numLargeChunks),
		},
	}, nil
}
