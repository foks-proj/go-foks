// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

func lockCheckPerms(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	lock rem.KVLock,
) error {
	dir, err := loadDir(m, tx, pid, lock.Idp.ParentDirID, proto.KVVersion(0))
	if err != nil {
		return err
	}
	bad, err := role.LessThan(dir.WriteRole)
	if err != nil {
		return err
	}
	if bad {
		return core.KVPermssionError{}
	}
	return nil
}

func lockAttemptTimeout(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	lock rem.KVLock,
	timeout time.Duration,
) error {
	var ctime time.Time
	var lockIDRaw []byte
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT ctime, lock_id FROM locks
		WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3 AND dirent_id=$4`,
		int(m.ShortHostID()),
		pid.Shorten().ExportToDB(),
		lock.Idp.ParentDirID.ExportToDB(),
		lock.Idp.DirentID.ExportToDB(),
	).Scan(&ctime, &lockIDRaw)
	if err != nil && err == pgx.ErrNoRows {
		return core.NotFoundError("lock")
	}
	if err != nil {
		return err
	}
	var lockID rem.LockID
	err = lockID.ImportFromDB(lockIDRaw)
	if err != nil {
		return err
	}
	if time.Since(ctime) < timeout {
		return core.KVLockAlreadyHeldError{}
	}
	tag, err := tx.Exec(
		m.Ctx(),
		`DELETE FROM locks 
		WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3 AND dirent_id=$4 AND lock_id=$5`,
		int(m.ShortHostID()),
		pid.Shorten().ExportToDB(),
		lock.Idp.ParentDirID.ExportToDB(),
		lock.Idp.DirentID.ExportToDB(),
		lockID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("locks delete")
	}
	return nil
}

func lockAcquire(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	lock rem.KVLock,
	timeout time.Duration,
) error {
	err := lockCheckPerms(m, tx, pid, role, lock)
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO locks (short_host_id, short_party_id, dir_id, dirent_id, lock_id, ctime)
 		    VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (short_host_id, short_party_id, dir_id, dirent_id) DO NOTHING`,
			int(m.ShortHostID()),
			pid.Shorten().ExportToDB(),
			lock.Idp.ParentDirID.ExportToDB(),
			lock.Idp.DirentID.ExportToDB(),
			lock.LockID.ExportToDB(),
		)
		switch {
		case err == nil && tag.RowsAffected() == 1:
			return nil
		case err == nil && tag.RowsAffected() == 0:
			if i == 0 {
				err := lockAttemptTimeout(m, tx, pid, lock, timeout)
				if err != nil {
					return err
				}
			} else {
				return core.KVLockAlreadyHeldError{}
			}
		default:
			return err
		}
	}
	return core.InternalError("unreachable")
}

func lockRelease(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	lock rem.KVLock,
) error {
	err := lockCheckPerms(m, tx, pid, role, lock)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(
		m.Ctx(),
		`DELETE FROM locks
		WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3 AND dirent_id=$4 AND lock_id=$5`,
		int(m.ShortHostID()),
		pid.Shorten().ExportToDB(),
		lock.Idp.ParentDirID.ExportToDB(),
		lock.Idp.DirentID.ExportToDB(),
		lock.LockID.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		// We conclude the delete didn't work because the lock was timed out by another thread.
		return core.KVLockTimeoutError{}
	}
	return nil
}
