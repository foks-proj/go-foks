// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Lock struct {
	sync.Mutex
	heartbeatFailed bool
	hostID          core.ShortHostID
	id              []byte
	pid             int
	typ             proto.ServerType
}

func NewLock(h core.ShortHostID, typ proto.ServerType) (*Lock, error) {
	id := make([]byte, 16)
	err := core.RandomFill(id)
	if err != nil {
		return nil, err
	}
	return &Lock{
		hostID: h,
		typ:    typ,
		id:     id,
		pid:    os.Getpid(),
	}, nil
}

func (l *Lock) ID() []byte {
	l.Mutex.Lock()
	defer l.Mutex.Unlock()
	return l.id
}

var errLockNotFound = errors.New("lock not found")

func (l *Lock) Acquire(m MetaContext, timeout time.Duration) error {
	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	err = l.read(m, db, timeout)
	if err == nil {
		m.Infow("Lock.Acquire", "lock_id", l.id, "pid", l.pid, "host_id", l.hostID, "success", "already held", "hostID", m.ShortHostID())
		return nil
	}

	if err == errLockNotFound {
		m.Infow("Lock.Acquire", "lock_id", l.id, "pid", l.pid, "host_id", l.hostID, "success", "acquired", "hostID", m.ShortHostID())
		return l.insert(m, db)
	}

	loerr, lockedOut := err.(core.LockedError)
	if !lockedOut {
		m.Warnw("Lock.Acquire", "lock_id", l.id, "pid", l.pid, "host_id", l.hostID, "err", err, "hostID", m.ShortHostID())
		return err
	}
	if loerr.Age > timeout {
		m.Infow("Lock.Acquire", "lock_id", l.id, "pid", l.pid, "host_id", l.hostID, "success", "stolen", "hostID", m.ShortHostID())
		return l.steal(m, db, loerr.Pid, loerr.Id)
	}

	m.Warnw(
		"Lock.Acquire",
		"err", err,
		"age", loerr.Age,
		"pid", loerr.Pid,
		"lock_id", loerr.Id,
		"hostID", m.ShortHostID(),
	)
	return err
}

func (l *Lock) read(m MetaContext, db *pgxpool.Conn, timeout time.Duration) error {
	var age int
	var pid int
	var lockID []byte

	err := db.QueryRow(m.Ctx(),
		`SELECT 
        	EXTRACT(EPOCH FROM (NOW() - hbtime))::int,
		   pid, lock_id
		 FROM locks
		 WHERE short_host_id=$1
		 AND server_type=$2`,
		int(l.hostID),
		int(l.typ),
	).Scan(&age, &pid, &lockID)

	if err == pgx.ErrNoRows {
		return errLockNotFound
	}

	if err != nil {
		return err
	}

	if pid == l.pid && bytes.Equal(lockID, l.id) {
		return nil
	}

	ageDur := Seconds(age).Duration()
	return core.LockedError{
		Age: ageDur,
		Pid: pid,
		Id:  lockID,
	}
}

func (l *Lock) insert(m MetaContext, db *pgxpool.Conn) error {

	// No lock, insert one
	tag, err := db.Exec(m.Ctx(),
		`INSERT INTO locks (short_host_id, server_type, hbtime, pid, lock_id)
			 VALUES ($1, $2, NOW(), $3, $4)`,
		int(l.hostID),
		int(l.typ),
		l.pid,
		l.id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("merkle_chunker_runlock")
	}
	return err
}

func (l *Lock) steal(m MetaContext, db *pgxpool.Conn, existingPid int, existingId []byte) (err error) {

	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = TxRollback(m.Ctx(), tx, err)
	}()

	tag, err := tx.Exec(m.Ctx(),
		`UPDATE locks
		SET hbtime=NOW(), lock_id=$1, pid=$2
		WHERE short_host_id=$3 AND server_type=$4 AND pid=$5 AND lock_id=$6`,
		l.id,
		l.pid,
		int(l.hostID),
		int(l.typ),
		existingPid,
		existingId,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("merkle_chunker_runlock")
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}
	return nil
}

func (l *Lock) Release(m MetaContext) error {
	if l.getHeartbeatFailure() {
		return errors.New("cannot release lock after heartbeat failure")
	}

	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	tag, err := db.Exec(m.Ctx(),
		`DELETE FROM locks WHERE short_host_id=$1 AND server_type=$2 AND pid=$3 AND lock_id=$4`,
		int(l.hostID),
		int(l.typ),
		os.Getpid(),
		l.id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("merkle_chunker_runlock DELETE")
	}
	return nil
}

func (l *Lock) getHeartbeatFailure() bool {
	l.Lock()
	defer l.Unlock()
	return l.heartbeatFailed
}

func (l *Lock) setHeartbeatFailure() {
	l.Lock()
	defer l.Unlock()
	l.heartbeatFailed = true
}

func (l *Lock) Heartbeat(m MetaContext) error {
	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	tag, err := db.Exec(m.Ctx(),
		`UPDATE locks SET hbtime=NOW() WHERE short_host_id=$1 AND server_type=$2 AND pid=$3 AND lock_id=$4`,
		int(l.hostID),
		int(l.typ),
		os.Getpid(),
		l.id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		l.setHeartbeatFailure()
		return core.UpdateError("merkle_chunker_runlock heartbeat")
	}
	return nil
}
