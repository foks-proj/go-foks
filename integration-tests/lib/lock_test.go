// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestLockSimple(t *testing.T) {
	m := testMetaContext()
	hostID := m.G().HostChain().HostID().Short
	lock, err := shared.NewLock(hostID, proto.ServerType_Test)
	require.NoError(t, err)
	require.NotNil(t, lock)

	err = lock.Acquire(m, time.Hour)
	require.NoError(t, err)

	lock2, err := shared.NewLock(hostID, proto.ServerType_Test)
	require.NoError(t, err)
	require.NotNil(t, lock2)
	err = lock2.Acquire(m, time.Hour)
	require.Error(t, err)
	require.IsType(t, core.LockedError{}, err)

	advanceClock := func(id []byte) {
		db, err := m.G().Db(m.Ctx(), shared.DbTypeServerConfig)
		require.NoError(t, err)
		defer db.Release()
		tag, err := db.Exec(m.Ctx(), "UPDATE locks SET hbtime = hbtime - interval '24 hours' WHERE lock_id=$1", id)
		require.NoError(t, err)
		require.Equal(t, int64(1), tag.RowsAffected())
	}

	advanceClock(lock.ID())
	err = lock2.Acquire(m, time.Hour)
	require.NoError(t, err)

	advanceClock(lock2.ID())
	err = lock2.Heartbeat(m)
	require.NoError(t, err)

	lock3, err := shared.NewLock(hostID, proto.ServerType_Test)
	require.NoError(t, err)
	require.NotNil(t, lock3)
	err = lock3.Acquire(m, time.Hour)
	require.Error(t, err)
	require.IsType(t, core.LockedError{}, err)

	err = lock2.Release(m)
	require.NoError(t, err)
}
