// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestHostIdMapFilter(t *testing.T) {
	env := globalTestEnv.Fork(t, common.SetupOpts{})
	defer func() {
		_ = env.ShutdownFn()
	}()
	m := env.MetaContext()

	mainId := m.G().ShortHostID()
	start := time.Now().Add(time.Hour * 100)

	db, err := m.Db(shared.DbTypeServerConfig)
	require.NoError(t, err)
	defer db.Release()

	ins := func(parent core.ShortHostID, vhost core.ShortHostID, tm time.Time) {
		vhid, err := proto.RandomID16er[proto.VHostID]()
		require.NoError(t, err)
		var hid proto.HostID
		err = core.RandomFill(hid[:])
		require.NoError(t, err)
		tag, err := db.Exec(m.Ctx(),
			`INSERT INTO hosts(short_host_id, host_id, vhost_id, 
			   root_short_host_id, 
			   parent_short_host_id, ctime)
			 VALUES($1, $2, $3, $4, $5, $6)`,
			vhost.ExportToDB(),
			hid.ExportToDB(),
			vhid.ExportToDB(),
			parent.ExportToDB(),
			parent.ExportToDB(),
			tm,
		)
		require.NoError(t, err)
		require.Equal(t, int64(1), tag.RowsAffected())
	}

	hidm := m.G().HostIDMap()

	ins(mainId, 100, start)
	ins(mainId, 101, start.Add(time.Second))
	other := core.ShortHostID(4000)
	ins(other, 200, start.Add(time.Second))

	res, err := hidm.Filter(m, []core.ShortHostID{mainId, 100, 101, 200})
	require.NoError(t, err)
	require.Equal(t, []core.ShortHostID{mainId, 100, 101}, res)

	now := start.Add(time.Hour)

	ins(mainId, 105, now.Add(time.Second*2))
	ins(other, 204, now.Add(time.Second))
	res, err = hidm.Filter(m, []core.ShortHostID{mainId, 100, 101, 105, 200, 204})
	require.NoError(t, err)
	require.Equal(t, []core.ShortHostID{mainId, 100, 101, 105}, res)

	now = now.Add(time.Hour)

	ins(mainId, 110, now)
	res, err = hidm.Filter(m, []core.ShortHostID{mainId, 100, 101, 105, 200, 204, 110, 4000})
	require.NoError(t, err)
	require.Equal(t, []core.ShortHostID{mainId, 100, 101, 105, 110}, res)

	res, err = hidm.Filter(m, []core.ShortHostID{mainId, 100, 105, 204, 4000})
	require.NoError(t, err)
	require.Equal(t, []core.ShortHostID{mainId, 100, 105}, res)
}
