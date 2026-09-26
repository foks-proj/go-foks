// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// TestPersistTeamNameLookupsNoPoisonOnWriteFailure pins the regression the
// review fix addressed: the in-memory memo (persistedNames) must record a name
// as persisted only AFTER the DB write lands, never before. Recording it first
// makes one transient write failure permanent -- every later call skips
// exactly the rows that never reached disk, and cold-start offline name
// resolution quietly stops working for them.
//
// A working soft DB is opened and then its handle is closed, so the write
// fails the way a transient DB fault would. The memo must stay empty.
func TestPersistTeamNameLookupsNoPoisonOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	g := NewGlobalContext()
	g.Cfg().TestSetHomeCLIFlag(t.TempDir())
	g.Cfg().TestSetLogTargets("stdout", "stderr")
	g.Cfg().TestSetTestingMode()
	require.NoError(t, g.Configure(ctx))

	// Open the soft DB, then close its handle so every later write fails.
	db, err := g.Db(ctx, DbTypeSoft)
	require.NoError(t, err)
	require.NoError(t, db.db.Close())

	au := &UserContext{Info: proto.UserInfo{Fqu: proto.FQUser{}}}
	tm := NewTeamMinder(au)
	m := NewMetaContextTODO(g)

	// Precondition: a soft-DB write genuinely fails now.
	err = m.DbPutTx(DbTypeSoft, []PutArg{{
		Typ: lcl.DataType_TeamNameLookup,
		Key: "probe",
		Val: &proto.FQTeam{},
	}})
	require.Error(t, err, "precondition: the soft DB write must fail")

	names := map[proto.FQTeamString]proto.FQTeam{
		proto.FQTeamString("someteam@somehost"): {},
	}
	tm.persistTeamNameLookups(m, names)

	require.Empty(t, tm.persistedNames,
		"a failed write must not mark names as persisted")
}
