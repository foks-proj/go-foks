// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package sql

import (
	_ "embed"
)

//go:embed foks_users.sql
var foksUsers string

//go:embed foks_merkle_tree.sql
var foksMerkleTree string

//go:embed foks_merkle_raft.sql
var foksMerkleRaft string

//go:embed foks_server_config.sql
var foksServerConfig string

//go:embed foks_beacon.sql
var foksBeacon string

//go:embed foks_kv_store.sql
var foksKVStore string

var SQL = map[string]string{
	"foks_users":         foksUsers,
	"foks_merkle_tree":   foksMerkleTree,
	"foks_merkle_raft":   foksMerkleRaft,
	"foks_server_config": foksServerConfig,
	"foks_beacon":        foksBeacon,
	"foks_kv_store":      foksKVStore,
}

//go:embed patches/foks_users/p1.sql
var foksUsersPatch1 string

var Patches = map[string]map[int]string{
	"foks_users": {
		1: foksUsersPatch1,
	},
}
