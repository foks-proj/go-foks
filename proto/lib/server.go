// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"strings"
)

func (t ServerType) Hostname(base Hostname) (Hostname, error) {
	var pfx string
	var err error

	switch t {
	case ServerType_Reg:
		pfx = "reg"
	case ServerType_User:
		pfx = "user"
	case ServerType_MerkleQuery:
		pfx = "mq"
	case ServerType_KVStore:
		pfx = "kv"
	case ServerType_Probe:
	case ServerType_Web:
		pfx = "web"
	default:
		err = DataError("not a front-facing server")
	}

	if err != nil {
		return "", err
	}
	if len(pfx) > 0 {
		return Hostname(fmt.Sprintf("%s.%s", pfx, base)), nil
	}
	return base, nil
}

func (t ServerType) ToString() string {
	switch t {
	case ServerType_Reg:
		return "reg"
	case ServerType_User:
		return "user"
	case ServerType_MerkleBuilder:
		return "merkle_builder"
	case ServerType_MerkleBatcher:
		return "merkle_batcher"
	case ServerType_InternalCA:
		return "internal_ca"
	case ServerType_MerkleQuery:
		return "merkle_query"
	case ServerType_MerkleSigner:
		return "merkle_signer"
	case ServerType_Queue:
		return "queue"
	case ServerType_Probe:
		return "probe"
	case ServerType_Beacon:
		return "beacon"
	case ServerType_KVStore:
		return "kv_store"
	case ServerType_Quota:
		return "quota"
	case ServerType_Web:
		return "web"
	case ServerType_Autocert:
		return "autocert"
	default:
		return "none"
	}
}

func (t ServerType) ToCommand() string {
	ret := t.ToString()
	return strings.Replace(ret, "_", "-", -1)
}

func (t *ServerType) ImportFromString(s string) error {
	switch s {
	case "reg":
		*t = ServerType_Reg
	case "user":
		*t = ServerType_User
	case "merkle-builder":
		*t = ServerType_MerkleBuilder
	case "merkle-batcher":
		*t = ServerType_MerkleBatcher
	case "internal-ca":
		*t = ServerType_InternalCA
	case "merkle-signer":
		*t = ServerType_MerkleSigner
	case "queue":
		*t = ServerType_Queue
	case "web":
		*t = ServerType_Web
	case "beacon":
		*t = ServerType_Beacon
	case "probe":
		*t = ServerType_Probe
	case "kv-store":
		*t = ServerType_KVStore
	case "quota":
		*t = ServerType_Quota
	case "autocert":
		*t = ServerType_Autocert
	default:
		return DataError("server type not know")
	}
	return nil
}

var AllServers []ServerType = []ServerType{
	ServerType_Reg, ServerType_User, ServerType_MerkleBuilder, ServerType_InternalCA, ServerType_MerkleQuery,
	ServerType_Queue, ServerType_MerkleBatcher, ServerType_MerkleSigner, ServerType_Probe,
	ServerType_Beacon, ServerType_KVStore, ServerType_Quota, ServerType_Autocert,
}

// FrontFacingServers interact with clients and are exposed to the outside internet.
var FrontFacingServers []ServerType = []ServerType{
	ServerType_Reg, ServerType_User, ServerType_MerkleQuery, ServerType_KVStore,
	ServerType_Probe, ServerType_Web,
}

var CoreServers []ServerType = []ServerType{
	ServerType_Reg, ServerType_User, ServerType_MerkleBuilder, ServerType_InternalCA, ServerType_MerkleQuery,
	ServerType_Queue, ServerType_MerkleBatcher, ServerType_MerkleSigner, ServerType_Probe,
	ServerType_KVStore,
}

func (t ServerType) IsFrontFacing() bool {
	for _, s := range FrontFacingServers {
		if t == s {
			return true
		}
	}
	return false
}

func (t ServerType) ServiceID() UID {
	var ret UID
	ret[0] = byte(EntityType_User)
	ret[len(ret)-1] = byte(t)
	return ret
}

func UIDToServerType(u UID) ServerType {
	if u[0] != byte(EntityType_User) {
		return ServerType_None
	}
	lst := len(u) - 1
	for _, c := range u[1:lst] {
		if c != 0 {
			return ServerType_None
		}
	}
	return ServerType(u[lst])
}
