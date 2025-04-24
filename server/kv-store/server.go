// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"context"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LargeFileStreamer interface {
	Next() ([]byte, error)
	Len() int
}

type LargeStorageStrategy int

const (
	LargeStorageStrategySQL LargeStorageStrategy = iota
)

func (s LargeStorageStrategy) ExportToDB() string {
	switch s {
	case LargeStorageStrategySQL:
		return "sql"
	default:
		return "unknown"
	}
}

type LargeFileStorageEngine interface {
	Strategy() LargeStorageStrategy
	Finalize(m shared.MetaContext, tx pgx.Tx, fid proto.FileID) error
	Get(m shared.MetaContext, rq shared.Querier, pid proto.PartyID,
		id proto.FileID, offset proto.Offset) (*rem.GetEncryptedChunkRes, error)
}

type Server struct {
	shared.BaseRPCServer
	lfe LargeFileStorageEngine
}

var _ shared.RPCServer = (*Server)(nil)

func (s *Server) ToRPCServer() shared.RPCServer { return s }
func (s *Server) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValid(m, uhc, key)
}

func (s *Server) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &ClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}

func (s *Server) Setup(m shared.MetaContext) error {
	cfg, err := m.G().Config().KVStoreServerConfig(m.Ctx())
	if err != nil {
		return err
	}
	p := cfg.BlobStorePath()
	switch {
	case p == "sql":
		s.lfe, err = NewBlobSQLStorage(m)
		if err != nil {
			return err
		}
	case strings.HasPrefix(p, "s3://"):
		return core.VersionNotSupportedError("s3 storage")
	default:
		return core.BadArgsError("invalid blob store path")
	}
	return nil
}

// Auth isn't needed for team shares on remote servers.
func (s *Server) RequireAuth() shared.AuthType { return shared.AuthTypeNone }

func (s *Server) ServerType() proto.ServerType {
	return proto.ServerType_KVStore
}

type ClientConn struct {
	shared.BaseClientConn
	srv *Server
	xp  rpc.Transporter
}

var _ shared.ClientConn = (*ClientConn)(nil)

func (c *ClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(rem.KVStoreProtocol(c))
}

func (c *ClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *ClientConn) preamble(
	ctx context.Context,
	hdr rem.KVReqHeader,
	f func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error,
) error {
	return c.auth(ctx, hdr.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			err := checkVersionVector(m, db, pid, role, hdr.Precondition)
			if err != nil {
				return err
			}
			return f(m, db, pid, role)
		})
}

func (c *ClientConn) auth(
	ctx context.Context,
	auth rem.KVAuth,
	f func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, r proto.Role) error,
) error {
	m := shared.NewMetaContextConn(ctx, c)
	typ, err := auth.GetT()
	if err != nil {
		return err
	}
	var pid proto.PartyID
	var role proto.Role
	switch typ {
	case rem.KVAuthType_User:
		uid := m.UID()
		if uid.IsZero() {
			return core.AuthError{}
		}
		pid = m.UID().ToPartyID()
		role = m.Role()
	case rem.KVAuthType_Team:
		db, err := m.Db(shared.DbTypeUsers)
		if err != nil {
			return err
		}
		defer db.Release()
		tok := auth.Team()
		tmp, err := shared.CheckTeamVOBearerToken(m, db, tok, 0)
		if err != nil {
			return err
		}
		idOrName := tmp.Req.Team.IdOrName
		typ, err := idOrName.GetId()
		if err != nil {
			return err
		}
		if !typ {
			return core.InternalError("team id expected")
		}
		pid = idOrName.True().ToPartyID()
		role = tmp.Role
		if !tmp.Req.Member.Host.Eq(m.HostID().Id) {
			return core.HostMismatchError{}
		}
	default:
		return core.BadArgsError("invalid auth type")
	}

	cfg, err := m.G().HostIDMap().Config(m, m.ShortHostID())
	if err != nil {
		return err
	}
	if !cfg.Typ.SupportKVStore() {
		return core.KVNotAvailableError{}
	}

	kvdb, err := m.KVShard(pid)
	if err != nil {
		return err
	}
	defer kvdb.Release()
	err = f(m, kvdb, pid, role)
	if err != nil {
		return err
	}
	return nil
}

func assertAtOrAbove(r1 proto.Role, r2 proto.Role, op proto.KVOp, rsrc proto.KVNodeType) error {
	ok, err := r1.IsAtOrAbove(r2)
	if err != nil {
		return err
	}
	if !ok {
		return core.KVPermssionError{
			KVPermError: proto.KVPermError{Op: op, Resource: rsrc},
		}
	}
	return nil
}

func assertAdmin(role proto.Role) error {
	ok, err := role.IsAdminOrAbove()
	if err != nil {
		return err
	}
	if !ok {
		return core.AuthError{}
	}
	return nil
}

func (c *ClientConn) KvMkdir(ctx context.Context, arg rem.KvMkdirArg) error {
	return c.preamble(ctx, arg.Hdr,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvMkdir",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return putDir(m, tx, pid, role, &arg.Dir)
				})
		})
}

func (c *ClientConn) KvPut(ctx context.Context, arg rem.KvPutArg) error {
	return c.preamble(ctx, arg.Hdr,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvPut",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return putDirent(m, tx, pid, role, arg)
				})
		})
}

func (c *ClientConn) KvPutRoot(ctx context.Context, arg rem.KvPutRootArg) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvPutRoot",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return putRoot(m, tx, pid, role, arg)
				})
		})
}

func (c *ClientConn) KvPutSmallFileOrSymlink(ctx context.Context, arg rem.KvPutSmallFileOrSymlinkArg) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvPutFile",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return putSmallFileOrSymlink(m, tx, pid, role, arg)
				})
		})
}

func (c *ClientConn) KvGetRoot(ctx context.Context, auth rem.KVAuth) (proto.KVRoot, error) {
	var ret proto.KVRoot
	err := c.auth(ctx, auth, func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
		tmp, err := getRoot(m, db, pid, role)
		if err != nil {
			return err
		}
		ret = *tmp
		return nil
	})
	return ret, err
}

func (c *ClientConn) KvGet(ctx context.Context, arg rem.KvGetArg) (rem.KVGetRes, error) {
	var ret rem.KVGetRes
	err := c.preamble(ctx, arg.Hdr,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := getDirent(m, db, pid, role, arg)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		})
	return ret, err
}

func (c *ClientConn) KvFileUploadInit(ctx context.Context, arg rem.KvFileUploadInitArg) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvFileUploadInit",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return fileUploadInit(m, c.srv.lfe, tx, pid, role, arg)
				})
		})
}

func (c *ClientConn) KvFileUploadChunk(ctx context.Context, arg rem.KvFileUploadChunkArg) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvFileUploadChunk",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return fileUploadChunk(m, c.srv.lfe, tx, pid, role, arg)
				})
		})
}

func (c *ClientConn) KvGetNode(ctx context.Context, arg rem.KvGetNodeArg) (rem.KVGetNodeRes, error) {
	var ret rem.KVGetNodeRes
	err := c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := getNode(m, c.srv.lfe, db, pid, role, arg)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		})
	return ret, err
}

func (c *ClientConn) KvList(ctx context.Context, arg rem.KvListArg) (rem.KVListRes, error) {
	var ret rem.KVListRes
	err := c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := listDir(m, db, pid, role, arg)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		})
	return ret, err
}

func (c *ClientConn) KvGetEncryptedChunk(ctx context.Context, arg rem.KvGetEncryptedChunkArg) (rem.GetEncryptedChunkRes, error) {
	var ret rem.GetEncryptedChunkRes
	err := c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := getChunk(m, c.srv.lfe, db, pid, role, arg)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		})
	return ret, err

}

func (c *ClientConn) KvGetDir(ctx context.Context, arg rem.KvGetDirArg) (proto.KVDirPair, error) {
	var ret proto.KVDirPair
	err := c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := getDir(m, db, pid, role, arg.Id)
			if err != nil {
				return err
			}
			ret = *tmp
			return nil
		})
	return ret, err
}

func (c *ClientConn) KvCacheCheck(
	ctx context.Context,
	arg rem.KVReqHeader,
) error {
	return c.preamble(ctx, arg,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return checkVersionVector(m, db, pid, role, arg.Precondition)
		})
}

func (c *ClientConn) KvLockAcquire(
	ctx context.Context,
	arg rem.KvLockAcquireArg,
) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvLockAcquire",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return lockAcquire(m, tx, pid, role, arg.Lock, arg.Timeout.Duration())
				})
		})
}

func (c *ClientConn) KvLockRelease(
	ctx context.Context,
	arg rem.KvLockReleaseArg,
) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			return shared.RetryTx(m, db, "kvLockRelease",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return lockRelease(m, tx, pid, role, arg.Lock)
				})
		})
}

func (c *ClientConn) KvUsage(
	ctx context.Context,
	arg rem.KVAuth,
) (
	proto.KVUsage,
	error,
) {
	var res proto.KVUsage
	err := c.auth(ctx, arg,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			tmp, err := getUsage(m, db, pid)
			if err != nil {
				return err
			}
			res = *tmp
			return nil
		})
	return res, err

}

var _ rem.KVStoreInterface = (*ClientConn)(nil)
