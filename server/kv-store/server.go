// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"context"
	"errors"
	"fmt"
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

func (c *ClientConn) RegisterProtocols(m shared.MetaContext, srv shared.RPCRegistrar) error {
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
		// Fork-only (docs/kv-channel-acl.md): the acting user for channel-ACL
		// checks. A user store never carries channel storage, but set it
		// uniformly so the chokepoint has one source of identity.
		m = withActor(m, &uid)
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
		pid, err = idOrName.True().ToPartyID()
		if err != nil {
			return err
		}
		role = tmp.Role
		if !tmp.Req.Team.Host.Eq(m.HostID().Id) {
			return core.HostMismatchError{Which: "team host in kv-store auth"}
		}
		// Fork-only (docs/kv-channel-acl.md): the acting user for channel-ACL
		// checks. The connection may be anonymous (RequireAuth is
		// AuthTypeNone), so the verified identity is the member the bearer
		// token's signed challenge named. A remote member or a team acting as
		// member yields no actor, and tagged nodes then fail closed.
		if tmp.Req.Member.Host.Eq(m.HostID().Id) {
			if mu, uerr := tmp.Req.Member.Party.UID(); uerr == nil {
				m = withActor(m, &mu)
			}
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

func assertAdmin(role proto.Role, what string) error {
	ok, err := role.IsAdminOrAbove()
	if err != nil {
		return err
	}
	if !ok {
		return core.PermissionError(
			fmt.Sprintf("team admin permission needed for %s", what),
		)
	}
	return nil
}

func (c *ClientConn) KvMkdir(ctx context.Context, arg rem.KvMkdirArg) (rem.KVMkdirRes, error) {
	var res rem.KVMkdirRes
	err := c.preamble(ctx, arg.Hdr,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			chid, err := authorizeKVNodeCreate(m, pid, arg.ChannelID)
			if err != nil {
				return err
			}
			return shared.RetryTx(m, db, "kvMkdir",
				func(m shared.MetaContext, tx pgx.Tx) error {
					wasReplay, err := putDir(m, tx, pid, role, &arg.Dir, chid)
					if err != nil {
						return err
					}
					res.WasReplay = wasReplay
					return nil
				})
		})
	if err != nil {
		return rem.KVMkdirRes{}, err
	}
	return res, nil
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

func (c *ClientConn) KvPutSmallFileOrSymlink(ctx context.Context, arg rem.KvPutSmallFileOrSymlinkArg) (rem.KVPutSmallFileOrSymlinkRes, error) {
	var res rem.KVPutSmallFileOrSymlinkRes
	err := c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			chid, err := authorizeKVNodeCreate(m, pid, arg.ChannelID)
			if err != nil {
				return err
			}
			return shared.RetryTx(m, db, "kvPutFile",
				func(m shared.MetaContext, tx pgx.Tx) error {
					wasReplay, err := putSmallFileOrSymlink(m, tx, pid, role, arg, chid)
					if err != nil {
						return err
					}
					res.WasReplay = wasReplay
					return nil
				})
		})
	if err != nil {
		return rem.KVPutSmallFileOrSymlinkRes{}, err
	}
	return res, nil
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
			chid, err := authorizeKVNodeCreate(m, pid, arg.ChannelID)
			if err != nil {
				return err
			}
			return shared.RetryTx(m, db, "kvFileUploadInit",
				func(m shared.MetaContext, tx pgx.Tx) error {
					return fileUploadInit(m, c.srv.lfe, tx, pid, role, arg, chid)
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

// KvChannelMkRoot registers a directory as a private channel's storage root
// (fork-only; docs/kv-channel-acl.md §7 H3). The root is the one place a
// tagged directory may hang beneath an untagged parent. Registration demands
// an ACL owner or a team admin -- the standing rtChannelGrant demands -- and
// the directory must already exist carrying this channel's tag, which only a
// member could have created. Registering the same root twice is a replay and
// succeeds; a different root for a channel that has one is refused.
func (c *ClientConn) KvChannelMkRoot(ctx context.Context, arg rem.KvChannelMkRootArg) error {
	return c.auth(ctx, arg.Auth,
		func(m shared.MetaContext, db *pgxpool.Conn, pid proto.PartyID, role proto.Role) error {
			chid := arg.ChannelID.Short().Int64()
			err := authorizeKVNodeManage(m, pid, chid, role)
			if errors.Is(err, errKVNodeMasked) {
				// Same answer as a channel that does not exist.
				return core.NotFoundError("channel")
			}
			if err != nil {
				return err
			}
			var dirChid *int64
			err = db.QueryRow(
				m.Ctx(),
				`SELECT channel_id FROM dir
				 WHERE short_host_id=$1 AND short_party_id=$2 AND dir_id=$3
				 ORDER BY version DESC LIMIT 1`,
				int(m.ShortHostID()), pid.Shorten().ExportToDB(),
				arg.DirID.ExportToDB(),
			).Scan(&dirChid)
			if err != nil && errors.Is(err, pgx.ErrNoRows) {
				return core.NotFoundError("dir")
			}
			if err != nil {
				return err
			}
			if dirChid == nil || *dirChid != chid {
				return core.BadArgsError("directory does not carry this channel's tag")
			}
			return registerChannelRoot(m, db, pid, chid, arg.DirID)
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

func (c *ClientConn) SelectVHost(
	ctx context.Context,
	arg proto.HostID,
) error {
	return shared.SelectVHost(ctx, c, arg)
}

var _ rem.KVStoreInterface = (*ClientConn)(nil)
