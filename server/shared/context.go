// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"time"

	"github.com/foks-proj/go-ctxlog"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/keybase/clockwork"
	"go.uber.org/zap"
)

type UserHostContext struct {
	HostID *core.HostID
	Uid    proto.UID
	Role   proto.Role
}

type MetaContext struct {
	g        *GlobalContext
	ctx      context.Context
	userHost UserHostContext
}

func NewMetaContextMain(opts *GlobalContextOpts) MetaContext {
	return NewMetaContext(context.Background(), NewGlobalContext(opts))
}

func NewMetaContext(ctx context.Context, g *GlobalContext) MetaContext {
	return MetaContext{ctx: ctx, g: g}
}

func NewMetaContextWithUserHost(
	ctx context.Context,
	g *GlobalContext,
	uh UserHostContext,
) MetaContext {
	return MetaContext{
		ctx:      ctx,
		g:        g,
		userHost: uh,
	}
}

func (m MetaContext) Reset() MetaContext {
	return MetaContext{
		ctx: m.ctx,
		g:   m.g,
	}
}

func (m MetaContext) WithUserHost(uh UserHostContext) MetaContext {
	m.userHost = uh
	return m
}

func NewMetaContextWithHostID(
	ctx context.Context,
	g *GlobalContext,
	hid *core.HostID,
) MetaContext {
	return NewMetaContextWithUserHost(ctx, g, UserHostContext{HostID: hid})
}

func (m MetaContext) G() *GlobalContext {
	return m.g
}

func (m MetaContext) Ctx() context.Context {
	return m.ctx
}

func NewMetaContextTODO(g *GlobalContext) MetaContext {
	return MetaContext{ctx: context.TODO(), g: g}
}

func NewMetaContextBackground(g *GlobalContext) MetaContext {
	return MetaContext{ctx: context.Background(), g: g}
}

func (m MetaContext) WithContext(ctx context.Context) MetaContext {
	m.ctx = ctx
	return m
}

func (m MetaContext) WithLogTag(k string) MetaContext {
	m.ctx = ctxlog.WithLogTag(m.ctx, k)
	return m
}

func (m MetaContext) WithContextCancel() (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithCancel(m.ctx)
	return m, f
}

func (m MetaContext) WithContextTimeout(d time.Duration) (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithTimeout(m.ctx, d)
	return m, f
}

func (m MetaContext) BackgroundWithCancel() (MetaContext, func()) {
	var f func()
	m.ctx, f = context.WithCancel(context.Background())
	return m, f
}

func (m MetaContext) Background() MetaContext {
	return m.WithContext(context.Background())
}

func (m MetaContext) logWithSkip() *zap.SugaredLogger {
	return m.G().Log().WithOptions(zap.AddCallerSkip(1))
}

func (m MetaContext) Error(s string) {
	m.logWithSkip().Error(s)
}

func (m MetaContext) Infof(format string, args ...interface{}) {
	m.logWithSkip().Infof(format, args...)
}

func (m MetaContext) Errorf(format string, args ...interface{}) {
	m.logWithSkip().Errorf(format, args...)
}

func (m MetaContext) addCtxLog(keysAndValues ...interface{}) []interface{} {
	return core.AddCtxLog(m.ctx, keysAndValues...)
}

func (m MetaContext) Warnw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Warnw(msg, m.addCtxLog(keysAndValues...)...)
}
func (m MetaContext) Debugw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Debugw(msg, m.addCtxLog(keysAndValues...)...)
}
func (m MetaContext) Infow(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Infow(msg, m.addCtxLog(keysAndValues...)...)
}
func (m MetaContext) Errorw(msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Errorw(msg, m.addCtxLog(keysAndValues...)...)
}

func (m MetaContext) Shutdown() {
	m.G().Shutdown()
}

func (m MetaContext) Configure(opts GlobalCLIConfigOpts) error {
	return m.g.Configure(m.ctx, opts)
}

func (m MetaContext) ShortHostID() core.ShortHostID {
	if m.userHost.HostID != nil {
		return m.userHost.HostID.Short
	}
	return m.G().ShortHostID()
}

func (m MetaContext) MerkleCli() (*rem.MerkleQueryClient, error) {
	return m.G().MerkleCli(m.Ctx())
}

func (m MetaContext) GetKV(o core.Codecable, key KVKey) error {
	return m.G().GetKV(m.Ctx(), o, key, m.ShortHostID())
}
func (m MetaContext) PutKV(o core.Codecable, key KVKey) error {
	return m.G().PutKV(m.Ctx(), o, key, m.ShortHostID())
}
func (m MetaContext) Renew() MetaContext {
	return NewMetaContextBackground(m.G())
}

func (m MetaContext) Db(typ DbType) (*pgxpool.Conn, error) {
	return m.G().Db(m.Ctx(), typ)
}

func (m MetaContext) CnameResolver() core.CNameResolver {
	return m.g.CnameResolver()
}

func (m MetaContext) HostID() core.HostID {
	if m.userHost.HostID != nil {
		return *m.userHost.HostID
	}
	return m.g.HostID()
}

func (m MetaContext) GetHostID(hostID proto.HostID) (*core.HostID, error) {
	return m.G().HostIDMap().LookupByHostID(m, hostID)
}

func (m MetaContext) GetHostIDByShort(short core.ShortHostID) (*core.HostID, error) {
	return m.G().HostIDMap().LookupByShortID(m, short)
}

func (m MetaContext) GetVHost(hn proto.Hostname) (*core.HostID, error) {
	return m.G().HostIDMap().LookupByHostname(m, hn)
}

func (m MetaContext) UID() proto.UID {
	return m.userHost.Uid
}

func (m MetaContext) Role() proto.Role {
	return m.userHost.Role
}
func (m MetaContext) Rolep() *proto.Role {
	tmp := m.userHost.Role
	return &tmp
}

func (m MetaContext) UIDp() *proto.UID {
	tmp := m.userHost.Uid
	return &tmp
}

func (m MetaContext) WithShortHostID(s core.ShortHostID) (MetaContext, error) {
	hid, err := m.GetHostIDByShort(s)
	if err != nil {
		return m, err
	}
	m.userHost.HostID = hid
	return m, nil
}

func (m MetaContext) WithHostID(hid *core.HostID) MetaContext {
	m.userHost.HostID = hid
	return m
}

func SelectVHost(ctx context.Context, c ClientConn, hid proto.HostID) error {
	m := NewMetaContextConn(ctx, c)
	hid2, err := m.GetHostID(hid)
	if err != nil {
		return err
	}
	c.SetHostID(hid2)
	return nil
}

func (m MetaContext) WithProtoHostID(h *proto.HostID) (MetaContext, error) {
	if m.userHost.HostID != nil && h != nil && !m.userHost.HostID.Id.Eq(*h) {
		return m, core.HostMismatchError{}
	}
	if h == nil {
		return m, nil
	}
	hid, err := m.GetHostID(*h)
	if err != nil {
		return m, err
	}
	return m.WithHostID(hid), nil
}

func NewMetaContextFromArg(
	ctx context.Context,
	c ClientConn,
	hid *proto.HostID,
) (
	MetaContext,
	error,
) {
	m := NewMetaContextConn(ctx, c)
	return m.WithProtoHostID(hid)
}

func (m MetaContext) IsPrimaryHost() bool {
	if m.userHost.HostID == nil {
		return true
	}
	return m.userHost.HostID.Short == m.G().HostID().Short
}

func (m MetaContext) Stripe() Striper {
	return m.G().Stripe()
}

func (m MetaContext) Clock() clockwork.Clock {
	return m.G().Clock()
}

func (m MetaContext) SetClock(c clockwork.Clock) {
	m.G().SetClock(c)
}

func (m MetaContext) Now() time.Time {
	return m.G().Now()
}

func (m MetaContext) KVShard(pid proto.PartyID) (*pgxpool.Conn, error) {
	return m.G().KVShardMgr().GetConn(m, pid)
}

func (m MetaContext) KVShards(pids []proto.PartyID) (*ConnIter, error) {
	return m.G().KVShardMgr().GetSomeConns(m, pids)
}

func (m MetaContext) ForSomeShards(
	pids []proto.PartyID,
	fn func(conn *pgxpool.Conn, parties []proto.PartyID) error,
) error {
	return m.G().KVShardMgr().DoSome(m, pids, fn)
}

func (m MetaContext) ForAllShards(
	fn func(conn *pgxpool.Conn) error,
) error {
	return m.G().KVShardMgr().DoAll(m, fn)
}

func (m MetaContext) KVShardByID(i proto.KVShardID) (*pgxpool.Conn, error) {
	return m.G().KVShardMgr().GetConnByShardID(m, i)
}

func (m MetaContext) PrivateHostKeyIOer(
	id proto.HostID,
	typ proto.EntityType,
) (HostKeyIOer, error) {
	cfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	return cfg.PrivateKeyIOer(m.Ctx(), id, typ)
}

func (m MetaContext) HostConfig() (*proto.HostConfig, error) {
	return m.G().HostIDMap().Config(m, m.ShortHostID())
}

func (m MetaContext) WarnwWithContext(ctx context.Context, msg string, keysAndValues ...interface{}) {
	m.logWithSkip().Warnw(msg, core.AddCtxLog(ctx, keysAndValues...)...)
}
