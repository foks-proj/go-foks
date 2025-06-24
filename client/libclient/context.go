// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type MetaContext struct {
	core.MetaContext
	g *GlobalContext
}

func NewMetaContext(ctx context.Context, g *GlobalContext) MetaContext {
	return MetaContext{
		MetaContext: core.NewMetaContext(ctx, g.Log),
		g:           g,
	}

}

func NewMetaContextMain() MetaContext {
	g := NewGlobalContext()
	return NewMetaContextBackground(g)
}

func (m MetaContext) G() *GlobalContext {
	return m.g
}

func (m MetaContext) Setup(cmd *cobra.Command) error {
	return m.g.Setup(m.Ctx(), cmd)
}

func NewMetaContextTODO(g *GlobalContext) MetaContext {
	return MetaContext{
		MetaContext: core.NewMetaContextTODO(g.Log),
		g:           g,
	}
}

func NewMetaContextBackground(g *GlobalContext) MetaContext {
	return MetaContext{
		MetaContext: core.NewMetaContextBackground(g.Log),
		g:           g,
	}
}

func (m MetaContext) WithContextTimeout(d time.Duration) (MetaContext, func()) {
	ret := m
	var f func()
	ret.MetaContext, f = m.MetaContext.WithContextTimeout(d)
	return ret, f
}

func (m MetaContext) WithContextCancel() (MetaContext, func()) {
	ret := m
	var f func()
	ret.MetaContext, f = m.MetaContext.WithContextCancel()
	return ret, f
}

func (m MetaContext) WithLogTag(k string) MetaContext {
	ret := m
	ret.MetaContext = m.MetaContext.WithLogTag(k)
	return ret
}

func (m MetaContext) BackgroundWithCancel() (MetaContext, func()) {
	ret := m
	var f func()
	ret.MetaContext, f = m.MetaContext.BackgroundWithCancel()
	return ret, f
}

func (m MetaContext) Background() MetaContext {
	m.MetaContext = m.MetaContext.Background()
	return m
}

func (m MetaContext) Configure() error {
	return m.G().Configure(m.Ctx())
}

func (m MetaContext) LoadActiveUser(opts LoadActiveUserOpts) error {
	return m.G().LoadActiveUser(m.Ctx(), opts)
}

func (m MetaContext) DbPutTx(which DbType, rows []PutArg) error {
	return m.G().DbPutTx(m.Ctx(), which, rows)
}

func (m MetaContext) DbPut(which DbType, row PutArg) error {
	return m.G().DbPut(m.Ctx(), which, row)
}

func (m MetaContext) DbGet(out core.Codecable, which DbType, s Scoper, typ lcl.DataType, gkey any) (proto.Time, error) {
	return m.G().DbGet(m.Ctx(), out, which, s, typ, gkey)
}
func (m MetaContext) DbGetGlobalKV(out core.Codecable, which DbType, key core.KVKey) (proto.Time, error) {
	return m.G().DbGetGlobalKV(m.Ctx(), out, which, key)
}

func (m MetaContext) Shutdown() {
	m.G().Shutdown()
}

func (m MetaContext) DbDelete(which DbType, s Scoper, typ lcl.DataType, gkey any) error {
	return m.G().DbDelete(m.Ctx(), which, s, typ, gkey)
}

func (m MetaContext) DbDeleteGlobalKV(which DbType, key core.KVKey) error {
	return m.G().DbDeleteGlobalKV(m.Ctx(), which, key)
}

func (m MetaContext) DbGetCounter(which DbType, s Scoper, typ lcl.DataType) (int64, proto.Time, error) {
	return m.G().DbGetCounter(m.Ctx(), which, s, typ)
}

func (m MetaContext) ActiveUserClientCert() (*tls.Certificate, error) {
	return m.G().ActiveUserClientCert(m.Ctx())
}

func DbGetGlobalSet[
	T any,
	PT interface {
		*T
		core.CryptoPayloader
	}](
	m MetaContext,
	which DbType,
	key core.KVKey,
) ([]T, []proto.Time, error) {
	return DbGetGlobalSetGctx[T, PT](m.Ctx(), m.G(), which, key)
}

func (m MetaContext) DbDeleteFromGlobalSet(which DbType, key core.KVKey, h proto.StdHash) error {
	return m.G().DbDeleteFromGlobalSet(m.Ctx(), which, key, h)
}

func (m MetaContext) ResolveHostID(hid proto.HostID, opts *chains.ResolveOpts) (*chains.ResolveRes, error) {
	parg := chains.ProbeArg{
		HostID: hid,
	}
	if opts != nil && opts.Timeout > 0 {
		parg.Timeout = opts.Timeout
	}
	pr, err := m.g.discovery.Probe(m, parg)
	if err != nil {
		return nil, err
	}
	return &chains.ResolveRes{
		Probe: pr,
		Addr:  pr.CanonicalAddr(),
	}, nil
}

func (m MetaContext) CnameResolver() core.CNameResolver {
	return m.g.CnameResolver()
}

func (m MetaContext) NetworkConditioner() core.NetworkConditioner {
	return m.g.NetworkConditioner()
}

func (m MetaContext) WithLogTagI(k string) chains.MetaContext {
	return m.WithLogTag(k)
}

func (m MetaContext) ProbeByAddr(addr proto.TCPAddr, timeout time.Duration) (*chains.Probe, error) {
	return m.g.discovery.Probe(m, chains.ProbeArg{Addr: addr, Timeout: timeout})
}

func (m MetaContext) Probe(arg chains.ProbeArg) (*chains.Probe, error) {
	return m.g.discovery.Probe(m, arg)
}

func (g *GlobalContext) WarnwWithContext(
	ctx context.Context,
	msg string,
	keysAndValues ...interface{},
) {
	core.WarnwWithContext(ctx, g.Log(), msg, keysAndValues...)
}

func (m MetaContext) SetAsAgent() error {
	return m.g.SetAsAgent(m.Ctx())

}
