// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"go.uber.org/zap"
)

func Connect(m MetaContext, t proto.ServerType, clientCert *tls.Certificate) (rpc.Transporter, error) {

	_, addr, tlsCfg, err := m.G().ListenParams(m.Ctx(), t)
	if err != nil {
		return nil, err
	}

	rootCAs, err := m.G().CertMgr().PoolForBaseHost(m, nil,
		[]proto.CKSAssetType{proto.CKSAssetType_BackendCA},
	)
	if err != nil {
		return nil, err
	}
	tlsCfg.RootCAs = rootCAs
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}

	conn, err := tls.Dial("tcp", addr.String(), tlsCfg)
	if err != nil {
		return nil, err
	}
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	lf := rpc.NewSimpleLogFactory(rpc.NilLogOutput{}, nil)
	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	xp := rpc.NewTransport(m.Ctx(), conn, lf, nil, wef, core.RpcMaxSz)
	return xp, nil
}

func GetClientCertChainForService(m MetaContext, t proto.ServerType, key proto.DeviceID) ([][]byte, error) {
	m = m.WithLogTag("gccfs")
	xp, err := Connect(m, proto.ServerType_InternalCA, nil)
	if err != nil {
		m.Warnw("GetClientCertChainForService", "stage", "connect", "err", err)
		return nil, err
	}
	defer xp.Close()
	gcli := rpc.NewClient(xp, nil, nil)
	cli := infra.InternalCAClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	m.Infow("GetClientCertChainForService", "stage", "call", "service", t.ServiceID(), "key", key)
	ret, err := cli.GetClientCertChainForService(m.Ctx(), infra.GetClientCertChainForServiceArg{
		Service: t.ServiceID(),
		Key:     key,
	})
	m.Infow("GetClientCertChainForService", "stage", "return", "ret", ret, "err", err)
	return ret, err
}

type BackendClient struct {
	sync.Mutex
	g          *GlobalContext
	cert       [][]byte
	certTime   time.Time
	key        *proto.Ed25519SecretKey
	typ        proto.ServerType
	callerType proto.ServerType
	cli        *core.RpcClient
	opts       *core.RpcClientOpts
}

type RpcClientMetaContext struct {
	MetaContext
}

func (m RpcClientMetaContext) WithLogTag(s string) core.RpcClientMetaContexter {
	ret := RpcClientMetaContext{
		MetaContext: m.MetaContext.WithLogTag(s),
	}
	return ret
}

func (m RpcClientMetaContext) Infow(msg string, keysAndValues ...interface{}) {
	m.MetaContext.Infow(msg, keysAndValues...)
}

func (m RpcClientMetaContext) Warnw(msg string, keysAndValues ...interface{}) {
	m.MetaContext.Warnw(msg, keysAndValues...)
}

func (m RpcClientMetaContext) RPCLogOptions() (rpc.LogOptions, error) {
	return m.G().Config().RPCLogOptions(m.Ctx())
}

func (m RpcClientMetaContext) Ctx() context.Context {
	return m.MetaContext.Ctx()

}
func (m RpcClientMetaContext) Log() *zap.Logger {
	return m.G().Log().Desugar()
}

func (m RpcClientMetaContext) Background() core.RpcClientMetaContexter {
	return RpcClientMetaContext{MetaContext: m.MetaContext.Background()}
}

func (m RpcClientMetaContext) NetworkConditioner() core.NetworkConditioner {
	return nil
}

var _ core.RpcClientMetaContexter = RpcClientMetaContext{}

func NewBackendClient(g *GlobalContext, typ proto.ServerType, callerType proto.ServerType, opts *core.RpcClientOpts) *BackendClient {
	ret := &BackendClient{g: g, typ: typ, callerType: callerType, opts: opts}
	return ret
}

func (c *BackendClient) Cli(ctx context.Context) (*core.RpcClient, error) {
	err := c.init(ctx)
	if err != nil {
		return nil, err
	}
	return c.cli, nil
}

func (c *BackendClient) init(ctx context.Context) error {
	c.Lock()
	defer c.Unlock()
	if c.cli != nil {
		return nil
	}

	_, addr, _, err := c.g.ListenParams(ctx, c.typ)
	if err != nil {
		return err
	}

	m := NewMetaContext(ctx, c.g)

	// Also add frontend CAs since merkle_query service is both a backend and frontent service
	// Also add the backend CA (v2 CA) from CKS.
	rootCAs, err := c.g.CertMgr().PoolForBaseHost(
		m,
		nil,
		[]proto.CKSAssetType{
			proto.CKSAssetType_HostchainFrontendCA,
			proto.CKSAssetType_BackendCA,
		},
	)
	if err != nil {
		return err
	}
	rm := RpcClientMetaContext{
		MetaContext: m,
	}
	cli := core.NewRpcClient(
		rm,
		addr,
		rootCAs,
		func(ctx context.Context) (*tls.Certificate, error) { return c.TLSCert(ctx) },
		c.opts,
	)
	c.cli = cli
	return nil
}

// TLSCert makes a client cert for this service to be able to connect to another
// backend service. The key for the caller is stored persistently in Postgres.
// The key must be signed by the "internal CA", and we cache that cert for
// 6 hours by default (but can tune it via config file). Note, this whole
// chain can be called from within the context of the inner loop of the
// rpc_client connection class, via the clientCertHook callback. We had a nasty
// bug here earlier where the context threaded through was canceled, and this
// whole chain failed after the cert expired.
func (n *BackendClient) TLSCert(ctx context.Context) (*tls.Certificate, error) {
	m := NewMetaContext(ctx, n.g)
	n.Lock()
	defer n.Unlock()
	if n.key == nil {
		key, err := FetchOrGenerateServiceKey(m, n.callerType)
		if err != nil {
			return nil, err
		}
		n.key = key
	}
	eid, err := n.key.EntityID(proto.EntityType_Device)
	if err != nil {
		return nil, err
	}

	settings, err := m.G().Config().Settings(ctx)
	if err != nil {
		return nil, err
	}
	cit := settings.ConnectionIdleTimeout()

	if n.cert == nil || n.certTime.Add(cit).Before(time.Now()) {
		m.Infow("TLSCert", "refresh", true, "callerType", n.callerType, "eid", eid)
		cert, err := GetClientCertChainForService(m, n.callerType, proto.DeviceID(eid))
		if err != nil {
			return nil, err
		}
		n.cert = cert
		n.certTime = time.Now()
	}

	tlsCert := &tls.Certificate{
		PrivateKey:  n.key.SecretKeyEd25519(),
		Certificate: n.cert,
	}

	return tlsCert, nil
}

func (c *BackendClient) Close() error {
	if c.cli != nil {
		c.cli.Shutdown()
	}
	return nil
}
