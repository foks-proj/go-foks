// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/clockwork"
	"go.uber.org/zap"
)

type RpcClientMetaContexter interface {
	WithLogTag(string) RpcClientMetaContexter
	Background() RpcClientMetaContexter
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	RPCLogOptions() (rpc.LogOptions, error)
	Ctx() context.Context
	Log() *zap.Logger
	CnameResolver() CNameResolver
	NetworkConditioner() NetworkConditioner
}

type getXpRes struct {
	xp  rpc.Transporter
	err error
}

type refcount struct {
	time time.Time
	i    int
}

type connectionMgr struct {
	tlsConfig      *tls.Config
	remote         proto.TCPAddr
	clientCertHook func(context.Context) (*tls.Certificate, error)
	xp             rpc.Transporter
	eofCh          <-chan struct{}
	getXpCh        <-chan (chan<- getXpRes)
	refcountCh     <-chan refcount
	resetCh        <-chan (chan<- struct{})
	opts           *RpcClientOpts

	rcMu sync.Mutex
	rc   *refcount
}

func (c *connectionMgr) serve(m RpcClientMetaContexter) {
	m = m.Background().WithLogTag("connmgr")
	m.Infow("starting", "remote", c.remote)
	go c.xpLoop(m)
	go c.refcountLoop(m)
}

func (c *connectionMgr) setRefcount(m RpcClientMetaContexter, rc refcount) {
	c.rcMu.Lock()
	defer c.rcMu.Unlock()

	if c.rc == nil || !rc.time.Before(c.rc.time) {
		c.rc = &rc
		if c.opts.testRefcountUpdateCh != nil {
			c.opts.testRefcountUpdateCh <- rc.i
		}
	}
}

func (c *connectionMgr) refcountLoop(m RpcClientMetaContexter) {
	for {
		select {
		case <-c.eofCh:
			m.Infow("exiting refcount loop")
			if c.opts.testExitCh != nil {
				c.opts.testExitCh <- 1
			}
			return
		case rc := <-c.refcountCh:
			c.setRefcount(m, rc)
		}
	}
}

func (c *connectionMgr) checkIdle(m RpcClientMetaContexter) {
	c.rcMu.Lock()
	defer c.rcMu.Unlock()
	if c.rc == nil {
		return
	}
	now := c.opts.Clock.Now()
	if c.rc.i == 0 && now.Sub(c.rc.time) > c.opts.IdleTimeout {
		m.Infow("closing idle connection", "remote", c.remote)
		c.xp.Close()
		c.xp = nil
		c.rc = nil
		if c.opts.testIdleDisconnectCh != nil {
			c.opts.testIdleDisconnectCh <- struct{}{}
		}
	}
}

func (c *connectionMgr) xpLoop(m RpcClientMetaContexter) {
	for {
		select {
		case <-c.eofCh:
			m.Infow("exiting xp loop")
			if c.opts.testExitCh != nil {
				c.opts.testExitCh <- 0
			}
			return
		case <-c.opts.Clock.After(c.opts.PollInterval):
			c.checkIdle(m)
		case retCh := <-c.getXpCh:
			retCh <- c.getXp(m)
		case waitCh := <-c.resetCh:
			c.resetXp(m)
			waitCh <- struct{}{}
		}
	}
}

func (c *connectionMgr) resetXp(m RpcClientMetaContexter) {
	m.Infow("resetXp")
	if c.xp != nil {
		tmp := c.xp
		c.xp = nil
		tmp.Close()
	}
}

func (c *connectionMgr) getXp(m RpcClientMetaContexter) getXpRes {
	if c.xp != nil && c.xp.IsConnected() {
		return getXpRes{xp: c.xp}
	}

	if c.xp != nil {
		m.Infow("found dead connection")
		c.xp.Close()
		c.xp = nil
	}

	conn, err := c.connectLoop(m)
	if err != nil {
		return getXpRes{err: err}
	}
	err = conn.Handshake()
	if err != nil {
		return getXpRes{err: err}
	}
	opts, err := m.RPCLogOptions()
	if err != nil {
		return getXpRes{err: err}
	}

	lf := rpc.NewSimpleLogFactory(
		NewZapLogWrapper(m.Log()),
		opts,
	)
	wef := rem.RegMakeGenericErrorWrapper(ErrorToStatus)
	xp := rpc.NewTransport(m.Ctx(), conn, lf, nil, wef, RpcMaxSz)

	if c.opts != nil && c.opts.ConfigConnHook != nil {
		err = c.opts.ConfigConnHook(m.Ctx(), xp)
		if err != nil {
			m.Warnw("configConnHook", "err", err)
			return getXpRes{err: err}
		}
	}

	c.xp = xp
	return getXpRes{xp: xp}
}

func (c *connectionMgr) makeTlsConfig(m RpcClientMetaContexter) (*tls.Config, error) {
	var cfg *tls.Config
	if c.tlsConfig != nil {
		cfg = c.tlsConfig.Clone()
	}
	if c.clientCertHook != nil {
		cert, err := c.clientCertHook(m.Ctx())
		if err != nil {
			m.Warnw("clientCertHook", "err", err)
			return nil, err
		}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
	}
	return cfg, nil
}

func resolve(r CNameResolver, addr proto.TCPAddr) (proto.TCPAddr, proto.Hostname, error) {
	var zed proto.TCPAddr
	var hn proto.Hostname
	if r == nil {
		return addr, hn, nil
	}
	host, port, err := addr.Split()
	if err != nil {
		return zed, hn, err
	}
	newHost := r.Resolve(host)
	if newHost == "" {
		return addr, hn, nil
	}

	ret := proto.NewTCPAddrPortOpt(newHost, port)
	return ret, host, nil
}

func (c *connectionMgr) tlsConfigureAndConnect(m RpcClientMetaContexter) (*tls.Conn, error) {
	cfg, err := c.makeTlsConfig(m)
	if err != nil {
		return nil, err
	}
	host, origHost, err := resolve(m.CnameResolver(), c.remote)
	if err != nil {
		return nil, err
	}
	if origHost != "" {
		cfg.ServerName = origHost.String()
	}

	var which string

	if c.opts != nil {
		which = c.opts.DebugName
	}
	m.Infow("connectMgr.dial",
		"host", host,
		"origHost", origHost,
		"remote", c.remote,
		"which", which)

	conn, err := tls.Dial("tcp", string(host), cfg)
	if err != nil {
		m.Warnw("connectMgr.dial", "host", host, "err", err)
		return nil, err
	}
	err = conn.Handshake()
	if err != nil {
		m.Warnw("connectMgr.handshake", "host", host, "err", err)
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *connectionMgr) runNetworkConditionerOnConnect(
	m RpcClientMetaContexter,
) error {
	if m.NetworkConditioner() == nil {
		return nil
	}
	err := m.NetworkConditioner().FailConnect(c.remote)
	if err == nil {
		return nil
	}
	m.Infow("connect", "remote", c.remote, "stage", "netcond", "err", err)
	return err
}

func (c *connectionMgr) connectLoop(m RpcClientMetaContexter) (*tls.Conn, error) {
	var conn *tls.Conn
	var err error
	wait := c.opts.MinConnectWait
	lim := c.opts.MaxConnectWait

	err = c.runNetworkConditionerOnConnect(m)
	if err != nil {
		return nil, err
	}

	for i := 0; i < c.opts.NumConnectAttempts; i++ {

		m.Infow("connect", "remote", c.remote, "try", i)
		conn, err = c.tlsConfigureAndConnect(m)
		if err == nil {
			m.Infow("connected")
			return conn, nil
		}
		m.Warnw("connect", "err", err, "try", i, "wait", wait, "errtype", fmt.Sprintf("%T", err))
		select {
		case <-c.eofCh:
			return nil, io.EOF
		case <-c.opts.Clock.After(wait):
		}
		wait *= 2
		if wait > lim {
			wait = lim
		}
	}
	return nil, io.EOF
}

type RpcClient struct {
	sync.Mutex
	tlsConfig     *tls.Config
	remote        proto.TCPAddr
	nOut          int
	killConnMgrCh chan<- struct{}
	getXpCh       chan<- (chan<- getXpRes)
	refcountCh    chan<- refcount
	resetCh       chan<- (chan<- struct{})
	opts          *RpcClientOpts
	cm            *connectionMgr
	dead          bool
}

type RpcClientOpts struct {
	Timeout            time.Duration
	IdleTimeout        time.Duration
	PollInterval       time.Duration
	NumConnectAttempts int
	MaxConnectWait     time.Duration
	MinConnectWait     time.Duration
	ConfigConnHook     func(context.Context, rpc.Transporter) error

	DebugName string

	// For testing purposes
	Clock                clockwork.Clock
	testIdleDisconnectCh chan<- struct{}
	testRefcountUpdateCh chan<- int
	testExitCh           chan<- int
}

func NewRpcClientOpts() *RpcClientOpts {
	return &RpcClientOpts{
		Clock:              clockwork.NewRealClock(),
		Timeout:            300 * time.Second,
		IdleTimeout:        5 * time.Minute,
		PollInterval:       10 * time.Second,
		NumConnectAttempts: 20,
		MaxConnectWait:     30 * time.Second,
		MinConnectWait:     1 * time.Second,
	}
}

func (o *RpcClientOpts) WithName(s string) *RpcClientOpts {
	o.DebugName = s
	return o
}

func NewRpcClient(
	m RpcClientMetaContexter,
	addr proto.TCPAddr,
	rootCAs *x509.CertPool,
	clientCertHook func(context.Context) (*tls.Certificate, error),
	opts *RpcClientOpts,
) *RpcClient {
	if opts == nil {
		opts = NewRpcClientOpts()
	}

	var tlsConfig tls.Config
	if rootCAs != nil {
		tlsConfig.RootCAs = rootCAs
	}
	eofCh := make(chan struct{})
	getXpCh := make(chan (chan<- getXpRes), 100)
	refcountCh := make(chan refcount)
	resetCh := make(chan (chan<- struct{}))

	mgr := &connectionMgr{
		tlsConfig:      &tlsConfig,
		clientCertHook: clientCertHook,
		remote:         addr,
		eofCh:          eofCh,
		getXpCh:        getXpCh,
		resetCh:        resetCh,
		refcountCh:     refcountCh,
		opts:           opts,
	}

	go mgr.serve(m)

	res := &RpcClient{
		remote:        addr,
		tlsConfig:     &tlsConfig,
		killConnMgrCh: eofCh,
		getXpCh:       getXpCh,
		refcountCh:    refcountCh,
		resetCh:       resetCh,
		opts:          opts,
		cm:            mgr, // for testing
	}
	return res
}

func (c *RpcClient) Shutdown() {
	c.Lock()
	c.dead = true
	c.Unlock()
	close(c.killConnMgrCh)
}

func (c *RpcClient) Reset() {
	waitCh := make(chan struct{})
	c.resetCh <- waitCh
	<-waitCh
}

func (c *RpcClient) now() time.Time {
	return c.opts.Clock.Now()
}

func (c *RpcClient) inc() {
	c.Lock()
	defer c.Unlock()
	c.nOut++
	n := c.nOut
	c.refcountCh <- refcount{time: c.now(), i: n}
}

func (c *RpcClient) dec() {
	c.Lock()
	defer c.Unlock()
	c.nOut--
	n := c.nOut
	c.refcountCh <- refcount{time: c.now(), i: n}
}

func (c *RpcClient) isDead() bool {
	c.Lock()
	defer c.Unlock()
	return c.dead
}

func (c *RpcClient) Connect(ctx context.Context) (rpc.Transporter, error) {
	if c.isDead() {
		return nil, InternalError("attempt to use an RpcClient after Shutdown()")
	}
	retCh := make(chan getXpRes, 1)
	select {
	case c.getXpCh <- retCh:
	case <-ctx.Done():
		return nil, NewConnectError(
			"RpcClient.Connect failed at stage 1",
			ctx.Err(),
		)
	}
	select {
	case res := <-retCh:
		if res.err != nil {
			return nil, res.err
		}
		return res.xp, nil
	case <-ctx.Done():
		return nil, NewConnectError(
			"RpcClient.Connect failed at stage 2",
			ctx.Err(),
		)
	}
}

func (c *RpcClient) ConnectCli(ctx context.Context) (rpc.GenericClient, error) {
	xp, err := c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return rpc.NewClient(xp, nil, nil), nil
}

func (c *RpcClient) Call(ctx context.Context, method rpc.Methoder, arg interface{}, res interface{}, timeout time.Duration) error {
	return NotImplementedError{}
}

func (c *RpcClient) CallCompressed(ctx context.Context, method rpc.Methoder, arg interface{}, res interface{}, cType rpc.CompressionType, timeout time.Duration) error {
	return NotImplementedError{}
}

func (c *RpcClient) Notify(ctx context.Context, method rpc.Methoder, arg interface{}, timeout time.Duration) error {
	return NotImplementedError{}
}

var _ rpc.GenericClient = (*RpcClient)(nil)

func (c *RpcClient) Call2(ctx context.Context, method rpc.Methoder, arg interface{}, res interface{}, timeout time.Duration, ew rpc.ErrorUnwrapper) error {

	if c.opts.Timeout > 0 {
		var canc func()
		ctx, canc = context.WithTimeout(ctx, c.opts.Timeout)
		defer canc()
	}

	gcli, err := c.ConnectCli(ctx)
	if err != nil {
		return err
	}
	c.inc()
	defer c.dec()
	err = gcli.Call2(ctx, method, arg, res, timeout, ew)

	if errors.Is(err, io.EOF) {
		return RPCEOFError{}
	}

	return err
}

func (c *RpcClient) Transport(ctx context.Context) (rpc.Transporter, error) {
	return c.Connect(ctx)
}

func MakeConfigConnHook(
	st proto.ServerType,
	hid proto.HostID,
	wcw WithContextWarner,
) func(context.Context, rpc.Transporter) error {

	if hid.IsZero() {
		return nil
	}

	type selector interface {
		SelectVHost(context.Context, proto.HostID) error
	}

	var clienter func(cli *rpc.Client) selector

	switch st {
	case proto.ServerType_Reg:
		clienter = func(cli *rpc.Client) selector {
			return NewRegClient(cli, wcw)
		}
	case proto.ServerType_MerkleQuery:
		clienter = func(cli *rpc.Client) selector {
			return NewMerkleQueryClient(cli, wcw)
		}
	default:
		break
	}

	if clienter == nil {
		return nil
	}

	return func(ctx context.Context, xp rpc.Transporter) error {
		gcli := rpc.NewClient(xp, nil, nil)
		cli := clienter(gcli)
		return cli.SelectVHost(ctx, hid)
	}
}
