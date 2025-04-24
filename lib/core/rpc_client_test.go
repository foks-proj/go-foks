// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"testing"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/clockwork"
	"github.com/mattn/go-isatty"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type rpcLogMetaContext struct {
	ctx context.Context
	log ThinLog
}

func newRpcLogMetaContext() rpcLogMetaContext {
	cfg := zap.NewProductionConfig()
	if isatty.IsTerminal(os.Stdout.Fd()) {
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	log := zap.Must(cfg.Build())
	ctx := context.Background()
	return rpcLogMetaContext{ctx: ctx, log: NewThinLog(ctx, log)}
}

func (m rpcLogMetaContext) withCancel() (rpcLogMetaContext, context.CancelFunc) {
	var cancel context.CancelFunc
	m.ctx, cancel = context.WithCancel(m.ctx)
	return m, cancel
}

func (m rpcLogMetaContext) Log() *zap.Logger {
	return m.log.l
}

func (m rpcLogMetaContext) Background() RpcClientMetaContexter {
	m.ctx = context.Background()
	return m
}

func (m rpcLogMetaContext) NetworkConditioner() NetworkConditioner {
	return nil
}

func (m rpcLogMetaContext) WithLogTag(s string) RpcClientMetaContexter {
	return m
}

func (m rpcLogMetaContext) CnameResolver() CNameResolver {
	return PassthroughCNameResolver{}
}

func (m rpcLogMetaContext) Infow(msg string, keysAndValues ...interface{}) {
	m.log.Infow(msg, keysAndValues...)
}

func (m rpcLogMetaContext) Warnw(msg string, keysAndValues ...interface{}) {
	m.log.Warnw(msg, keysAndValues...)
}

func (m rpcLogMetaContext) Ctx() context.Context {
	return m.ctx
}

func (m rpcLogMetaContext) RPCLogOptions() (rpc.LogOptions, error) {
	return nil, nil
}

var _ RpcClientMetaContexter = rpcLogMetaContext{}

type testServer struct {
	cl        clockwork.Clock
	listener  net.Listener
	caCert    []byte
	quitCh    chan struct{}
	addr      net.Addr
	connectTo string
	tlsConfig *tls.Config
}

func (s *testServer) start(t *testing.T) {
	caPriv, caCert, err := GenCAInMem()
	require.NoError(t, err)
	host := "localhost"
	serverPriv, serverCert, err := MakeCertificateInMem([]string{host}, caPriv, caCert)
	require.NoError(t, err)
	require.NotNil(t, serverPriv)
	require.NotNil(t, serverCert)
	cert := tls.Certificate{
		Certificate: [][]byte{serverCert},
		PrivateKey:  serverPriv,
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", host+":0", &tlsConfig)
	require.NoError(t, err)
	require.NotNil(t, listener)
	s.listener = listener
	s.caCert = caCert
	quitCh := make(chan struct{})
	s.quitCh = quitCh
	s.addr = listener.Addr()
	s.connectTo = fmt.Sprintf("%s:%d", host, s.addr.(*net.TCPAddr).Port)
	cp := x509.NewCertPool()
	parsedCACert, err := x509.ParseCertificate(s.caCert)
	require.NoError(t, err)
	cp.AddCert(parsedCACert)
	s.tlsConfig = &tls.Config{RootCAs: cp}

	go s.serve(t, quitCh)
}

func (s *testServer) stop(t *testing.T) {
	s.listener.Close()
	close(s.quitCh)
}

type handler struct {
	s    *testServer
	t    *testing.T
	conn *tls.Conn
	xp   rpc.Transporter
	srv  *rpc.Server
}

func (h *handler) ErrorWrapper() func(error) proto.Status {
	return ErrorToStatus
}

func (h *handler) Fast(ctx context.Context, arg int64) (int64, error) {
	return arg + 1, nil
}

func (h *handler) Slow(ctx context.Context, arg lcl.SlowArg) (int64, error) {
	<-h.s.cl.After(arg.Wait.Duration())
	return arg.X + 1, nil
}

func (h *handler) Disconnect(ctx context.Context) error {
	h.xp.Close()
	return io.EOF
}

func (s *testServer) handleConn(t *testing.T, conn net.Conn) {
	ctls, ok := conn.(*tls.Conn)
	require.True(t, ok)
	err := ctls.Handshake()
	require.NoError(t, err)

	lf := rpc.NewSimpleLogFactory(
		rpc.NilLogOutput{}, nil,
	)
	wef := rem.RegMakeGenericErrorWrapper(ErrorToStatus)
	xp := rpc.NewTransport(context.Background(), conn, lf, nil, wef, RpcMaxSz)
	srv := rpc.NewServer(xp, wef)
	h := handler{s: s, t: t, conn: ctls, xp: xp, srv: srv}
	err = srv.RegisterV2(lcl.TestLibsProtocol(&h))
	require.NoError(t, err)
	<-srv.Run()
	err = srv.Err()
	if err == io.EOF {
		err = nil
	}
	require.NoError(t, err)
}

func (s *testServer) serve(t *testing.T, quitCh chan struct{}) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			<-quitCh
			return
		}
		require.NoError(t, err)
		require.NotNil(t, conn)
		go s.handleConn(t, conn)
	}
}

func (s *testServer) dial(t *testing.T) *tls.Conn {
	conn, err := tls.Dial("tcp", s.connectTo, s.tlsConfig)
	require.NoError(t, err)
	err = conn.Handshake()
	require.NoError(t, err)
	return conn
}

var _ lcl.TestLibsInterface = (*handler)(nil)

func TestRpcClientDial(t *testing.T) {
	srv := testServer{}
	srv.start(t)
	defer srv.stop(t)
	srv.dial(t)
}

func TestRpcConnectIdleReconnect(t *testing.T) {
	srv := testServer{}
	srv.start(t)
	defer srv.stop(t)
	m := newRpcLogMetaContext()
	clock := clockwork.NewFakeClock()
	opts := NewRpcClientOpts()
	opts.Clock = clock
	idleDisconnectCh := make(chan struct{}, 10)
	refcountCh := make(chan int, 10)
	exitCh := make(chan int, 10)
	opts.testIdleDisconnectCh = idleDisconnectCh
	opts.testRefcountUpdateCh = refcountCh
	opts.testExitCh = exitCh

	m, canc := m.withCancel()

	gcli := NewRpcClient(m, proto.TCPAddr(srv.connectTo), srv.tlsConfig.RootCAs, nil, opts)
	cli := lcl.TestLibsClient{Cli: gcli, ErrorUnwrapper: StatusToError}
	ctx := context.Background()
	arg := int64(1)

	// Very simple test.
	testFast := func() {
		res, err := cli.Fast(ctx, arg)
		require.NoError(t, err)
		require.Equal(t, arg+1, res)
	}

	// To get this test to work, we have to make sure that the refcount on the connection has gone to 0
	// before we advance the clock. Otherwise, we could get a race in the test, where the refcount
	// didn't get to update but the polling already happened. Easist way to do this is to just drain
	// the refcounts down to 0 and then advance the clock.
	drainRefcounts := func() {
		for {
			i := <-refcountCh
			if i == 0 {
				return
			}
		}
	}

	testFast()
	drainRefcounts()
	clock.Advance(opts.IdleTimeout / 10)
	require.NotNil(t, gcli.cm.xp)
	require.True(t, gcli.cm.xp.IsConnected())

	testFast()
	drainRefcounts()
	canc()

	clock.Advance(opts.IdleTimeout * 2)
	clock.Advance(opts.PollInterval * 2)
	<-idleDisconnectCh
	require.Nil(t, gcli.cm.xp)

	testFast()
	drainRefcounts()
	clock.Advance(opts.IdleTimeout / 10)
	require.NotNil(t, gcli.cm.xp)
	require.True(t, gcli.cm.xp.IsConnected())

	gcli.Shutdown()

	// make sure that both loops shut down. One exits with code 0, then other with code 1.
	v := []int{<-exitCh, <-exitCh}
	sort.Ints(v)
	require.Equal(t, []int{0, 1}, v)
}

func TestRpcDisconnectReconnect(t *testing.T) {
	srv := testServer{}
	srv.start(t)
	defer srv.stop(t)
	m := newRpcLogMetaContext()
	gcli := NewRpcClient(m, proto.TCPAddr(srv.connectTo), srv.tlsConfig.RootCAs, nil, nil)
	cli := lcl.TestLibsClient{Cli: gcli, ErrorUnwrapper: StatusToError}
	ctx := context.Background()
	arg := int64(1)

	// Very simple test.
	testFast := func() {
		res, err := cli.Fast(ctx, arg)
		require.NoError(t, err)
		require.Equal(t, arg+1, res)
	}

	testFast()

	err := cli.Disconnect(ctx)
	require.Error(t, err)
	require.Equal(t, RPCEOFError{}, err)

	testFast()
}
