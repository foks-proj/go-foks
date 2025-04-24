// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"crypto/tls"
	"io"
	"net"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"go.uber.org/zap"
)

func RPCServeWithSignals(m MetaContext, s RPCServer, launchCh chan<- error) error {

	bindAddr, listener, isTLS, err := doListen(m, s)

	launchErr := func(e error) error {
		if launchCh != nil {
			launchCh <- e
		}
		return e
	}

	if err != nil {
		return launchErr(err)
	}

	s.SetListening(listener, isTLS)
	m.G().TakeServerConfig(s, listener)
	m.Infow("ServeWithSignals", "type", s.ServerType().String(), "addr", listener.Addr().String())

	m.Infow(
		"listening",
		"localAddr", bindAddr,
		"port", port(listener),
		"isTLS", isTLS)

	ch := make(chan net.Conn)
	doneCh := make(chan struct{})
	quitCh := make(chan struct{})

	// If we want to run background processing loops, etc, we should do it here,
	// running until the context is canceled. Note that if there's a catastrophic
	// failure in the background loop, it can shut down the whole server. For instance,
	// a service might detect that it lost its exclusive lock, and therefore should get
	// out of the way.
	mbg, finish := m.WithContextCancel()
	defer finish()
	bgShutdownCh := make(chan error)
	mbg = mbg.WithLogTag("bg")
	err = s.RunBackgroundLoops(mbg, bgShutdownCh)
	if err != nil {
		return launchErr(err)
	}

	// If the caller wants to know when it's OK to call us, then
	// it's now. BTW, it might be an error case.
	if launchCh != nil {
		launchCh <- nil
	}

	go func() {
		keepGoing := true
		for keepGoing {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-quitCh: // don't report errors due to closed listener
				default:
					m.Errorw("in accept", "err", err.Error())
				}
				keepGoing = false
			} else {
				ch <- conn
			}
		}
	}()

	keepGoing := true
	nOut := 0
	startShutdown := func() {
		if keepGoing {
			close(quitCh)
			listener.Close()
			m.Infow("shutdown", "state", "listener closed", "mOut", nOut)
			keepGoing = false
		}
	}
	for keepGoing || nOut > 0 {
		select {
		case conn := <-ch:
			nOut++
			go serveConnection(m, s, conn, doneCh)
		case <-doneCh:
			nOut--
			if !keepGoing {
				m.Infow("shutdown", "state", "drained connection", "nOut", nOut)
			}
		case err := <-bgShutdownCh:
			if err != nil {
				m.Warnw("shutdown", "state", "background loop", "err", err)
			}
			startShutdown()
		case <-m.Ctx().Done():
			startShutdown()
		}
	}
	err = s.Shutdown(m.Renew())
	if err != nil {
		m.Warnw("shutdown", "state", "server.Shutdown", "err", err)
	}
	m.Infow("shutdown", "state", "complete")
	return nil
}

func serveConnection(m MetaContext, s RPCServer, conn net.Conn, doneCh chan<- struct{}) {

	defer (func() {
		doneCh <- struct{}{}
	})()

	ctls, ok := conn.(*tls.Conn)
	if ok {
		err := ctls.Handshake()
		if err != nil {
			m.Warnw("servConnection",
				"stage", "TLS handshake",
				"err", err,
				"remoteAddr", conn.RemoteAddr().String(),
			)
			return
		}
	}

	m = m.WithLogTag("conn")

	if m.G().LogRemoteIP(m.Ctx()) || s.IsInternal() {
		m.Infow("serveConnection",
			"stage", "new connection",
			"remote", conn.RemoteAddr().String(),
		)
	}

	opts, err := m.G().RPCLogOptions(m.Ctx())
	if err != nil {
		m.Warnw("serveConnection",
			"stage", "parse log options",
			"err", err,
		)
	}

	uhc, authErr := authConnection(m, s, ctls)
	if authErr != nil {
		m.Warnw("serveConnection",
			"stage", "authConnection",
			"err", authErr,
		)
	}

	m.Infow("serveConnection", "stage", "OK")

	lf := rpc.NewSimpleLogFactory(
		core.NewZapLogWrapper(m.G().Log().Desugar()),
		opts,
	)
	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	xp := rpc.NewTransport(m.Ctx(), conn, lf, nil, wef, core.RpcMaxSz)
	srv := rpc.NewServer(xp, wef)
	cliCon := s.NewClientConn(xp, uhc)

	rerr := cliCon.RegisterProtocols(m, srv)

	if rerr != nil {
		m.Warnw("serveConnection",
			"stage", "registerProtocols",
			"err", rerr,
		)
	}

	if authErr != nil {
		xp.KillIncoming(authErr)
	}

	select {
	case <-srv.Run():
		m.Infow("client disconnected")
		err = srv.Err()
		if err != nil && err != io.EOF {
			m.Warnw("error on conn shutdown", zap.Error(err))
		}
	case <-m.Ctx().Done():
		m.Infow("serveConnection", "stage", "server shutdown")
	}

	m.Infow("serveConnection", "stage", "exit")
}

func configureTLS(
	m MetaContext,
	s Server,
	tlsConfig *tls.Config,
) error {
	if tlsConfig == nil {
		return nil
	}
	tlsConfig.GetConfigForClient = m.G().CertMgr().MakeGetConfigForClient(m, tlsConfig, s.ServerType())

	return nil
}

func doListen(m MetaContext, s Server) (BindAddr, net.Listener, bool, error) {
	bindAddr, _, tlsConfig, err := m.G().ListenParams(m.Ctx(), s.ServerType())
	if err != nil {
		return "", nil, false, err
	}

	err = configureTLS(m, s, tlsConfig)
	if err != nil {
		return "", nil, false, err
	}

	var listener net.Listener
	var isTLS bool

	if tlsConfig == nil {
		listener, err = net.Listen("tcp", string(bindAddr))
	} else {
		listener, err = tls.Listen("tcp", string(bindAddr), tlsConfig)
		isTLS = true
	}
	return bindAddr, listener, isTLS, err
}

func extractClientKey(m MetaContext, s RPCServer, ctls *tls.Conn) (*proto.FQUser, proto.EntityID) {

	state := ctls.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		m.Warnw("extractClientKey",
			"stage", "PeerCertificates",
			"err", "none found",
		)
		return nil, nil
	}

	cert := state.PeerCertificates[0]
	var skid proto.SubjectKeyID
	err := core.DecodeFromBytes(&skid, cert.SubjectKeyId)

	if err != nil {
		m.Warnw("extractClientKey",
			"stage", "decode",
			"err", err,
		)
		return nil, nil
	}

	key, err := skid.KeyType.ImportFromPublicKey(cert.PublicKey)
	if err != nil {
		m.Warnw("extractClientKey",
			"stage", "importKey",
			"err", err)
		return nil, nil
	}

	return &skid.Fqu, key

}

func authConnection(m MetaContext, s RPCServer, ctls *tls.Conn) (UserHostContext, error) {

	var ret UserHostContext

	fqup, key := extractClientKey(m, s, ctls)

	authTyp := s.RequireAuth()

	if fqup == nil && authTyp != AuthTypeNone {
		m.Warnw("authConnection",
			"err", "auth required but not found",
		)
		return ret, core.AuthError{}
	}

	if fqup == nil {
		return ret, nil
	}

	hid, err := m.GetHostID(fqup.HostID)
	if err != nil {
		m.Warnw("authConnection",
			"stage", "GetHostID",
			"err", err)
		return ret, core.AuthError{}
	}

	uhc := UserHostContext{
		Uid:    fqup.Uid,
		HostID: hid,
	}

	role, err := s.CheckDeviceKey(m, uhc, key)

	if err != nil {
		m.Warnw("authConnection",
			"stage", "checkDeviceKey",
			"err", err)
		return ret, core.AuthError{}
	}

	if role != nil {
		uhc.Role = *role
	}

	if authTyp != AuthTypeExternal {
		return uhc, nil
	}

	sso, err := m.G().HostIDMap().SSO(m, hid.Short)
	if err != nil {
		m.Warnw("authConnection",
			"stage", "SSO",
			"err", err)
		return ret, err
	}
	if sso == proto.SSOProtocolType_None {
		return uhc, nil
	}

	err = AuthSSO(m, sso, uhc)
	if err != nil {
		m.Warnw("authConnection",
			"stage", "AuthSSO",
			"err", err)
		ret.HostID = uhc.HostID
		return ret, err
	}

	return uhc, nil
}
