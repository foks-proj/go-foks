// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"golang.org/x/crypto/acme/autocert"
)

type AutocertDoneResult struct {
	Etime time.Time
}

type AutocertDoer interface {
	Start(m MetaContext) error
	Stop()
	DoOne(m MetaContext, pkg AutocertPackage) (*AutocertDoneResult, error)
	SetBindAddr(t proto.TCPAddr)
	GetBindAddr() proto.TCPAddr
}

// RealAutocertDoer listens on Port for connections proving ownership
// of hostname. It will yield a Key/Cert pair for a valid X509/TLS
// cert for that hostname, signed by Let's Encrypt's CA.
type RealAutocertDoer struct {
	mgr     *autocert.Manager
	handler http.Handler
	srv     *http.Server
	g       *GlobalContext
	addr    proto.TCPAddr
}

var _ AutocertDoer = &RealAutocertDoer{}

func NewRealAutocertDoer() *RealAutocertDoer {
	return &RealAutocertDoer{
		mgr: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
		},
	}
}

func (a *RealAutocertDoer) SetBindAddr(addr proto.TCPAddr) {
	a.addr = addr
}

func (a *RealAutocertDoer) GetBindAddr() proto.TCPAddr {
	return a.addr
}

func (a *RealAutocertDoer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	m := NewMetaContextBackground(a.g)
	m.Debugw("autocert", "req", req.RequestURI)
	a.handler.ServeHTTP(resp, req)
}

func (a *RealAutocertDoer) startupServer(m MetaContext) error {
	addr, err := a.addr.Portify(proto.Port(80))
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:    addr.String(),
		Handler: a,
	}
	a.g = m.G()
	a.srv = server
	a.handler = a.mgr.HTTPHandler(nil)
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	p := port(listener)
	m.Infow("autocertMgr", "stage", "start", "msg", "listening", "port", p, "bind_addr", addr)
	go func() {
		err := server.Serve(listener)
		if err != http.ErrServerClosed {
			m.Errorw("autocert", "err", err)
		}
	}()
	return nil
}

func (a *RealAutocertDoer) Start(m MetaContext) error {
	return a.startupServer(m)
}

func (a *RealAutocertDoer) Stop() {
	a.srv.Close()
}

func (a *RealAutocertDoer) DoOne(m MetaContext, pkg AutocertPackage) (*AutocertDoneResult, error) {

	m.Debugw("RealAutocertDoer.DoOne", "hn", pkg.Hostname)

	res, err := a.fetchCerts(m, pkg)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func getExpireTimeFromTLSCert(cert *tls.Certificate) (time.Time, error) {
	var zed time.Time
	if cert == nil {
		return zed, core.NotFoundError("no cert provided")
	}
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter, nil
	}
	if len(cert.Certificate) == 0 {
		return zed, core.NotFoundError("no certs in chain")
	}
	tmp, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return zed, err
	}
	return tmp.NotAfter, nil
}

func (a *RealAutocertDoer) fetchCerts(
	m MetaContext,
	pkg AutocertPackage,
) (
	*AutocertDoneResult,
	error,
) {
	m.Debugw("autocert", "msg", "fetching certs", "serverName", string(pkg.Hostname), "addr", a.addr, "styp", pkg.ServerType.String())

	var cert *tls.Certificate

	type result struct {
		res *AutocertDoneResult
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		var err error
		var exp time.Time
		cert, err = a.mgr.GetCertificate(&tls.ClientHelloInfo{
			ServerName: string(pkg.Hostname),
		})
		if err != nil {
			m.Warnw("autocert", "msg", "failed to fetch certs", "err", err)
		} else {
			exp, err = getExpireTimeFromTLSCert(cert)
			if err != nil {
				m.Warnw("autocert", "msg", "failed to get expiry from new cert", "err", err)
			}
		}
		resCh <- result{res: &AutocertDoneResult{Etime: exp}, err: err}
	}()

	timeout := 30 * time.Second
	if pkg.Timeout != 0 {
		timeout = pkg.Timeout
	}

	var res result
	select {
	case res = <-resCh:
		if res.err != nil {
			return nil, res.err
		}
	case <-m.G().Clock().After(timeout):
		return nil, core.TimeoutError{}
	}

	err := storeAutocert(m, pkg, cert)
	if err != nil {
		return nil, err
	}

	return &AutocertDoneResult{Etime: res.res.Etime}, nil
}
