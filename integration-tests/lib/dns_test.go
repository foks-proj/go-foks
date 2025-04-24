// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeDNSServer struct {
	addr   proto.TCPAddr
	port   proto.Port
	cnames map[proto.Hostname]proto.Hostname
	ns     map[proto.Hostname][]proto.Hostname
	conn   *net.UDPConn
}

func (f *fakeDNSServer) ServeDNS(w dns.ResponseWriter, inMsg *dns.Msg) {
	outMsg := new(dns.Msg)
	outMsg.SetReply(inMsg)
	outMsg.Authoritative = true

	for _, q := range inMsg.Question {
		switch q.Qtype {
		case dns.TypeNS:
			ns, ok := f.ns[proto.Hostname(q.Name)]
			if ok {
				for _, n := range ns {
					outMsg.Answer = append(outMsg.Answer, &dns.NS{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						Ns: n.String(),
					})
				}
			}
		case dns.TypeCNAME:
			cname, ok := f.cnames[proto.Hostname(q.Name)]
			if ok {
				outMsg.Answer = append(outMsg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target: cname.String(),
				})
			}
		}
	}
	if err := w.WriteMsg(outMsg); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

func (f *fakeDNSServer) init(ctx context.Context) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	// Get the assigned port
	addr := conn.LocalAddr().(*net.UDPAddr)
	f.port = proto.Port(addr.Port)
	fmt.Printf("Runnning fake %s on port %d\n", f.addr, f.port)
	f.conn = conn
	return nil
}

func (f *fakeDNSServer) run(doneCh <-chan struct{}) error {

	// Create and configure the DNS server
	server := &dns.Server{
		Handler:    f,
		PacketConn: f.conn,
	}

	errCh := make(chan error, 1)

	go func() {
		err := server.ActivateAndServe()
		errCh <- err
	}()

	defer func() {
		_ = server.Shutdown()
		f.conn.Close()
	}()

	select {
	case <-doneCh:
		return nil
	case err := <-errCh:
		return err
	}
}

type fakeInternet struct {
	dns []*fakeDNSServer
}

func (f *fakeInternet) init(ctx context.Context) error {
	for _, s := range f.dns {
		err := s.init(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeInternet) run(ctx context.Context) error {
	doneCh := make(chan struct{})
	resCh := make(chan error, len(f.dns))
	for _, s := range f.dns {
		go func(s *fakeDNSServer) {
			resCh <- s.run(doneCh)
		}(s)
	}
	<-ctx.Done()
	close(doneCh)
	for range f.dns {
		err := <-resCh
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeInternet) redirector() func(addr proto.TCPAddr) (proto.TCPAddr, error) {
	return func(addr proto.TCPAddr) (proto.TCPAddr, error) {
		for _, s := range f.dns {
			if s.addr.Hostname().NormEq(addr.Hostname()) {
				return proto.NewTCPAddr("localhost", s.port), nil
			}
		}
		return addr, nil
	}
}

func TestCheckCNAME(t *testing.T) {

	catsIoNs := []proto.Hostname{
		proto.Hostname("ns-825.awsdns-39.net."),
		proto.Hostname("ns-1024.awsdns-35.org."),
		proto.Hostname("ns-434.awsdns-10.com."),
		proto.Hostname("ns-631.awsdns-90.co.uk."),
	}
	vCatsIoNs := []proto.Hostname{
		proto.Hostname("ns-1.awsdns-1.co.uk."),
		proto.Hostname("ns-2.awsdns-2.org."),
		proto.Hostname("ns-3.awsdns-3.com."),
		proto.Hostname("ns-4.awsdns-4.net."),
	}

	rootNs := map[proto.Hostname][]proto.Hostname{
		proto.Hostname("cats.io."): catsIoNs,
	}

	cloudflare := fakeDNSServer{
		addr: proto.TCPAddr("1.1.1.1"),
		ns:   rootNs,
	}

	google := fakeDNSServer{
		addr: proto.TCPAddr("8.8.8.8"),
		ns:   rootNs,
	}

	topNs := map[proto.Hostname][]proto.Hostname{
		proto.Hostname("v.cats.io."): vCatsIoNs,
	}

	awsTopUk := fakeDNSServer{
		addr: proto.TCPAddr("ns-631.awsdns-90.co.uk."),
		ns:   topNs,
	}

	awsTopOrg := fakeDNSServer{
		addr: proto.TCPAddr("ns-1024.awsdns-35.org."),
		ns:   topNs,
	}

	awsTopCom := fakeDNSServer{
		addr: proto.TCPAddr("ns-434.awsdns-10.com."),
		ns:   topNs,
	}

	awsTopNet := fakeDNSServer{
		addr: proto.TCPAddr("ns-825.awsdns-39.net."),
		ns:   topNs,
	}

	from := proto.Hostname("meow.v.cats.io.")
	to := proto.Hostname("hosting.ne43.cloud.")

	cnames := map[proto.Hostname]proto.Hostname{from: to}

	awsUk := fakeDNSServer{
		addr:   proto.TCPAddr("ns-1.awsdns-1.co.uk."),
		cnames: cnames,
	}
	awsOrg := fakeDNSServer{
		addr:   proto.TCPAddr("ns-2.awsdns-2.org."),
		cnames: cnames,
	}
	awsCom := fakeDNSServer{
		addr:   proto.TCPAddr("ns-3.awsdns-3.com."),
		cnames: cnames,
	}
	awsNet := fakeDNSServer{
		addr:   proto.TCPAddr("ns-4.awsdns-4.net."),
		cnames: cnames,
	}

	internet := fakeInternet{
		dns: []*fakeDNSServer{&cloudflare, &google, &awsTopUk, &awsTopOrg, &awsTopCom, &awsTopNet,
			&awsUk, &awsOrg, &awsCom, &awsNet},
	}

	m := globalTestEnv.MetaContext()
	m, cancel := m.WithContextCancel()

	err := internet.init(m.Ctx())
	require.NoError(t, err)

	resCh := make(chan error, 1)
	go func() {
		err := internet.run(m.Ctx())
		resCh <- err
	}()

	runIt := func() error {
		return shared.CheckCNAME(m, from, to,
			[]proto.TCPAddr{google.addr, cloudflare.addr},
			5*time.Second, internet.redirector())
	}
	err = runIt()
	require.NoError(t, err)

	// Test if the root-level DNS gives conflicting answers for authoritative NSes
	google.ns = map[proto.Hostname][]proto.Hostname{
		proto.Hostname("cats.io."): catsIoNs[1:],
	}
	err = runIt()
	require.Error(t, err)
	require.Equal(t, core.DNSError{Stage: "AssertEq (len)", Err: core.HostMismatchError{}}, err)

	google.ns = map[proto.Hostname][]proto.Hostname{
		proto.Hostname("cats.io."): append([]proto.Hostname{"mamma.net."}, catsIoNs[1:]...),
	}
	err = runIt()
	require.Error(t, err)
	require.Equal(t, core.DNSError{Stage: "AssertEq (inclusion)", Err: core.HostMismatchError{}}, err)

	google.ns = rootNs
	awsNet.cnames = map[proto.Hostname]proto.Hostname{from: proto.Hostname("hosting.ne43.ru.")}
	err = runIt()
	require.Error(t, err)
	require.Equal(t, core.DNSError{Stage: "strictCNAMECheck", Err: core.HostMismatchError{}}, err)

	cancel()
	err = <-resCh
	require.NoError(t, err)
}
