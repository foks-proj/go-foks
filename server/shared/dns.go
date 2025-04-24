// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"net"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/miekg/dns"
)

// Check that the CNAME record From points to To, and use the specified DNS servers to
// check / double-check / triangulate
type cnameChecker struct {
	servers    []proto.TCPAddr
	from       proto.Hostname
	to         proto.Hostname
	timeout    time.Duration
	redirector func(proto.TCPAddr) (proto.TCPAddr, error)
}

type nsServerSet struct {
	servers []proto.TCPAddr
	mp      map[proto.Hostname]bool
}

func (n *nsServerSet) isEmpty() bool {
	return len(n.servers) == 0
}

func (n *nsServerSet) all() []proto.TCPAddr {
	if n == nil {
		return nil
	}
	return n.servers
}

func (n *nsServerSet) AssertEq(m *nsServerSet) error {
	if len(n.servers) != len(m.servers) {
		return core.DNSError{Stage: "AssertEq (len)", Err: core.HostMismatchError{}}
	}
	for k := range n.mp {
		if !m.mp[k] {
			return core.DNSError{Stage: "AssertEq (inclusion)", Err: core.HostMismatchError{}}
		}
	}
	return nil
}

func (c *cnameChecker) checkArgs() (err error) {
	if c.from == "" {
		return core.BadArgsError("From cannot be empty")
	}
	if len(c.from.Split()) < 2 {
		return core.BadArgsError("From must have at least 2 parts")
	}
	if c.to == "" {
		return core.BadArgsError("To cannot be empty")
	}
	if len(c.to.Split()) < 2 {
		return core.BadArgsError("To must have at least 2 parts")
	}
	if len(c.servers) == 0 {
		return core.BadArgsError("Server cannot be empty")
	}

	// Use the identity function as the default redirector
	if c.redirector == nil {
		c.redirector = func(srv proto.TCPAddr) (proto.TCPAddr, error) { return srv, nil }
	}
	return nil
}

func newNsServerSet(lst []proto.Hostname) *nsServerSet {
	mp := make(map[proto.Hostname]bool)
	var srvs []proto.TCPAddr
	for _, h := range lst {
		h = h.Normalize()
		mp[h] = true
		srvs = append(srvs, proto.NewTCPAddrPortOpt(h, nil))
	}
	return &nsServerSet{
		servers: srvs,
		mp:      mp,
	}
}

func newNsServerSetWithAddrs(lst []proto.TCPAddr) *nsServerSet {
	mp := make(map[proto.Hostname]bool)
	var srvs []proto.TCPAddr
	for _, h := range lst {
		mp[h.Hostname().Normalize()] = true
		srvs = append(srvs, h)
	}
	return &nsServerSet{
		servers: srvs,
		mp:      mp,
	}
}

func (c *cnameChecker) nsLookupSingle(
	m MetaContext,
	host proto.Hostname,
	srv proto.TCPAddr,
) (*nsServerSet, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host.String()), dns.TypeNS)

	srv, err := c.mapServer(srv)
	if err != nil {
		return nil, err
	}

	// Set up the DNS client and send the query to the specified server
	client := new(dns.Client)
	response, _, err := client.Exchange(msg, srv.String())
	if err != nil {
		return nil, core.DNSError{Stage: "exchange", Err: err}
	}

	// Loop through the answer section to find the CNAME record
	var lst []proto.Hostname
	arr := response.Answer
	if len(arr) == 0 {
		arr = response.Ns
	}
	for _, ans := range arr {
		if ns, ok := ans.(*dns.NS); ok {
			hn := proto.Hostname(ns.Ns)
			lst = append(lst, hn)
		}
	}
	m.Infow("nsLookup", "srv", srv, "qry", host, "ns", lst)
	return newNsServerSet(lst), nil
}

func (c *cnameChecker) mapServer(srv proto.TCPAddr) (proto.TCPAddr, error) {
	srv, err := c.redirector(srv)
	var zed proto.TCPAddr
	if err != nil {
		return zed, core.DNSError{Stage: "redirector", Err: err}
	}
	srv, err = srv.Portify(53)
	if err != nil {
		return zed, core.DNSError{Stage: "portify", Err: err}
	}
	return srv, nil
}

func (c *cnameChecker) cnameLookupSingle(
	m MetaContext,
	host proto.Hostname,
	srv proto.TCPAddr,
) (*proto.Hostname, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host.String()), dns.TypeCNAME)

	srv, err := c.mapServer(srv)
	if err != nil {
		return nil, err
	}

	// Set up the DNS client and send the query to the specified server
	client := new(dns.Client)
	client.Dialer = &net.Dialer{Timeout: c.timeout}
	response, _, err := client.Exchange(msg, srv.String())
	if err != nil {
		return nil, core.DNSError{Stage: "exchange", Err: err}
	}

	// Loop through the answer section to find the CNAME record
	var ret *proto.Hostname
	for _, ans := range response.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			targ := proto.Hostname(cname.Target)
			m.Infow("cnameLookup", "srv", srv, "qry", host, "cname", targ)
			// Return the first CNAME record target
			if ret == nil {
				ret = &targ
				continue
			}
			if !ret.NormEq(targ) {
				m.Warnw("cnameLookup", "err", "CNAME mismatch", "expected", targ, "got", *ret)
				return nil, core.DNSError{Stage: "cnameLookup", Err: core.HostMismatchError{}}
			}
		}
	}
	if ret == nil {
		return nil, core.DNSError{Stage: "cnameLookup", Err: core.NotFoundError("no CNAME record found")}
	}
	return ret, nil
}

func (c *cnameChecker) strictNSLookup(
	m MetaContext,
	host proto.Hostname,
	servers *nsServerSet,
) (*nsServerSet, error) {
	if servers == nil || len(servers.servers) == 0 {
		return nil, core.InternalError("servers cannot be nil")
	}
	var ret *nsServerSet
	for _, srv := range servers.servers {
		tmp, err := c.nsLookupSingle(m, host, srv)
		if err != nil {
			return nil, err
		}
		if ret == nil {
			ret = tmp
			continue
		}
		err = ret.AssertEq(tmp)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (c *cnameChecker) traverseNSServerGraph(
	m MetaContext,
) (*nsServerSet, error) {

	// Given aa.bb.cc.dd.com, return { dd.com, cc.dd.com, bb.cc.dd.com, aa.bb.cc.dd.com }
	doms := core.Reverse(c.from.AllSuperdomains())

	prev := newNsServerSetWithAddrs(c.servers)

	for _, d := range doms {
		next, err := c.strictNSLookup(m, d, prev)
		if err != nil {
			return nil, err
		}
		if next.isEmpty() {
			return prev, nil
		}
		prev = next
	}
	return prev, nil
}

func (c *cnameChecker) strictCNAMECheck(
	m MetaContext,
	finalNs *nsServerSet,
) error {
	var checked bool
	for _, srv := range finalNs.all() {
		tmp, err := c.cnameLookupSingle(m, c.from, srv)
		if err != nil {
			return err
		}
		if !tmp.NormEq(c.to.WithTrailingDot()) {
			m.Warnw("strictCNAMECheck", "err", "CNAME mismatch", "expected", c.to, "got", *tmp)
			return core.DNSError{Stage: "strictCNAMECheck", Err: core.HostMismatchError{}}
		}
		checked = true
	}
	if !checked {
		m.Warnw("strictCNAMECheck", "err", "no CNAMEs found")
		return core.DNSError{Stage: "strictCNAMECheck", Err: core.NotFoundError("no CNAME record found")}
	}
	return nil
}

// CheckCNAME checks that the hostname From maps to To via the given set of servers.
// It will use those initial servers to find NS records, and then will itetatively
// traverse across the From domain. Along the way, it will check that all the
// server agree and return exactly the same set of NS records.
func CheckCNAME(
	m MetaContext,
	from proto.Hostname,
	to proto.Hostname,
	servers []proto.TCPAddr,
	timeout time.Duration,
	redirector func(proto.TCPAddr) (proto.TCPAddr, error), // mainly useful for testing
) error {
	c := cnameChecker{
		from:       from,
		to:         to,
		servers:    servers,
		timeout:    timeout,
		redirector: redirector,
	}
	err := c.checkArgs()
	if err != nil {
		return err
	}
	finalNs, err := c.traverseNSServerGraph(m)
	if err != nil {
		return err
	}
	err = c.strictCNAMECheck(m, finalNs)
	if err != nil {
		return err
	}
	return nil
}
