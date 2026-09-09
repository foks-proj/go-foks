// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package chains

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type Probe struct {
	di              DiscoveryInterface
	addr            proto.TCPAddr
	timeout         time.Duration
	res             rem.ProbeRes
	chain           *core.Hostchain
	root            *proto.MerkleRoot
	pz              *proto.PublicZone
	rootCAs         *x509.CertPool
	msess           *merkle.Session
	hostID          *proto.HostID
	prev            *core.Hostchain
	defport         proto.Port
	doCheckHostname bool

	refreshMu  sync.Mutex
	lastFailMu sync.Mutex
	lastFail   error

	// certFails counts consecutive certificate-validation failures against
	// this host. In memory on purpose: the offline path writes nothing to
	// local state, and a counter is not worth being the exception.
	certFails int

	merkleAgentMu sync.Mutex
	ma            *merkle.Agent

	// only for testing
	TestWaitCh            <-chan struct{}
	TestDoneProbeCh       chan<- struct{}
	TestRetryOnMerkleRace bool
}

func (p *Probe) PublicZone() *proto.PublicZone {
	return p.pz
}

func (p *Probe) Chain() *core.Hostchain {
	return p.chain
}

// Hostname is the hostname advertised in the chain itself. The chain sets up
// keys and then signs a public zone. The probe server is the public address
// of this host.
func (p *Probe) Hostname() proto.Hostname {
	return p.CanonicalAddr().Hostname()
}

// HostnameWithOptionalPort returns the canonical hostname of the server, with the
// port included only if it's not the default port. This is suitable for pretty-printing
// FOKS URLs, as we would on the web.
func (p *Probe) HostnameWithOptionalPort() (proto.TCPAddr, error) {
	return p.CanonicalAddr().MaybeElidePort(p.DefPort())
}

func (p *Probe) CanonicalAddr() proto.TCPAddr {
	var zed proto.TCPAddr
	if p.pz == nil {
		return zed
	}
	return p.pz.Services.Probe
}

func (p *Probe) DefPort() proto.Port {
	if p.defport != 0 {
		return p.defport
	}
	return p.di.DefProbePort()
}

func (p *Probe) RootCAs(m MetaContext) (*x509.CertPool, error) {
	if p.rootCAs != nil {
		return p.rootCAs, nil
	}
	ret, _, err := p.di.ProbeRootCAs(m)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (p *Probe) Reconnect(m MetaContext) error {
	return p.refresh(m)
}

func (p *Probe) refresh(m MetaContext) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	p.lastFailMu.Lock()
	err := p.lastFail
	p.lastFailMu.Unlock()

	if err == nil {
		return nil
	}
	return p.Run(m)
}

func (p *Probe) setLastFail(e error) {
	p.lastFailMu.Lock()
	defer p.lastFailMu.Unlock()
	p.lastFail = e
}

// noteCertOutcome records the outcome of one probe and reports whether this
// failure should be called a certificate problem rather than an outage. A
// success clears the count.
//
// It takes two consecutive certificate failures to say so. One is what a
// captive portal produces every time somebody opens a laptop in an airport,
// and a warning that fires there teaches people to dismiss it -- which costs
// exactly the attention the warning exists to buy. Two in a row against a host
// this device has already verified is the shape of an interception.
//
// Note what this does not do: it never suppresses the cached identity. If a
// bad certificate could stop the client serving what it already holds, anyone
// able to present one could switch the app off from the outside.
func (p *Probe) noteCertOutcome(e error) bool {
	p.lastFailMu.Lock()
	defer p.lastFailMu.Unlock()
	if !core.IsCertVerifyError(e) {
		p.certFails = 0
		return false
	}
	p.certFails++
	return p.certFails >= 2
}

func (p *Probe) certFailCount() int {
	p.lastFailMu.Lock()
	defer p.lastFailMu.Unlock()
	return p.certFails
}

func (p *Probe) handleConnectError(e error) bool {
	if !core.IsTransportError(e) {
		return false
	}
	p.setLastFail(e)
	return true
}

func (p *Probe) probe(m MetaContext) error {

	if p.addr.IsZero() {
		return core.MissingHostError{}
	}
	ctx := m.Ctx()

	if p.timeout > 0 {
		var canc func()
		ctx, canc = context.WithTimeout(ctx, p.timeout)
		defer canc()
	}

	host, err := p.addr.Portify(p.DefPort())
	if err != nil {
		return err
	}

	opts := core.NewRpcClientOpts()
	opts.Timeout = 0

	rootCAs, err := p.RootCAs(m)
	if err != nil {
		return err
	}
	gcli, err := p.di.MakeRpcClient(m, host, rootCAs, nil, opts)
	if err != nil {
		return err
	}

	defer gcli.Shutdown()
	cli := core.NewProbeClient(gcli, m)

	// We can't pass anything other but 0 here since we don't always have a hostID
	// It's fine, we might pay the price of a few more links, but it's OK,
	// won't be much bandwidth. Still i think we should fix this. TODO.
	arg := rem.ProbeArg{
		HostchainLastSeqno: 0,
		Hostname:           host.Hostname().Normalize(),
		HostID:             p.hostID,
	}

	p.res, err = cli.Probe(ctx, arg)

	if p.handleConnectError(err) {
		return err
	}

	if err != nil {
		return err
	}

	p.setLastFail(nil)
	p.noteCertOutcome(nil)

	if p.TestDoneProbeCh != nil {
		ch := p.TestDoneProbeCh
		p.TestDoneProbeCh = nil
		ch <- struct{}{}
	}

	return nil
}

func (p *Probe) playChain(m MetaContext) error {
	ch, err := core.PlayChain(p.addr, p.res.Hostchain, p.hostID)
	if err != nil {
		return err
	}
	p.chain = ch
	tmp := ch.HostID()
	p.hostID = &tmp
	return nil
}

func (p *Probe) checkChainAgainstPriorChains(m MetaContext) error {
	return core.CheckChainAgainstPriorChains(*p.chain, p.prev)
}

func (p *Probe) checkSigs(m MetaContext) error {

	err := p.checkMerkleSig(m.Ctx())
	if err != nil {
		return err
	}
	err = p.checkZoneSig(m)
	if err != nil {
		return err
	}
	return nil
}

func (p *Probe) checkZoneSig(m MetaContext) error {
	pz, err := core.CheckZoneSig(*p.chain, p.res)
	if err != nil {
		return err
	}
	p.pz = pz
	return nil
}

func (p *Probe) checkMerkleSig(ctx context.Context) error {

	keys := p.chain.Keys(proto.EntityType_HostMerkleSigner)
	var err error
	var root *proto.MerkleRoot

	for _, key := range keys {
		var ep core.EntityPublic
		ep, err = core.ImportEntityPublic(key)

		if err != nil {
			return err
		}

		root, err = core.Verify2[*proto.MerkleRoot](
			ep,
			p.res.MerkleRoot.Sig,
			&p.res.MerkleRoot.Inner)

		if err == nil {
			p.root = root
			return nil
		}
	}

	return core.MerkleVerifyError("no valid root sig found")
}

func (p *Probe) checkChainAgainstTree(m MetaContext) error {
	tail1 := p.chain.Tail()

	v, err := p.root.GetV()
	if err != nil {
		return err
	}
	if v != proto.MerkleRootVersion_V1 {
		return core.VersionNotSupportedError("merkle tree from future")
	}
	v1 := p.root.V1()
	tail2 := v1.Hostchain

	if !tail1.Eq(tail2) {
		return core.HostchainError("tail didn't match merkle tree")
	}

	return nil
}

func (b *Probe) MerkleAgent(m MetaContext) (*merkle.Agent, error) {
	err := b.refresh(m)
	if err != nil {
		return nil, err
	}
	return b.merkleAgentInner(m)
}

func (b *Probe) merkleAgentInner(m MetaContext) (*merkle.Agent, error) {
	b.merkleAgentMu.Lock()
	defer b.merkleAgentMu.Unlock()
	if b.ma != nil {
		m.Infow("merkleAgentInner", "msg", "reusing merkle agent")
		return b.ma, nil
	}
	rootCAs, err := b.chain.RootCACertPool()
	if err != nil {
		return nil, err
	}
	addr := b.pz.Services.MerkleQuery
	m.Infow("merkleAgentInner", "msg", "connect", "addr", addr)
	ret, err := b.di.MakeMerkleAgent(m, b.chain.HostID(), addr, rootCAs)
	if err != nil {
		return nil, err
	}
	b.ma = ret
	return ret, err
}

func (p *Probe) saveMerkleRoot(m MetaContext) error {

	// We need to stall here, in test, while we trigger a merkle race. Will never be non-nil in
	// production.
	if p.TestWaitCh != nil {
		ch := p.TestWaitCh
		p.TestWaitCh = nil
		<-ch
	}

	// On our first time through, this is going to be nil, meaning we are just reading the most
	// recent merkle root from the DB (since we needed to play the chain to get the host ID).
	// On our second time through, it's because we hit a (very unlikely!!) race in merkle accounting
	// so we reuse the session, and this time a race is fatal.
	if p.msess == nil {
		ma, err := p.merkleAgentInner(m)
		if err != nil {
			return err
		}
		ms := merkle.NewSession(ma)
		err = ms.Init(m.Ctx())
		if err != nil {
			return err
		}
		p.msess = ms
	} else if !p.msess.HostID().Eq(p.chain.HostID()) {
		return core.HostMismatchError{Which: "probe host ID"}
	}

	err := p.msess.Run(m.Ctx(), p.root)
	if err != nil {
		return err
	}
	return nil
}

func (p *Probe) saveHostchain(m MetaContext) error {
	err := p.di.StoreHostchainToDB(m, p.chain)
	if err != nil {
		return err
	}
	// The zone was verified by checkZoneSig earlier in this run; cache it so
	// a later cold start can hydrate offline (see hydrateFromCache).
	err = p.di.StorePublicZoneToDB(m, p.chain.HostID(), p.pz)
	if err != nil {
		return err
	}
	return nil
}

// hydrateFromCache rebuilds the probe's identity -- hostchain and public
// zone -- from the local DB after a network probe failed on transport. Both
// artifacts were fully verified before they were stored, so nothing is
// re-verified here; the last verified identity is simply rehydrated, exactly
// like the client's other verified-on-ingest caches. Worst case it is stale
// (a key rotation or address move the offline device cannot learn about),
// in which case connections fail and read as offline until a real probe
// succeeds again.
//
// Returns true when the probe is usable afterwards.
func (p *Probe) hydrateFromCache(m MetaContext) bool {
	// Hydrate ONLY from rows a fully verified prior run persisted --
	// saveHostchain writes them after every check (prior chains, signatures,
	// merkle inclusion, hostname pin, hostname match) has passed. In-memory
	// state from the CURRENT, failed run must never satisfy this: playChain
	// and checkZoneSig populate p.chain/p.pz from server-supplied data before
	// the merkle and pin checks run, so a transport failure mid-run can leave
	// a self-consistent but never-fully-verified identity in memory -- an
	// attacker on a taken-over hostname could serve exactly that and then
	// drop the merkle query. The DB rows are the verified-on-write source;
	// they also replace any partial in-memory state here.
	if p.hostID == nil {
		return false
	}
	ch, err := loadPrevChain(m, p.di, *p.hostID)
	if err != nil || ch == nil {
		return false
	}
	pz, err := p.di.LoadPublicZoneFromDB(m, *p.hostID)
	if err != nil || pz == nil {
		return false
	}
	p.chain = ch
	p.pz = pz
	return true
}

func (p *Probe) clean() {
	if p.msess != nil {
		p.msess = nil
	}
}

func (p *Probe) Run(m MetaContext) error {
	m = m.WithLogTagI("probe")
	defer p.clean()

	err := p.runOnce(m)

	// We retry once in the case of a merkle rollback error. It should work the second time since
	// we've written down a plausible merkle root, and can ensure that the merkle tree is properly
	// advancing. Likely we'll never hit this race. But we do test it (see TestProbeMekleRace)!
	if _, ok := err.(core.MerkleRollbackError); ok {
		p.TestRetryOnMerkleRace = true
		err = p.runOnce(m)
	}

	if err != nil {
		m.Errorw("probe", "err", err)
	}

	// A transport failure with a locally cached, previously verified identity
	// is survivable: hydrate and proceed offline. The failure is remembered
	// (lastFail), so the next refresh re-probes.
	if err != nil && core.IsTransportError(err) && p.hydrateFromCache(m) {
		// Reaching here means this device has verified this host before --
		// hydrateFromCache only succeeds on a chain and zone an earlier probe
		// accepted. That is exactly the condition under which a certificate
		// failure is worth reporting as such, and a captive portal is not:
		// portals intercept on first contact with a network, not repeatedly
		// against a host already known good.
		if p.noteCertOutcome(err) {
			m.Warnw("probe", "err", err,
				"note", "cannot verify server identity; serving cached identity",
				"certFails", p.certFailCount())
		} else {
			m.Warnw("probe", "err", err,
				"note", "network unreachable; hydrated verified identity from cache")
		}
		p.setLastFail(err)
		return nil
	}

	return err
}

func (p *Probe) runOnce(m MetaContext) error {

	m.Infow("probe", "stage", "start")

	err := p.probe(m)
	if err != nil {
		return err
	}

	err = p.playChain(m)
	if err != nil {
		return err
	}

	if p.prev == nil {
		p.prev, err = loadPrevChain(m, p.di, *p.hostID)
		if err != nil {
			return err
		}
	}

	err = p.checkChainAgainstPriorChains(m)
	if err != nil {
		return err
	}

	err = p.checkSigs(m)
	if err != nil {
		return err
	}

	err = p.checkChainAgainstTree(m)
	if err != nil {
		return err
	}

	err = p.saveMerkleRoot(m)
	if err != nil {
		return err
	}

	err = p.checkPin(m)
	if err != nil {
		return err
	}

	err = p.checkHostname(m)
	if err != nil {
		return err
	}

	err = p.saveHostchain(m)
	if err != nil {
		return err
	}

	m.Infow("probe", "stage", "complete")

	return nil
}

// A "pin" is a mapping of Hostname -> HostID, akin to TLS Cert-pinning.
// It should never change once established. It's to prevent malicious domain-takeover
// attacks. If the intent is really to remap foo.bar.com to point to a new HostID
// (maybe the old one was lost?), then manual intervention is required.
// Don't pin raw IP addresses -- this shows up in test.
func (p *Probe) checkPin(m MetaContext) error {
	hn := p.addr.Hostname().Normalize()
	if hn.IsIPAddr() {
		m.Infow("probe", "hn", hn, "msg", "skipping pin check for IP address")
		return nil
	}
	hid := p.chain.HostID()
	return p.di.CheckPin(m, hn, hid)
}

func (p *Probe) checkHostname(m MetaContext) error {
	if p.doCheckHostname &&
		!p.addr.NormEqIgnorePort(p.PublicZone().Services.Probe) {
		return core.HostMismatchError{Which: "probe hostname"}
	}
	return nil
}

func (p *Probe) RegGCli(m MetaContext) (*core.RpcClient, error) {
	gcli, err := p.RPCClient(m, proto.ServerType_Reg, nil)
	if err != nil {
		return nil, err
	}
	return gcli, nil
}

func (p *Probe) RegCli(m MetaContext) (*rem.RegClient, error) {
	gcli, err := p.RegGCli(m)
	if err != nil {
		return nil, err
	}
	tmp := core.NewRegClient(gcli, m)
	ret := &tmp
	return ret, nil
}

func (p *Probe) WithRegCli(m MetaContext, f func(rem.RegClient) error) error {
	gcli, err := p.RegGCli(m)
	if err != nil {
		return err
	}
	defer gcli.Shutdown()
	cli := core.NewRegClient(gcli, m)
	return f(cli)
}

func (p *Probe) RPCClient(m MetaContext, st proto.ServerType, cliCert *tls.Certificate) (*core.RpcClient, error) {

	if p == nil {
		return nil, core.InternalError("probe was nil")
	}
	err := p.refresh(m)
	if err != nil {
		return nil, err
	}

	if p.PublicZone() == nil {
		return nil, core.InternalError("probe has no public zone")
	}
	pool, err := p.Chain().RootCACertPool()
	if err != nil {
		return nil, err
	}
	srv := p.PublicZone().Services.Select(st)
	if srv == nil {
		return nil, core.InternalError("no server of type " + st.String())
	}

	opts := core.NewRpcClientOpts().WithName("probe")

	// For some clients, we create a hook that, right after a connection,
	// sends an RPC to the server to to select a vhost for the
	// rest of the session.
	opts.ConfigConnHook = core.MakeConfigConnHook(st, p.chain.HostID(), nil)

	return p.di.MakeRpcClient(m, *srv, pool, cliCert, opts)
}

func (p *Probe) IsConnected() bool {
	p.lastFailMu.Lock()
	defer p.lastFailMu.Unlock()
	return p.lastFail == nil
}

func (p *Probe) Connectivity() error {
	p.lastFailMu.Lock()
	defer p.lastFailMu.Unlock()
	return p.lastFail
}
