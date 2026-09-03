// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package chains

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type MetaContext interface {
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Ctx() context.Context
	WithLogTagI(tag string) MetaContext
	WarnwWithContext(ctx context.Context, msg string, keysAndValues ...interface{})
}

type DiscoveryInterface interface {
	MakeRpcClient(m MetaContext, addr proto.TCPAddr, rootCAs *x509.CertPool, cliCert *tls.Certificate, opts *core.RpcClientOpts) (*core.RpcClient, error)
	LoadHostchainFromDB(m MetaContext, hostID proto.HostID) (*core.Hostchain, error)
	MakeMerkleAgent(m MetaContext, hostID proto.HostID, addr proto.TCPAddr, rootCAs *x509.CertPool) (*merkle.Agent, error)
	StoreHostchainToDB(m MetaContext, hc *core.Hostchain) error
	CheckPin(m MetaContext, hn proto.Hostname, hid proto.HostID) error
	ProbeRootCAs(m MetaContext) (*x509.CertPool, []string, error)
	HostsBeacon(m MetaContext) (proto.TCPAddr, error)
	DefProbePort() proto.Port
}

type DiscoveryMgr struct {
	cacheLock   sync.RWMutex
	probes      map[proto.HostID]*Probe
	hostAddrMap map[proto.TCPAddr]proto.HostID
	resolvMap   map[proto.HostID]proto.TCPAddr

	di DiscoveryInterface

	cliLock sync.Mutex
	cli     *core.RpcClient
}

func NewDiscoveryMgr(di DiscoveryInterface) *DiscoveryMgr {
	return &DiscoveryMgr{
		probes:      make(map[proto.HostID]*Probe),
		hostAddrMap: make(map[proto.TCPAddr]proto.HostID),
		resolvMap:   make(map[proto.HostID]proto.TCPAddr),
		di:          di,
	}
}

type ResolveOpts struct {
	Timeout time.Duration
}

type ResolveRes struct {
	Addr  proto.TCPAddr
	Probe *Probe
}

type ProbeArg struct {
	HostID  proto.HostID
	Addr    proto.TCPAddr
	Timeout time.Duration
	DefPort proto.Port
	Fresh   bool
	RootCAs *x509.CertPool

	prev          *core.Hostchain // previous hostchain, preloaded
	checkHostname bool            // if we did a beacon resolve, we need to check hostchain against probe zone
}

func (d ProbeArg) check() error {
	if d.HostID.IsZero() && d.Addr.IsZero() {
		return core.InternalError("bad arguement to Probe, no lookup mechanism given")
	}
	return nil
}

func (d *DiscoveryMgr) checkCacheForProbe(arg ProbeArg) *Probe {

	d.cacheLock.RLock()
	defer func() {
		d.cacheLock.RUnlock()
	}()
	if arg.Fresh {
		return nil
	}
	hid := arg.HostID
	if hid.IsZero() {
		hid = d.hostAddrMap[arg.Addr]
	}
	if hid.IsZero() {
		return nil
	}
	ret, ok := d.probes[arg.HostID]
	if ok {
		return ret
	}
	return nil
}

func loadPrevChain(m MetaContext, di DiscoveryInterface, id proto.HostID) (*core.Hostchain, error) {
	ch, err := di.LoadHostchainFromDB(m, id)
	if err != nil && errors.Is(err, core.RowNotFoundError{}) {
		// No prior chain, this is OK
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ch, nil
}

func (d *DiscoveryMgr) resolveHostAddr(m MetaContext, arg *ProbeArg) error {
	if !arg.Addr.IsZero() {
		return nil
	}
	addrp, prev, err := d.ResolveHostAddr(m, arg.HostID)
	if err != nil {
		return err
	}
	arg.Addr = *addrp
	arg.prev = prev
	arg.checkHostname = true
	return nil
}

func (d *DiscoveryMgr) ResolveHostAddr(m MetaContext, hostID proto.HostID) (*proto.TCPAddr, *core.Hostchain, error) {

	prev, err := loadPrevChain(m, d.di, hostID)
	if err != nil {
		return nil, nil, err
	}

	if prev != nil && !prev.Addr().IsZero() {
		tmp := prev.Addr()
		return &tmp, prev, nil
	}

	d.cacheLock.RLock()
	addr := d.resolvMap[hostID]
	d.cacheLock.RUnlock()

	if !addr.IsZero() {
		return &addr, nil, nil
	}

	addrp, err := d.resolveViaBeacon(m, hostID)
	if err != nil {
		return nil, nil, err
	}

	d.cacheLock.Lock()
	d.resolvMap[hostID] = *addrp
	d.cacheLock.Unlock()

	return addrp, nil, nil
}

// Probe returns (non-nil, nil) on success. It mostly returns (nil, non-nil)
// on error. But in the case of a ConnectinoError, it will return (non-nil, non-nil)
// so that the caller can try again later.
func (d *DiscoveryMgr) Probe(m MetaContext, arg ProbeArg) (*Probe, error) {

	pr, cached, err := d.makeProbe(m, arg)
	if err != nil {
		return nil, err
	}
	if cached {
		return pr, nil
	}
	err = pr.Run(m)

	// If we failed to connect, then we can still return the dead
	// probe, and we can try to rejeuvenate it later.
	if core.IsTransportError(err) {
		return pr, err
	}

	if err != nil {
		return nil, err
	}

	d.cacheProbe(pr)
	return pr, nil
}

func (d *DiscoveryMgr) cacheProbe(pr *Probe) {
	d.cacheLock.Lock()
	defer d.cacheLock.Unlock()
	hostID := pr.Chain().HostID()
	addr := pr.CanonicalAddr()
	d.probes[hostID] = pr
	d.hostAddrMap[addr] = hostID
	d.resolvMap[hostID] = addr
}

func (d *DiscoveryMgr) MakeProbe(m MetaContext, arg ProbeArg) (*Probe, error) {
	ret, _, err := d.makeProbe(m, arg)
	return ret, err
}

func (d *DiscoveryMgr) makeProbe(m MetaContext, arg ProbeArg) (*Probe, bool, error) {

	if err := arg.check(); err != nil {
		return nil, false, err
	}

	if ret := d.checkCacheForProbe(arg); ret != nil {
		return ret, true, nil
	}

	err := d.resolveHostAddr(m, &arg)
	if err != nil {
		return nil, false, err
	}

	pr := &Probe{
		di:      d.di,
		addr:    arg.Addr,
		prev:    arg.prev,
		timeout: arg.Timeout,
		defport: arg.DefPort,
		rootCAs: arg.RootCAs,
	}
	if !arg.HostID.IsZero() {
		pr.hostID = &arg.HostID
	}
	return pr, false, nil
}

func (d *DiscoveryMgr) getBeaconCli(m MetaContext) (*rem.BeaconClient, error) {
	gcli, err := d.getBeaconGCli(m)
	if err != nil {
		return nil, err
	}
	ret := core.NewBeaconClient(gcli, m)
	return &ret, nil
}

func (d *DiscoveryMgr) getBeaconGCli(m MetaContext) (*core.RpcClient, error) {

	d.cliLock.Lock()
	cli := d.cli
	d.cliLock.Unlock()

	if cli != nil {
		return cli, nil
	}

	addr, err := d.di.HostsBeacon(m)
	if err != nil {
		return nil, err
	}
	if addr == "" {
		return nil, core.NoDefaultHostError{}
	}
	rootCAs, _, err := d.di.ProbeRootCAs(m)
	if err != nil {
		return nil, err
	}
	ret, err := d.di.MakeRpcClient(m, addr, rootCAs, nil, nil)
	if err != nil {
		return nil, err
	}

	d.cliLock.Lock()
	d.cli = cli
	d.cliLock.Unlock()

	return ret, nil
}

func (d *DiscoveryMgr) resolveViaBeacon(m MetaContext, i proto.HostID) (*proto.TCPAddr, error) {
	cli, err := d.getBeaconCli(m)
	if err != nil {
		return nil, err
	}
	res, err := cli.BeaconLookup(m.Ctx(), i)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
