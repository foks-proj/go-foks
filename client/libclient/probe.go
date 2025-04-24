// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type DiscoveryEngine struct{}

func UpcastChainsContext(m chains.MetaContext) (MetaContext, error) {
	ret, ok := m.(MetaContext)
	if !ok {
		return ret, core.InternalError("chains.MetaContext is not a libclient.MetaContext")
	}
	return ret, nil
}

func (e *DiscoveryEngine) MakeMerkleAgent(mc chains.MetaContext, hostID proto.HostID, addr proto.TCPAddr, rootCAs *x509.CertPool) (*merkle.Agent, error) {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return nil, err
	}
	return NewMerkleAgent(m.G(), hostID, addr, rootCAs), nil
}

func (e *DiscoveryEngine) MakeRpcClient(mc chains.MetaContext, addr proto.TCPAddr, rootCAs *x509.CertPool, cliCert *tls.Certificate, opts *core.RpcClientOpts) (*core.RpcClient, error) {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return nil, err
	}
	return NewRpcClient(m.G(), addr, rootCAs, cliCert, opts), nil
}

func (e *DiscoveryEngine) LoadHostchainFromDB(mc chains.MetaContext, hid proto.HostID) (*core.Hostchain, error) {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return nil, err
	}

	var raw proto.HostchainState
	_, err = m.DbGet(&raw, DbTypeHard, &hid, lcl.DataType_Hostchain, core.EmptyKey{})
	if err != nil {
		return nil, err
	}
	ret := core.NewHostchain()
	err = ret.Import(raw)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (e *DiscoveryEngine) StoreHostchainToDB(mc chains.MetaContext, hc *core.Hostchain) error {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return err
	}
	exp, err := hc.Export()
	if err != nil {
		return err
	}
	hid := hc.HostID()
	err = m.DbPut(DbTypeHard, PutArg{
		Scope: &hid,
		Typ:   lcl.DataType_Hostchain,
		Key:   core.EmptyKey{},
		Val:   &exp,
	})
	if err != nil {
		return err
	}
	m.Infow("StoreHostchainToDB", "obj", exp)
	return nil
}

func (e *DiscoveryEngine) CheckPin(mc chains.MetaContext, hn proto.Hostname, hid proto.HostID) error {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return err
	}

	dbKey := core.KVKey("hostID-pin:" + hn.String())
	var existing proto.HostID
	_, err = m.DbGetGlobalKV(&existing, DbTypeHard, dbKey)

	var found bool
	if err != nil && errors.Is(err, core.RowNotFoundError{}) {
		err = nil
	} else if err != nil {
		return err
	} else {
		found = true
	}

	if err != nil {
		return err
	}

	if found && !existing.Eq(hid) {
		return core.HostPinError{
			Host: hn,
			Old:  existing,
			New:  hid,
		}
	}

	// No need to rewrite the pin, it's already correct.
	if found {
		return nil
	}

	err = m.DbPut(DbTypeHard, PutArg{
		Key: dbKey,
		Val: &hid,
	})

	if err != nil {
		return err
	}
	return nil
}

func (e *DiscoveryEngine) DefProbePort() proto.Port {
	return DefProbePort
}

func (e *DiscoveryEngine) ProbeRootCAs(mc chains.MetaContext) (*x509.CertPool, []string, error) {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return nil, nil, err
	}
	return m.G().Cfg().ProbeRootCAs(m.Ctx())
}

func (e *DiscoveryEngine) HostsBeacon(mc chains.MetaContext) (proto.TCPAddr, error) {
	m, err := UpcastChainsContext(mc)
	if err != nil {
		return "", err
	}
	return m.G().Cfg().HostsBeacon(), nil
}

var _ chains.DiscoveryInterface = (*DiscoveryEngine)(nil)
var _ chains.MetaContext = MetaContext{}

type ProbeCollection struct {
	sync.RWMutex
	m  map[proto.HostID]*chains.Probe
	lt core.Locktab[proto.HostID]
}

func (c *ProbeCollection) getFromCache(hid proto.HostID) *chains.Probe {
	c.RLock()
	defer c.RUnlock()
	if c.m == nil {
		return nil
	}
	return c.m[hid]
}

func (c *ProbeCollection) setInCache(hid proto.HostID, p *chains.Probe) {
	c.Lock()
	defer c.Unlock()
	if c.m == nil {
		c.m = make(map[proto.HostID]*chains.Probe)
	}
	c.m[hid] = p
}

func (c *ProbeCollection) Get(m MetaContext, hid proto.HostID) (*chains.Probe, error) {

	// Single flight all action for the hostID
	lte := c.lt.Acquire(hid)
	defer lte.Release()

	ret := c.getFromCache(hid)
	if ret != nil {
		return ret, nil
	}

	ret, err := m.Probe(chains.ProbeArg{HostID: hid})
	if err != nil {
		return nil, err
	}
	c.setInCache(hid, ret)
	return ret, nil
}
