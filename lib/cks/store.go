// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cks

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/clockwork"
)

type Tx interface {
}

type Index struct {
	HostID core.HostID
	Type   proto.CKSAssetType
}

func (i Index) Short() shortIndex {
	return shortIndex{
		hostID: i.HostID.Short,
		typ:    i.Type,
	}
}

type shortIndex struct {
	hostID core.ShortHostID
	typ    proto.CKSAssetType
}

type EncData struct {
	KeyBox  proto.CKSBox
	KeyID   proto.EntityID
	Cert    proto.CKSCertChain
	Etime   time.Time
	Primary bool
}

type Storer interface {
	Put(context.Context, Tx, Index, EncData) error
	Get(context.Context, Tx, Index) ([]EncData, error)
}

type HostMapper interface {
	HostIDForHostname(context.Context, proto.Hostname) (*core.HostID, error)
}

type node struct {
	sync.Mutex
	id   Index
	time time.Time // when it was read from DB
	data *CertSet
}

// CKS = "Crypto key store." For storing x509 keys and certs in the main database, with one layer
// of simple and flexible encryption and with a fast in-memory cache.
type CKS struct {
	sync.Mutex
	keyring         *Keyring
	backend         Storer
	mapper          HostMapper
	refreshInternal time.Duration
	cache           map[shortIndex]*node
	clock           clockwork.Clock
}

func NewCKS(kr *Keyring, backend Storer, mapper HostMapper, i time.Duration, clock clockwork.Clock) *CKS {
	if clock == nil {
		clock = clockwork.NewRealClock()
	}
	return &CKS{
		keyring:         kr,
		backend:         backend,
		mapper:          mapper,
		refreshInternal: i,
		cache:           make(map[shortIndex]*node),
		clock:           clock,
	}
}

func (s *CKS) withLockedNode(id Index, f func(*node) error) error {
	s.Lock()
	ret := s.cache[id.Short()]
	if ret == nil {
		ret = &node{id: id, data: &CertSet{}}
		s.cache[id.Short()] = ret
	}
	ret.Lock()
	s.Unlock()
	err := f(ret)
	ret.Unlock()
	return err
}

func (s *CKS) PutCert(
	ctx context.Context,
	tx Tx,
	id Index,
	d *X509Bundle,
) error {
	return s.withLockedNode(id, func(n *node) error {
		box, err := s.keyring.Seal(&d.Key)
		if err != nil {
			return err
		}
		data := EncData{
			KeyBox:  *box,
			Cert:    d.Cert,
			Etime:   d.Etime,
			KeyID:   d.KeyID,
			Primary: d.Primary,
		}
		err = s.backend.Put(ctx, tx, id, data)
		if err != nil {
			return err
		}
		n.time = s.clock.Now()
		n.data.add(d)
		return nil
	},
	)
}

func importPrivateKey(key proto.CKSCertKey) (crypto.PrivateKey, error) {
	typ, err := key.GetT()
	if err != nil {
		return nil, err
	}
	switch typ {
	case proto.CKSCertKeyType_Ed25519:
		tmp := key.Ed25519()
		return tmp.SecretKeyEd25519(), nil
	case proto.CKSCertKeyType_X509:
		return x509.ParsePKCS8PrivateKey(key.X509())
	default:
		return nil, core.VersionNotSupportedError("CKS cert key type")
	}
}

func importCert(key proto.CKSCertKey, cert proto.CKSCertChain) (*tls.Certificate, error) {
	ckey, err := importPrivateKey(key)
	if err != nil {
		return nil, err
	}
	leaf := cert.Leaf()
	if leaf == nil {
		return nil, core.X509Error("no certs in chain")
	}
	x509Cert, err := x509.ParseCertificate(leaf)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: cert.ToRaw(),
		PrivateKey:  ckey,
		Leaf:        x509Cert,
	}, nil
}

type X509Bundle struct {
	sync.Mutex
	Key          proto.CKSCertKey
	KeyID        proto.EntityID
	Primary      bool
	Etime        time.Time
	Cert         proto.CKSCertChain
	preparedCert *tls.Certificate
}

func (d *X509Bundle) BuildCert() (*tls.Certificate, error) {
	d.Lock()
	defer d.Unlock()
	if d.preparedCert != nil {
		return d.preparedCert, nil
	}
	tmp, err := importCert(d.Key, d.Cert)
	if err != nil {
		return nil, err
	}
	d.preparedCert = tmp
	return tmp, nil
}

type CertSet struct {
	sync.Mutex
	Certs   []*X509Bundle
	Primary *X509Bundle
	capool  *x509.CertPool
}

func (cs *CertSet) add(d *X509Bundle) {
	cs.Certs = append(cs.Certs, d)
	if d.Primary {
		cs.Primary = d
	}
}

func (cs *CertSet) BuildPool() (*x509.CertPool, error) {
	cs.Lock()
	defer cs.Unlock()
	if cs.capool != nil {
		return cs.capool, nil
	}
	pool := x509.NewCertPool()
	for _, c := range cs.Certs {
		cert, err := c.BuildCert()
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert.Leaf)
	}
	cs.capool = pool
	return pool, nil
}

func (s *CKS) GetCertByHostname(
	ctx context.Context,
	tx Tx,
	host proto.Hostname,
	typ proto.CKSAssetType,
) (
	*CertSet,
	error,
) {
	host = host.Normalize()
	hid, err := s.mapper.HostIDForHostname(ctx, host)
	if err != nil {
		return nil, err
	}
	id := Index{
		HostID: *hid,
		Type:   typ,
	}
	return s.GetCert(ctx, tx, id)
}

func (s *CKS) GetCert(
	ctx context.Context,
	tx Tx,
	id Index,
) (
	*CertSet,
	error,
) {
	var ret *CertSet

	openOne := func(data *EncData) (*X509Bundle, error) {
		var payload proto.CKSCertKey
		err := s.keyring.Open(&payload, &data.KeyBox)
		if err != nil {
			return nil, err
		}
		return &X509Bundle{
			Key:     payload,
			Cert:    data.Cert,
			Etime:   data.Etime,
			KeyID:   data.KeyID,
			Primary: data.Primary,
		}, nil
	}

	err := s.withLockedNode(id, func(n *node) error {
		now := s.clock.Now()
		if n.data != nil && now.Sub(n.time) < s.refreshInternal {
			ret = n.data
			return nil
		}
		data, err := s.backend.Get(ctx, tx, id)
		if err != nil {
			return err
		}
		ret = &CertSet{}
		for _, d := range data {
			tmp, err := openOne(&d)
			if err != nil {
				return err
			}
			ret.add(tmp)
		}
		n.data = ret
		n.time = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}
