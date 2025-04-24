// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cks

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

type mockStorer struct {
	m map[core.ShortHostID][]EncData
}

func newMockStorer() *mockStorer {
	return &mockStorer{
		m: make(map[core.ShortHostID][]EncData),
	}
}

func (m *mockStorer) Put(ctx context.Context, tx Tx, id Index, dat EncData) error {
	set, ok := m.m[id.HostID.Short]
	if !ok {
		set = make([]EncData, 0)
	}
	set = append(set, dat)
	m.m[id.HostID.Short] = set
	return nil
}

func (m *mockStorer) Get(ctx context.Context, tx Tx, id Index) ([]EncData, error) {
	n, ok := m.m[id.HostID.Short]
	if !ok {
		return nil, core.NotFoundError("cert pair")
	}
	return n, nil
}

type mockMapper struct {
	m map[proto.Hostname]*core.HostID
}

func (m *mockMapper) HostIDForHostname(ctx context.Context, host proto.Hostname) (*core.HostID, error) {
	id, ok := m.m[host]
	if !ok {
		return nil, core.NotFoundError("host")
	}
	return id, nil
}

func (m *mockMapper) PutAlias(ctx context.Context, tx Tx, host proto.Hostname, id *core.HostID) error {
	m.m[host] = id
	return nil
}

func newMockMapper() *mockMapper {
	return &mockMapper{
		m: make(map[proto.Hostname]*core.HostID),
	}
}

func (m *mockMapper) add(host proto.Hostname, id *core.HostID) {
	m.m[host] = id
}

var _ HostMapper = (*mockMapper)(nil)

var _ Storer = (*mockStorer)(nil)

func TestStore(t *testing.T) {

	cl := clockwork.NewFakeClockAt(time.Now())
	ms := newMockStorer()
	mm := newMockMapper()
	key, err := NewEncKey()
	require.NoError(t, err)
	kr := NewKeyring()
	err = kr.AddCurr(key)
	require.NoError(t, err)

	s := NewCKS(kr, ms, mm, time.Minute, cl)

	caPriv, caCert, err := core.GenCAInMem()
	require.NoError(t, err)
	ed, ok := caPriv.(ed25519.PrivateKey)
	require.True(t, ok)
	var protKey proto.Ed25519SecretKey
	err = protKey.ImportFromEd21559Private(ed)
	require.NoError(t, err)
	ctx := context.Background()
	id := core.HostID{Short: 1}

	certKey := proto.NewCKSCertKeyWithEd25519(protKey)

	etime := cl.Now().Add(time.Hour)

	index := Index{
		HostID: id,
		Type:   proto.CKSAssetType_BackendCA,
	}
	err = s.PutCert(ctx, nil, index, &X509Bundle{
		Key:   certKey,
		Cert:  proto.NewCKSCertChainFromSingle(caCert),
		Etime: etime,
	},
	)
	require.NoError(t, err)

	dn := proto.Hostname("nike.okta.com")
	mm.add(dn, &id)

	dat, err := s.GetCertByHostname(ctx, nil, dn, proto.CKSAssetType_BackendCA)
	require.NoError(t, err)
	require.Len(t, dat.Certs, 1)
	caCert2, err := dat.Certs[0].BuildCert()
	require.NoError(t, err)
	require.Equal(t, caCert, caCert2.Certificate[0])
	require.Equal(t, etime, dat.Certs[0].Etime)
}
