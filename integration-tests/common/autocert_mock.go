// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	"errors"
	"sync"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
)

type FakeAutocertDoer struct {
	sync.Mutex
	badHosts map[proto.Hostname]bool
	addr     proto.TCPAddr
	ProbeCA  X509CA
}

func NewFakeAutocertDoer(p X509CA) *FakeAutocertDoer {
	return &FakeAutocertDoer{
		badHosts: make(map[proto.Hostname]bool),
		ProbeCA:  p,
	}
}

func (f *FakeAutocertDoer) SetBindAddr(a proto.TCPAddr) {
	f.addr = a
}

func (f *FakeAutocertDoer) GetBindAddr() proto.TCPAddr {
	return f.addr
}

func (f *FakeAutocertDoer) Start(m shared.MetaContext) error {
	return nil
}

func (f *FakeAutocertDoer) Stop() {
}

func (f *FakeAutocertDoer) DoOne(
	m shared.MetaContext,
	pkg shared.AutocertPackage,
) (*shared.AutocertDoneResult, error) {
	f.Lock()
	defer f.Unlock()

	if f.badHosts[pkg.Hostname] {
		return nil, errors.New("acme autocert failed")
	}

	res, err := EmulateLetsEncrypt(
		m,
		[]proto.Hostname{pkg.Hostname},
		nil,
		f.ProbeCA,
		proto.CKSAssetType_RootPKIFrontendX509Cert,
	)

	if err != nil {
		return nil, err
	}
	return res, nil
}

func (f *FakeAutocertDoer) SetBadHost(hn proto.Hostname) {
	f.Lock()
	defer f.Unlock()
	f.badHosts[hn] = true
}

func (f *FakeAutocertDoer) ClearBadHost(hn proto.Hostname) {
	f.Lock()
	defer f.Unlock()
	delete(f.badHosts, hn)
}

var _ shared.AutocertDoer = &FakeAutocertDoer{}
