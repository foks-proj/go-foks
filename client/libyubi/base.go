// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-piv/piv-go/v2/piv"
)

type BusBase struct {
	sync.Mutex
	handleTab map[proto.YubiCardName]*Handle
}

func newBusBase() *BusBase {
	return &BusBase{
		handleTab: make(map[proto.YubiCardName]*Handle),
	}
}

func (b *BusBase) handle(ctx context.Context, bus Bus, n proto.YubiCardName) (*Handle, error) {
	b.Lock()
	defer b.Unlock()

	h, ok := b.handleTab[n]
	if !ok {
		h = newHandle(bus, n)
		b.handleTab[n] = h
	}
	return h, nil
}

func (b *BusBase) ClearSecrets() {
	b.Lock()
	defer b.Unlock()
	for _, h := range b.handleTab {
		h.clearSecrets()
	}
}

func (h *Handle) clearSecrets() {
	h.Lock()
	defer h.Unlock()
	h.pin = nil
	h.mgmt = nil
}

func (h *Handle) decref() {
	h.Lock()
	defer h.Unlock()

	h.refcount--
	if h.refcount < 0 {
		panic("refcount < 0")
	}

	if h.refcount == 0 && h.card != nil {
		h.card.Close()
		h.card = nil
	}
}

func (h *Handle) closer() func() {
	h.refcount++
	return h.decref
}

func (h *Handle) SetPIN(pin proto.YubiPIN) {
	h.Lock()
	defer h.Unlock()
	h.pin = &pin
}

func defaultManagementKey() *proto.YubiManagementKey {
	var ret proto.YubiManagementKey
	copy(ret[:], piv.DefaultManagementKey)
	return &ret
}

func (h *Handle) SetManagementKey(mk *proto.YubiManagementKey) {
	h.Lock()
	defer h.Unlock()
	h.mgmt = mk
}

func (h *Handle) ManagementKey() *proto.YubiManagementKey {
	h.Lock()
	defer h.Unlock()
	return h.mgmt
}

func (h *Handle) Card(ctx context.Context) (Card, func(), error) {
	h.Lock()
	defer h.Unlock()

	if h.card != nil {
		return h.card, h.closer(), nil
	}

	card, err := h.bus.openCard(ctx, h.nm)
	if err != nil {
		return nil, nil, err
	}
	h.card = card
	return card, h.closer(), nil
}

func newHandle(b Bus, nm proto.YubiCardName) *Handle {
	return &Handle{
		bus: b,
		nm:  nm,
	}
}

var SlotMin = proto.YubiSlot(0x82)
var SlotMax = proto.YubiSlot(0x95)

func forAllSlots(ctx context.Context, bus Bus, f func(proto.YubiSlot, piv.Slot) (bool, error)) error {

	for i := SlotMin; i <= SlotMax; i++ {
		slot, err := bus.Slot(i)
		if err != nil {
			return err
		}
		keepGoing, err := f(i, slot)
		if err != nil {
			return err
		}
		if !keepGoing {
			return nil
		}
	}
	return nil
}

type findSlotsRes struct {
	h       *Handle
	keySlot *piv.Slot
	kemSlot *piv.Slot
	kemPv   *ecdsa.PublicKey
}

func (h *Handle) findSlots(
	ctx context.Context,
	pk *ecdsa.PublicKey,
	pq *proto.YubiSlotAndPQKeyID,
) (
	*findSlotsRes,
	error,
) {

	if pk == nil && pq == nil {
		return nil, core.InternalError("need either pk or pq, or both")
	}

	card, closefn, err := h.Card(ctx)
	if err != nil {
		return nil, err
	}
	defer closefn()
	var ret findSlotsRes
	var found bool
	ret.h = h

	err = forAllSlots(ctx, h.bus, func(_ proto.YubiSlot, s piv.Slot) (bool, error) {
		cert, err := card.Attest(s)
		if err == piv.ErrNotFound {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		certPk := checkIsEC256(cert)
		if certPk == nil {
			return true, nil
		}
		switch {
		case pk != nil && ret.keySlot == nil && checkCertMatchesPublicKey(cert, pk):
			ret.keySlot = &s
		case pq != nil && ret.kemSlot == nil:
			id, err := core.ComputeYubiPQKeyID(certPk)
			if err != nil {
				return false, err
			}
			if id.Eq(&pq.Id) {
				ret.kemSlot = &s
				ret.kemPv = certPk
			}
		}
		if (pk == nil || ret.keySlot != nil) && (pq == nil || ret.kemSlot != nil) {
			found = true
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &ret, nil
}

func checkCertMatchesPublicKey(cert *x509.Certificate, pk *ecdsa.PublicKey) bool {
	ekey := checkIsEC256(cert)
	if ekey == nil {
		return false
	}
	return ekey.X.Cmp(pk.X) == 0 && ekey.Y.Cmp(pk.Y) == 0
}

func checkIsEC256(cert *x509.Certificate) *ecdsa.PublicKey {
	if cert == nil {
		return nil
	}
	ecdsa, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	if ecdsa.Curve != elliptic.P256() {
		return nil
	}
	return ecdsa
}
