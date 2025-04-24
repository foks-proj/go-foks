// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-piv/piv-go/v2/piv"
)

func findSlotsOnCard(
	ctx context.Context,
	h *Handle,
	pk *ecdsa.PublicKey,
	pq *proto.YubiSlotAndPQKeyID,
) (
	*findSlotsRes,
	error,
) {
	return h.findSlots(ctx, pk, pq)
}

func findKeySlow(
	ctx context.Context,
	bus Bus,
	pk *ecdsa.PublicKey,
	pq *proto.YubiSlotAndPQKeyID,
) (
	*findSlotsRes,
	error,
) {
	cards, err := bus.Cards(ctx, true)
	if err != nil {
		return nil, err
	}
	for _, c := range cards {

		h, err := bus.Handle(ctx, c)
		if err != nil {
			return nil, err
		}
		res, err := findSlotsOnCard(ctx, h, pk, pq)
		if res != nil && err == nil {
			return res, nil
		}
	}
	return nil, core.KeyNotFoundError{}
}

// findKeyByInfo finds the classical key via YubiKeyInfo, and also the PQ key,
// optionally, if passed.
func findKeyByInfo(
	ctx context.Context,
	bus Bus,
	yi proto.YubiKeyInfo,
	pk *ecdsa.PublicKey,
	pq *proto.YubiSlotAndPQKeyID,
) (*KeySuiteCore, *KeySuiteCore, error) {

	if pk == nil && pq == nil {
		return nil, nil, core.InternalError("need either pk or pq, or both")
	}

	h, err := bus.Handle(ctx, yi.Card.Name)
	if err != nil {
		return nil, nil, err
	}
	card, closefn, err := h.Card(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer closefn()
	srl, err := card.Serial()
	if err != nil {
		return nil, nil, err
	}
	if srl != yi.Card.Serial {
		return nil, nil, core.YubiError("serial number mismatch")
	}
	var cls *KeySuiteCore

	if pk != nil {

		slot, err := bus.Slot(yi.Key.Slot)
		if err != nil {
			return nil, nil, err
		}
		cert, err := card.Attest(slot)
		if err != nil {
			return nil, nil, err
		}
		if !checkCertMatchesPublicKey(cert, pk) {
			return nil, nil, core.YubiError("public key mismatch")
		}
		cls = &KeySuiteCore{
			ch:   h,
			slot: slot,
			id:   yi.Key.Id,
			pk:   pk,
		}
	}
	var kem *KeySuiteCore

	if pq != nil {
		kemSlot, err := bus.Slot(pq.Slot)
		if err != nil {
			return nil, nil, err
		}
		kemCert, err := card.Attest(kemSlot)
		if err != nil {
			return nil, nil, err
		}
		pk := checkIsEC256(kemCert)
		if pk == nil {
			return nil, nil, core.YubiError("slot for KEM key wasn't ECDSA/PC256")
		}
		id, err := core.ComputeYubiPQKeyID(pk)
		if err != nil {
			return nil, nil, err
		}
		if !id.Eq(&pq.Id) {
			return nil, nil, core.YubiError("KEM key ID mismatch")
		}
		kem = &KeySuiteCore{
			ch:   h,
			slot: kemSlot,
			id:   yi.Key.Id,
			pk:   pk,
		}
	}

	return cls, kem, nil
}

func newKeyFromSlot(
	c Card,
	slot piv.Slot,
	mk *proto.YubiManagementKey,
	opts *GenerateKeyOpts,
) (crypto.PublicKey, error) {
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		TouchPolicy: piv.TouchPolicyNever,
		PINPolicy:   opts.PINPolicy(),
	}
	var mks []byte
	if mk != nil {
		mks = mk.Bytes()
	} else {
		mks = piv.DefaultManagementKey
	}
	pub, err := c.GenerateKey(mks, slot, key)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func loadCore(
	ctx context.Context,
	bus Bus,
	i proto.YubiKeyInfo,
	p *proto.YubiSlotAndPQKeyID,
) (
	*KeySuiteCore,
	*KeySuiteCore, // PQ key
	error,
) {
	var pk *ecdsa.PublicKey
	var err error

	if i.Key.Id != nil {
		pk, err = i.Key.Id.ExportToECDSA()
		if err != nil {
			return nil, nil, err
		}
	}

	if pk == nil && p == nil {
		return nil, nil, core.InternalError("need either i.Key.Id or pq, or both")
	}

	core, kem, err := findKeyByInfo(ctx, bus, i, pk, p)
	if err == nil {
		return core, kem, nil
	}
	res, err := findKeySlow(ctx, bus, pk, p)
	if err != nil {
		return nil, nil, err
	}
	core = &KeySuiteCore{
		ch:   res.h,
		slot: *res.keySlot,
		id:   i.Key.Id,
		pk:   pk,
	}
	if p != nil {
		kem = &KeySuiteCore{
			ch:   res.h,
			slot: *res.kemSlot,
			id:   i.Key.Id,
			pk:   res.kemPv,
		}
	}
	return core, kem, nil
}

func loadPQ(
	ctx context.Context,
	bus Bus,
	i proto.YubiKeyInfoHybrid,
) (
	*KeySuitePQ,
	error,
) {
	card := proto.YubiKeyInfo{
		Card: i.Card,
	}
	_, core, err := loadCore(ctx, bus, card, &i.PqKey)
	if core == nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	ss, err := core.GenerateSelfSecret(ctx)
	if err != nil {
		return nil, err
	}
	return NewKeySuitePQ(core, ss)
}

func loadHybrid(
	ctx context.Context,
	bus Bus,
	i proto.YubiKeyInfoHybrid,
	r proto.Role,
	h proto.HostID,
) (
	*KeySuiteHybrid,
	error,
) {
	yki := proto.YubiKeyInfo{
		Card: i.Card,
		Key:  i.Key,
	}
	core, pq, err := loadCore(ctx, bus, yki, &i.PqKey)
	if err != nil {
		return nil, err
	}
	ss, err := pq.GenerateSelfSecret(ctx)
	if err != nil {
		return nil, err
	}
	pqs, err := NewKeySuitePQ(pq, ss)
	if err != nil {
		return nil, err
	}
	ret := KeySuiteHybrid{
		KeySuite: KeySuite{
			KeySuiteCore: *core,
			role:         r,
			hid:          h,
		},
		Pq: *pqs,
	}
	return &ret, nil
}

func load(
	ctx context.Context,
	bus Bus,
	i proto.YubiKeyInfo,
	r proto.Role,
	h proto.HostID,
) (
	*KeySuite,
	error,
) {
	core, _, err := loadCore(ctx, bus, i, nil)
	if err != nil {
		return nil, err
	}
	return &KeySuite{
		KeySuiteCore: *core,
		role:         r,
		hid:          h,
	}, nil
}

func dangerousAccessPQKey(
	ctx context.Context,
	bus Bus,
	i proto.YubiKeyInfo,
) (
	*KeySuitePQ,
	error,
) {
	core, _, err := loadCore(ctx, bus, i, nil)
	if err != nil {
		return nil, err
	}
	ss, err := core.GenerateSelfSecret(ctx)
	if err != nil {
		return nil, err
	}
	return NewKeySuitePQ(core, ss)
}

func getCardID(
	ctx context.Context,
	bus Bus,
	name proto.YubiCardName,
) (
	*proto.YubiCardID,
	error,
) {
	h, err := bus.Handle(ctx, name)
	if err != nil {
		return nil, err
	}
	card, close, err := h.Card(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	serial, err := card.Serial()
	if err != nil {
		return nil, err
	}
	return &proto.YubiCardID{
		Name:   name,
		Serial: serial,
	}, nil

}

func listCards(ctx context.Context, bus Bus) ([]proto.YubiCardID, error) {
	cards, err := bus.Cards(ctx, true)
	if err != nil {
		return nil, err
	}
	ret := make([]proto.YubiCardID, len(cards))
	for i, name := range cards {
		info, err := getCardID(ctx, bus, name)
		if err != nil {
			return nil, err
		}
		ret[i] = *info
	}
	return ret, nil
}

func openCardByID(ctx context.Context, bus Bus, i proto.YubiCardID) (Card, *Handle, func(), error) {
	h, err := bus.Handle(ctx, i.Name)
	if err != nil {
		return nil, nil, nil, err
	}
	card, close, err := h.Card(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := card.Serial()
	if err != nil {
		close()
		return nil, nil, nil, err
	}
	if serial != i.Serial {
		close()
		return nil, nil, nil, core.YubiError("serial number mismatch")
	}
	return card, h, close, nil
}

func explore(ctx context.Context, bus Bus, i proto.YubiCardID) (*proto.YubiCardInfo, error) {
	card, h, close, err := openCardByID(ctx, bus, i)
	if err != nil {
		return nil, err
	}
	defer close()

	ret := proto.YubiCardInfo{Id: i}

	exploreSlot := func(raw proto.YubiSlot, slot piv.Slot) error {
		cert, err := card.Attest(slot)
		if err == piv.ErrNotFound {
			ret.EmptySlots = append(ret.EmptySlots, raw)
			return nil
		}
		if err != nil {
			return err
		}
		key := checkIsEC256(cert)
		if key == nil {
			return nil
		}
		eid, err := proto.EntityType_Yubi.ImportFromPublicKey(key)
		if err != nil {
			return err
		}
		yid := proto.YubiID(eid)

		ret.Keys = append(ret.Keys, proto.YubiSlotAndKeyID{Id: yid, Slot: raw})
		return nil
	}

	err = forAllSlots(ctx, bus, func(raw proto.YubiSlot, slot piv.Slot) (bool, error) {
		err := exploreSlot(raw, slot)
		if err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if h.ManagementKey() != nil {
		ret.Mks = proto.ManagementKeyState_PINRetrieved
	} else {
		dmk, err := card.HasDefaultManagementKey()
		if err != nil {
			return nil, err
		}
		if dmk {
			ret.Mks = proto.ManagementKeyState_Default
		} else {
			ret.Mks = proto.ManagementKeyState_ShouldTryPIN
		}
	}

	return &ret, nil
}

func generateKeyCore(
	ctx context.Context,
	bus Bus,
	i proto.YubiCardID,
	slot proto.YubiSlot,
	opts *GenerateKeyOpts,
) (
	*KeySuiteCore,
	error,
) {
	card, handle, close, err := openCardByID(ctx, bus, i)
	if err != nil {
		return nil, err
	}
	defer close()
	yslot, err := bus.Slot(slot)
	if err != nil {
		return nil, err
	}

	pk, err := newKeyFromSlot(card, yslot, handle.ManagementKey(), opts)
	if err != nil {
		return nil, err
	}
	eid, err := proto.EntityType_Yubi.ImportFromPublicKey(pk)
	if err != nil {
		return nil, err
	}
	yid := proto.YubiID(eid)

	return &KeySuiteCore{
		ch:   handle,
		id:   yid,
		pk:   pk,
		slot: yslot,
	}, nil
}

func generateKeyPQ(
	ctx context.Context,
	bus Bus,
	i proto.YubiCardID,
	slot proto.YubiSlot,
	opts *GenerateKeyOpts,
) (
	*KeySuitePQ,
	error,
) {
	core, err := generateKeyCore(ctx, bus, i, slot, opts)
	if err != nil {
		return nil, err
	}
	ss, err := core.GenerateSelfSecret(ctx)
	if err != nil {
		return nil, err
	}
	return NewKeySuitePQ(core, ss)
}

func generateKeyHybrid(
	ctx context.Context,
	bus Bus,
	i proto.YubiCardID,
	slot proto.YubiSlot,
	kemSlot proto.YubiSlot,
	r proto.Role,
	h proto.HostID,
	opts *GenerateKeyOpts,
) (
	*KeySuiteHybrid,
	error,
) {
	key, err := generateKey(ctx, bus, i, slot, r, h, opts)
	if err != nil {
		return nil, err
	}
	kem, err := generateKeyPQ(ctx, bus, i, kemSlot, opts)
	if err != nil {
		return nil, err
	}
	ret := key.Fuse(kem)
	return ret, nil
}

func inputPIN(
	ctx context.Context,
	bus Bus,
	i proto.YubiCardID,
	pin proto.YubiPIN,
) (
	proto.ManagementKeyState,
	error,
) {
	var mks proto.ManagementKeyState
	card, h, close, err := openCardByID(ctx, bus, i)
	if err != nil {
		return mks, err
	}
	defer close()
	pin = fillDefaultPIN(pin)

	err = card.ValidatePIN(pin)
	if err != nil {
		return mks, err
	}
	h.SetPIN(pin)

	mk, err := card.GetManagementKey(pin)
	if err == nil {
		h.SetManagementKey(mk)
		mks = proto.ManagementKeyState_PINRetrieved
	} else if errors.Is(err, core.YubiDefaultManagementKeyError{}) {
		mks = proto.ManagementKeyState_Default
		err = nil
	} else if _, ok := err.(core.KeyNotFoundError); ok {
		mks = proto.ManagementKeyState_Unknown
		err = nil
	}

	if err != nil {
		return mks, err
	}

	return mks, nil
}

func generateKey(
	ctx context.Context,
	bus Bus,
	i proto.YubiCardID,
	slot proto.YubiSlot,
	r proto.Role,
	h proto.HostID,
	opts *GenerateKeyOpts,
) (
	*KeySuite,
	error,
) {
	core, err := generateKeyCore(ctx, bus, i, slot, opts)
	if err != nil {
		return nil, err
	}
	return &KeySuite{
		KeySuiteCore: *core,
		role:         r,
		hid:          h,
	}, nil
}

func findCardIDBySerial(
	ctx context.Context,
	bus Bus,
	serial proto.YubiSerial,
) (
	*proto.YubiCardID,
	error,
) {
	v, err := listCards(ctx, bus)
	if err != nil {
		return nil, err
	}
	for _, card := range v {
		if card.Serial == serial {
			tmp := card
			return &tmp, nil
		}
	}
	return nil, core.YubiError("card not found")
}

func findCardBySerial(ctx context.Context, bus Bus, serial proto.YubiSerial) (*proto.YubiCardInfo, error) {
	found, err := findCardIDBySerial(ctx, bus, serial)
	if err != nil {
		return nil, err
	}
	card, err := explore(ctx, bus, *found)
	if err != nil {
		return nil, err
	}
	return card, nil
}

func validatePIN(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	pin proto.YubiPIN,
	doUnlock bool,
) error {
	card, h, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()

	pin = fillDefaultPIN(pin)
	err = card.ValidatePIN(pin)
	if err != nil {
		return err
	}
	if !doUnlock {
		return nil
	}

	h.SetPIN(pin)

	mk, err := card.GetManagementKey(pin)
	switch {
	case err == nil:
		h.SetManagementKey(mk)
		return nil
	case errors.Is(err, core.YubiDefaultManagementKeyError{}):
		h.SetManagementKey(defaultManagementKey())
		return nil
	default:
		return err
	}
}

func setPIN(ctx context.Context, bus Bus, id proto.YubiCardID, old proto.YubiPIN, new proto.YubiPIN) error {
	card, _, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()
	return card.SetPIN(old, new)
}

func setPUK(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	old proto.YubiPUK,
	new proto.YubiPUK,
) error {
	card, _, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()
	return card.SetPUK(old, new)
}

func validatePUK(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	puk proto.YubiPUK,
) error {
	card, _, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()
	return card.ValidatePUK(puk)
}

func setOrGetManagementKey(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	pin proto.YubiPIN,
) (
	*proto.YubiManagementKey,
	bool,
	error,
) {
	card, _, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return nil, false, err
	}
	defer close()
	return card.SetOrGetManagementKey(pin)
}

func hasDefaultManagementKey(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
) (
	bool,
	error,
) {
	card, _, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return false, err
	}
	defer close()
	def, err := card.HasDefaultManagementKey()
	if err != nil {
		return false, err
	}
	return def, nil
}

func getManagementKey(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
) (
	*proto.YubiManagementKey,
	error,
) {
	_, h, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return nil, err
	}
	defer close()
	mk := h.ManagementKey()
	return mk, nil
}

func setManagementKey(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	old *proto.YubiManagementKey,
	new proto.YubiManagementKey,
) error {
	card, h, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()
	h.clearSecrets()
	return card.SetManagementKey(old, new)
}

func resetPINandPUK(
	ctx context.Context,
	bus Bus,
	id proto.YubiCardID,
	mk proto.YubiManagementKey,
	pin proto.YubiPIN,
	puk proto.YubiPUK,
) error {
	card, h, close, err := openCardByID(ctx, bus, id)
	if err != nil {
		return err
	}
	defer close()
	h.clearSecrets()

	err = card.SetRetries(mk, 3, 3)
	if err != nil {
		return err
	}

	var defPin proto.YubiPIN
	err = card.SetPIN(defPin, pin)
	if err != nil {
		return err
	}

	var defPuk proto.YubiPUK
	err = card.SetPUK(defPuk, puk)
	if err != nil {
		return err
	}

	return nil
}
