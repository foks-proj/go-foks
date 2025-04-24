// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"crypto"
	"os"
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/require"
)

func (d *Dispatch) testInit(ctx context.Context, t *testing.T) *nextSlotter {
	if d.test != nil {
		return d.test
	}
	d.test = &nextSlotter{
		nxt: SlotMin,
	}
	cards, err := d.bus.Cards(ctx, true)
	require.NoError(t, err)
	require.NotZero(t, len(cards))
	d.test.nm = cards[0]
	return d.test
}

func (l *nextSlotter) nextSlot(t *testing.T) proto.YubiSlot {
	require.LessOrEqual(t, l.nxt, SlotMax)
	ret := l.nxt
	l.nxt++
	return ret
}

func (d *Dispatch) nextTestKeyCore(
	ctx context.Context,
	t *testing.T,
) *KeySuiteCore {

	tkl := d.testInit(ctx, t)
	h, err := d.bus.Handle(ctx, tkl.nm)
	require.NoError(t, err)
	card, closeFn, err := h.Card(ctx)
	require.NoError(t, err)
	defer closeFn()

	probe := func() *KeySuiteCore {
		slot, err := d.bus.Slot(tkl.nextSlot(t))
		require.NoError(t, err)
		cert, err := card.Attest(slot)
		require.True(t, err == nil || err == piv.ErrNotFound)

		var pub crypto.PublicKey

		if err == nil {
			pub = checkIsEC256(cert)
		} else {
			pub, err = newKeyFromSlot(card, slot, h.ManagementKey(), nil)
			require.NoError(t, err)
		}

		eid, err := proto.EntityType_Yubi.ImportFromPublicKey(pub)
		require.NoError(t, err)
		yid := proto.YubiID(eid)

		return &KeySuiteCore{
			ch:   h,
			slot: slot,
			id:   yid,
			pk:   pub,
		}
	}

	for {
		if ret := probe(); ret != nil {
			return ret
		}
	}
}

func (d *Dispatch) NextTestKey(
	ctx context.Context,
	t *testing.T,
	role proto.Role,
	h proto.HostID,
) *KeySuiteHybrid {
	core := d.nextTestKeyCore(ctx, t)
	pqCore := d.nextTestKeyCore(ctx, t)
	ss, err := pqCore.GenerateSelfSecret(ctx)
	require.NoError(t, err)
	pqk, err := NewKeySuitePQ(pqCore, ss)
	require.NoError(t, err)
	parent := &KeySuite{
		KeySuiteCore: *core,
		role:         role,
		hid:          h,
	}
	ret := parent.Fuse(pqk)
	return ret
}

// Use in VSCode to change the yubi mode.
var realForce = false

func GetRealForce() bool {
	if realForce {
		return true
	}
	val := os.Getenv("USE_REAL_YUBIKEY")
	return val == "1"
}

func AllocDispatchTest() (*Dispatch, error) {
	if GetRealForce() {
		return allocRealYubi()
	}
	bus, err := NewMockBus()
	if err != nil {
		return nil, err
	}
	return &Dispatch{bus: bus}, nil
}
