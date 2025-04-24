// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/require"
)

func TestDeterminism(t *testing.T) {
	var seed [16]byte
	err := core.RandomFill(seed[:])
	require.NoError(t, err)
	var bus []*MockBus
	for i := 0; i < 2; i++ {
		mb, err := NewMockBusWithSeed(seed[:], 2)
		require.NoError(t, err)
		bus = append(bus, mb)
	}
	bg := context.Background()
	var cardNames [][]proto.YubiCardName
	for _, b := range bus {
		cn, err := b.Cards(bg, false)
		require.NoError(t, err)
		cardNames = append(cardNames, cn)
	}
	require.Equal(t, cardNames[0], cardNames[1])

	chkOld := func(cardPos int, slot int) {

		var keys []*ecdsa.PublicKey
		for _, b := range bus {
			h, err := b.Handle(bg, cardNames[0][cardPos])
			require.NoError(t, err)
			card, close, err := h.Card(bg)
			require.NoError(t, err)
			defer close()
			slot, err := b.Slot(proto.YubiSlot(slot))
			require.NoError(t, err)
			oldCert, err := card.Attest(slot)
			require.NoError(t, err)
			ok := oldCert.PublicKey.(*ecdsa.PublicKey)
			keys = append(keys, ok)
		}

		eq := keys[0].Equal(keys[1])
		require.True(t, eq)
	}

	chkOld(0, 0x82)
	chkOld(1, 0x88)

	chkNew := func(cardPos int, slot int) {

		policy := piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			TouchPolicy: piv.TouchPolicyNever,
			PINPolicy:   piv.PINPolicyNever,
		}
		var keys []*ecdsa.PublicKey
		for i, b := range bus {
			h, err := b.Handle(bg, cardNames[0][cardPos])
			require.NoError(t, err)
			card, close, err := h.Card(bg)
			require.NoError(t, err)
			defer close()
			slot, err := b.Slot(proto.YubiSlot(slot))
			require.NoError(t, err)
			var newKey crypto.PublicKey
			if i == 0 {
				newKey, err = card.GenerateKey(piv.DefaultManagementKey, slot, policy)
				require.NoError(t, err)
			} else {
				oldCert, err := card.Attest(slot)
				require.NoError(t, err)
				newKey = oldCert.PublicKey
			}
			keys = append(keys, newKey.(*ecdsa.PublicKey))
		}

		eq := keys[0].Equal(keys[1])
		require.True(t, eq)
	}

	chkNew(0, 0x8b)
	chkNew(1, 0x8b)
	chkNew(1, 0x8e)
}
