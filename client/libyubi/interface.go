// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libyubi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"sync"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-piv/piv-go/v2/piv"
)

type KeyLoc struct {
	Serial proto.YubiSerial
	Slot   proto.YubiSlot
}

type BusType int

const (
	BusTypeNone BusType = 0
	BusTypeReal BusType = 1
	BusTypeMock BusType = 2
)

type Bus interface {
	Cards(ctx context.Context, filter bool) ([]proto.YubiCardName, error)
	Handle(ctx context.Context, n proto.YubiCardName) (*Handle, error)
	Slot(proto.YubiSlot) (piv.Slot, error)
	Type() BusType
	ClearSecrets()

	// Used internally
	openCard(ctx context.Context, nm proto.YubiCardName) (Card, error)
}

type Handle struct {
	sync.Mutex
	nm       proto.YubiCardName
	card     Card
	bus      Bus
	refcount int

	// If the user enters a PIN and it is successfully verified, the PIN field below
	// is set. Furthermore, if there is a management key stored on the card, as protected
	// by the given pin, that will be present here too.
	pin  *proto.YubiPIN
	mgmt *proto.YubiManagementKey
}

type Card interface {
	Serial() (proto.YubiSerial, error)
	PrivateKey(piv.Slot, crypto.PublicKey, piv.KeyAuth) (crypto.PrivateKey, error)
	Attest(piv.Slot) (*x509.Certificate, error)
	Close() error
	GenerateKey([]byte, piv.Slot, piv.Key) (crypto.PublicKey, error)
	SharedKey(priv crypto.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error)

	// PIN/PUK etc:
	ValidatePIN(pin proto.YubiPIN) error
	ValidatePUK(puk proto.YubiPUK) error
	SetPIN(old, new proto.YubiPIN) error
	SetPUK(old, new proto.YubiPUK) error

	HasDefaultManagementKey() (bool, error)
	GetManagementKey(pin proto.YubiPIN) (*proto.YubiManagementKey, error)
	SetManagementKey(old *proto.YubiManagementKey, new proto.YubiManagementKey) error

	// SetOrGetManagement key is a mix of both Get and Set above, but keeps a lock
	// between the two operations. Return true if made a new key, and false if
	// just returning the existing key.
	SetOrGetManagementKey(pin proto.YubiPIN) (*proto.YubiManagementKey, bool, error)

	// Resets the PIN and PUK
	SetRetries(proto.YubiManagementKey, int, int) error
}
