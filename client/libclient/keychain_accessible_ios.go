// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

//go:build ios

package libclient

import (
	"github.com/keybase/go-keychain"
)

// secretKeyAccessible is the kSecAttrAccessible class for the keychain item
// that wraps a device key seed (see addItem in platform_darwin.go).
//
// ThisDeviceOnly on iOS. The plain WhenUnlocked class used on macOS is
// included in encrypted Finder/iTunes and iCloud backups and restores onto a
// DIFFERENT device; the ThisDeviceOnly classes are excluded from backups
// entirely. On iOS that distinction is the difference between a device key
// seed that is bound to the hardware it was minted on and one that rides
// along in whatever backup the user happens to take.
//
// Same unlock semantics either way -- readable whenever the device is
// unlocked -- so this costs nothing at runtime. It only forecloses restoring
// the wrapping key onto another device, which a device key seed should not
// survive anyway: enrolling a new device is what the kex flow is for.
const secretKeyAccessible keychain.Accessible = keychain.AccessibleWhenUnlockedThisDeviceOnly
