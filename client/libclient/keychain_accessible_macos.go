// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

//go:build darwin && !ios

package libclient

import (
	"github.com/keybase/go-keychain"
)

// secretKeyAccessible is the kSecAttrAccessible class for the keychain item
// that wraps a device key seed (see addItem in platform_darwin.go).
//
// Unchanged on macOS. Two reasons not to tighten this to ThisDeviceOnly here
// along with iOS:
//
//   - It would break Migration Assistant. Moving a Mac to new hardware is an
//     ordinary, supported thing to do, and a user who does it expects their
//     login keychain -- and so their FOKS device -- to come with them. On iOS
//     the equivalent is restoring a backup onto a second device, which is a
//     thing a device key seed specifically should not survive.
//   - It would be mostly theatre anyway. go-keychain v0.0.1 does not set
//     kSecUseDataProtectionKeychain, so on macOS these items land in the
//     legacy file-based keychain, where access is governed by the keychain's
//     own lock state and per-item ACLs rather than by the data-protection
//     accessibility classes. kSecAttrAccessible is accepted and stored, but
//     it is not the thing enforcing anything.
//
// Split into its own file rather than branched on runtime.GOOS so that the
// iOS and macOS choices are each stated once, at compile time, next to the
// reasoning for them.
const secretKeyAccessible keychain.Accessible = keychain.AccessibleWhenUnlocked
