// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"io/fs"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

const DefProbePort = proto.DefProbePort
const AppName = "foks"
const AppDisplayName = "FOKS"

// AppBundleID is the reverse-DNS identifier for FOKS. On macOS it names the
// app bundle that gives the launchd agent (labeled AppBundleID + ".agent") a
// display name and icon in System Settings.
const AppBundleID = "com.ne43.foks"

const DefProbeAddr = proto.TCPAddr("foks.app")

// MkdirAllMode is the mode for directories holding FOKS client state -- the
// config dir, the log dir, and the dir holding the sqlite DBs. Nothing here is
// meant to be read by another user or by the owner's group.
var MkdirAllMode = fs.FileMode(0o700)

func MacOSServiceName(isTest bool) string {
	return KeychainServiceName(isTest)
}

func KeychainServiceName(isTest bool) string {
	ret := AppName
	if isTest {
		ret = ret + "-test"
	}
	return ret
}
