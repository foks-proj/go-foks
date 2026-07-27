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

var MkdirAllMode = fs.FileMode(0o750)

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
