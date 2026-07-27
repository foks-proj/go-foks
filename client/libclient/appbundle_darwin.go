// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"bytes"
	_ "embed"
	"os"
	"os/exec"
	"text/template"

	"github.com/foks-proj/go-foks/lib/core"
)

//go:embed assets/foks.icns
var foksIcns []byte

// LsRegister is the LaunchServices registration tool. Homebrew's prefix is
// outside the paths LaunchServices auto-scans, and even for ~/Applications a
// scan may not have happened yet, so we register the bundle explicitly.
var LsRegister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

// AppBundle writes a minimal macOS app bundle whose only purpose is to give
// the launchd agent a human-readable name and icon in System Settings →
// Login Items & Extensions. Without one, Background Task Management falls
// back to the code-signing organization name ("NE43 INC") and a generic icon.
// See https://github.com/foks-proj/go-foks/issues/312.
type AppBundle struct {
	path core.Path // e.g. ~/Applications/FOKS.app
}

func NewAppBundle() (*AppBundle, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &AppBundle{
		path: core.Path(home).JoinStrings("Applications", AppDisplayName+".app"),
	}, nil
}

func (a *AppBundle) Path() core.Path { return a.path }

func (a *AppBundle) infoPlistTemplate() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>{{.BundleID}}</string>
	<key>CFBundleName</key><string>{{.Name}}</string>
	<key>CFBundleDisplayName</key><string>{{.Name}}</string>
	<key>CFBundleExecutable</key><string>foks</string>
	<key>CFBundleIconFile</key><string>foks</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>{{.Version}}</string>
	<key>LSUIElement</key><true/>
</dict>
</plist>
`
}

// Write lays down the bundle: Info.plist, the embedded icon, and a symlink to
// the current foks binary as the bundle executable. It is idempotent and safe
// to rerun on every agent start (e.g. after an upgrade moves the binary).
func (a *AppBundle) Write(m MetaContext) error {
	contents := a.path.JoinStrings("Contents")
	infoPlist := contents.JoinStrings("Info.plist")
	icns := contents.JoinStrings("Resources", "foks.icns")
	link := contents.JoinStrings("MacOS", "foks")

	t, err := template.New("infoPlist").Parse(a.infoPlistTemplate())
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, struct {
		BundleID string
		Name     string
		Version  string
	}{
		BundleID: AppBundleID,
		Name:     AppDisplayName,
		Version:  core.CurrentSoftwareVersion.String(),
	})
	if err != nil {
		return err
	}
	err = infoPlist.MakeParentDirs()
	if err != nil {
		return err
	}
	err = infoPlist.WriteFile(buf.Bytes(), 0o644)
	if err != nil {
		return err
	}

	err = icns.MakeParentDirs()
	if err != nil {
		return err
	}
	err = icns.WriteFile(foksIcns, 0o644)
	if err != nil {
		return err
	}

	prog, err := os.Executable()
	if err != nil {
		return err
	}
	err = link.MakeParentDirs()
	if err != nil {
		return err
	}
	err = link.Remove()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return core.Path(prog).Symlink(link)
}

// Register tells LaunchServices about the bundle so that Background Task
// Management can resolve AssociatedBundleIdentifiers to a name and icon.
func (a *AppBundle) Register(m MetaContext) error {
	cmd := exec.CommandContext(m.Ctx(), LsRegister, "-f", a.path.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.Warnw("AppBundle::Register", "path", a.path, "out", string(out), "err", err)
		return err
	}
	return nil
}

// Install writes and registers the bundle. Failures are logged but returned
// to the caller to treat as non-fatal; the agent is fully functional without
// the bundle, which only affects System Settings cosmetics.
func (a *AppBundle) Install(m MetaContext) error {
	err := a.Write(m)
	if err != nil {
		m.Warnw("AppBundle::Install", "stage", "write", "path", a.path, "err", err)
		return err
	}
	return a.Register(m)
}
