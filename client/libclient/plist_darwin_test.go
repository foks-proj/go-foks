// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"text/template"
)

func plutilLint(t *testing.T, b []byte) {
	t.Helper()
	cmd := exec.Command("/usr/bin/plutil", "-lint", "-")
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("plutil lint failed: %v\n%s\ninput:\n%s", err, out, b)
	}
}

// Render the launchd and app-bundle plist templates and validate the output
// with plutil. The launchd template once shipped literal backslash-escaped
// quotes in its DOCTYPE (raw string vs interpreted string mixup); this catches
// that class of regression.
func TestPlistTemplatesLint(t *testing.T) {
	p := NewPlist()
	lt, err := template.New("launchd").Parse(p.Template())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = lt.Execute(&buf, struct {
		Label, BundleID, Program, Home, Config, LogDir string
	}{
		Label:    AppBundleID + ".agent",
		BundleID: AppBundleID,
		Program:  "/usr/local/bin/foks",
		Home:     "/tmp/home",
		Config:   "/tmp/config.toml",
		LogDir:   "/tmp/logs",
	})
	if err != nil {
		t.Fatal(err)
	}
	plutilLint(t, buf.Bytes())

	ab := &AppBundle{}
	it, err := template.New("infoPlist").Parse(ab.infoPlistTemplate())
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	err = it.Execute(&buf, struct {
		BundleID, Name, Version string
	}{
		BundleID: AppBundleID,
		Name:     AppDisplayName,
		Version:  "0.1.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	plutilLint(t, buf.Bytes())
}

// Write the app bundle into a scratch home twice: once from nothing, and once
// over an existing bundle, since `foks ctl start` rewrites it on every run and
// must replace the executable symlink rather than fail on it.
func TestAppBundleWrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ab, err := NewAppBundle()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err = ab.Write(MetaContext{})
		if err != nil {
			t.Fatal(err)
		}
	}
	contents := ab.Path().JoinStrings("Contents")
	prog, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink(contents.JoinStrings("MacOS", "foks").String())
	if err != nil {
		t.Fatal(err)
	}
	if link != prog {
		t.Fatalf("symlink points to %q, expected %q", link, prog)
	}
	infoPlist, err := contents.JoinStrings("Info.plist").ReadFile()
	if err != nil {
		t.Fatal(err)
	}
	plutilLint(t, infoPlist)
	icns, err := contents.JoinStrings("Resources", "foks.icns").ReadFile()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(icns, foksIcns) {
		t.Fatal("icns on disk doesn't match embedded asset")
	}
}
