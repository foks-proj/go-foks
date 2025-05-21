// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package libclient

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/foks-proj/go-foks/lib/core"
)

type ConfigGetter func() string
type RunModeGetter func() RunMode
type EnvGetter func(s string) string

type Base struct {
	appName             string
	getHomeFromCmd      ConfigGetter
	getHomeFromConfig   ConfigGetter
	getMobileSharedHome ConfigGetter
	getRunMode          RunModeGetter
	getenvFunc          EnvGetter
}

type DirType int

const (
	DirTypeHome    DirType = 1
	DirTypeConfig  DirType = 2
	DirTypeCache   DirType = 3
	DirTypeData    DirType = 4
	DirTypeRuntime DirType = 5
	DirTypeLog     DirType = 6
)

type HomeFinder interface {
	CacheDir() (string, error)
	SharedCacheDir() (string, error)
	ConfigDir() (string, error)
	DownloadsDir() (string, error)
	Home(emptyOk bool) (string, error)
	MobileSharedHome(emptyOk bool) (string, error)
	DataDir() (string, error)
	SharedDataDir() (string, error)
	RuntimeDir() (string, error)
	Normalize(s string) string
	LogDir() (string, error)
	ServiceSpawnDir() (string, error)
	InfoDir() (string, error)
	IsNonstandardHome() (bool, error)
}

func HomeFindDir(hf HomeFinder, typ DirType) (string, error) {
	switch typ {
	case DirTypeHome:
		return hf.Home(false)
	case DirTypeConfig:
		return hf.ConfigDir()
	case DirTypeCache:
		return hf.CacheDir()
	case DirTypeData:
		return hf.DataDir()
	case DirTypeRuntime:
		return hf.RuntimeDir()
	case DirTypeLog:
		return hf.LogDir()
	default:
		return "", core.InternalError("bad directory type")
	}
}

func (b Base) getHome() string {
	if b.getHomeFromCmd != nil {
		ret := b.getHomeFromCmd()
		if ret != "" {
			return ret
		}
	}
	if b.getHomeFromConfig != nil {
		ret := b.getHomeFromConfig()
		if ret != "" {
			return ret
		}
	}
	return ""
}

func (b Base) IsNonstandardHome() (bool, error) {
	return false, fmt.Errorf("unsupported on %s", runtime.GOOS)
}

// we mock out the getenv function for testing
func (b Base) getenv(s string) string {
	if b.getenvFunc != nil {
		return b.getenvFunc(s)
	}
	return os.Getenv(s)
}

func (b Base) Join(elem ...string) string { return filepath.Join(elem...) }

type XdgPosix struct {
	Base
}

func (x XdgPosix) Normalize(s string) string { return s }

func (x XdgPosix) Home(emptyOk bool) (string, error) {
	ret := x.getHome()
	if len(ret) == 0 && !emptyOk {
		ret = x.getenv("HOME")
	}
	if ret == "" {
		return "", core.HomeError("none found")
	}
	resolved, err := filepath.Abs(ret)
	if err != nil {
		return ret, err
	}
	return resolved, nil
}

// IsNonstandardHome is true if the home directory gleaned via cmdline,
// env, or config is different from that in /etc/passwd.
func (x XdgPosix) IsNonstandardHome() (bool, error) {
	passed, err := x.Home(false)
	if err != nil {
		return false, err
	}
	if passed == "" {
		return false, nil
	}
	passwd, err := user.Current()
	if err != nil {
		return false, err
	}
	passwdAbs, err := filepath.Abs(passwd.HomeDir)
	if err != nil {
		return false, err
	}
	passedAbs, err := filepath.Abs(passed)
	if err != nil {
		return false, err
	}
	return passedAbs != passwdAbs, nil
}

func (x XdgPosix) MobileSharedHome(emptyOk bool) (string, error) {
	return x.Home(emptyOk)
}

func (x XdgPosix) dirHelper(xdgEnvVar string, prefixDirs ...string) (string, error) {
	appName := x.appName
	if x.getRunMode() != RunModeProd {
		appName = appName + "." + x.getRunMode().ToString()
	}

	isNonstandard, isNonstandardErr := x.IsNonstandardHome()
	xdgSpecified := x.getenv(xdgEnvVar)

	// If the user specified a nonstandard home directory, or there's no XDG
	// environment variable present, use the home directory from the
	// commandline/environment/config.
	if (isNonstandardErr == nil && isNonstandard) || xdgSpecified == "" {
		d, err := x.Home(false)
		if err != nil {
			return "", err
		}
		alternateDir := x.Join(append([]string{d}, prefixDirs...)...)
		return x.Join(alternateDir, appName), nil
	}

	// Otherwise, use the XDG standard.
	return x.Join(xdgSpecified, appName), nil
}

func (x XdgPosix) ConfigDir() (string, error)      { return x.dirHelper("XDG_CONFIG_HOME", ".config") }
func (x XdgPosix) CacheDir() (string, error)       { return x.dirHelper("XDG_CACHE_HOME", ".cache") }
func (x XdgPosix) SharedCacheDir() (string, error) { return x.CacheDir() }
func (x XdgPosix) DataDir() (string, error)        { return x.dirHelper("XDG_DATA_HOME", ".local", "share") }
func (x XdgPosix) SharedDataDir() (string, error)  { return x.DataDir() }
func (x XdgPosix) DownloadsDir() (string, error) {
	xdgSpecified := x.getenv("XDG_DOWNLOAD_DIR")
	if xdgSpecified != "" {
		return xdgSpecified, nil
	}
	h, err := x.Home(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "Downloads"), nil
}
func (x XdgPosix) RuntimeDir() (string, error) { return x.dirHelper("XDG_RUNTIME_DIR", ".config") }
func (x XdgPosix) InfoDir() (string, error)    { return x.RuntimeDir() }

func (x XdgPosix) ServiceSpawnDir() (string, error) {
	ret, err := x.RuntimeDir()
	if err != nil {
		return "", err
	}
	if ret != "" {
		return ret, nil
	}
	ret, err = os.MkdirTemp("", "foks_agent")
	return ret, err
}

func (x XdgPosix) LogDir() (string, error) {
	// There doesn't seem to be an official place for logs in the XDG spec, but
	// according to http://stackoverflow.com/a/27965014/823869 at least, this
	// is the best compromise.
	return x.CacheDir()
}

type Darwin struct {
	Base
	forceIOS bool // for testing
}

func (d Darwin) isIOS() bool {
	return isIOS || d.forceIOS
}

func (d Darwin) appDir(dir string, prefixDirs []string) string {
	dirs := []string{dir}
	dirs = append(dirs, prefixDirs...)
	dirs = append(dirs, d.appName)

	runMode := d.getRunMode()
	if runMode != RunModeProd {
		dirs = append(dirs, runMode.ToString())
	}
	return filepath.Join(dirs...)
}

func (d Darwin) sharedHome() (string, error) {
	homeDir, err := d.Home(false)
	if err != nil {
		return "", err
	}
	if !d.isIOS() {
		return homeDir, nil
	}

	// check if we have a shared container path, and if so, that is where the shared home is.
	sharedHome := d.getMobileSharedHome()
	if sharedHome != "" {
		return sharedHome, nil
	}
	return homeDir, nil
}

func (d Darwin) CacheDir() (string, error) {
	h, err := d.Home(false)
	if err != nil {
		return "", err
	}
	return d.appDir(h, []string{"Library", "Caches"}), nil
}

func (d Darwin) SharedCacheDir() (string, error) {
	h, err := d.sharedHome()
	if err != nil {
		return "", err
	}
	return d.appDir(h, []string{"Library", "Caches"}), nil
}

func (d Darwin) ConfigDir() (string, error) {
	h, err := d.sharedHome()
	if err != nil {
		return "", err
	}
	return d.appDir(h, []string{"Library", "Application Support"}), nil
}
func (d Darwin) DataDir() (string, error) {
	h, err := d.Home(false)
	if err != nil {
		return "", err
	}
	return d.appDir(h, []string{"Library", "Application Support"}), nil
}
func (d Darwin) SharedDataDir() (string, error) {
	h, err := d.sharedHome()
	if err != nil {
		return "", err
	}
	return d.appDir(h, []string{"Library", "Application Support"}), nil
}
func (d Darwin) RuntimeDir() (string, error)      { return d.CacheDir() }
func (d Darwin) ServiceSpawnDir() (string, error) { return d.RuntimeDir() }

func (d Darwin) LogDir() (string, error) {
	runMode := d.getRunMode()
	h, err := d.Home(false)
	if err != nil {
		return "", err
	}
	dirs := []string{h, "Library", "Logs", d.appName}
	if runMode != RunModeProd {
		dirs = append(dirs, runMode.ToString())
	}
	return filepath.Join(dirs...), nil
}

func (d Darwin) InfoDir() (string, error) {
	// If the user is explicitly passing in a HomeDirectory, make the PID file directory
	// local to that HomeDir. This way it's possible to have multiple keybases in parallel
	// running for a given run mode, without having to explicitly specify a PID file.

	if d.getHome() != "" {
		return d.CacheDir()
	}
	return d.appDir(os.TempDir(), nil), nil
}

func (d Darwin) DownloadsDir() (string, error) {
	h, err := d.Home(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "Downloads"), nil
}

func (d Darwin) Home(emptyOk bool) (string, error) {
	ret := d.getHome()
	if len(ret) == 0 && !emptyOk {
		ret = d.getenv("HOME")
	}
	return ret, nil
}

func (d Darwin) MobileSharedHome(emptyOk bool) (string, error) {
	var ret string
	if d.getMobileSharedHome != nil {
		ret = d.getMobileSharedHome()
	}
	if len(ret) == 0 && !emptyOk {
		ret = d.getenv("MOBILE_SHARED_HOME")
	}
	return ret, nil
}

func (d Darwin) Normalize(s string) string { return s }

type Win32 struct {
	Base
}

var win32SplitRE = regexp.MustCompile(`[/\\]`)

func (w Win32) Split(s string) []string {
	return win32SplitRE.Split(s, -1)
}

func (w Win32) Unsplit(v []string) string {
	if len(v) > 0 && len(v[0]) == 0 {
		v2 := make([]string, len(v))
		copy(v2, v)
		v[0] = string(filepath.Separator)
	}
	result := filepath.Join(v...)
	// filepath.Join doesn't add a separator on Windows after the drive
	if len(v) > 0 && result[len(v[0])] != filepath.Separator {
		v = append(v[:1], v...)
		v[1] = string(filepath.Separator)
		result = filepath.Join(v...)
	}
	return result
}

func (w Win32) Normalize(s string) string {
	return w.Unsplit(w.Split(s))
}

// foksDir returns the directory we're going to use for almost all FOKS data, from cache to
// more durable goods, like secret key files. Why not use os.UserCacheDir() and os.UserConfigDir()?
// Well they both aren't named very well. It turns out the os.UserCacheDir() is referring to
// ~/AppData/Local, which means data that isn't synced across the LAN via various windows workgroup
// configurations. ~/AppData/Roaming, which is returned by os.UserConfigDir(), is synced, but we
// don't want that for secret keys. So we're not going to use it. From what I can tell, there is
// no risk that the data in ~/AppData/Local will be treated like a cache and swept away. Only
// data in ~/AppData/Local/Temp seems to be subject to this treatment. However, I'm concerned that
// Go will eventually change the meaning of os.UserCacheDir(), so we're just doing what it
// does internaly (read the %LocalAppData% environment variable).
func (w Win32) foksDir() (string, error) {

	dir := os.Getenv("LocalAppData")
	if dir == "" {
		return "", core.HomeError("%LocalAppData% is not defined; cannot find home directory")
	}

	packageName := "foks"
	dirs := []string{dir, packageName}

	if w.getRunMode() != RunModeProd {
		runModeName := w.getRunMode().ToString()
		dirs = append(dirs, runModeName)
	}

	return w.Unsplit(dirs), nil
}

func (w Win32) CacheDir() (string, error)        { return w.foksDir() }
func (w Win32) SharedCacheDir() (string, error)  { return w.foksDir() }
func (w Win32) ConfigDir() (string, error)       { return w.foksDir() }
func (w Win32) DataDir() (string, error)         { return w.foksDir() }
func (w Win32) SharedDataDir() (string, error)   { return w.foksDir() }
func (w Win32) RuntimeDir() (string, error)      { return w.foksDir() }
func (w Win32) InfoDir() (string, error)         { return w.foksDir() }
func (w Win32) ServiceSpawnDir() (string, error) { return w.foksDir() }
func (w Win32) LogDir() (string, error)          { return w.foksDir() }

func (w Win32) DownloadsDir() (string, error) {
	// Prefer to use USERPROFILE instead of w.Home() because the latter goes
	// into APPDATA.
	user, err := user.Current()
	if err == nil {
		return filepath.Join(user.HomeDir, "Downloads"), nil
	}
	d, err := w.Home(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "Downloads"), nil
}

func (w Win32) Home(emptyOk bool) (string, error) {
	ret := w.getHome()

	if ret == "" && !emptyOk {
		dir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		ret = dir
	}

	if ret == "" {
		var err error
		if !emptyOk {
			err = core.HomeError("cannot find home directory via APPDATA variable")
		}
		return ret, err
	}

	packageName := "foks"
	dirs := []string{ret, packageName}

	if w.getRunMode() != RunModeProd {
		runModeName := w.getRunMode().ToString()
		dirs = append(dirs, runModeName)
	}

	return filepath.Join(dirs...), nil
}

func (w Win32) MobileSharedHome(emptyOk bool) (string, error) {
	return w.Home(emptyOk)
}

func NewHomeFinder(appName string, getHomeFromCmd ConfigGetter, getHomeFromConfig ConfigGetter, getMobileSharedHome ConfigGetter,
	osname string, getRunMode RunModeGetter, getenv EnvGetter) HomeFinder {
	base := Base{appName, getHomeFromCmd, getHomeFromConfig, getMobileSharedHome, getRunMode, getenv}
	switch getRuntimeGroup(osname) {
	case RuntimeGroupWindows:
		return Win32{base}
	case RuntimeGroupDarwin:
		return Darwin{Base: base}
	default:
		return XdgPosix{base}
	}
}
