// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"errors"
	"net"
	"os"
	"path/filepath"
)

type Path string

func (p Path) String() string {
	return string(p)
}
func (p Path) Dir() Path {
	return Path(filepath.Dir(p.String()))
}
func (p Path) Base() Path {
	return Path(filepath.Base(p.String()))
}
func (p Path) TmpPattern() string {
	return p.Base().String() + ".tmp.*"
}
func (p Path) AdjacentTemp() (*os.File, error) {
	return os.CreateTemp(p.Dir().String(), p.TmpPattern())
}
func (p Path) MakeParentDirs() error {
	dir := p.Dir()
	err := os.MkdirAll(dir.String(), 0o755)
	if err != nil {
		return err
	}
	return nil
}
func (p Path) IsNil() bool {
	return p == ""
}
func (p Path) ReadFile() ([]byte, error) {
	return os.ReadFile(p.String())
}
func (p Path) WriteFile(data []byte, perm os.FileMode) error {
	return os.WriteFile(p.String(), data, perm)
}

func (p Path) Stat() (os.FileInfo, error) {
	return os.Stat(p.String())
}

func (p Path) ExistsAsFile() bool {
	info, err := p.Stat()
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func (p Path) JoinStrings(s ...string) Path {
	parts := []string{p.String()}
	parts = append(parts, s...)
	return Path(filepath.Join(parts...))
}

func MkdirTemp(pattern string) (Path, error) {
	fn, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}
	return Path(fn), nil
}

func (p Path) RemoveAll() error {
	return os.RemoveAll(p.String())
}

func (p Path) Join(p2 ...Path) Path {
	parts := []string{p.String()}
	for _, e := range p2 {
		parts = append(parts, e.String())
	}
	return Path(filepath.Join(parts...))
}
func (p Path) Append(s string) Path {
	return Path(p.String() + s)
}

func (p Path) Mkdir(mod os.FileMode) error {
	return os.Mkdir(p.String(), mod)
}
func (p Path) OpenFile(flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(p.String(), flag, perm)
}

func (p *Path) Set(s string) error {
	*p = Path(s)
	return nil
}

func (p *Path) Type() string {
	return "core.Path"
}

func (p Path) Chdir() error {
	return os.Chdir(p.String())
}

func (p Path) Dial() (net.Conn, error) {
	conn, err := net.Dial("unix", p.String())
	if err == nil {
		return conn, nil
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return nil, err
	}

	// On macOS, we hit this branch...
	if errors.Is(opErr.Err, os.ErrNotExist) {
		return nil, AgentConnectError{Path: p}
	}

	// On windows, we hit this branch. It might not be necessary to be this
	// specific.
	var syscallErr *os.SyscallError
	if opErr.Op == "dial" &&
		opErr.Net == "unix" &&
		errors.As(opErr.Err, &syscallErr) &&
		syscallErr.Syscall == "connect" {
		return nil, AgentConnectError{Path: p}
	}
	return nil, err
}

func (p Path) Remove() error {
	return os.Remove(p.String())
}

func (p Path) Listen() (net.Listener, error) {
	return net.Listen("unix", p.String())
}

func Getwd() (Path, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return Path(cwd), nil
}
