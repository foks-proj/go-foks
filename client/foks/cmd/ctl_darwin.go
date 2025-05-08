// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

//go:build darwin

package cmd

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/spf13/cobra"
)

func RunCtlStart(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := setupCtlCmd(m)
	if err != nil {
		return err
	}
	p := libclient.NewPlist()
	err = p.Load(m)
	prnt := m.G().UIs().Terminal.Printf

	prnt("Loading plist file: %s\n", p.Path())
	if err != nil {
		return err
	}
	prnt("foks agent is running in the background, and will start automatically on login\n")
	prnt("Use `foks ctl stop` to stop and uninstall it\n")
	return nil
}

func RunCtlStop(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := setupCtlCmd(m)
	if err != nil {
		return err
	}

	p := libclient.NewPlist()
	label, path, err := p.Unload(m)
	prnt := m.G().UIs().Terminal.Printf
	prnt("booting out: %s\n", label)
	prnt("removing plist file: %s\n", path)
	if err != nil {
		return err
	}
	return nil
}

func RunCtlStatus(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := setupCtlCmd(m)
	if err != nil {
		return err
	}
	p := libclient.NewPlist()
	s, err := p.Status(m)
	if err != nil {
		return err
	}
	fmt.Printf("%s", s.String())
	return nil
}

func RunCtlRestart(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := setupCtlCmd(m)
	if err != nil {
		return err
	}
	p := libclient.NewPlist()
	pid, label, err := p.Restart(m)
	if err != nil {
		return err
	}
	prnt := m.G().UIs().Terminal.Printf
	prnt("killing existing PID: %d\n", pid)
	prnt("restart label: %s\n", label)
	return nil
}

func doDaemonize(m libclient.MetaContext) error {
	return core.NotImplementedError{}
}

func AddPlatformCtlCommands(m libclient.MetaContext, cmd *cobra.Command) {
}
