// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type BeaconRegister struct {
	CLIAppBase
	Delay time.Duration
	Tries int
	Wait  time.Duration
}

func (k *BeaconRegister) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "beacon-register",
		Short: "Register this host with the global beacon service",
	}
	ret.Flags().IntVar(&k.Tries, "tries", 10, "number of tries to register before failing")
	ret.Flags().DurationVar(&k.Wait, "wait", 0, "wait time between registration attempts (default 30s)")
	ret.Flags().DurationVar(&k.Delay, "delay", 0, "delay (on startup); default 0s")

	return ret
}

func (k *BeaconRegister) Run(m shared.MetaContext) error {
	err := shared.InitHostID(m)
	if err != nil {
		return err
	}

	nTries := k.Tries
	if nTries <= 0 {
		nTries = 1
	}

	time.Sleep(k.Delay)

	for i := range nTries {
		if i > 0 && k.Wait > 0 {
			m.Infow("Sleeping before next attempt", "attempt", i, "of", nTries, "wait", k.Wait)
			time.Sleep(k.Wait)
		}
		m.Infow("Registering", "attempt", i, "of", nTries)
		var zed proto.Hostname
		err = shared.BeaconRegisterCli(m, zed, nil)
		if err == nil {
			m.Infow("Success", "attempt", i, "of", nTries)
			return nil
		}
		m.Warnw("failed", "attempt", i, "of", nTries, "error", err)
	}
	return err
}

func (k *BeaconRegister) SetGlobalContext(g *shared.GlobalContext) {}
func (m *BeaconRegister) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if m.Tries <= 1 && m.Wait > 0 {
		return core.BadArgsError("cannot use --wait without --tries > 1")
	}
	return nil
}

var _ shared.CLIApp = (*BeaconRegister)(nil)

func init() {
	AddCmd(&BeaconRegister{})
}
