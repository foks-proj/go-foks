// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/spf13/cobra"
)

func setupCtlCmd(m libclient.MetaContext) error {
	err := m.Configure()
	if err != nil {
		return err
	}
	return nil
}

func ctlCmd(m libclient.MetaContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "ctl",
		Short:        "control the FOKS background agent",
		Long:         `Start, stop, restart the FOKS background agent, using local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return errors.New("ctl command requires subcommand")
		},
	}
	stop := &cobra.Command{
		Use:          "stop",
		Short:        "stop the FOKS background agent via local daemonization tools",
		Long:         `Stop the FOKS background agent, using local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunCtlStop(m, cmd, arg)
		},
	}
	cmd.AddCommand(stop)
	shutdown := &cobra.Command{
		Use:          "shutdown",
		Short:        "shudown the FOKS background agent via shutdown RPC to agent",
		Long:         `shutdown the FOKS background agent, can get restarted by local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunCtlShutdown(m, cmd, arg)
		},
	}
	cmd.AddCommand(shutdown)

	addStartCmd(m, cmd)

	status := &cobra.Command{
		Use:          "status",
		Short:        "print status of the FOKS background agent via launch or systemd, depending on your system",
		Long:         `print status of FOKS background agent, using local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunCtlStatus(m, cmd, arg)
		},
	}
	cmd.AddCommand(status)
	socket := &cobra.Command{
		Use:          "socket",
		Short:        "print the path to the FOKS background agent socket",
		Long:         "print the path to the FOKS background agent socket",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunCtlSocket(m, cmd, arg)
		},
	}
	cmd.AddCommand(socket)
	restart := &cobra.Command{
		Use:          "restart",
		Short:        "restart the FOKS background agent via local daemonization tools",
		Long:         `Restart the FOKS background agent, using local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunCtlRestart(m, cmd, arg)
		},
	}
	cmd.AddCommand(restart)

	AddPlatformCtlCommands(m, cmd)
	return cmd
}

func addStartCmd(m libclient.MetaContext, parent *cobra.Command) {

	var startWait bool
	invalDur := time.Duration(-1)
	startWaitFor := invalDur

	checkArgs := func() error {
		if !startWait && startWaitFor != invalDur {
			return core.BadArgsError("cannot specify --wait-for without --wait")
		}
		if startWaitFor != invalDur && startWaitFor <= 10*time.Millisecond {
			return core.BadArgsError("cannot specify 0 or tiny duration for --wait-for")
		}
		if startWaitFor == invalDur {
			startWaitFor = 30 * time.Second
		}
		return nil
	}

	start := &cobra.Command{
		Use:          "start",
		Short:        "start the FOKS background agent via launch or systemd, depending on your system",
		Long:         `Start the FOKS background agent, using local daeomization tools`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			err := checkArgs()
			if err != nil {
				return err
			}
			err = RunCtlStart(m, cmd, arg)
			if err != nil {
				return err
			}
			if !startWait {
				return nil
			}
			err = waitForAgentSocket(m, startWaitFor)
			if err != nil {
				return err
			}
			return nil
		},
	}

	start.Flags().BoolVar(&startWait, "wait", false,
		"block until the agent is accepting connections on its socket")
	start.Flags().DurationVar(&startWaitFor, "wait-for", invalDur, "specify time to wait [default: 10s]")

	parent.AddCommand(start)
}

func runCtlCmd(
	m libclient.MetaContext,
	cmd *cobra.Command,
	arg []string,
	fn func(m libclient.MetaContext, ctlCli *lcl.CtlClient) error,
) error {
	err := agent.Startup(m, agent.StartupOpts{NoStandalone: true})
	if err != nil {
		return err
	}
	gcli, clean, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer clean()
	cli := newClient[lcl.CtlClient](m, gcli)
	err = fn(m, &cli)
	if err != nil {
		return err
	}
	return nil
}

func RunCtlShutdown(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	return runCtlCmd(m, cmd, arg,
		func(m libclient.MetaContext, ctlCli *lcl.CtlClient) error {
			pid, err := ctlCli.Shutdown(m.Ctx())
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("shutdown agent with pid=%d\n", pid)
			return nil
		},
	)
}

func RunCtlSocket(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := m.Configure()
	if err != nil {
		return err
	}
	s, err := m.G().Cfg().SocketFile()
	if err != nil {
		return err
	}
	m.G().UIs().Terminal.Printf("%s\n", s)
	return nil
}

func waitForAgentSocket(m libclient.MetaContext, timeout time.Duration) error {

	now := time.Now()
	end := now.Add(timeout)

	sock, err := m.G().Cfg().SocketFile()
	if err != nil {
		return err
	}
	dialWait := 500 * time.Millisecond
	sleepWait := 250 * time.Millisecond

	for {
		tmp, err := sock.DialTimeout(dialWait)
		if err == nil {
			tmp.Close()
			return nil
		}
		m.Warnw("dial agent sock failed", "sock", sock.String(), "err", err)
		if time.Now().After(end) {
			break
		}
		time.Sleep(sleepWait)
	}
	return core.TimeoutError{}
}

func init() {
	AddCmd(ctlCmd)
}
