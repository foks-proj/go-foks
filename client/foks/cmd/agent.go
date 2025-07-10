// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/spf13/cobra"

	_ "net/http/pprof"
)

type AgentCmdConfig struct {
	daemonize bool
}

func agentCmd(m libclient.MetaContext) *cobra.Command {
	var acfg AgentCmdConfig
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "run a foks background agent",
		Long: `The FOKS background agent is a persistent process that
manages local key state.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunAgent(m, cmd, &acfg, arg)
		},
	}
	cmd.Flags().BoolVarP(&acfg.daemonize, "daemon", "d", false, "daemonize the agent to background")
	return cmd
}

type AgentCmd struct {
	cfg   *AgentCmdConfig
	agent *agent.Agent
	sock  net.Listener
}

func RunAgent(m libclient.MetaContext, cmd *cobra.Command, acfg *AgentCmdConfig, arg []string) error {
	m.G().SetName("agent")
	a := AgentCmd{cfg: acfg}
	return a.Run(m)
}

func socketFileCheck(f core.Path, full core.Path) (bool, error) {
	stat, err := f.Stat()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, core.SocketError{Msg: err.Error(), Path: full}
	}
	if stat.IsDir() {
		return false, core.SocketError{Msg: "socket file is a directory", Path: full}
	}
	return true, nil
}

// doListen checks if the socket file exists before listening on it. Existing
// sockets are further checked by attempting to connect to them. If no connection
// possible, the existing socket is removed. If a connection is possible, an error
// is raised.
func (a *AgentCmd) doListen(m libclient.MetaContext, f core.Path, full core.Path) error {
	exists, err := socketFileCheck(f, full)
	if err != nil {
		return err
	}
	if exists {
		conn, err := f.Dial()
		if err == nil {
			conn.Close()
			return core.SocketError{
				Msg:  "already in use",
				Path: full,
			}
		}
		m.Infow("doListen", "path", f, "action", "remote-stale")
		err = f.Remove()
		if err != nil {
			return err
		}
	}
	sock, err := f.Listen()
	if err != nil {
		return err
	}
	a.sock = sock
	return nil
}

func (a *AgentCmd) bind(m libclient.MetaContext) error {
	file, err := m.G().Cfg().SocketFile()
	if err != nil {
		return err
	}
	err = file.MakeParentDirs()
	if err != nil {
		return err
	}
	m.Infow("bind", "socket", file)

	err = libclient.SocketDance(m, file,
		func(m libclient.MetaContext, f core.Path) error {
			return a.doListen(m, f, file)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (a *AgentCmd) Cleanup(m libclient.MetaContext) error {
	if a.agent != nil {
		a.agent.Stop()
	}
	m.G().Shutdown()
	return nil
}

func (a *AgentCmd) awaitShutdown(m libclient.MetaContext) error {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	select {
	case s := <-sigc:
		m.Infow("shutdown", "signal", s)
	case <-a.agent.TriggerStopCh():
		m.Infow("shutdown", "which", "trigger")
	case <-a.agent.StopperFileCh():
		m.Infow("shutdown", "which", "stopper file")
	}

	return nil
}

func (a *AgentCmd) Run(m libclient.MetaContext) (err error) {
	m = m.WithLogTag("agent")
	err = m.Configure()
	if err != nil {
		return err
	}
	m.Infow("startup", "pid", os.Getpid())
	defer func() {
		tmp := a.Cleanup(m)
		if err == nil && tmp != nil {
			err = tmp
		}
	}()

	err = agent.InitTesting(m)
	if err != nil {
		return err
	}

	asto, err := m.G().Cfg().AgentStartupTimeout()
	if err != nil {
		return err
	}
	err = m.LoadActiveUser(libclient.LoadActiveUserOpts{
		Timeout: asto,
	})
	if err != nil {
		m.Warnw("AgentCmd.Run", "stage", "LoadActiveUser", "err", err)
		err = nil
	}

	err = agent.InitDevTools(m)
	if err != nil {
		return err
	}

	err = a.bind(m)
	if err != nil {
		return err
	}

	a.agent = agent.NewAgent(m)

	m.Infow("serve")

	err = a.agent.ServeWithListener(m, a.sock)
	if err != nil {
		return err
	}

	err = a.awaitShutdown(m)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	AddCmd(agentCmd)
}
