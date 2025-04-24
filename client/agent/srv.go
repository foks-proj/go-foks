// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libgit"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type Agent struct {
	sync.Mutex
	g        *libclient.GlobalContext
	listener net.Listener
	wg       sync.WaitGroup

	quitCalled bool
	sessions   *Sessions

	// Can be triggered by a control channel to ask the agent to shutdown
	triggerStopCh chan struct{}
	stopTriggered bool

	stopperFileCh chan struct{}

	bg *libclient.BgJobMgr
}

func NewAgent(m libclient.MetaContext) *Agent {
	return &Agent{
		g:             m.G(),
		sessions:      NewSessions(),
		triggerStopCh: make(chan struct{}),
		stopperFileCh: make(chan struct{}),
	}
}

func (a *Agent) stopperFileLoop(m libclient.MetaContext) {

	m = m.Background().WithLogTag("stopperFileLoop")

	doIt := m.G().Cfg().GetAgentCheckStopper()
	if !doIt {
		return
	}

	stopperFile, err := m.G().Cfg().GetAgentStopperFile()
	if err != nil {
		m.Warnw("stopperFileLoop", "err", err)
		return
	}

	findFile := func() bool {
		_, err := stopperFile.Stat()
		return err == nil
	}

	m.Infow("stopperFileLoop", "stage", "start", "file", stopperFile)

	first := true

	for {
		if findFile() {
			break
		}
		time.Sleep(3 * time.Second)
		first = false
	}

	if !first {
		m.Infow("stopperFileLoop", "stage", "stop", "file", stopperFile)
	} else {
		m.Errorw("stopperFileLoop", "stage", "stop", "file", stopperFile,
			"msg", "file found but on first iteration; stale file from previous run?")
	}

	a.Lock()
	defer a.Unlock()
	close(a.stopperFileCh)
}

// Called by some agent connection (Like a control channel), that sends a message
// back up to us and then our caller, which then calls Stop().
func (a *Agent) TriggerStop() {
	a.Lock()
	defer a.Unlock()
	if a.stopTriggered {
		return
	}
	a.stopTriggered = true
	close(a.triggerStopCh)
}

func (a *Agent) TriggerStopCh() <-chan struct{} {
	return a.triggerStopCh
}

func (a *Agent) StopperFileCh() <-chan struct{} {
	return a.stopperFileCh
}

func (a *Agent) SessionBase(id proto.UISessionID) *SessionBase {
	i := a.sessions.Get(id)
	if i == nil {
		return nil
	}
	return i.Base()
}

func (a *Agent) stopListener() {
	a.Lock()
	defer a.Unlock()
	if !a.quitCalled {
		a.quitCalled = true
		a.listener.Close()
	}
}

func (a *Agent) didQuit() bool {
	a.Lock()
	defer a.Unlock()
	return a.quitCalled
}

func (a *Agent) Stop() {
	if a.bg != nil {
		a.bg.Stop()
	}
	a.stopListener()
	a.wg.Wait()
}

func (a *Agent) startBg(m libclient.MetaContext) error {
	cfg, err := m.G().Cfg().BgConfig()
	if err != nil {
		return err
	}
	bg := libclient.NewBgJobMgr(*cfg)
	a.bg = bg
	bg.Run(m)
	return nil
}

func (a *Agent) ServeWithListener(m libclient.MetaContext, l net.Listener) error {
	err := a.startBg(m)
	if err != nil {
		return err
	}
	a.listener = l
	a.wg.Add(1)
	go a.serve(m)
	go a.stopperFileLoop(m)
	return nil
}

func (a *Agent) serve(m libclient.MetaContext) {
	defer a.wg.Done()
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			if a.didQuit() {
				return
			}
			m.Warnw("Agent.serve.Accept", "err", err)
		} else {
			a.wg.Add(1)
			go func() {
				a.handleConn(m, conn)
				a.wg.Done()
			}()
		}
	}
}

func (a *Agent) handleConn(m libclient.MetaContext, conn net.Conn) {
	NewAgentConn(a, conn).Serve(m)
}

type AgentConn struct {
	g     *libclient.GlobalContext
	agent *Agent
	conn  net.Conn
	xp    rpc.Transporter
	srv   *rpc.Server

	gitMu sync.Mutex
	git   *libgit.Agent
}

func NewAgentConn(a *Agent, c net.Conn) *AgentConn {
	return &AgentConn{
		agent: a,
		conn:  c,
	}
}

func (c *AgentConn) Serve(m libclient.MetaContext) {

	var rpcLogOpts rpc.LogOptions
	tmp, err := m.G().Cfg().RPCLogOptions()
	if err != nil {
		m.Warnw("rpcLogOpts", "err", err)
		rpcLogOpts = &rpc.StandardLogOptions{}
	} else {
		rpcLogOpts = tmp
	}

	lf := rpc.NewSimpleLogFactory(
		core.NewZapLogWrapper(m.G().Log()),
		rpcLogOpts,
	)

	wef := rem.RegMakeGenericErrorWrapper(core.ErrorToStatus)
	xp := rpc.NewTransport(
		m.Ctx(),
		c.conn,
		lf,
		nil,
		wef,
		core.RpcMaxSz,
	)
	c.xp = xp
	c.srv = rpc.NewServer(xp, wef)
	protocols := []rpc.ProtocolV2{
		lcl.SignupProtocol(c),
		lcl.GeneralProtocol(c),
		lcl.CtlProtocol(c),
		lcl.UserProtocol(c),
		lcl.DeviceAssistProtocol(c),
		lcl.YubiProtocol(c),
		lcl.DeviceProtocol(c),
		lcl.PassphraseProtocol(c),
		lcl.TeamProtocol(c),
		lcl.KVProtocol(c),
		lcl.BackupProtocol(c),
		lcl.GitHelperProtocol(c),
		lcl.GitProtocol(c),
		lcl.AdminProtocol(c),
		lcl.UtilProtocol(c),
		lcl.KeyProtocol(c),
	}
	otherProtocols := OtherProtocols(c)
	protocols = append(protocols, otherProtocols...)
	for _, p := range protocols {
		err = c.srv.RegisterV2(p)
		if err != nil {
			m.Warnw("serve", "stage", "registerv2", "protocol", p, "err", err)
		}
	}
	c.g = m.G()
	<-c.srv.Run()
	err = c.srv.Err()
	if err != nil && err != io.EOF {
		m.Errorw("server error", "err", err)
	}
}

func AcceptWithCancel(ctx context.Context, l net.Listener) (net.Conn, error) {

	type listenRes struct {
		c net.Conn
		e error
	}

	ch := make(chan listenRes)

	go func() {
		net, err := l.Accept()
		ch <- listenRes{net, err}
	}()

	select {
	case <-ctx.Done():
		l.Close()
		<-ch
		return nil, ctx.Err()
	case res := <-ch:
		return res.c, res.e
	}
}

func (c *AgentConn) CheckArgHeader(ctx context.Context, h lcl.Header) error {
	return nil
}

func (c *AgentConn) MakeResHeader() lcl.Header {
	return lcl.NewHeaderWithV1(
		lcl.HeaderV1{
			Semver: core.CurrentClientVersion,
		},
	)
}
