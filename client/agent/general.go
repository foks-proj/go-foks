// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (a *AgentConn) GetActiveUser(ctx context.Context) (proto.UserContext, error) {
	m := a.MetaContext(ctx)
	var zed proto.UserContext
	au, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return zed, err
	}
	exp, err := au.Export()
	if err != nil {
		return zed, err
	}
	return *exp, nil
}

func (a *AgentConn) getVHostMgmtHost(
	m libclient.MetaContext,
	prb *chains.Probe,
	res *lcl.GetDefaultServerRes,
	timeout time.Duration,
) error {
	rcli, err := prb.RegCli(m)
	if err != nil {
		return err
	}

	mgmtHost, err := rcli.GetVHostMgmtHost(m.Ctx())
	if err != nil {
		return err
	}

	pres, err := a.probe(m, mgmtHost, timeout)
	res.Mgmt = &lcl.HostStatusPair{
		Host:   mgmtHost,
		Status: core.ErrorToStatus(err),
	}

	if err == nil {
		res.Mgmt.Host = pres.CanonicalAddr()
	}

	return nil

}

func (a *AgentConn) GetDefaultServer(
	ctx context.Context,
	arg lcl.GetDefaultServerArg,
) (
	lcl.GetDefaultServerRes,
	error,
) {
	var res lcl.GetDefaultServerRes
	sess := a.agent.SessionBase(arg.SessionId)
	if sess == nil {
		return res, core.SessionNotFoundError(arg.SessionId)
	}

	m := a.MetaContext(ctx)
	mOrig := m
	if arg.Timeout > 0 {
		timeout := arg.Timeout.Duration()
		var canc func()
		m, canc = m.WithContextTimeout(timeout)
		defer canc()
	}

	var def proto.TCPAddr
	prb, err := a.probe(m, def, 0)

	// It's OK if no default host, we'll just return an empty host, this isn't an error condition
	if _, ok := err.(core.NoDefaultHostError); ok || prb == nil {
		return res, nil
	}

	srv := prb.CanonicalAddr()
	res.BigTop.Host = srv

	// Don't return an error here since we want the caller to know which default host we tried.
	// Send the err as a status field in the RPC reply.
	if err != nil {
		res.BigTop.Status = core.ErrorToStatus(err)
		return res, nil
	}

	tmpErr := a.getVHostMgmtHost(mOrig, prb, &res, arg.Timeout.Duration())
	if tmpErr != nil {
		m.Warnw("getVHostMgmtHost", "err", tmpErr)
	}

	sess.defaultServer = prb
	return res, nil
}

func (c *AgentConn) PutServer(ctx context.Context, arg lcl.PutServerArg) (proto.RegServerConfig, error) {
	var ret proto.RegServerConfig
	sess, err := c.agent.sessions.Base(arg.SessionId)
	if err != nil {
		return ret, err
	}
	m := c.MetaContext(ctx)
	defPort := libclient.DefProbePort
	var prb *chains.Probe

	if arg.Server == nil {
		prb = sess.defaultServer
	} else {
		tmp, err := arg.Server.Portify(defPort)
		if err != nil {
			return ret, err
		}
		tmout := arg.Timeout.Duration()
		if tmout == 0 {
			tmout = 10 * time.Second
		}
		dur := tmout.String()
		m.Infow("discover", "timeout", dur, "host", tmp)

		// Crucial to create a new context here, so later in the function,
		// our contexst isn't timed out. Just to be sure, we change it to
		// a new context (m2) so we don't introduce bugs down the line.
		m2, canc := m.WithContextTimeout(tmout)
		defer canc()
		rootCAs, err := m2.G().ProbeRootCAs(m.Ctx())
		if err != nil {
			return ret, err
		}
		prb, err = probe(m2, 0, tmp, rootCAs)
		if err != nil {
			m2.Infow("discover", "err", err)
			return ret, err
		}
	}
	if prb == nil || prb.PublicZone() == nil {
		return ret, core.InternalError("no public zone found")
	}
	cli, err := prb.RegCli(m)
	if err != nil {
		return ret, err
	}
	cfg, err := cli.GetServerConfig(m.Ctx())
	if err != nil {
		return ret, err
	}
	sess.homeServer = prb
	sess.ssoCfg = cfg.Sso
	sess.regServerType = arg.Typ
	sess.hostType = cfg.Typ
	return cfg, nil

}

func (c *AgentConn) ClearDeviceNag(ctx context.Context, val bool) error {
	m := c.MetaContext(ctx)
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{})
	if err != nil {
		return err
	}
	ucli, err := au.UserClient(m)
	if err != nil {
		return err
	}
	err = ucli.ClearDeviceNag(m.Ctx(), val)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConn) GetUnifiedNags(
	ctx context.Context,
	arg lcl.GetUnifiedNagsArg,
) (
	lcl.UnifiedNagRes,
	error,
) {
	var ret lcl.UnifiedNagRes
	m := c.MetaContext(ctx)
	nm := libclient.NagMinder{
		WithRateLimit: arg.WithRateLimit,
		CliVersion:    arg.Cv,
	}
	err := nm.Run(m)
	if err != nil {
		return ret, err
	}
	ret.Nags = nm.GetResult()
	return ret, nil
}

func (c *AgentConn) SnoozeUpgradeNag(
	ctx context.Context,
	arg lcl.SnoozeUpgradeNagArg,
) error {
	m := c.MetaContext(ctx)
	return libclient.SnoozeVersionUpgrade(m,
		arg.Dur.Duration(),
		arg.Val,
	)
}

var _ lcl.GeneralInterface = (*AgentConn)(nil)
