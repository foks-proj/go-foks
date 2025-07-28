package agent

import (
	"context"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (a *AgentConn) BotTokenNew(
	ctx context.Context,
	role proto.Role,
) (
	lcl.BotTokenString,
	error,
) {
	var zed lcl.BotTokenString
	m := a.MetaContext(ctx)
	r, err := a.prepareNewDevice(m, role)
	if err != nil {
		return zed, err
	}
	bkp, err := core.NewBotToken()
	if err != nil {
		return zed, err
	}
	ks, err := bkp.KeySuite(role, r.hostID)
	if err != nil {
		return zed, err
	}
	dln, err := bkp.DeviceLabelAndName()
	if err != nil {
		return zed, err
	}
	lkr := libclient.NewLoopbackKexRunner(
		m.G(),
		r.devKey,
		ks,
		r.au.FQU(),
		role,
		*dln,
		r.lke,
		r.tok,
	)
	err = lkr.Run(ctx)
	if err != nil {
		return zed, err
	}
	ret, err := bkp.Export()
	if err != nil {
		return zed, err
	}
	return ret, nil
}

func (a *AgentConn) BotTokenLoad(
	ctx context.Context,
	arg lcl.BotTokenLoadArg,
) error {
	m := a.MetaContext(ctx)
	var tok core.BotToken
	err := tok.Import(arg.Tok)
	if err != nil {
		return err
	}
	prb, err := a.probe(m, arg.Host, 30*time.Second)
	if err != nil {
		return err
	}
	hostID := prb.Chain().HostID()
	ks, err := tok.KeySuite(proto.OwnerRole, hostID)
	if err != nil {
		return err
	}

	regCli, err := prb.RegCli(m)
	if err != nil {
		return err
	}
	lures, err := lookupDeviceOnServer(m, ks, *regCli, hostID)
	if err != nil {
		return err
	}
	uctx, err := populateUserContext(lures, prb, ks, proto.KeyGenus_BotToken, nil)
	if err != nil {
		return err
	}

	uctx.Devname = tok.Name()
	err = libclient.SetActiveUser(m, uctx)
	if err != nil {
		return err
	}
	err = uctx.PopulateWithDevkey(m)
	if err != nil {
		return err
	}
	return nil
}

var _ lcl.BotTokenInterface = (*AgentConn)(nil)
