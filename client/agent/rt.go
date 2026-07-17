package agent

import (
	"context"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (c *AgentConn) rtInit(
	ctx context.Context,
	cfg lcl.RTConfig,
) (
	librt.MetaContext,
	*librt.Minder,
	error,
) {
	m := librt.NewMetaContext(c.MetaContext(ctx))
	ret, err := librt.InitReq(m, cfg.Team)
	if err != nil {
		return m, nil, err
	}
	return m, ret, err
}

func (c *AgentConn) ClientRTMakeChannel(
	ctx context.Context,
	arg lcl.ClientRTMakeChannelArg,
) (
	proto.RTChannelID,
	error,
) {
	var zed proto.RTChannelID
	m, minder, err := c.rtInit(ctx, arg.Cfg)
	if err != nil {
		return zed, err
	}
	t, err := arg.Cfg.Channel.GetT()
	if err != nil {
		return zed, err
	}
	if t != lcl.RTChannelSpecifierType_Name {
		return zed, core.BadArgsError("expected a channel name")
	}
	nm := arg.Cfg.Channel.Name().Name
	chid, err := minder.MakeChannel(
		m,
		arg.Cfg.Team,
		arg.Cfg.AppID,
		nm,
		arg.Desc,
		arg.Cfg.Roles,
	)
	if err != nil {
		return zed, err
	}
	return *chid, nil
}

func (c *AgentConn) ClientRTListChannelsForTeam(
	ctx context.Context,
	arg lcl.RTConfig,
) (
	lcl.RTChannelSetForTeam,
	error,
) {
	var zed lcl.RTChannelSetForTeam
	m, minder, err := c.rtInit(ctx, arg)
	if err != nil {
		return zed, err
	}
	lst, err := minder.ListAllChannelsForTeam(m, arg.Team, arg.AppID)
	if err != nil {
		return zed, err
	}
	return *lst, nil
}

func (c *AgentConn) ClientRTSend(
	ctx context.Context,
	arg lcl.ClientRTSendArg,
) (
	proto.RTMsgSeq,
	error,
) {
	var zed proto.RTMsgSeq
	m, minder, err := c.rtInit(ctx, arg.Cfg)
	if err != nil {
		return zed, err
	}
	res, err := minder.Send(m, arg.Cfg.Team, arg.Cfg.AppID, arg.Cfg.Channel, arg.Body)
	if err != nil {
		return zed, err
	}
	return res.Seq, nil
}

func (c *AgentConn) ClientRTGetThread(
	ctx context.Context,
	arg lcl.ClientRTGetThreadArg,
) (
	lcl.RTThreadView,
	error,
) {
	var zed lcl.RTThreadView
	m, minder, err := c.rtInit(ctx, arg.Cfg)
	if err != nil {
		return zed, err
	}
	view, err := minder.GetThreadView(m, arg.Cfg.Team, arg.Cfg.AppID, arg.Cfg.Channel, arg.Before, uint(arg.Num))
	if err != nil {
		return zed, err
	}
	return *view, nil
}

func (c *AgentConn) ClientRTInboxView(
	ctx context.Context,
	arg lcl.ClientRTInboxViewArg,
) (
	lcl.RTInboxView,
	error,
) {
	var zed lcl.RTInboxView
	m := librt.NewMetaContext(c.MetaContext(ctx))
	minder, err := librt.InitUserReq(m)
	if err != nil {
		return zed, err
	}
	if !arg.LocalOnly {
		_, err = minder.SyncInbox(m, arg.AppID)
		if err != nil {
			return zed, err
		}
	}
	view, err := minder.LocalInbox(m, arg.AppID)
	if err != nil {
		return zed, err
	}
	return *view, nil
}

var _ lcl.RealTimeInterface = (*AgentConn)(nil)
