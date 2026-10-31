package realtime

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type Server struct {
	shared.BaseRPCServer
}

func (s *Server) ToRPCServer() shared.RPCServer { return s }
func (s *Server) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValid(m, uhc, key)
}
func (s *Server) RequireAuth() shared.AuthType { return shared.AuthTypeExternal }

func (s *Server) ServerType() proto.ServerType {
	return proto.ServerType_RealTime
}

func (s *Server) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &ClientConn{
		srv:            s,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(s.G(), uhc),
	}
}
func (c *ClientConn) RegisterProtocols(m shared.MetaContext, srv shared.RPCRegistrar) error {
	return srv.RegisterV2(rem.RealTimeProtocol(c))
}

func (c *ClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

type ClientConn struct {
	shared.BaseClientConn
	srv *Server
	xp  rpc.Transporter
}

func (s *Server) Setup(m shared.MetaContext) error {
	return nil
}

func (c *ClientConn) RtNewChannel(ctx context.Context, arg rem.RtNewChannelArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	err := MakeChannel(m, arg)
	return err
}

// RtGetChannel is inventory row 6: unimplemented upstream and unimplemented
// here. When it is implemented it MUST load and authorize the channel through
// authorizeChannel(accessRead) like every other per-channel read, not with a
// bare SELECT. TestRealtimeRpcInventory's source guard fails the build if a
// query against `channels` appears outside the allowlisted call sites, so this
// obligation is enforced rather than merely written down.
func (c *ClientConn) RtGetChannel(ctx context.Context, arg proto.RTChannelID) (res rem.RTChannelMetadata, err error) {
	return res, core.NotImplementedError{}
}

func (c *ClientConn) RtListAllChannelsForTeam(
	ctx context.Context,
	arg rem.RtListAllChannelsForTeamArg,
) (
	rem.RTChannelSet,
	error,
) {
	var ret rem.RTChannelSet
	m := shared.NewMetaContextConn(ctx, c)
	p, err := ListAllChannels(m, arg.Team, arg.AppID, arg.Last)
	if err != nil {
		return ret, err
	}
	return *p, nil
}

func (c *ClientConn) RtSend(ctx context.Context, arg rem.RTSendArg) (res rem.RTSendRes, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := SendMessage(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtGetThread(ctx context.Context, arg rem.RTThreadQuery) (res rem.RTThreadPage, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := GetThread(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtGetInboxVersion(ctx context.Context, arg rem.RTInboxKey) (res proto.RTInboxVersion, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	return GetInboxVersion(m, arg)
}
func (c *ClientConn) RtGetChangedThreads(ctx context.Context, arg rem.RTGetChangedThreadsArg) (res rem.RTInboxDelta, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := GetChangedThreads(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtReadThrough(ctx context.Context, arg rem.RTReadThroughArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return MarkReadThrough(m, arg)
}
func (c *ClientConn) RtSetPushToken(ctx context.Context, arg rem.RtSetPushTokenArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return SetPushToken(m, arg)
}
func (c *ClientConn) RtPollInbox(ctx context.Context, arg rem.RTPollInboxArg) (res proto.RTInboxPollRes, err error) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := PollInbox(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}
func (c *ClientConn) RtSelectVHost(ctx context.Context, arg proto.HostID) error {
	return shared.SelectVHost(ctx, c, arg)
}
func (c *ClientConn) RtGetThreadRecents(
	ctx context.Context,
	arg rem.RtGetThreadRecentsArg,
) (
	res rem.RTMsgList,
	err error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	ret, err := GetThreadRecents(m, arg)
	if err != nil {
		return res, err
	}
	return *ret, nil
}

// Fork-only private-channel ACL management; see docs/rt-private-channel-acl.md.

func (c *ClientConn) RtChannelGrant(ctx context.Context, arg rem.RtChannelGrantArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return GrantChannelMember(m, arg)
}

func (c *ClientConn) RtChannelRevoke(ctx context.Context, arg rem.RtChannelRevokeArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return RevokeChannelMember(m, arg)
}

func (c *ClientConn) RtChannelMembers(
	ctx context.Context,
	arg proto.RTChannelID,
) (
	res []rem.RTChannelAclEntry,
	err error,
) {
	m := shared.NewMetaContextConn(ctx, c)
	return ListChannelMembers(m, arg)
}

// Fork-only delegated push release; see pushhold.go.

func (c *ClientConn) RtSetPushHold(ctx context.Context, arg rem.RtSetPushHoldArg) error {
	return SetPushHold(shared.NewMetaContextConn(ctx, c), arg)
}

func (c *ClientConn) RtClearPushHold(ctx context.Context, arg rem.RtClearPushHoldArg) error {
	return ClearPushHold(shared.NewMetaContextConn(ctx, c), arg)
}

func (c *ClientConn) RtReleasePushes(ctx context.Context, arg rem.RtReleasePushesArg) error {
	return ReleasePushes(shared.NewMetaContextConn(ctx, c), arg)
}

func (c *ClientConn) RtNotifyMembers(ctx context.Context, arg rem.RtNotifyMembersArg) error {
	return NotifyMembers(shared.NewMetaContextConn(ctx, c), arg)
}

func (c *ClientConn) RtUpdateChannel(ctx context.Context, arg rem.RtUpdateChannelArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return UpdateChannel(m, arg)
}

func (c *ClientConn) RtSetChannelArchived(ctx context.Context, arg rem.RtSetChannelArchivedArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return SetChannelArchived(m, arg)
}

func (c *ClientConn) RtSetChannelMuted(ctx context.Context, arg rem.RtSetChannelMutedArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return SetChannelMuted(m, arg)
}

func (c *ClientConn) RtSetReadReceipts(ctx context.Context, arg rem.RtSetReadReceiptsArg) error {
	m := shared.NewMetaContextConn(ctx, c)
	return SetReadReceipts(m, arg)
}

func (c *ClientConn) RtGetReadReceipts(ctx context.Context, arg proto.RTAppID) (bool, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return GetReadReceipts(m, rem.RtGetReadReceiptsArg{AppID: arg})
}

var _ shared.RPCServer = (*Server)(nil)

var _ rem.RealTimeInterface = (*ClientConn)(nil)
