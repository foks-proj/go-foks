package agent

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func (c *AgentConn) ClientRTMakeChannel(
	ctx context.Context,
	arg lcl.ClientRTMakeChannelArg,
) (
	proto.RTChannelID,
	error,
) {
	var zed proto.RTChannelID
	return zed, core.NotImplementedError{}
}

var _ lcl.RealTimeInterface = (*AgentConn)(nil)
