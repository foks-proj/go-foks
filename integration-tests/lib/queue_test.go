// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/stretchr/testify/require"
)

// Simple test of the inter-server native queue service. Checks that frontend servers
// can connect to the queue service, that it can authenticate properly, and communicate,
// etc. Involves therefore communication with the internal CA, which needs to issue
// an intermediate client cert, etc.
func TestQueueService(t *testing.T) {
	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	ctx := context.Background()
	crt := u.ClientCertRobust(ctx, t)
	tcli, closeFn, err := newTestProtClient(ctx, crt, nil)
	require.NoError(t, err)
	defer closeFn()

	var rbuf [32]byte
	err = core.RandomFill(rbuf[:])
	require.NoError(t, err)
	var laneId infra.QueueLaneID
	laneId[0] = 0x4
	laneId[len(laneId)-1] = 0xf
	ret, err := tcli.TestQueueService(ctx, infra.TestQueueServiceArg{
		QueueId: infra.QueueID_Kex,
		LaneId:  laneId,
		Msg:     rbuf[:],
	})
	require.NoError(t, err)
	require.Equal(t, rbuf[:], ret)
}
