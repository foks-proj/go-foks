// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

func TestPlanExpiration(t *testing.T) {
	bob := makeBobAndHisAgent(t)
	defer bob.stop(t)
	awc := newAdminWebClient(t, bob, nil)
	awc.makePlan(t, "Basic 18 Epsilon")
	merklePoke(t)

	m := awc.env.MetaContext()
	qcli, fn := common.TestQuotaSrvCli(t, m)
	defer func() {
		err := fn()
		require.NoError(t, err)
	}()
	ctx := m.Ctx()
	err := qcli.TestSetConfig(ctx, infra.QuotaConfig{
		Delay: 1,
		Slacks: infra.Slacks{
			NoPlanUser: 1024 * 512,
			PlanUser:   1024 * 512,
		},
	})
	require.NoError(t, err)
	defer func() {
		err = qcli.TestUnsetConfig(ctx)
		require.NoError(t, err)
	}()

	var bdat [1024 * 200]byte
	err = core.RandomFill(bdat[:])
	require.NoError(t, err)
	dir, err := os.MkdirTemp("", "foks_test_")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	big1 := filepath.Join(dir, "big1.txt")
	sdat := base64.StdEncoding.EncodeToString(bdat[:])
	testWriteFile(t, big1, sdat)
	smol1 := filepath.Join(dir, "smol1.txt")
	testWriteFile(t, smol1, "smol1")

	bob.agent.runCmd(t, nil, "kv", "put", "-f", "/big1.txt", big1)
	bob.agent.runCmd(t, nil, "kv", "put", "-f", "/smol1.txt", smol1)

	fqu := awc.getFQU(t)

	err = qcli.TestBumpUsage(ctx, infra.TestBumpUsageArg{
		Hid: fqu.HostID,
		Pid: fqu.Uid.ToPartyID(),
		Amt: proto.Size(1024 * 600),
	})
	require.NoError(t, err)

	err = qcli.Poke(ctx)
	require.NoError(t, err)

	err = bob.agent.runCmdErr(nil, "kv", "put", "-f", "/smol3.txt", smol1)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	awc.login(t)
	awc.clickOnFirstPlanAndPrice(t)
	awc.doCheckout(t)

	err = qcli.Poke(ctx)
	require.NoError(t, err)
	bob.agent.runCmd(t, nil, "kv", "put", "-f", "/smol3.txt", smol1)

	existingClock := m.Clock()
	fakeClock := clockwork.NewFakeClockAt(m.Now())
	m.SetClock(fakeClock)
	defer m.SetClock(existingClock)

	fakeClock.Advance(time.Duration(35*24) * time.Hour)

	err = qcli.Poke(ctx)
	require.NoError(t, err)

	err = bob.agent.runCmdErr(nil, "kv", "put", "-f", "/smol4.txt", smol1)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	awc.login(t)
	awc.clickOnFirstPlanAndPrice(t)
	awc.doCheckout(t)

	err = qcli.Poke(ctx)
	require.NoError(t, err)
	bob.agent.runCmd(t, nil, "kv", "put", "-f", "/smol4.txt", smol1)
}

func TestRenew(t *testing.T) {

	doRenew := func(viaWebhook bool) {

		bob := makeBobAndHisAgent(t)
		defer bob.stop(t)
		awc := newAdminWebClient(t, bob, nil)
		awc.makePlan(t, "Basic 18 Epsilon")
		merklePoke(t)

		m := awc.env.MetaContext()
		qcli, fn := common.TestQuotaSrvCli(t, m)
		defer func() {
			err := fn()
			require.NoError(t, err)
		}()
		ctx := m.Ctx()
		err := qcli.TestSetConfig(ctx, infra.QuotaConfig{
			Delay: 1,
			Slacks: infra.Slacks{
				NoPlanUser: 1024 * 512,
				PlanUser:   1024 * 512,
			},
			NoResurrection: viaWebhook,
		})
		require.NoError(t, err)
		defer func() {
			err = qcli.TestUnsetConfig(ctx)
			require.NoError(t, err)
		}()

		var bdat [1024 * 200]byte
		err = core.RandomFill(bdat[:])
		require.NoError(t, err)
		dir, err := os.MkdirTemp("", "foks_test_")
		require.NoError(t, err)
		defer os.RemoveAll(dir)
		big1 := filepath.Join(dir, "big1.txt")
		sdat := base64.StdEncoding.EncodeToString(bdat[:])
		testWriteFile(t, big1, sdat)

		bob.agent.runCmd(t, nil, "kv", "put", "-f", "/big1.txt", big1)

		fqu := awc.getFQU(t)

		err = qcli.TestBumpUsage(ctx, infra.TestBumpUsageArg{
			Hid: fqu.HostID,
			Pid: fqu.Uid.ToPartyID(),
			Amt: proto.Size(1024 * 600),
		})
		require.NoError(t, err)

		err = qcli.Poke(ctx)
		require.NoError(t, err)

		err = bob.agent.runCmdErr(nil, "kv", "put", "-f", "/big2.txt", big1)
		require.Error(t, err)
		require.Equal(t, core.OverQuotaError{}, err)

		awc.login(t)
		awc.clickOnFirstPlanAndPrice(t)
		awc.doCheckout(t)

		err = qcli.Poke(ctx)
		require.NoError(t, err)
		bob.agent.runCmd(t, nil, "kv", "put", "-f", "/big3.txt", big1)

		existingClock := m.Clock()
		fakeClock := clockwork.NewFakeClockAt(m.Now())
		m.SetClock(fakeClock)
		defer m.SetClock(existingClock)

		fakeClock.Advance(time.Duration(29*24) * time.Hour)
		err = qcli.Poke(ctx)
		require.NoError(t, err)

		bob.agent.runCmd(t, nil, "kv", "put", "-f", "/big4.txt", big1)

		// Two ways to check renewal:
		if viaWebhook {
			// 1. Simulate the webhook that gets sent by Stripe after
			// a successful payment on a subscription renewal.
			awc.injectSubscriptionReupEvent(t)
		} else {
			// 2. We were about to cancel a user, but "resurrected" them
			// by checking the stripe status for the user at the last minute.
			// This might happen if the webhook was missed or delayed.
			err := m.Stripe().(*common.FakeStripe).Renew(m, fqu.Uid)
			require.NoError(t, err)
		}

		fakeClock.Advance(time.Duration(24*24) * time.Hour)
		err = qcli.Poke(ctx)
		require.NoError(t, err)

		bob.agent.runCmd(t, nil, "kv", "put", "-f", "/big5.txt", big1)

	}
	doRenew(true)
	doRenew(false)
}
