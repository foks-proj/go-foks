// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestLargeFileUsage(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	dev := mdt.dev[0]
	file := dev.pathify("big.txt")
	sz := 1024 * 1024
	chnk := 4096
	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)
	usage, err := dev.kvm.GetUsage(dev.mc, lcl.KVConfig{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), usage.Small.Num)
	require.Equal(t, proto.Size(0), usage.Small.Sum)
	require.Equal(t, uint64(1), usage.Large.Base.Num)
	require.Equal(t, uint64(sz/chnk), usage.Large.NumChunks)
	require.Greater(t, usage.Large.Base.Sum, proto.Size(sz))
}

func randomPlanName(t *testing.T) string {
	return common.RandomPlanName(t)
}

func TestWritesOverQuotaFail(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	m := mdt.tew.MetaContext()
	ctx := m.Ctx()
	cli, fn := common.TestQuotaSrvCli(t, m)
	defer func() {
		err := fn()
		require.NoError(t, err)
	}()
	dev := mdt.dev[0]
	au := dev.mc.G().ActiveUser()

	err := cli.TestSetConfig(ctx, infra.QuotaConfig{
		Delay: 1,
		Slacks: infra.Slacks{
			NoPlanUser: 1024 * 512,
			PlanUser:   1024 * 512,
		},
	})
	require.NoError(t, err)
	defer func() {
		err = cli.TestUnsetConfig(ctx)
		require.NoError(t, err)
	}()
	err = cli.Poke(ctx)
	require.NoError(t, err)

	sz := 1024 * 10
	chnk := 4096

	for i := 0; i < 2; i++ {
		file := dev.pathify(fmt.Sprintf("med%d.txt", i))
		writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)
		err = cli.Poke(ctx)
		require.NoError(t, err)
	}

	err = cli.TestBumpUsage(ctx, infra.TestBumpUsageArg{
		Hid: au.HostID(),
		Pid: au.UID().ToPartyID(),
		Amt: proto.Size(1024 * 1024 * 30),
	})
	require.NoError(t, err)

	// even though we bumped the usage, there is still no overage since
	// we will only set the in_quota flag on the next write. Do that now.
	sz = 1024
	file := dev.pathify("smol1.txt")
	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)

	// After we poke, we should get an error.
	err = cli.Poke(ctx)
	require.NoError(t, err)

	file = dev.pathify("smol2.txt")
	_, err = writeRandomFileWithConfigAndErr(dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	plan := infra.Plan{
		MaxSeats:    10,
		Quota:       1024 * 1024 * 50,
		DisplayName: "Basic 50",
		Name:        randomPlanName(t),
		Scope:       infra.QuotaScope_Teams,
		Points: []string{
			"Up to 10 teams can share quota",
			"50MB of total storage quota, with unlimited transfer",
		},
		Prices: []infra.PlanPrice{
			{
				Cents: 499,
				Pi: infra.PaymentInterval{
					Interval: infra.Interval_Month,
					Count:    1,
				},
			},
		},
	}

	rPlan, err := cli.MakePlan(ctx, infra.MakePlanArg{
		Plan: plan,
		Opts: infra.MakePlanOpts{},
	})
	require.NoError(t, err)

	subid, err := shared.FakeStripe("sub")
	require.NoError(t, err)

	id, err := cli.SetPlan(ctx, infra.SetPlanArg{
		Fqu:         au.FQU(),
		Plan:        rPlan.Id,
		Price:       rPlan.Prices[0].Id,
		Replace:     false,
		StripeSubId: infra.StripeSubscriptionID(subid),
		ValidFor:    proto.ExportDurationSecs(24 * 30 * time.Hour),
	})
	require.NoError(t, err)
	require.True(t, id.IsZero())

	file = dev.pathify("smol2.txt")
	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)
	err = cli.Poke(ctx)
	require.NoError(t, err)
	file = dev.pathify("smol3.txt")
	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, lcl.KVConfig{}, chnk)
}

func TestQuotaAndTeams(t *testing.T) {
	mdt := setupMultiDeviceTest(t, 1, libkv.CacheSettings{UseMem: true, UseDisk: true})
	m := mdt.tew.MetaContext()
	ctx := m.Ctx()
	cli, fn := common.TestQuotaSrvCli(t, m)
	defer func() {
		err := fn()
		require.NoError(t, err)
	}()

	err := cli.TestSetConfig(ctx, infra.QuotaConfig{
		Delay: 1,
		Slacks: infra.Slacks{
			FloatingTeam: 1024 * 25,
			NoPlanUser:   1024 * 100,
			PlanUser:     1,
		},
		NoPlanMaxTeams: 1,
	})
	require.NoError(t, err)
	defer func() {
		err = cli.TestUnsetConfig(ctx)
		require.NoError(t, err)
	}()

	err = cli.Poke(ctx)
	require.NoError(t, err)

	team := mdt.tew.makeTeamForOwner(t, mdt.user)
	fqt := team.ToFQTeamParsed(t)

	dev := mdt.dev[0]
	file := dev.pathify("tm1.txt")
	sz := 1024 * 30
	chnk := 4096
	doublePoke(t, m)
	tmCfg := lcl.KVConfig{ActingAs: fqt}

	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, tmCfg, chnk)
	err = cli.Poke(ctx)
	require.NoError(t, err)

	file = dev.pathify("tm2.txt")
	_, err = writeRandomFileWithConfigAndErr(dev.kvm, dev.mc, file, sz, tmCfg, chnk)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	tid, err := team.id.ToTeamID()
	require.NoError(t, err)
	err = cli.AssignQuotaMaster(ctx, infra.AssignQuotaMasterArg{
		Fqu:  dev.parent.user.FQUser(),
		Team: tid,
	})
	require.NoError(t, err)

	err = cli.Poke(ctx)
	require.NoError(t, err)

	writeRandomFileWithConfig(t, dev.kvm, dev.mc, file, sz, tmCfg, chnk)

	team2 := mdt.tew.makeTeamForOwner(t, mdt.user)
	tid2, err := team2.id.ToTeamID()
	require.NoError(t, err)
	err = cli.AssignQuotaMaster(ctx, infra.AssignQuotaMasterArg{
		Fqu:  dev.parent.user.FQUser(),
		Team: tid2,
	})
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	err = cli.UnassignQuotaMaster(ctx, infra.UnassignQuotaMasterArg{
		Fqu:  dev.parent.user.FQUser(),
		Team: tid,
	})
	require.NoError(t, err)

	err = cli.Poke(ctx)
	require.NoError(t, err)

	file = dev.pathify("tm3.txt")
	_, err = writeRandomFileWithConfigAndErr(dev.kvm, dev.mc, file, sz, tmCfg, chnk)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

}
