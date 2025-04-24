// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestNewVanityDomain(t *testing.T) {
	defer common.DebugEntryAndExit()()

	dom := RandomDomain(t)
	stem := proto.Hostname("foks." + dom)
	baseHostname := stem
	cannedStem := proto.Hostname("canned." + dom)
	tew := ForkNewTestEnvWrapperWithOpts(t,
		common.SetupOpts{
			Hostnames: &common.Hostnames{
				Probe: []proto.Hostname{
					baseHostname,
					cannedStem.Wildcard(),
				},
			},
			UseCertDirs:         true,
			MerklePollWait:      time.Hour,
			UseMockAutocertDoer: true,
		},
	)
	defer tew.Shutdown()
	env := tew.TestEnv
	helper := common.NewMockVanityHelper(env.X509Material().ProbeCA)
	vh := env.G.VanityHelper()
	env.G.SetVanityHelper(helper)
	defer env.G.SetVanityHelper(vh)

	mgmtHostId := tew.VHostMakeWithOpts(t, baseHostname, shared.VHostInitOpts{
		Config: proto.HostConfig{
			Metering: proto.Metering{VHosts: true},
			Typ:      proto.HostType_VHostManagement,
		},
	})
	u := tew.NewTestUserAtVHost(t, mgmtHostId)
	tew.DirectMerklePokeInTest(t)

	m := tew.MetaContext()
	plan := common.MakeRandomPlan(
		t,
		m,
		"foks",
		infra.Plan{
			MaxSeats:  1,
			MaxVhosts: 2,
			Quota:     1024 * 10,
			Scope:     infra.QuotaScope_VHost,
		},
	)
	cli, fn := common.TestQuotaSrvCli(t, m)
	defer func() {
		err := fn()
		require.NoError(t, err)
	}()
	subid, err := shared.FakeStripe("sub")
	require.NoError(t, err)

	setPlan := func(u *TestUser) {

		id, err := cli.SetPlan(m.Ctx(), infra.SetPlanArg{
			Fqu:         u.FQUser(),
			Plan:        plan.Id,
			Price:       plan.Prices[0].Id,
			Replace:     false,
			StripeSubId: infra.StripeSubscriptionID(subid),
			ValidFor:    proto.ExportDurationSecs(24 * 30 * time.Hour),
		})
		require.NoError(t, err)
		require.True(t, id.IsZero())
	}
	setPlan(u)

	hid := mgmtHostId.HostID
	m = m.WithUserHost(
		shared.UserHostContext{
			HostID: &hid,
			Uid:    u.uid,
		},
	)

	cfg, ok := env.G.Config().(*shared.ConfigJSonnet)
	require.True(t, ok)
	require.NotNil(t, cfg)

	hostingDomain := proto.Hostname("hosting.") + stem

	cfg.Data.VHosts.Vanity.HostingDomain_ = shared.DNSZoneJSON{
		Domain_: hostingDomain,
		ZoneID_: proto.ZoneID("FAKEZONEID1"),
	}

	inviteCode := rem.MultiUseInviteCode("lola+paolo")

	makeVanityHost := func() (*core.HostIDAndName, error) {
		vanity := proto.Hostname("nike." + RandomDomain(t))
		gs := env.Beacon(t)
		vm := shared.VanityMinder{
			Vstem:      vanity,
			Beacon:     gs,
			InviteCode: inviteCode,
			Metering: proto.Metering{
				Users:        true,
				PerVHostDisk: true,
			},
		}
		err = vm.Stage1(m)
		if err != nil {
			return nil, err
		}
		hs := vm.GetHostedStem()

		env.G.CnameResolver().Add(vanity, hs)
		err = vm.Stage2(m)
		if err != nil {
			return nil, err
		}
		host, err := vm.HostIDAndName()
		if err != nil {
			return nil, err
		}
		return host, nil
	}
	vanityHost, err := makeVanityHost()
	require.NoError(t, err)
	vhost1 := vanityHost.Hostname

	ic := rem.NewInviteCodeWithMultiuse(inviteCode)

	tu := tew.NewTestUserAtVHostWithOpts(t, vanityHost, &TestUserOpts{InviteCode: &ic})

	mu := tew.NewClientMetaContext(t, tu)
	_, err = libclient.LoadMe(mu, mu.G().ActiveUser())
	require.NoError(t, err)

	// Test that we go over quota with the second user created.
	_, err = tew.NewTestUserAtVHostWithOptsAndErr(t, vanityHost, &TestUserOpts{InviteCode: &ic})
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	// Next we're going to test disk quota.
	ctx := m.Ctx()
	err = cli.TestSetConfig(ctx, infra.QuotaConfig{
		Delay: 1,
		Slacks: infra.Slacks{
			NoPlanUser: 1024 * 2,
			PlanUser:   1024 * 2,
		},
	})
	require.NoError(t, err)
	defer func() {
		err = cli.TestUnsetConfig(ctx)
		require.NoError(t, err)
	}()
	err = cli.Poke(ctx)
	require.NoError(t, err)

	// Next test the vhost-based quota system
	kvmc := libkv.NewMetaContext(mu)
	kvm := libkv.NewMinderWithCacheSettings(
		mu.G().ActiveUser(),
		libkv.CacheSettings{UseMem: true, UseDisk: true},
	)

	writeRandomFile(t, kvm, kvmc, "/smol1.txt", 1024*5)
	err = cli.Poke(ctx)
	require.NoError(t, err)

	writeRandomFile(t, kvm, kvmc, "/med1.txt", 1024*8)
	err = cli.Poke(ctx)
	require.NoError(t, err)

	_, err = writeRandomFileWithConfigAndErr(kvm, kvmc, "/smol2.txt", 1024*5, lcl.KVConfig{}, 1024*5)
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	gs := env.Beacon(t)
	vm := shared.VanityMinder{
		Vstem:      vhost1,
		Beacon:     gs,
		InviteCode: inviteCode,
		Metering: proto.Metering{
			Users:        true,
			PerVHostDisk: true,
		},
	}
	err = vm.Stage1(m)
	require.Error(t, err)
	require.Equal(t, core.HostInUseError{Host: vhost1}, err)

	// Can make 1 more vhost, no problem.
	_, err = makeVanityHost()
	require.NoError(t, err)

	// Next one should fail with an over-quota error.
	_, err = makeVanityHost()
	require.Error(t, err)
	require.Equal(t, core.OverQuotaError{}, err)

	// now test the canned domain system with a different user. light test
	cannedPrefix := proto.Hostname("myhost")
	cannedFull := cannedPrefix.Join(cannedStem)
	env.G.CnameResolver().Add(cannedFull, baseHostname)
	cInviteCode := rem.MultiUseInviteCode("canned+invite+code")
	cvhm := shared.CannedMinder{
		Hostname:     cannedPrefix,
		CannedDomain: cannedStem,
		InviteCode:   cInviteCode,
		Metering: proto.Metering{
			Users:        true,
			PerVHostDisk: true,
		},
		Beacon: gs,
	}
	err = cvhm.Run(m)
	require.Error(t, err)
	// Our original user should be over quota, just as the test directly above.
	require.Equal(t, core.OverQuotaError{}, err)

	v := tew.NewTestUserAtVHost(t, mgmtHostId)
	tew.DirectMerklePokeInTest(t)
	setPlan(v)

	// Switch users from u to v
	m = m.WithUserHost(
		shared.UserHostContext{
			HostID: &hid,
			Uid:    v.uid,
		},
	)
	err = cvhm.Run(m)
	require.NoError(t, err)
	cnid, err := cvhm.HostIDAndName()
	require.NoError(t, err)
	cic := rem.NewInviteCodeWithMultiuse(cInviteCode)
	tv := tew.NewTestUserAtVHostWithOpts(t, cnid, &TestUserOpts{InviteCode: &cic})

	mv := tew.NewClientMetaContext(t, tv)
	_, err = libclient.LoadMe(mv, mu.G().ActiveUser())
	require.NoError(t, err)
}
