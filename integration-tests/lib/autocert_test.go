// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"
	"time"

	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

func TestAutocertLooper(t *testing.T) {
	te := globalTestEnv

	hn := proto.Hostname("vanity." + RandomDomain(t))
	vh := te.VHostMake(t, hn)

	m := te.MetaContext().WithHostID(&vh.HostID)

	accfg, err := m.G().Config().AutocertServiceConfig(m.Ctx())
	require.NoError(t, err)

	// Doctor the VhostsConfig so that there is someplace to write down
	// the key and cert.
	vhc, err := m.G().Config().VHostsConfig(m.Ctx())
	require.NoError(t, err)
	vhcj, ok := vhc.(*shared.VHostsConfigJSON)
	require.True(t, ok)
	dir, err := core.MkdirTemp("autocert_test")
	require.NoError(t, err)
	defer func() {
		_ = dir.RemoveAll()
	}()

	var ca common.X509CA
	err = ca.Generate(dir, "autocert_test_ca")
	require.NoError(t, err)

	fad := common.NewFakeAutocertDoer(ca)
	acl := shared.NewAutocertLooper(accfg, vhcj, fad)
	err = acl.Start(m)
	require.NoError(t, err)
	defer acl.Stop()

	err = acl.DoHost(m,
		infra.DoAutocertArg{
			WaitFor: proto.ExportDurationMilli(time.Hour),
			Pkg: infra.AutocertPackage{
				Hostname: hn,
				Hostid:   m.HostID().Id,
				Styp:     proto.ServerType_Probe,
				IsVanity: true,
			},
		},
	)
	require.NoError(t, err)

	// Assert that the cert is in our CKS storage system.
	_, err = m.G().CertMgr().ServerCert(m, nil, hn, proto.CKSAssetType_RootPKIFrontendX509Cert)
	require.NoError(t, err)

	hn2 := proto.Hostname("bad." + RandomDomain(t))

	cl := clockwork.NewFakeClockAt(time.Now())
	m.G().SetClock(cl)
	defer m.G().SetClock(nil)

	defCfg := shared.DefaultAutocertServiceConfig{}

	host2Sequence := func() {
		ch := make(chan *shared.AutocertHostError)
		acl.SetTestFailCh(ch)

		inc := defCfg.InitialBackoffs()[0] + time.Second
		fad.SetBadHost(hn2)

		doCh := make(chan error)

		arg2 := infra.DoAutocertArg{
			WaitFor: proto.ExportDurationMilli(time.Hour),
			Pkg: infra.AutocertPackage{
				Hostname: hn2,
				Hostid:   m.HostID().Id,
				Styp:     proto.ServerType_Probe,
				IsVanity: true,
			},
		}

		go func() {
			err := acl.DoHost(m, arg2)
			doCh <- err
		}()

		ahe := <-ch
		require.Equal(t, hn2, ahe.Hostname)
		require.Equal(t, core.AutocertFailedError{}, ahe.Err)
		fad.ClearBadHost(hn2)

		cl.Advance(inc)
		err = acl.DoSome(m)
		require.NoError(t, err)

		err = <-doCh
		require.NoError(t, err)

		err = acl.DoHost(m, arg2)
		require.NoError(t, err)
		acl.SetTestFailCh(nil)
	}

	host2RefreshSequence := func() {
		ch := make(chan *shared.AutocertHostError)
		acl.SetTestFailCh(ch)
		fad.SetBadHost(hn2)
		err = acl.DoSome(m)
		require.NoError(t, err)
		ahe := <-ch
		require.Equal(t, hn2, ahe.Hostname)
		require.Equal(t, core.AutocertFailedError{}, ahe.Err)
		fad.ClearBadHost(hn2)

		cl.Advance(defCfg.RefreshBackoff() + time.Second)

		succCh := make(chan proto.Hostname)
		acl.SetTestSuccessCh(succCh)

		err = acl.DoSome(m)
		require.NoError(t, err)
		acl.SetTestFailCh(nil)

		tmp := <-succCh
		require.Equal(t, hn2, tmp)
		acl.SetTestFailCh(nil)
		acl.SetTestSuccessCh(nil)
	}

	host2Sequence()
	cl.Advance(defCfg.RefreshIn())
	host2RefreshSequence()
}
