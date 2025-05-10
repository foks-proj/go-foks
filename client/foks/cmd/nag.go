// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/foks-proj/go-foks/proto/lib"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func PartingConsoleMessage(
	m libclient.MetaContext,
) error {
	err := DoUnifiedNags(m)
	if err != nil {
		return err
	}
	return nil
}

func checkUnifiedNags(m libclient.MetaContext, withRateLimit bool) (*lcl.UnifiedNagRes, error) {
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return nil, err
	}
	defer cleanFn()
	cli := lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	info, err := cli.GetUnifiedNags(m.Ctx(), lcl.GetUnifiedNagsArg{
		WithRateLimit: withRateLimit,
		Cv: proto.ClientVersionExt{
			Vers:            core.CurrentClientVersion,
			LinkerVersion:   libclient.LinkerVersion,
			LinkerPackaging: libclient.LinkerPackaging,
		},
	})
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func DoUnifiedNags(m libclient.MetaContext) error {
	nags, err := checkUnifiedNags(m, true)
	if err != nil {
		return err
	}
	for _, nag := range nags.Nags {
		err := doNag(m, nag)
		if err != nil {
			return err
		}
	}
	return nil
}

func doNag(m libclient.MetaContext, nag lcl.UnifiedNag) error {

	typ, err := nag.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case lcl.NagType_ClientVersionClash:
		return doClientVersionClashNag(m, nag.Clientversionclash())
	case lcl.NagType_ClientVersionCritical:
		return doClientVersionCriticalNag(m, nag.Clientversioncritical())
	case lcl.NagType_ClientVersionUpgradeAvailable:
		return doClientVersionUpgradeAvailable(m, nag.Clientversionupgradeavailable())
	case lcl.NagType_TooFewDevices:
		return doTooFewDevicesNag(m, nag.Toofewdevices())
	}
	return nil
}

func doClientVersionUpgradeAvailable(
	m libclient.MetaContext,
	n lib.ServerClientVersionInfo,
) error {
	return core.NotImplementedError{}
}

func doClientVersionCriticalNag(
	m libclient.MetaContext,
	n lib.ServerClientVersionInfo,
) error {
	return core.NotImplementedError{}
}

func doClientVersionClashNag(
	m libclient.MetaContext,
	nag lcl.CliVersionPair,
) error {
	return core.NotImplementedError{}
}

func doTooFewDevicesNag(
	m libclient.MetaContext, dni lcl.DeviceNagInfo) error {

	msg := "\n ☠️ ☠️  " + ui.BoldErrorStyle.Render("DATA LOSS WARNING") + " ☠️️ ☠️\n\n" +
		ui.ErrorStyle.Render(
			" You only have one active device; if you lose access to it, you will lose access to all\n"+
				" data stored in this account. FOKS uses true end-to-end encryption, so your service provider\n"+
				" does not store backup keys. Protect yourself! Try:\n",
		)
	es := m.G().UIs().Terminal.ErrorStream()
	fmt.Fprintf(es, "%s", msg)
	msg = ui.NextStepsTable(ui.NextStepsTableOpts{BackupOnly: true})
	fmt.Fprintf(es, "\n%s\n", msg)

	msg = " If you prefer to YOLO it and dismiss this warning without action, the command is:\n\n" +
		"    foks notify clear-device-nag\n\n"
	fmt.Fprintf(es, "%s\n", msg)

	return nil
}
