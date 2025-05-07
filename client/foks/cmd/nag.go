// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
)

func PartingConsoleMessage(
	m libclient.MetaContext,
) error {
	_, err := DeviceNag(m)
	if err != nil {
		return err
	}
	return nil
}

func checkShouldNag(m libclient.MetaContext, withRateLimit bool) (bool, error) {
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return false, err
	}
	defer cleanFn()
	cli := lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	info, err := cli.GetDeviceNag(m.Ctx(), withRateLimit)
	if err != nil {
		return false, err
	}
	return info.DoNag, nil
}

func DeviceNag(m libclient.MetaContext) (bool, error) {
	doit, err := checkShouldNag(m, true)
	if err != nil {
		return false, err
	}
	if !doit {
		return false, nil
	}
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

	return true, nil
}
