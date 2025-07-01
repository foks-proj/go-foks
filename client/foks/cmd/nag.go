// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"
	"strings"

	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
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
			Vers:            core.CurrentSoftwareVersion,
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
	n lcl.UpgradeNagInfo,
) error {
	es := m.G().UIs().Terminal.ErrorStream()
	isatty := es.IsATTY()
	msg := "Your FOKS software is outdated; please upgrade"
	if n.Server.Newest != nil {
		msg += fmt.Sprintf(" (your version: %s; latest version: %s)",
			n.Agent, n.Server.Newest,
		)
	}
	fmt.Fprintf(es, "%s\n",
		maybeRender(isatty, ui.WarningStyle.Render, msg),
	)
	fmt.Fprintf(es, "  - to snooze this message for 14 days, run `foks notify snooze-upgrade-nag`\n")
	return nil
}

func maybeRender(isAtty bool, hook func(...string) string, msg string) string {
	if !isAtty {
		return msg
	}
	return hook(msg)
}

func upgradeInstructions(
	m libclient.MetaContext,
	n proto.ServerClientVersionInfo,
) error {
	es := m.G().UIs().Terminal.ErrorStream()
	switch libclient.LinkerPackaging {
	case "brew":
		fmt.Fprintf(es, "  - to upgrade via brew, run `brew upgrade foks`\n")
	case "apt", "deb":
		fmt.Fprintf(es, "  - to upgrade via apt, run `apt update && apt install foks`\n")
	case "yum":
		fmt.Fprintf(es, "  - to upgrade via yum, run `yum update foks`\n")
	case "dnf", "rpm":
		fmt.Fprintf(es, "  - to upgrade via dnf, run `dnf upgrade --refresh && dnf update foks`\n")
	}

	return nil
}

func doClientVersionCriticalNag(
	m libclient.MetaContext,
	n lcl.UpgradeNagInfo,
) error {
	es := m.G().UIs().Terminal.ErrorStream()
	isatty := es.IsATTY()
	var parts []string
	crit := maybeRender(isatty, ui.BoldErrorStyle.Render, "Critical: ")
	parts = append(parts, crit)
	msg := maybeRender(isatty, ui.ErrorStyle.Render,
		"Your FOKS software is critically outdated; please upgrade",
	)
	parts = append(parts, msg)
	if n.Server.Newest != nil {
		msg = fmt.Sprintf(" (your version: %s; minimum version: %s; latest version: %s)",
			n.Agent,
			n.Server.Min,
			n.Server.Newest,
		)
		msg = maybeRender(isatty, ui.ErrorStyle.Render, msg)
		parts = append(parts, msg)
	}
	fmt.Fprintln(es, strings.Join(parts, ""))

	err := upgradeInstructions(m, n.Server)
	if err != nil {
		return err
	}

	return nil
}

func doClientVersionClashNag(
	m libclient.MetaContext,
	nag lcl.CliVersionPair,
) error {
	cmp := nag.Cli.Cmp(nag.Agent)
	es := m.G().UIs().Terminal.ErrorStream()
	isatty := es.IsATTY()
	var msg string
	warning := maybeRender(isatty, ui.BoldStyle.Render, "Warning")
	if cmp < 0 {
		msg = fmt.Sprintf("%s: CLI is older than FOKS agent; bad install? (%s < %s)",
			warning, nag.Cli, nag.Agent,
		)
	} else if cmp > 0 {
		msg = fmt.Sprintf("%s: CLI is newer than FOKS agent; try restarting the FOKS agent via `foks ctl restart` (%s > %s)",
			warning, nag.Cli, nag.Agent)
	} else {
		return nil
	}
	fmt.Fprintf(es, "%s\n",
		maybeRender(isatty, ui.WarningStyle.Render, msg),
	)
	return nil
}

func doTooFewDevicesNag(
	m libclient.MetaContext, dni lcl.DeviceNagInfo) error {
	es := m.G().UIs().Terminal.ErrorStream()
	isatty := es.IsATTY()

	msg := "\n ☠️ ☠️  " +
		maybeRender(isatty, ui.BoldErrorStyle.Render, "DATA LOSS WARNING") + " ☠️️ ☠️\n\n" +
		maybeRender(isatty, ui.ErrorStyle.Render,
			" You only have one active device; if you lose access to it, you will lose access to all\n"+
				" data stored in this account. FOKS uses true end-to-end encryption, so your service provider\n"+
				" does not store backup keys. Protect yourself! Try:\n",
		)
	pad := "      "
	fmt.Fprintf(es, "%s", msg)
	fmt.Fprintf(es, "\n%s🛟 %s\n\n",
		pad,
		maybeRender(isatty, ui.HappyStyle.Render, "foks key new"),
	)

	fmt.Fprintf(es, " If you prefer to YOLO it and dismiss this warning without action, the command is:\n\n"+
		"%s🔥 foks notify clear-device-nag\n\n", pad)

	return nil
}
