// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"time"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

func clearDeviceNag(m libclient.MetaContext, top *cobra.Command) {
	var reset bool
	ret := &cobra.Command{
		Use:          "clear-device-nag",
		Short:        "clear device nag",
		Long:         `Clear device nag`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(
				m,
				&agent.StartupOpts{},
				func(c lcl.GeneralClient) error {
					return c.ClearDeviceNag(m.Ctx(), !reset)
				})
		},
	}
	ret.Flags().BoolVar(&reset, "reset", false, "reset device nag")
	top.AddCommand(ret)
}

func snoozeUpgradeNag(m libclient.MetaContext, top *cobra.Command) {
	var reset bool
	var sdur string

	ret := &cobra.Command{
		Use:          "snooze-upgrade-nag",
		Short:        "snooze upgrade nag",
		Long:         `Snooze upgrade nag notification`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			dur, err := time.ParseDuration(sdur)
			if err != nil {
				return err
			}

			return quickStartLambda(
				m,
				&agent.StartupOpts{},
				func(c lcl.GeneralClient) error {
					return c.SnoozeUpgradeNag(m.Ctx(),
						lcl.SnoozeUpgradeNagArg{
							Val: !reset,
							Dur: proto.ExportDurationSecs(dur),
						},
					)
				})
		},
	}
	ret.Flags().BoolVar(&reset, "reset", false, "unsnooze upgrade nag")
	ret.Flags().StringVar(&sdur, "duration", "336h", "snooze duration (default 14 days)")
	top.AddCommand(ret)
}

func notifyCmd(m libclient.MetaContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "notifications",
		Aliases:      []string{"notif", "notify", "notifications", "notifs"},
		Short:        "notify operations",
		Long:         `Notify operations`,
		SilenceUsage: true,
	}
	clearDeviceNag(m, cmd)
	snoozeUpgradeNag(m, cmd)
	return cmd
}

func init() {
	AddCmd(notifyCmd)
}
