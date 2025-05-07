// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

func quickCmd(
	m libclient.MetaContext,
	top *cobra.Command,
	name string,
	aliases []string,
	short string,
	long string,
	run func(*cobra.Command, []string) error,
) {
	if long == "" {
		long = short
	}
	cmd := &cobra.Command{
		Use:          name,
		Aliases:      aliases,
		Short:        short,
		Long:         long,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, arg []string) error { return run(cmd, arg) },
	}
	top.AddCommand(cmd)
}

func deleteMacOSKeychainItem(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"delete-macos-keychain-item", nil,
		"delete macOS keychain item for current user; testing only!", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				return cli.DeleteMacOSKeychainItem(m.Ctx())
			})
		},
	)
}

func dumpSecretStore(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"dump-secret-store", nil,
		"dump secret store contents; for testing only!", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				res, err := cli.LoadSecretStore(m.Ctx())
				if err != nil {
					return err
				}
				err = JSONOutput(m, res)
				if err != nil {
					return err
				}
				return nil
			})
		},
	)

}

func getUnlockedSKMWK(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"get-unlocked-skmwk", nil,
		"get the unlocked secret key material wrapping keys; for testing only!", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				res, err := cli.GetUnlockedSKMWK(m.Ctx())
				if err != nil {
					return err
				}
				err = JSONOutput(m, res)
				if err != nil {
					return err
				}
				return nil
			})
		},
	)
}

func getNoiseFile(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"get-noise-file", nil,
		"get the location of the encryption noise file; for testing only!", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				res, err := cli.GetNoiseFile(m.Ctx())
				if err != nil {
					return err
				}
				m.G().UIs().Terminal.Printf("%s\n", res)
				return nil
			})
		},
	)
}

func clearUserConnection(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"clear-user-state", nil,
		"clear RPC connections to user server, etc; for testing only", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				return cli.ClearUserState(m.Ctx())
			})
		},
	)
}

func triggerBgUserJob(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"trigger-bg-user-job", nil,
		"trigger background job for cleaning all in-memory users; for testing only", "",
		func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				return cli.TestTriggerBgUserJob(m.Ctx())
			})
		},
	)
}

func setFakeTeamIndexRange(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"set-fake-team-index-range", nil,
		"set a fake team index range for the given team (for testing only)", "",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 2 {
				return core.BadArgsError("need fully-qualified teamID and range")
			}
			fqt, err := core.ParseFQTeamSimple(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			rr, err := core.ParseRationalRange(arg[1])
			if err != nil {
				return err
			}
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				return cli.SetFakeTeamIndexRange(m.Ctx(), lcl.SetFakeTeamIndexRangeArg{
					Team: *fqt,
					Tir:  rr.Export(),
				})
			})
		},
	)
}

func getNag(m libclient.MetaContext, top *cobra.Command) {
	var useRateLimit bool
	cmd := &cobra.Command{
		Use:          "get-device-nag",
		Short:        "get the device nag bit; for testing only!",
		Long:         "get the device nag bit; for testing only!",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			err := agent.Startup(m, agent.StartupOpts{NeedUser: true})
			if err != nil {
				return err
			}
			ret, err := checkUnifiedNags(m, useRateLimit)
			if err != nil {
				return err
			}
			err = JSONOutput(m, ret)
			if err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useRateLimit, "rate-limit", false, "use rate limit")
	top.AddCommand(cmd)
}

func setNetworkConditions(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"set-network-conditions", nil,
		"set network conditions for testing", "",
		func(cmd *cobra.Command, arg []string) error {
			baErr := core.BadArgsError("need one arg: clear OR dead")
			if len(arg) != 1 {
				return baErr
			}
			var nc lcl.NetworkConditions
			switch arg[0] {
			case "clear":
				nc = lcl.NewNetworkConditionsDefault(
					lcl.NetworkConditionsType_Clear,
				)
			case "dead":
				nc = lcl.NewNetworkConditionsDefault(
					lcl.NetworkConditionsType_Catastrophic,
				)
			default:
				return baErr
			}
			return quickStartLambda(m, nil, func(cli lcl.TestClient) error {
				return cli.SetNetworkConditions(m.Ctx(), nc)
			})
		},
	)
}

func testCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:    "test",
		Short:  "test CLI features; use in testing only!",
		Long:   "test CLI features; use in testing only!",
		Hidden: true,
	}
	deleteMacOSKeychainItem(m, top)
	getNoiseFile(m, top)
	clearUserConnection(m, top)
	triggerBgUserJob(m, top)
	dumpSecretStore(m, top)
	setFakeTeamIndexRange(m, top)
	setNetworkConditions(m, top)
	getUnlockedSKMWK(m, top)
	getNag(m, top)
	return top
}

func init() {
	AddCmd(testCmd)
}
