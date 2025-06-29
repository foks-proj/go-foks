// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"errors"
	"time"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type ProvisionCmdConfig struct{}

type deviceSelfProvisionCmdCfg struct {
	deviceName string
	role       string
}

func deviceCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "device",
		Aliases:      []string{"dev"},
		Short:        "low-level device commands",
		Long:         "low-level commands for managing FOKS devices",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	var pcfg ProvisionCmdConfig
	prov := &cobra.Command{
		Use:          "provision",
		Aliases:      []string{"new"},
		Short:        "provision this device for FOKS using an existing device as a helper",
		Long:         `provision this device for FOKS using an existing device as a helper`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runProvision(m, cmd, &pcfg, arg)
		},
	}
	top.AddCommand(prov)

	var spcfg deviceSelfProvisionCmdCfg
	makePermanent := &cobra.Command{
		Use:          "make-permanent",
		Aliases:      []string{"perm"},
		Short:        "make a permament key on this device",
		Long:         "make a permament key on this device, using a backup key or a YubiKey to provision it",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runMakePermanent(m, cmd, &spcfg, arg)
		},
	}
	makePermanent.Flags().StringVar(&spcfg.deviceName, "name", "", "device name")
	makePermanent.Flags().StringVar(&spcfg.role, "role", "", "device role")
	top.AddCommand(makePermanent)

	return top
}

func runMakePermanent(
	m libclient.MetaContext,
	cmd *cobra.Command,
	spcfg *deviceSelfProvisionCmdCfg,
	arg []string,
) error {
	err := agent.Startup(m, agent.StartupOpts{NeedUnlockedUser: true})
	if err != nil {
		return err
	}
	role := proto.OwnerRole
	if spcfg.role != "" {
		tmp, err := proto.RoleString(spcfg.role).Parse()
		if err != nil {
			return err
		}
		role = *tmp
	}

	if spcfg.deviceName == "" {
		return ArgsError("device name is required")
	}
	dn, dnn, err := core.FixAndNormalizeDeviceName(spcfg.deviceName)
	if err != nil {
		return err
	}

	dln := proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			Name:       dnn,
			DeviceType: proto.DeviceType_Computer,
			Serial:     proto.FirstDeviceSerial,
		},
		Name: dn,
	}

	return withClient(m,
		func(cli lcl.DeviceClient) error {
			return cli.SelfProvision(m.Ctx(), lcl.SelfProvisionArg{
				Dln:  dln,
				Role: role,
			})
		},
	)
}

type assistState struct {
	devcli    lcl.DeviceAssistClient
	gencli    lcl.GeneralClient
	cleanupFn func()
	sessId    proto.UISessionID
}

func (a *assistState) init(m libclient.MetaContext) error {
	gcli, fn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	a.devcli = lcl.DeviceAssistClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	a.gencli = lcl.GeneralClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	a.cleanupFn = fn

	sess, err := a.gencli.NewSession(m.Ctx(), proto.UISessionType_Assist)
	if err != nil {
		fn()
		return err
	}
	a.sessId = sess
	return nil
}

func (a *assistState) cleanup(m libclient.MetaContext) error {
	err := a.gencli.FinishSession(m.Ctx(), a.sessId)
	if err != nil {
		m.Warnw("cleanup", "err", err)
	}
	if a.cleanupFn != nil {
		a.cleanupFn()
	}
	return nil
}

func (a *assistState) confirmUser(m libclient.MetaContext) error {
	user, err := a.devcli.AssistInit(m.Ctx(), a.sessId)
	if err != nil {
		return err
	}
	err = m.G().UIs().Assist.ConfirmActiveUser(m, user)
	if err != nil {
		return err
	}
	return nil
}

func (a *assistState) startKex(m libclient.MetaContext) (proto.KexHESP, error) {
	return a.devcli.AssistStartKex(m.Ctx(), a.sessId)
}

func (a *assistState) runKex(m libclient.MetaContext, ourHesp proto.KexHESP) error {
	return runKex(
		func() error { return a.devcli.AssistWaitForKexComplete(m.Ctx(), a.sessId) },
		func(lastErr error) (*proto.KexHESP, error) {
			return m.G().UIs().Assist.GetKexHESP(m, ourHesp, lastErr)
		},
		func(theirs proto.KexHESP) error {
			return a.devcli.AssistGotKexInput(m.Ctx(), lcl.KexSessionAndHESP{
				SessionId: a.sessId,
				Hesp:      theirs,
			})
		},
	)
}

func (a *assistState) runSimpleUI(m libclient.MetaContext) (err error) {

	err = a.init(m)
	if err != nil {
		return err
	}
	defer func() {
		tmp := a.cleanup(m)
		if tmp != nil && err == nil {
			err = tmp
		}
	}()

	err = a.confirmUser(m)
	if err != nil {
		return err
	}

	ourHesp, err := a.startKex(m)
	if err != nil {
		return err
	}

	err = a.runKex(m, ourHesp)
	if err != nil {
		return err
	}

	return nil
}

type provisionState struct {
	baseSignupProvisionState
}

func newProvisionState() *provisionState {
	return &provisionState{
		baseSignupProvisionState: baseSignupProvisionState{
			typ: proto.UISessionType_Provision,
		},
	}
}

func (s *provisionState) runKex(m libclient.MetaContext, ourHesp proto.KexHESP) error {
	return runKex(
		func() error {
			return s.cli.WaitForKexComplete(m.Ctx(), s.sessId)
		},
		func(lastErr error) (*proto.KexHESP, error) {
			return m.G().UIs().Signup.GetKexHESP(m, ourHesp, lastErr)
		},
		func(theirs proto.KexHESP) error {
			return s.cli.GotKexInput(m.Ctx(), lcl.KexSessionAndHESP{
				SessionId: s.sessId,
				Hesp:      theirs,
			})
		},
	)
}

func runKex(
	waiter func() error,
	uiGetter func(lastErr error) (*proto.KexHESP, error),
	kexPoster func(theirs proto.KexHESP) error,
) error {

	doneCh := make(chan error, 1)
	go func() {
		err := waiter()
		doneCh <- err
	}()

	var lastErr error
	var complete bool

	for i := 0; i < 10; i++ {

		theirs, err := uiGetter(lastErr)
		if err != nil && errors.Is(err, core.CanceledInputError{}) {
			complete = true
			break
		}

		if err != nil {
			return err
		}

		err = kexPoster(*theirs)

		if err == nil {
			complete = true
			break
		}

		if !errors.Is(err, core.KexBadSecretError{}) {
			return err
		}

		lastErr = err
	}

	if !complete {
		return core.TooManyTriesError{}
	}

	select {
	case err := <-doneCh:
		return err
	case <-time.After(1 * time.Minute):
		return core.TimeoutError{}
	}
}

func (s *provisionState) startKex(m libclient.MetaContext) (proto.KexHESP, error) {
	return s.cli.StartKex(m.Ctx(), s.sessId)
}

func (s *provisionState) runSimpleUI(m libclient.MetaContext) (err error) {
	err = s.init(m)
	if err != nil {
		return err
	}
	defer func() {
		tmp := s.cleanup(m)
		if tmp != nil && err == nil {
			err = tmp
		}
	}()
	err = s.startUI(m)
	if err != nil {
		return err
	}
	err = s.startSession(m)
	if err != nil {
		return err
	}

	err = s.pickServer(m)
	if err != nil {
		return err
	}

	err = s.pickUsername(m)
	if err != nil {
		return err
	}

	err = s.pickDeviceName(m)
	if err != nil {
		return err
	}

	ourHesp, err := s.startKex(m)
	if err != nil {
		return err
	}

	err = s.runKex(m, ourHesp)
	if err != nil {
		return err
	}
	return nil
}

func runProvision(m libclient.MetaContext, cmd *cobra.Command, pcfg *ProvisionCmdConfig, arg []string) error {
	err := agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}

	if m.G().Cfg().SimpleUI() {
		ps := newProvisionState()
		err = ps.runSimpleUI(m)
	} else {
		err = ui.RunModelForSessionType(m, proto.UISessionType_Provision)
	}
	if err != nil {
		return err
	}
	return nil
}
