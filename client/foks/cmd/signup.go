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

type SignupCmdConfig struct {
}

func signupCmd(m libclient.MetaContext) *cobra.Command {
	var scfg SignupCmdConfig
	cmd := &cobra.Command{
		Use:          "signup",
		Short:        "signup for a new account on a FOKS server",
		Long:         `Signup usually requires an invitation code; runs interactively in the terminal`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunSignup(m, cmd, &scfg, arg)
		},
	}
	return cmd
}

type baseSignupProvisionState struct {
	cleanupFn func()
	sessId    proto.UISessionID
	gencli    lcl.GeneralClient
	cli       lcl.SignupClient
	usercli   lcl.UserClient
	ycli      lcl.YubiClient
	typ       proto.UISessionType
	sso       *proto.SSOConfig
}

type signupState struct {
	baseSignupProvisionState
}

func (s *signupState) pickExistingUser(m libclient.MetaContext) error {
	lst, err := s.usercli.GetExistingUsers(m.Ctx())
	if err != nil {
		return err
	}
	u, err := m.G().UIs().Signup.PickExistingUser(m, lst)
	if err != nil {
		return err
	}
	if u >= 0 {
		err = s.cli.LoginAs(m.Ctx(), lcl.LoginAsArg{SessionId: s.sessId, User: lst[u]})
		if err != nil {
			return err
		}
		return core.CancelSignupError{Stage: core.CancelSignupLoginInstead}
	}
	return nil
}

func (s *baseSignupProvisionState) init(m libclient.MetaContext) error {
	gcli, fn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	s.cleanupFn = fn
	s.cli = newClient[lcl.SignupClient](m, gcli)
	s.gencli = newClient[lcl.GeneralClient](m, gcli)
	s.usercli = newClient[lcl.UserClient](m, gcli)
	s.ycli = newClient[lcl.YubiClient](m, gcli)
	return nil
}

func (s *baseSignupProvisionState) startSession(m libclient.MetaContext) error {
	sess, err := s.gencli.NewSession(m.Ctx(), s.typ)
	if err != nil {
		return err
	}
	s.sessId = sess
	return nil
}

func (s *baseSignupProvisionState) cleanup(m libclient.MetaContext) error {
	err := s.gencli.FinishSession(m.Ctx(), s.sessId)
	if err != nil {
		m.Warnw("cleanup", "err", err)
	}

	if s.cleanupFn != nil {
		s.cleanupFn()
	}
	return nil
}

func (s *baseSignupProvisionState) pickServer(m libclient.MetaContext) error {
	res, err := s.gencli.GetDefaultServer(m.Ctx(), lcl.GetDefaultServerArg{SessionId: s.sessId})
	if err != nil && errors.Is(err, core.NoDefaultHostError{}) {
		err = nil
	}
	if err != nil {
		return err
	}
	err = core.StatusToError(res.BigTop.Status)
	if err != nil {
		return err
	}
	def := proto.TCPAddr("n/a")
	if !res.BigTop.Host.IsZero() {
		def = res.BigTop.Host
	}
	discoverTimeout := 10 * time.Second
	srv, err := m.G().UIs().Signup.PickServer(m, def, discoverTimeout)
	if err != nil {
		return err
	}
	regCfg, err := s.gencli.PutServer(m.Ctx(), lcl.PutServerArg{
		SessionId: s.sessId,
		Server:    srv,
		Timeout:   proto.ExportDurationMilli(discoverTimeout),
	})
	if err != nil {
		return err
	}
	s.sso = regCfg.Sso
	return nil
}

func (s *signupState) joinWaitList(m libclient.MetaContext) error {
	wlid, err := s.cli.JoinWaitList(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	err = m.G().UIs().Signup.ShowWaitListID(m, wlid)
	if err != nil {
		return err
	}
	return nil
}

func (s *signupState) getInviteCode(m libclient.MetaContext) error {
	if s.sso != nil && s.sso.Active != proto.SSOProtocolType_None {
		return nil
	}

	for i := 0; i < 10; i++ {
		code, err := m.G().UIs().Signup.GetInviteCode(m, i)

		if code == nil && err == (core.CancelSignupError{Stage: core.CancelSignupStageWaitList}) {
			tmp := s.joinWaitList(m)
			if tmp != nil {
				return tmp
			}
			return err
		}

		if err != nil {
			return err
		}

		if code == nil {
			return core.InternalError("unexpected nil code")
		}

		err = s.cli.PutInviteCode(m.Ctx(), lcl.PutInviteCodeArg{SessionId: s.sessId, InviteCode: *code})
		if err == nil {
			return nil
		}
		if !errors.Is(err, core.BadInviteCodeError{}) {
			return err
		}
	}
	return core.TooManyTriesError{}
}

func (s *signupState) pickPassphrase(m libclient.MetaContext) error {
	doit, err := s.cli.PromptForPassphrase(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	if !doit {
		return nil
	}

	confirmedPp, err := pickNewPassphrase(m, 10, func(isConfirm bool, isRetry bool) (*proto.Passphrase, error) {
		return m.G().UIs().Signup.GetPassphrase(m, isConfirm, isRetry)
	})

	if err != nil {
		return err
	}
	if confirmedPp == nil {
		return nil
	}

	err = s.cli.PutPassphrase(m.Ctx(),
		lcl.PutPassphraseArg{
			SessionID:  s.sessId,
			Passphrase: *confirmedPp,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *signupState) pickYubiDevice(m libclient.MetaContext) error {
	v, err := s.ycli.ListAllLocalYubiDevices(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	if len(v) == 0 {
		return nil
	}

	idx, err := m.G().UIs().Signup.PickYubiDevice(m, v)
	if err != nil {
		return err
	}

	if idx < 0 {
		return nil
	}

	if idx >= len(v) {
		return core.InternalError("selection is out-of-range")
	}

	err = s.ycli.UseYubi(m.Ctx(), lcl.UseYubiArg{SessionId: s.sessId, Idx: uint64(idx)})
	if err != nil {
		return err
	}
	return nil
}

func (s *signupState) getEmail(m libclient.MetaContext) error {
	if s.sso != nil && s.sso.Active != proto.SSOProtocolType_None {
		return nil
	}

	em, err := m.G().UIs().Signup.GetEmail(m)
	if err != nil {
		return err
	}
	err = s.cli.PutEmail(m.Ctx(), lcl.PutEmailArg{SessionId: s.sessId, Email: *em})
	if err != nil {
		return err
	}

	return nil
}

func (s *signupState) pickYubiSlot(m libclient.MetaContext) error {
	v, err := s.cli.ListYubiSlots(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	if v.Device == nil {
		return nil
	}
	if len(v.Device.Keys)+len(v.Device.EmptySlots) < 2 {
		return core.YubiError("not enough slots available")
	}

	ui := m.G().UIs().Signup

	var pri *proto.YubiSlot
	devList := *v.Device

	// We need to pick 2 yubi slots --- one for the primary key, and one for the
	// post-quantum KEM key seed.
	for i := range 2 {

		idx, err := ui.PickYubiSlot(m, devList, pri)

		if err != nil {
			return err
		}

		typ, err := idx.GetT()
		if err != nil {
			return err
		}
		if typ == proto.YubiIndexType_None {
			return core.CancelSignupError{Stage: core.CancelSignupPickYubiSlot}
		}

		cstyp := core.Sel(i == 0, proto.CryptosystemType_Classical, proto.CryptosystemType_PQKEM)

		res, err := s.cli.PutYubiSlot(
			m.Ctx(),
			lcl.PutYubiSlotArg{
				SessionId: s.sessId,
				Index:     idx,
				Typ:       cstyp,
			})

		if err != nil {
			return err
		}
		devList = res.Device
		pri = &res.ChosenSlot
	}

	return nil
}

func (s *baseSignupProvisionState) pickUsername(m libclient.MetaContext) error {
	if s.sso != nil && s.sso.Active != proto.SSOProtocolType_None {
		return nil
	}

	b, err := s.cli.IsUsernameServerAssigned(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	if b {
		return nil
	}

	for range 10 {
		un, err := m.G().UIs().Signup.GetUsername(m)
		if err != nil {
			return err
		}
		err = s.cli.PutUsername(m.Ctx(), lcl.PutUsernameArg{SessionId: s.sessId, Username: *un})
		if err == nil {
			return nil
		}

		switch s.typ {
		case proto.UISessionType_Signup:
			if !errors.Is(err, core.NameInUseError{}) {
				return err
			}
		case proto.UISessionType_Provision:
			if !errors.Is(err, core.UserNotFoundError{}) {
				return err
			}
		}
	}
	return nil
}

func (s *baseSignupProvisionState) pickDeviceName(m libclient.MetaContext) error {
	name, err := m.G().UIs().Signup.GetDeviceName(m)
	if err != nil {
		return err
	}
	err = s.cli.PutDeviceName(m.Ctx(), lcl.PutDeviceNameArg{SessionId: s.sessId, DeviceName: *name})
	if err != nil {
		return err
	}
	return nil
}

func (s *signupState) finish(m libclient.MetaContext) error {

	_, err := s.cli.Finish(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	return nil
}

func (s *baseSignupProvisionState) startUI(m libclient.MetaContext) error {
	err := m.G().UIs().Signup.Begin(m)
	if err != nil {
		return err
	}
	return nil
}

func (s *baseSignupProvisionState) doSSOLogin(m libclient.MetaContext) error {
	if s.sso == nil {
		return nil
	}
	if s.sso.Active == proto.SSOProtocolType_None {
		return nil
	}
	if s.sso.Oauth2 == nil {
		return core.InternalError("SSO protocol is active but no OAuth2 config")
	}
	startRes, err := s.cli.SignupStartSsoLoginFlow(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	err = m.G().UIs().Signup.ShowSSOLoginURL(m, startRes.Url)
	if err != nil {
		return err
	}
	waitRes, err := s.cli.SignupWaitForSsoLogin(m.Ctx(), s.sessId)
	if err != nil {
		return err
	}
	err = m.G().UIs().Signup.ShowSSOLoginResult(m, waitRes)
	if err != nil {
		return err
	}
	return nil
}

func (s *signupState) runSimpleUI(m libclient.MetaContext) (err error) {
	err = s.init(m)
	if err != nil {
		return err
	}
	defer func() {
		tmp := s.cleanup(m)
		if err == nil && tmp != nil {
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

	err = s.pickExistingUser(m)
	if err != nil {
		return err
	}

	err = s.pickYubiDevice(m)
	if err != nil {
		return err
	}

	err = s.pickPassphrase(m)
	if err != nil {
		return err
	}

	err = s.pickServer(m)
	if err != nil {
		return err
	}

	err = s.doSSOLogin(m)
	if err != nil {
		return err
	}

	err = s.getEmail(m)
	if err != nil {
		return err
	}

	err = s.getInviteCode(m)
	if err != nil {
		return err
	}

	err = s.pickYubiSlot(m)
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

	err = s.finish(m)
	if err != nil {
		return err
	}

	return nil
}

func newSignupState() *signupState {
	return &signupState{
		baseSignupProvisionState: baseSignupProvisionState{
			typ: proto.UISessionType_Signup,
		},
	}
}

func RunSignup(m libclient.MetaContext, cmd *cobra.Command, scfg *SignupCmdConfig, arg []string) error {
	err := agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}

	if m.G().Cfg().SimpleUI() {
		ss := newSignupState()
		m.Infow("run", "ui", "promptUI")
		err = ss.runSimpleUI(m)
	} else {
		m.Infow("run", "ui", "bubble")
		err = ui.RunModelForSessionType(m, proto.UISessionType_Signup)
	}

	if err == (core.CancelSignupError{Stage: core.CancelSignupStageWaitList}) {
		m.Infow("didn't sign up, joined wait list")
		err = nil
	}
	if err != nil {
		return err
	}
	return nil
}

func init() {
	AddCmd(signupCmd)
}
