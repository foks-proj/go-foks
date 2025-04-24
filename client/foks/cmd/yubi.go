// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"strings"
	"unicode"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libyubi"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type yubiExploreFlags struct {
	serial int
	slot   int
	host   string
}

func addExploreFlags(cmd *cobra.Command, cfg *yubiExploreFlags) {
	cmd.Flags().StringVarP(&cfg.host, "host", "", "", "host to explore (needs -slot and -serial)")
	addSerialAndSlotFlags(cmd, cfg)
}

func addSerialAndSlotFlags(cmd *cobra.Command, cfg *yubiExploreFlags) {
	cmd.Flags().IntVarP(&cfg.serial, "serial", "", 0, "serial number of the YubiKey to explore")
	cmd.Flags().IntVarP(&cfg.slot, "slot", "", 0, "slot of the YubiKey to explore (needs -serial and -host)")
}

func yubiUseCmd(m libclient.MetaContext, nm string, aliases []string, longExtra string) *cobra.Command {

	long := "Use a YuibKey that was previsiouly enabled for use with a FOKS user on a new device"
	if longExtra != "" {
		long = long + ".\n" + longExtra
	}

	var provisionCfg yubiExploreFlags
	provision := &cobra.Command{
		Use:          nm,
		Aliases:      aliases,
		Short:        "use existing YubiKey on a new device",
		Long:         long,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runYubiUse(m, cmd, &provisionCfg, arg)
		},
	}
	addExploreFlags(provision, &provisionCfg)
	return provision
}

type yubiSetPinOpts struct {
	serial int
	oldPin string
	newPin string
	oldPuk string
	newPuk string
}

func (o yubiSetPinOpts) runWizard() bool {
	return o.oldPin == "" && o.newPin == "" && o.oldPuk == "" && o.newPuk == "" && o.serial == 0
}

func checkPIN(p string) error {
	if len(p) > 0 && !proto.YubiPIN(p).IsValid() {
		return ArgsError("PIN must be 6-8 digits")
	}
	return nil
}

func checkPUK(p string) error {
	if len(p) > 0 && !proto.YubiPUK(p).IsValid() {
		return ArgsError("PUK must be 6-8 digits")
	}
	return nil
}

func (o yubiSetPinOpts) validate() error {
	if (o.newPin != "") != (o.newPuk != "") {
		return ArgsError("must provide both new-pin and new-puk")
	}
	if o.newPin != "" && o.serial == 0 {
		return ArgsError("must provide --serial with new-pin and --new-puk")
	}
	err := checkPIN(o.oldPin)
	if err != nil {
		return err
	}
	err = checkPIN(o.newPin)
	if err != nil {
		return err
	}
	err = checkPUK(o.oldPuk)
	if err != nil {
		return err
	}
	err = checkPUK(o.newPuk)
	if err != nil {
		return err
	}
	return nil
}

func yubiSetPinCmd(m libclient.MetaContext) *cobra.Command {
	var opts yubiSetPinOpts

	setPin := &cobra.Command{
		Use:     "set-pin-and-puk",
		Aliases: []string{"set-pin"},
		Short:   "set PIN for YubiKey",
		Long: core.MustRewrap(`Set the PIN for the YubiKey; also will set the PUK and management key.

Run with no arguments to use the wizard. Or supply --current-pin and --new-pin,
--current-puk and --new-puk to run without interactivity. Leaving --current-pin
and --current-puk empty will force use of factory defaults, in both cases.

The command wil get accept input (via flags or via wizard) to set the PIN and
PUK. The management key, if not already set, will be set to a random 24-byte
value. There is no need to remember this key. The encrypted management key is both
written to the YubiKey and to the server. Read on for more details!

The PIN protects the sign and decryption operations for private keys stored on
the YubiKey. Users only have a few attempts (3) to successfully enter the PIN
before the YubiKey is locked. The PUK is used to unlock the YubiKey after it has
been locked. Users only have a few attempts (3) to successfully enter the PUK
before the PIN and PUK are locked. 

There is one more key called the "management key" that is used to change the PIN
and PUK and to change the retry limits mentioned above. The management key also
is required to generate new keys on the YubiKey. After this command, the
management key is encrypted with the PIN and written to the YubiKey, so that
only the PIN is required to retrieve the management key. There is still a
problem though. What happens if the user forgets the PIN, locking the key. Now
the management key is lost and we cannot create any further keys on the YubiKey.

The last remaining piece here is that when possible, the FOKS client encrypts
the management key with the user's latest per-user key and sends it up to the
server. This way, the user has a mechanism to recover the management key and
reset the PIN and PUK. Whenever the per-user key rotates, the management key is
re-encrypted with the new per-user key and sent to the server. The server is
asked to delete the old encryption but of course can refuse if it's dishonest.

Can I just set the PIN and not worry about the PUK or the management key? Would that
it were! If unset, the PUK and the management key will take on default values that
are known to the world. Knowing either one of these gives the ability to reset the PIN,
so setting the PIN without setting the PUK or the management key achieves nothing.

One last item here. FOKS has its own notion of "PUK" which stands for "per-user key".
This is different from the YubiKey's version of "PUK", which stands for "PIN unblock key".
Unfortunate acronym collision!`, 72, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runYubiSPP(m, cmd, arg, &opts)
		},
	}
	setPin.Flags().StringVar(&opts.oldPin, "current-pin", "", "current YubiKey PIN")
	setPin.Flags().StringVar(&opts.newPin, "new-pin", "", "new YubiKey PIN")
	setPin.Flags().StringVar(&opts.oldPuk, "current-puk", "", "current YubiKey PUK")
	setPin.Flags().StringVar(&opts.newPuk, "new-puk", "", "new YubiKey PUK")
	setPin.Flags().IntVar(&opts.serial, "serial", 0, "serial number of the YubiKey to set PIN for")
	return setPin
}

type yubiUnlockOpts struct {
	yubiPinFlags
}

func yubiUnlockCmd(m libclient.MetaContext) *cobra.Command {
	var opts yubiUnlockOpts
	unlock := &cobra.Command{
		Use:          "unlock",
		Short:        "unlock credentials with a Yubikey",
		Long:         "Unlock PUKs with a previously registered Yubikey",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runYubiUnlock(m, cmd, arg, &opts)
		},
	}
	addPinFlags(unlock, &opts.yubiPinFlags)
	return unlock
}

type yubiPinFlags struct {
	pin       string
	promptPin bool
}

func addPinFlags(cmd *cobra.Command, cfg *yubiPinFlags) {
	cmd.Flags().StringVar(&cfg.pin, "pin", "", "supply the current YubiKey PIN")
	cmd.Flags().BoolVar(&cfg.promptPin, "prompt-pin", false, "interactive prompt for YubiKey PIN")
}

type yubiNewFlags struct {
	yubiExploreFlags
	yubiPinFlags
	pqSlot      int
	role        string
	name        string
	lockWithPin bool
}

func yubiNewCmd(m libclient.MetaContext) *cobra.Command {
	var newCfg yubiNewFlags
	new := &cobra.Command{
		Use:          "new",
		Aliases:      []string{"create"},
		Short:        "Add a new YubiKey to a previously provisioned account",
		Long:         "Add a new YubiKey to a previously provisioned account",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runYubiNew(m, cmd, &newCfg, arg)
		},
	}
	addSerialAndSlotFlags(new, &newCfg.yubiExploreFlags)
	addPinFlags(new, &newCfg.yubiPinFlags)
	new.Flags().StringVarP(&newCfg.role, "role", "", "o", "role to add the YubiKey to")
	new.Flags().StringVar(&newCfg.name, "name", "", "role to add the YubiKey to")
	new.Flags().IntVar(&newCfg.pqSlot, "pq-slot", 0, "slot to use for a PQ key seed")
	new.Flags().BoolVar(&newCfg.lockWithPin, "lock-with-pin", false, "lock the YubiKey with a PIN")

	return new
}

type yubiRecoverCfg struct {
	mk     string
	newPin string
	newPuk string
	serial int
}

func yubiRecoverCmd(m libclient.MetaContext) *cobra.Command {
	var cfg yubiRecoverCfg
	recover := &cobra.Command{
		Use:     "recover",
		Aliases: []string{"recover-pin"},
		Short:   "Recover a locked YubiKey after PIN block",
		Long: `Recover a locked YubiKey after PIN block. The YubiKey gets locked
after 3 failed PIN attempts. You can unlock the YubiKey with knowledge of the 
24-byte "management key". When possible, FOKS will encrypt your management key
with your latest per-user key (PUK) and store it to the server. This configuration
allows you to recover the management key, which allows you to unblock the key
and reset your PIN.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runYubiRecover(m, cmd, arg, &cfg)
		},
	}
	recover.Flags().StringVar(&cfg.mk, "management-key", "", "management key to use for recovery (base62-encoded)")
	recover.Flags().StringVar(&cfg.newPin, "new-pin", "", "new YubiKey PIN")
	recover.Flags().StringVar(&cfg.newPuk, "new-puk", "", "new YubiKey PUK")
	recover.Flags().IntVar(&cfg.serial, "serial", 0, "serial number of the YubiKey to recover")
	return recover

}

func yubiCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "yubikey",
		Aliases:      []string{"yubi"},
		Short:        "yubikey commands",
		Long:         "Manage yubikeys",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return cmd.Help()
		},
	}

	use := yubiUseCmd(m, "use", []string{}, "This command is a synonym for `foks key use-yubi`.")
	top.AddCommand(use)

	var lsCfg yubiExploreFlags
	explore := &cobra.Command{
		Use:          "explore",
		Aliases:      []string{"ls"},
		Short:        "explore YubiKeys and slots",
		Long:         "Explore YubiKeys and slots and how they are used with FOKS accounts",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return RunYubiExplore(m, cmd, &lsCfg, arg)
		},
	}
	addExploreFlags(explore, &lsCfg)
	top.AddCommand(explore)

	top.AddCommand(yubiUnlockCmd(m))
	top.AddCommand(yubiNewCmd(m))
	top.AddCommand(yubiSetPinCmd(m))
	top.AddCommand(yubiRecoverCmd(m))

	return top
}

type yubiSetPinState struct {
	opts      yubiSetPinOpts
	gencli    lcl.GeneralClient
	ycli      lcl.YubiClient
	sgcli     lcl.SignupClient
	cleanupFn func()
	sid       proto.UISessionID
	res       lcl.SetOrGetManagementKeyRes
}

func (s *yubiSetPinState) init(m libclient.MetaContext) error {
	gcli, fn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	s.gencli = newClient[lcl.GeneralClient](m, gcli)
	s.ycli = newClient[lcl.YubiClient](m, gcli)
	s.sgcli = newClient[lcl.SignupClient](m, gcli)

	s.cleanupFn = fn

	id, err := s.gencli.NewSession(m.Ctx(), proto.UISessionType_YubiSPP)
	if err != nil {
		return err
	}
	s.sid = id
	return nil
}

func (s *yubiSetPinState) cleanup(m libclient.MetaContext) error {
	err := s.gencli.FinishSession(m.Ctx(), s.sid)
	if err != nil {
		return err
	}
	if s.cleanupFn != nil {
		s.cleanupFn()
	}
	return nil
}

func (s *yubiSetPinState) setPIN(m libclient.MetaContext) error {
	err := s.ycli.ValidateCurrentPIN(m.Ctx(), lcl.ValidateCurrentPINArg{
		SessionId: s.sid,
		Pin:       proto.YubiPIN(s.opts.oldPin),
	})
	if err != nil {
		return err
	}
	return s.ycli.SetPIN(m.Ctx(), lcl.SetPINArg{
		SessionId: s.sid,
		Pin:       proto.YubiPIN(s.opts.newPin),
	})
}

func (s *yubiSetPinState) setPUK(m libclient.MetaContext) error {
	err := s.ycli.ValidateCurrentPUK(m.Ctx(), lcl.ValidateCurrentPUKArg{
		SessionId: s.sid,
		Puk:       proto.YubiPUK(s.opts.oldPuk),
	})
	if err != nil {
		return err
	}
	return s.ycli.SetPUK(m.Ctx(), lcl.SetPUKArg{
		SessionId: s.sid,
		New:       proto.YubiPUK(s.opts.newPuk),
	})
}

func (s *yubiSetPinState) setOrGetManagementKey(m libclient.MetaContext) error {
	res, err := s.ycli.SetOrGetManagementKey(m.Ctx(), s.sid)
	s.res = res
	if err != nil {
		return err
	}
	return nil
}

func (s *yubiSetPinState) putSerial(m libclient.MetaContext) error {

	cards, err := s.ycli.ListAllLocalYubiDevices(m.Ctx(), s.sid)
	if err != nil {
		return err
	}

	idx := -1
	for i, card := range cards {
		if card.Serial == proto.YubiSerial(s.opts.serial) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ArgsError("YubiKey not found")
	}

	return s.ycli.UseYubi(m.Ctx(), lcl.UseYubiArg{
		SessionId: s.sid,
		Idx:       uint64(idx),
	})
}

func (s *yubiSetPinState) run(m libclient.MetaContext) (err error) {

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

	err = s.putSerial(m)
	if err != nil {
		return err
	}

	err = s.setPIN(m)
	if err != nil {
		return err
	}

	err = s.setPUK(m)
	if err != nil {
		return err
	}

	err = s.setOrGetManagementKey(m)
	if err != nil {
		return err
	}

	return nil
}

func runYubiSPPSimple(m libclient.MetaContext, opts yubiSetPinOpts) error {
	state := yubiSetPinState{opts: opts}
	err := state.run(m)
	if err != nil {
		return err
	}
	return JSONOutput(m, state.res)
}

func runYubiSPP(m libclient.MetaContext, cmd *cobra.Command, arg []string, opts *yubiSetPinOpts) error {

	err := opts.validate()
	if err != nil {
		return err
	}
	if len(arg) > 0 {
		return ArgsError("no arguments are allowed")
	}

	err = agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}

	if opts.runWizard() {
		return ui.RunYubiSPP(m)
	}

	err = runYubiSPPSimple(m, *opts)
	if err != nil {
		return err
	}

	return nil
}

func runYubiNew(m libclient.MetaContext, cmd *cobra.Command, cfg *yubiNewFlags, arg []string) error {
	err := agent.Startup(m, agent.StartupOpts{NeedUser: true, NeedUnlockedUser: true})
	if err != nil {
		return err
	}

	rs := proto.RoleString(cfg.role)
	role, err := rs.Parse()
	if err != nil {
		return err
	}

	noName := (cfg.name == "")
	noSerial := (cfg.serial == 0)
	noSlot := (cfg.slot == 0)
	noPqSlot := (cfg.pqSlot == 0)

	pinp, err := cfg.getPIN(m)
	if err != nil {
		return err
	}
	var pin proto.YubiPIN
	if pinp != nil {
		if libyubi.IsDefaultPIN(*pinp) {
			return ArgsError("cannot use default PIN")
		}
		pin = *pinp
	}

	if noName && noSerial && noSlot && noPqSlot {
		if pinp != nil || cfg.lockWithPin {
			return ArgsError("cannot specify --pin, --pint-promopt or --lock-with-pin without --name, --serial, --slot, and --pq-slot")
		}
		return ui.RunModelForSessionType(m, proto.UISessionType_YubiNew)
	}

	if noName {
		return ArgsError("must specify --name")
	}
	if noSerial {
		return ArgsError("must specify --serial")
	}
	if noSlot {
		return ArgsError("must specify --slot")
	}
	if noPqSlot {
		return ArgsError("must specify --pq-slot")
	}

	dn, dnn, err := core.FixAndNormalizeDeviceName(cfg.name)
	if err != nil {
		return err
	}

	dln := proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			Name:       dnn,
			DeviceType: proto.DeviceType_YubiKey,
			Serial:     proto.FirstDeviceSerial,
		},
		Name: dn,
	}

	err = withClient(m, func(cli lcl.YubiClient) error {
		return cli.YubiNew(m.Ctx(), lcl.YubiNewArg{
			Ss: proto.YubiSerialSlot{
				Serial: proto.YubiSerial(cfg.serial),
				Slot:   proto.YubiSlot(cfg.slot),
			},
			PqSlot:      proto.YubiSlot(cfg.pqSlot),
			Role:        *role,
			Dln:         dln,
			Pin:         pin,
			LockWithPin: cfg.lockWithPin,
		})
	})

	if err != nil {
		return err
	}

	return nil
}

func RunYubiExplore(m libclient.MetaContext, cmd *cobra.Command, cfg *yubiExploreFlags, arg []string) error {

	if cfg.host != "" && (cfg.slot == 0 || cfg.serial == 0) {
		return ArgsError("must specify -slot and -serial with host")
	}

	if cfg.slot != 0 && cfg.serial == 0 {
		return ArgsError("must specify -slot with -serial")
	}

	return quickStartLambda(m, nil, func(cli lcl.YubiClient) error {
		var out any
		var err error
		switch {
		case cfg.host == "" && cfg.slot == 0 && cfg.serial == 0:
			out, err = cli.YubiListAllCards(m.Ctx())
		case cfg.serial != 0 && cfg.slot == 0:
			out, err = cli.YubiListAllSlots(m.Ctx(), proto.YubiSerial(cfg.serial))
		case cfg.slot != 0 && cfg.serial != 0:
			out, err = cli.YubiMapSlotToUser(m.Ctx(), proto.YubiSerialSlotHost{
				Serial: proto.YubiSerial(cfg.serial),
				Slot:   proto.YubiSlot(cfg.slot),
				Host:   proto.TCPAddr(cfg.host),
			})
		default:
			return ArgsError("bad combination of flags")
		}
		if err != nil {
			return err
		}
		return JSONOutput(m, out)
	})
}

func (o *yubiPinFlags) getPIN(m libclient.MetaContext) (*proto.YubiPIN, error) {
	if !o.promptPin && o.pin == "" {
		return nil, nil
	}
	if o.promptPin && o.pin != "" {
		return nil, ArgsError("cannot specify --pin and --pin-prompt")
	}

	var pin proto.YubiPIN
	if o.promptPin {
		tmp, err := m.G().UIs().PIN.GetPIN(m)
		if err != nil {
			return nil, err
		}
		pin = *tmp
	} else {
		pin = proto.YubiPIN(o.pin)
	}
	if !pin.IsValid() {
		return nil, core.YubiBadPINFormatError{}
	}
	return &pin, nil
}

func runYubiUnlockPIN(m libclient.MetaContext, cli lcl.YubiClient, opts *yubiUnlockOpts) error {

	pin, err := opts.getPIN(m)
	if err != nil {
		return err
	}
	if pin == nil {
		return nil
	}

	// No session ID --> we grab the current yubi card out of the active user
	_, err = cli.InputPIN(m.Ctx(), lcl.InputPINArg{Pin: *pin})

	if err != nil {
		return err
	}

	return nil
}

func runYubiUnlock(m libclient.MetaContext, cmd *cobra.Command, arg []string, opts *yubiUnlockOpts) error {
	err := agent.Startup(m, agent.StartupOpts{NeedUser: true})
	if err != nil {
		return err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer cleanFn()

	cli := lcl.YubiClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	err = runYubiUnlockPIN(m, cli, opts)
	if err != nil {
		return err
	}

	err = cli.YubiUnlock(m.Ctx())
	if err != nil {
		return err
	}

	return nil
}

func runYubiUse(
	m libclient.MetaContext,
	cmd *cobra.Command,
	cfg *yubiExploreFlags,
	arg []string,
) error {
	err := agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}

	switch {
	case cfg.serial != 0 && cfg.slot != 0:
		err = withClient(m, func(cli lcl.YubiClient) error {
			return cli.YubiProvision(m.Ctx(),
				proto.YubiSerialSlotHost{
					Serial: proto.YubiSerial(cfg.serial),
					Slot:   proto.YubiSlot(cfg.slot),
					Host:   proto.TCPAddr(cfg.host),
				},
			)
		})
	case cfg.serial == 0 && cfg.slot == 0 && cfg.host == "":
		err = ui.RunModelForSessionType(m, proto.UISessionType_YubiProvision)
	default:
		return ArgsError("bad combination of flags; --slot is required")
	}

	if err != nil {
		return err
	}

	return nil
}

func removeAllWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func runYubiRecoverSimpleUI(
	m libclient.MetaContext,
	serial proto.YubiSerial,
	pin proto.YubiPIN,
	puk proto.YubiPUK,
	mk *proto.YubiManagementKey,
) error {
	return withClient(m, func(cli lcl.YubiClient) error {
		return cli.RecoverManagementKey(
			m.Ctx(),
			lcl.RecoverManagementKeyArg{
				Serial: serial,
				Pin:    pin,
				Puk:    puk,
				Mk:     mk,
			},
		)
	})
}

func runYubiRecover(
	m libclient.MetaContext,
	cmd *cobra.Command,
	arg []string,
	cfg *yubiRecoverCfg,
) error {

	var mk *proto.YubiManagementKey
	if cfg.mk != "" {
		raw, err := core.B62Decode(removeAllWhitespace(cfg.mk))
		if err != nil {
			return core.BadArgsError("bad management key specified")
		}
		var tmp proto.YubiManagementKey
		if len(raw) != len(tmp) {
			return core.BadArgsError("bad management key specified; wrong length")
		}
		copy(tmp[:], raw)
		mk = &tmp
	}

	needUser := mk == nil

	err := agent.Startup(m, agent.StartupOpts{NeedUser: needUser, NeedUnlockedUser: needUser})
	if err != nil {
		return err
	}

	var pin proto.YubiPIN
	if cfg.newPin != "" {
		pin = proto.YubiPIN(cfg.newPin)
		if !pin.IsValid() {
			return core.BadArgsError("bad new PIN specified")
		}
	}
	var puk proto.YubiPUK
	if cfg.newPuk != "" {
		puk = proto.YubiPUK(cfg.newPuk)
		if !puk.IsValid() {
			return core.BadArgsError("bad new PUK specified")
		}
	}
	if pin.IsZero() != puk.IsZero() {
		return core.BadArgsError("must specify both new-pin and new-puk")
	}
	if !pin.IsZero() && cfg.serial == 0 {
		return core.BadArgsError("must specify --serial with new-pin and new-puk")
	}
	if !pin.IsZero() && !puk.IsZero() {
		serial := proto.YubiSerial(cfg.serial)
		return runYubiRecoverSimpleUI(m, serial, pin, puk, mk)
	}

	return core.BadArgsError("UI-wizard not implemented; please use CLI args")
}

func init() {
	AddCmd(yubiCmd)
}
