// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package simple_ui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/manifoldco/promptui"
	"golang.org/x/term"
)

type SignupUI struct {
}

var promptTemplates promptui.PromptTemplates = promptui.PromptTemplates{
	Prompt:  "- {{ . }} ",
	Valid:   "✔ {{ . | green }} ",
	Invalid: "- {{ . | red }} ",
	Success: "✔ {{ . | green }} ",
}

func formatUserInfoAsPromptItem(u proto.UserInfo) (string, error) {
	return common_ui.FormatUserInfoAsPromptItem(u, nil)
}

func FormatPickUserItems(lst []proto.UserInfo) ([]string, int, error) {
	var items []string
	for _, u := range lst {
		pi, err := formatUserInfoAsPromptItem(u)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, pi)
	}
	newPos := len(items)
	items = append(items, "🆕 Go ahead and create a new user.")
	return items, newPos, nil

}

func (s *SignupUI) GetKexHESP(
	m libclient.MetaContext,
	ourHesp proto.KexHESP,
	lastErr error,
) (
	*proto.KexHESP,
	error,
) {
	return getKexHESP(m, ourHesp, lastErr, "Run `foks dev assist` on another device, and enter code here")
}

func getKexHESP(
	m libclient.MetaContext,
	ourHesp proto.KexHESP,
	lastErr error,
	promptStr string,
) (
	*proto.KexHESP,
	error,
) {

	fmt.Printf("💳 Key-exchange code: %s\n", ourHesp.String())

	var label string
	if lastErr != nil {
		label = "  - " + lastErr.Error() + "; try again"
	} else {
		label = promptStr
	}

	isEmpty := func(s string) bool {
		return s == "." || s == ""
	}

	kPrompt := promptui.Prompt{
		Label: label,
		Validate: func(s string) error {
			s = strings.TrimSpace(s)
			if isEmpty(s) {
				return nil
			}
			return core.KexSeedHESPConfig.ValidateInput(s)
		},
	}
	res, err := kPrompt.Run()
	if err != nil {
		return nil, err
	}
	if isEmpty(res) {
		return nil, core.CanceledInputError{}
	}
	tmp := proto.NewKexHESP(res)
	return &tmp, nil
}

func (s *SignupUI) PickExistingUser(m libclient.MetaContext, lst []proto.UserInfo) (int, error) {
	if len(lst) == 0 {
		return -1, nil
	}
	items, newPos, err := FormatPickUserItems(lst)
	if err != nil {
		return -1, err
	}
	prompt := promptui.Select{
		Label: "Really sign up as a new user? You can pick an existing user to use instead:",
		Items: items,
	}
	idx, _, err := prompt.Run()
	if err != nil {
		return -1, err
	}
	if idx == newPos {
		return -1, nil
	}
	if idx < 0 || idx >= len(lst) {
		return -1, fmt.Errorf("invalid index %d", idx)
	}
	return idx, nil
}

func (s *SignupUI) GetPassphrase(
	m libclient.MetaContext,
	confirm bool,
	prevErr bool,
) (
	*proto.Passphrase,
	error,
) {

	var prompt string
	switch {
	case confirm:
		prompt = "Confirm by retyping"
	case prevErr:
		prompt = "Passpharse mismatch; try again or leave blank if none"
	default:
		prompt = "Enter passphrase to encrypt local device key (or leave blank if none)"
	}
	fmt.Printf("%s: ", prompt)

	pp, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n")
	if len(pp) == 0 {
		return nil, nil
	}
	tmp := proto.Passphrase(string(pp))
	return &tmp, nil
}

func (s *SignupUI) PickServer(m libclient.MetaContext, def proto.TCPAddr, timeout time.Duration) (*proto.TCPAddr, error) {
	return pickServer(m, def, timeout)
}

func pickServer(m libclient.MetaContext, def proto.TCPAddr, timeout time.Duration) (*proto.TCPAddr, error) {
	if def != "" {
		prompt := promptui.Select{
			Label: "Select a home server",
			Items: []string{
				"🏠 " + string(def) + " (default)",
				"❓ Specify a custom server",
			},
		}
		idx, _, err := prompt.Run()
		if err != nil {
			return nil, err
		}
		if idx == 0 {
			return nil, nil
		}
	}
	cPrompt := promptui.Prompt{
		Label: "🗄️  Hostname:",
		Validate: func(input string) error {
			return core.ValidateTCPAddr(proto.TCPAddr(input))
		},
		Templates: &promptTemplates,
	}
	res, err := cPrompt.Run()
	if err != nil {
		return nil, err
	}
	ret := proto.TCPAddr(res)
	return &ret, nil
}

func (s *SignupUI) CheckedServer(m libclient.MetaContext, addr proto.TCPAddr, err error) error {
	return nil
}

func (s *SignupUI) GetEmail(m libclient.MetaContext) (*proto.Email, error) {
	prompt := promptui.Prompt{
		Label: "📧 Email address:",
		Validate: func(input string) error {
			return core.ValidateEmail(proto.Email(input))
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	tmp := proto.Email(res)
	return &tmp, nil
}

func (s *SignupUI) GetInviteCode(
	m libclient.MetaContext,
	icr proto.InviteCodeRegime,
	attempt int,
) (*lcl.InviteCodeString, error) {
	var label string
	isOpt := (icr == proto.InviteCodeRegime_CodeOptional)
	switch {
	case isOpt && attempt == 0:
		label = "✒️  Invite code (optional, push enter to forego it): "
	case isOpt && attempt > 0:
		label = fmt.Sprintf("✒️  invalid invite code (%d), try again (or leave blank): ", attempt)
	case !isOpt && attempt > 0:
		label = fmt.Sprintf("✒️  invalid invite code (%d), try again (or push enter to join waitlist): ", attempt)
	default:
		label = "✒️  Invite code (or push enter to join waitlist): "
	}

	isEmpty := func(s string) bool {
		return strings.Trim(s, " \t") == ""
	}

	prompt := promptui.Prompt{
		Label: label,
		Validate: func(input string) error {
			if isEmpty(input) {
				return nil
			}
			if len(input) < 5 {
				return errors.New("invite code too short")
			}
			return nil
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	if isEmpty(res) {
		return nil, core.CancelSignupError{Stage: core.CancelSignupStageWaitList}
	}
	tmp := lcl.InviteCodeString(res)
	ic := &tmp
	return ic, nil
}

func (s *SignupUI) CheckedInviteCode(m libclient.MetaContext, code lcl.InviteCodeString, err error) error {
	return nil
}

func (s *SignupUI) Begin(m libclient.MetaContext) error    { return nil }
func (s *SignupUI) Rollback(m libclient.MetaContext) error { return nil }
func (s *SignupUI) Commit(m libclient.MetaContext) error   { return nil }

func (s *SignupUI) Outputf(f string, args ...interface{}) {
	fmt.Printf(f, args...)
}

func (s *SignupUI) ShowSSOLoginURL(m libclient.MetaContext, url proto.URLString) error {
	s.Outputf("  🔗 Please visit SSO login: %s\n", url.String())
	return nil
}

func (s *SignupUI) ShowSSOLoginResult(m libclient.MetaContext, res proto.SSOLoginRes) error {
	s.Outputf("  🔑 SSO login successful:\n")
	s.Outputf("    🏛️  Issuer   : %s\n", res.Issuer.String())
	s.Outputf("    📛 Username : %s\n", res.Username.String())
	s.Outputf("    📧 Email    : %s\n", res.Email.String())
	return nil
}

func (s *SignupUI) ShowWaitListID(m libclient.MetaContext, wlid proto.WaitListID) error {
	ex, err := core.ExportShortID(proto.ShortID(wlid))
	if err != nil {
		return err
	}
	s.Outputf("🧾 Signed up for waitlist; your ID is %s\n", ex)
	return nil
}

func (s *SignupUI) PickYubiDevice(m libclient.MetaContext, v []proto.YubiCardID) (int, error) {
	var items []string
	for _, k := range v {
		items = append(items, fmt.Sprintf("🔑 %s 0x%x", string(k.Name), uint(k.Serial)))
	}
	noYubiIdx := len(v)
	items = append(items, "🖥️  Use local device keys instead")
	items = append(items, "☮️  Cancel signup")
	prompt := promptui.Select{
		Label: "Yubikey card(s) detected -- use as primary device key?",
		Items: items,
	}
	idx, _, err := prompt.Run()
	if err != nil {
		return -1, err
	}
	if idx < len(v) {
		return idx, nil
	}
	if idx == noYubiIdx {
		return -1, nil
	}
	return -1, core.CancelSignupError{Stage: core.CancelSignupPickYubi}
}

func (s *SignupUI) PickYubiSlot(m libclient.MetaContext, y proto.YubiCardInfo, primary *proto.YubiSlot) (proto.YubiIndex, error) {

	ret := proto.NewYubiIndexDefault(proto.YubiIndexType_None)

	emptySlots := y.EmptySlots
	keySlots := y.Keys

	hasEmptySlots := (len(emptySlots) > 0)
	hasExistingKeys := (len(keySlots) > 0)

	var keys []string
	var slots []string

	if hasExistingKeys {
		for _, k := range keySlots {
			s, err := k.Id.StringErr()
			if err != nil {
				return ret, err
			}
			keys = append(keys, fmt.Sprintf("🔑 Slot %d: %s", k.Slot, s))
		}
	}

	if hasEmptySlots {
		for _, k := range emptySlots {
			slots = append(slots, fmt.Sprintf("🎰 Slot %d", k))
		}
	}

	goBackErr := errors.New("go back")

	pick := func(promptStr string, goback string, seedItems []string, setter func(int)) error {
		items := append([]string{}, seedItems...)
		gobackIdx := -1
		if goback != "" {
			gobackIdx = len(items)
			items = append(items, goback)
		}
		noYubiIdx := len(items)
		items = append(items, "🖥️  Use local device keys instead")
		cancelIdx := len(items)
		items = append(items, "☮️  Cancel signup")
		prompt := promptui.Select{
			Label: promptStr,
			Items: items,
		}
		idx, _, err := prompt.Run()
		if err != nil {
			return err
		}
		if idx == cancelIdx {
			return core.CancelSignupError{Stage: core.CancelSignupPickYubiSlot}
		}
		if idx == noYubiIdx {
			return nil
		}
		if goback != "" && idx == gobackIdx {
			return goBackErr
		}
		setter(idx)
		return nil
	}

	pickExisting := func(promptStr string, goback string) error {
		return pick(promptStr, goback, keys, func(idx int) {
			ret = proto.NewYubiIndexWithReuse(uint64(idx))
		})
	}

	pickEmpty := func(promptStr string, goback string) error {
		return pick(promptStr, goback, slots, func(idx int) {
			ret = proto.NewYubiIndexWithEmpty(uint64(idx))

		})
	}

	var nr string
	if primary != nil {
		nr = " (STRONGLY DISCOURAGED FOR POST-QUANTUM KEY SEEDS!!)"
	}

	pqPrompt := "Pick an empty slot use a Post-quantum key seed store; " +
		"it's important you never use this key for anything else: "
	switch {
	case hasExistingKeys && !hasEmptySlots:
		prompt := "Pick an existing key to use (no empty slots available): "
		if primary != nil {
			prompt = "DANGER! You have no fresh slots to use as post-quantum key seeds; " +
				"you can pick an existing key slot, but it's STRONGLY DISCOURAGED: "
		}
		err := pickExisting(prompt, "")
		if err != nil {
			return ret, err
		}
	case !hasExistingKeys && hasEmptySlots:
		prompt := "Pick an empty slot to store new key to: "
		if primary != nil {
			prompt = pqPrompt
		}
		err := pickEmpty(prompt, "")
		if err != nil {
			return ret, err
		}
	case hasExistingKeys && hasEmptySlots:
		keepGoing := true
		for i := 0; keepGoing; i++ {
			var err error
			if i%2 == 0 {
				prompt0 := "Pick an empty slot to store new key to: "
				if primary != nil {
					prompt0 = pqPrompt
				}
				err = pickEmpty(prompt0,
					"♻️ Pick an existing key to use instead"+nr)
			} else {
				err = pickExisting("Pick an existing key to use"+nr+": ",
					"🆕 Generate a new key instead")
			}
			if err == nil {
				keepGoing = false
			} else if err != goBackErr {
				return ret, err
			}
		}
	default:
		return ret, core.InternalError("unhandled case: no slots or keys")
	}
	return ret, nil
}

func (s *SignupUI) GetUsername(m libclient.MetaContext) (*proto.NameUtf8, error) {
	prompt := promptui.Prompt{
		Label: "👤 Username (3-25 characters): ",
		Validate: func(input string) error {
			_, err := core.NormalizeName(proto.NameUtf8(input))
			return err
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	tmp := proto.NameUtf8(res)
	un := &tmp
	return un, nil

}

func (s *SignupUI) GetDeviceName(m libclient.MetaContext) (*proto.DeviceName, error) {
	prompt := promptui.Prompt{
		Label: "📱 Device name: ",
		Validate: func(input string) error {
			return core.CheckDeviceName(input)
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	dn := core.FixDeviceName(res)
	return &dn, nil
}

var _ libclient.SignupUIer = (*SignupUI)(nil)
