// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

// Yubi Set PIN and PUK abbreviated to YSPP

func newStateYSPPPickCard() state {
	return statePickYubi{
		bypassItem: false,
		needYubi:   true,
		loadListHook: func(ctx context.Context, mdl model) ([]proto.YubiCardID, error) {
			return mdl.ycli.ListAllLocalYubiDevices(ctx, mdl.sessId)
		},
		makeTitleHook: func(n int) string {
			return "Select a YubiKey to set PIN and PUK"
		},
		putHook: func(ctx context.Context, mdl model, yd proto.YubiCardID, i int) error {
			return mdl.ycli.UseYubi(
				ctx,
				lcl.UseYubiArg{SessionId: mdl.sessId, Idx: uint64(i)},
			)
		},
		nextHook: func(i *proto.YubiCardID) (state, tea.Cmd, error) {
			return newStateYSPPGetPIN(), nil, nil
		},
	}
}

func newStateYSPPHome() stateHome {
	return stateHome{
		oked:   false,
		letsDo: "Let's set a YubiKey PIN",
		nxt:    newStateYSPPPickCard(),
	}
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func pinValidator(s string) error {
	l := len(s)
	if (l > 0 && l < 6) || (l > 8) || !isAllDigits(s) {
		return errors.New("PIN must be between 6 and 8 numerical digits")
	}
	return nil
}

func pukValidator(s string) error {
	l := len(s)
	if (l != 0 && l != 8) || !isAllDigits(s) {
		return errors.New("PUK must be 8 numerical digits")
	}
	return nil
}

type stateFinishYSPP struct{}

var _ stateFinishSub = stateFinishYSPP{}

func (s stateFinishYSPP) view(b stateFinishBase) string {
	return "\n 🔒 Your YubiKey was successfully locked down 🔒\n\n" + pushAnyKeyToExit() + "\n\n"
}

func (s stateFinishYSPP) init(mctx libclient.MetaContext, mdl model) tea.Msg {
	return finishRes{}
}

func newStateFinishYSPP() stateFinishBase { return stateFinishBase{sub: stateFinishYSPP{}} }

func newStateYSPPSetManagementKey() state {
	return stateShowKey{
		nextState: func(s stateShowKey, mdl model) state {
			return newStateFinishYSPP()
		},
		initHook: func(mctx libclient.MetaContext, mdl model) (string, string, error) {
			res, err := mdl.ycli.SetOrGetManagementKey(mctx.Ctx(), mdl.sessId)
			var succ string
			if err != nil {
				return "", succ, err
			}
			key := res.Key.String()
			var b strings.Builder

			if res.WasMade {
				whatThe := "Here is the new management key for your YubiKey. You can write it down and " +
					"keep it in a safe place. If you ever forget your PIN or your PUK, you can use the " +
					"management key to regain access to your YubiKey. We will also store it in two places: " +
					"on the YubiKey itself, encrypted with your new PIN; and on your FOKS server, encrypted for your " +
					"user key."

				fmt.Fprintf(&b,
					"%s\n   %s\n\n",
					libterm.MustRewrapSense(whatThe, 2),
					key,
				)
				succ = "YubiKey management key set"
			} else {

				whatThe := "Here is the management key for your YubiKey, which we read off the key and " +
					"did not change. You can write it down and keep it in a safe place if you haven't already."
				fmt.Fprintf(&b,
					"%s\n   %s\n\n",
					libterm.MustRewrapSense(whatThe, 2),
					key,
				)
				succ = "YubiKey management key verified"
			}

			return b.String(), succ, nil
		},
	}
}

func newStateYSPPSetPUK() state {
	return stateNewPassphrase{
		prompt:        "Please supply a new YubiKey PUK, used to recover after failed PIN tries",
		promptCanSkip: "or press enter if currently unset",
		noConfirm:     false,
		allowSkip:     false,
		postEmpty:     false,
		validator:     pukValidator,
		what:          "PUK",
		summaryLabel:  "YubiKey PUK set",
		nextHook: func() (state, error) {
			return newStateYSPPSetManagementKey(), nil
		},
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			puk, err := pp.ToYubiPUKOrZero()
			if err != nil {
				return err
			}
			err = mdl.ycli.SetPUK(
				mctx.Ctx(),
				lcl.SetPUKArg{
					SessionId: mdl.sessId,
					New:       puk,
				},
			)
			return err
		},
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			return true, nil
		},
	}

}

func newStateYSPPGetPUK() state {
	return stateNewPassphrase{
		prompt:        "Please supply existing YubiKey PUK",
		promptCanSkip: "or press enter if currently unset",
		noConfirm:     true,
		allowSkip:     true,
		postEmpty:     true,
		validator:     pukValidator,
		what:          "PUK",
		summaryLabel:  "Current YubiKey PUK verified",
		nextHook: func() (state, error) {
			return newStateYSPPSetPUK(), nil
		},
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			tmp, err := pp.ToYubiPUKOrZero()
			if err != nil {
				return err
			}
			return mdl.ycli.ValidateCurrentPUK(mctx.Ctx(),
				lcl.ValidateCurrentPUKArg{
					SessionId: mdl.sessId,
					Puk:       tmp,
				},
			)
		},
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			return true, nil
		},
	}
}

func newStateYSPPSetPin() state {
	return stateNewPassphrase{
		prompt:    "Please supply a new YubiKey PIN",
		noConfirm: false,
		allowSkip: false,
		postEmpty: false,
		validator: pinValidator,
		nextHook: func() (state, error) {
			return newStateYSPPGetPUK(), nil
		},
		what:         "PIN",
		summaryLabel: "YubiKey PIN set",
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			pin, err := pp.ToYubiPIN()
			if err != nil {
				return err
			}
			return mdl.ycli.SetPIN(mctx.Ctx(),
				lcl.SetPINArg{
					SessionId: mdl.sessId,
					Pin:       pin,
				},
			)
		},
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			return true, nil
		},
	}
}

func newStateYSPPGetPIN() state {
	return stateNewPassphrase{
		prompt:        "Please supply your existing YubiKey PIN",
		promptCanSkip: "or press enter if currently unset",
		noConfirm:     true,
		allowSkip:     true,
		postEmpty:     true,
		validator:     pinValidator,
		what:          "PIN",
		summaryLabel:  "Current YubiKey PIN verified",
		nextHook: func() (state, error) {
			return newStateYSPPSetPin(), nil
		},
		postHook: func(mctx libclient.MetaContext, mdl model, pp proto.Passphrase) error {
			pin, err := pp.ToYubiPINOrZero()
			if err != nil {
				return err
			}
			return mdl.ycli.ValidateCurrentPIN(mctx.Ctx(),
				lcl.ValidateCurrentPINArg{
					SessionId: mdl.sessId,
					Pin:       pin,
				},
			)
		},
		initHook: func(mctx libclient.MetaContext, mdl model) (bool, error) {
			return true, nil
		},
	}
}

func RunYubiSPP(m libclient.MetaContext) error {
	return RunNewModelForStateAndSessionType(
		m,
		newStateYSPPHome(),
		proto.UISessionType_YubiSPP,
	)
}
