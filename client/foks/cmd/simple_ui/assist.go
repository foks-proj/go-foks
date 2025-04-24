// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package simple_ui

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/manifoldco/promptui"
)

type AssistUI struct {
}

var _ libclient.DeviceAssistUIer = &AssistUI{}

func (s *AssistUI) ConfirmActiveUser(m libclient.MetaContext, u proto.UserInfo) error {
	i, err := formatUserInfoAsPromptItem(u)
	if err != nil {
		return err
	}
	prompt := promptui.Select{
		Label: "Continue provisioning as " + i + " ?",
		Items: []string{
			"✅ Yes",
			"❌ No",
		},
	}
	idx, _, err := prompt.Run()
	if err != nil {
		return err
	}
	if idx == 0 {
		return nil
	}
	return core.CanceledInputError{}
}

func (s *AssistUI) GetKexHESP(
	m libclient.MetaContext,
	ourHesp proto.KexHESP,
	lastErr error,
) (
	*proto.KexHESP,
	error,
) {
	return getKexHESP(m, ourHesp, lastErr, "Run `foks dev provision` on another device, and enter code here")
}
