// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package simple_ui

import (
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/manifoldco/promptui"
)

type BackupUI struct {
}

func (b *BackupUI) GetBackupKeyHESP(m libclient.MetaContext) (lcl.BackupHESP, error) {
	prompt := promptui.Prompt{
		Label: "🔑 Backup Key>",
		Validate: func(s string) error {
			return core.ValidateBackupHESP(lcl.BackupHESPString(s))
		},

		Templates: &promptTemplates,
	}
	s, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	ret := lcl.BackupHESPString(s).Split()
	return ret, nil
}

func (b *BackupUI) PickServer(m libclient.MetaContext, def proto.TCPAddr, timeout time.Duration) (*proto.TCPAddr, error) {
	return pickServer(m, def, timeout)
}

func (b *BackupUI) CheckedServer(m libclient.MetaContext, addr proto.TCPAddr, err error) error {
	return nil
}

var _ libclient.BackupUIer = &BackupUI{}
