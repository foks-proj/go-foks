// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"io"
	"os"
	"time"

	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/mattn/go-isatty"
)

type SignupUIer interface {
	Begin(m MetaContext) error
	Rollback(m MetaContext) error
	Commit(m MetaContext) error

	PickExistingUser(m MetaContext, lst []proto.UserInfo) (int, error)

	// -1 == use no device
	PickYubiDevice(m MetaContext, lst []proto.YubiCardID) (int, error)

	PickServer(m MetaContext, def proto.TCPAddr, timeout time.Duration) (*proto.TCPAddr, error)
	CheckedServer(m MetaContext, addr proto.TCPAddr, e error) error

	GetInviteCode(m MetaContext, icr proto.InviteCodeRegime, attempt int) (*lcl.InviteCodeString, error)
	CheckedInviteCode(m MetaContext, code lcl.InviteCodeString, e error) error

	ShowWaitListID(m MetaContext, wlid proto.WaitListID) error

	ShowSSOLoginURL(m MetaContext, url proto.URLString) error
	ShowSSOLoginResult(m MetaContext, res proto.SSOLoginRes) error

	// If primary is set, that means we're picking for a PQ seed slot,
	// and we can't pick primary (since it's already been picked).
	PickYubiSlot(m MetaContext, y proto.YubiCardInfo, primary *proto.YubiSlot) (proto.YubiIndex, error)

	GetEmail(m MetaContext) (*proto.Email, error)
	GetUsername(m MetaContext) (*proto.NameUtf8, error)
	GetDeviceName(m MetaContext) (*proto.DeviceName, error)
	GetPassphrase(m MetaContext, confirm bool, prevErr bool) (*proto.Passphrase, error)

	GetKexHESP(m MetaContext, ourHesp proto.KexHESP, lastErr error) (*proto.KexHESP, error)
}

type DeviceAssistUIer interface {
	ConfirmActiveUser(m MetaContext, u proto.UserInfo) error
	GetKexHESP(m MetaContext, ourHesp proto.KexHESP, lastErr error) (*proto.KexHESP, error)
}

type IOStreamer interface {
	io.WriteCloser
	IsATTY() bool
}

type OSFileWrapper struct {
	*os.File
}

var WrappedStderr = OSFileWrapper{File: os.Stderr}

var _ IOStreamer = OSFileWrapper{}

func (f OSFileWrapper) IsATTY() bool {
	return isatty.IsTerminal(f.Fd())
}

type TerminalUIer interface {
	Printf(fmt string, args ...interface{})
	OutputStream() io.WriteCloser
	ErrorStream() IOStreamer
	IsOutputTTY() bool
	ReadLine(string) (string, error)
}

type GetPassphraseFlags struct {
	IsNew     bool
	IsConfirm bool
	IsRetry   bool
}

type PassphraseUIer interface {
	GetPassphrase(m MetaContext, uc proto.UserInfo, flags GetPassphraseFlags) (*proto.Passphrase, error)
}

type PINUIer interface {
	GetPIN(m MetaContext) (*proto.YubiPIN, error)
}

type BackupUIer interface {
	GetBackupKeyHESP(m MetaContext) (lcl.BackupHESP, error)
	PickServer(m MetaContext, def proto.TCPAddr, timeout time.Duration) (*proto.TCPAddr, error)
	CheckedServer(m MetaContext, addr proto.TCPAddr, e error) error
}

type SSOLoginUIer interface {
	ShowSSOLoginURL(m MetaContext, url proto.URLString) error
	ShowSSOLoginResult(m MetaContext, res proto.SSOLoginRes, err error) error
}

type LogSendUIer interface {
	ShowStartSend(m MetaContext) error
	ShowCompleteSend(m MetaContext, err error) error
	ApproveLogs(m MetaContext, log lcl.LogSendSet) error
	ShowLogSendRes(m MetaContext, res lcl.LogSendRes) error
}

type UIs struct {
	Signup     SignupUIer
	Terminal   TerminalUIer
	Assist     DeviceAssistUIer
	Passphrase PassphraseUIer
	Backup     BackupUIer
	SSOLogin   SSOLoginUIer
	PIN        PINUIer
	LogSend    LogSendUIer
}
