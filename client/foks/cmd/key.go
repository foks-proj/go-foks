// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/foks/cmd/common_ui"
	"github.com/foks-proj/go-foks/client/foks/cmd/ui"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type switchCmdCfg struct {
	fqu      string
	role     string
	yubi     bool
	device   bool
	backup   bool
	botToken bool
	keyID    string
}

func (s *switchCmdCfg) flagCommand(c *cobra.Command, verb string, devFlag bool) {
	c.Flags().StringVarP(&s.fqu, "user", "u", "", "fully qualified user (via ID or name)")
	c.Flags().StringVar(&s.role, "role", "", "role (e.g., 'o', 'a', or 'm0' or 'm-30')")
	c.Flags().BoolVar(&s.yubi, "yubi", false, fmt.Sprintf("%s yubikey", verb))
	if devFlag {
		c.Flags().BoolVar(&s.device, "device", false, fmt.Sprintf("%s device", verb))
	}
	c.Flags().BoolVar(&s.backup, "backup", false, fmt.Sprintf("%s backup key", verb))
	c.Flags().BoolVar(&s.botToken, "bot-token", false, fmt.Sprintf("%s bot token", verb))
	c.Flags().StringVar(&s.keyID, "key-id", "", fmt.Sprintf("key ID to %s", verb))
}

func switchCmd(m libclient.MetaContext) *cobra.Command {
	var cfg switchCmdCfg
	cmd := &cobra.Command{
		Use:          "switch",
		Short:        "switch active key",
		Long:         `Switch to a different profile, changing the active key and (optionally) user"`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runSwitch(m, cmd, &cfg, arg)
		},
	}
	cfg.flagCommand(cmd, "switch to", true)
	return cmd
}

func removeCmd(m libclient.MetaContext) *cobra.Command {
	var cfg switchCmdCfg
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "remove a key from the local database, without revoking it",
		Long: libterm.MustRewrapSense(`Remove a YubiKey or backup key from the local database, but do
not revoke the key.

When you sign up with a Yubikey, FOKS writes some basic information about the key to its
local database, so the software can find the key and the correct parameters later. The database
entry is reflected in 'foks key list'. This command removes that entry.

This command has two modes of operations. Either you can specify a key exactly via the 
flags and options; or provide no flags and options, in which case the command will
interactively prompt you to select a key to remove.`, 0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(m, cmd, &cfg, args)
		},
	}
	cfg.flagCommand(cmd, "remove", false)
	return cmd
}

func keyLockCmd(m libclient.MetaContext) *cobra.Command {
	return &cobra.Command{
		Use:          "lock",
		Short:        "lock active key by discarding private key material",
		Long:         "Lock active key by discarding private key material",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runKeyLock(m, cmd, arg)
		},
	}
}

func runKeyLock(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	return quickStartLambda(m, nil, func(cli lcl.UserClient) error {
		return cli.UserLock(m.Ctx())
	})
}

type keyListOpts struct {
	currentUserKeys bool
	otherProfiles   bool
}

func keyCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:     "key",
		Aliases: []string{"keys"},
		Short:   "manage FOKS keys",
		Long:    "Manage FOKS keys, including devices, YubiKeys and backup keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return subcommandHelp(cmd, args)
		},
	}

	new := &cobra.Command{
		Use:     "new",
		Aliases: []string{"create", "add"},
		Short:   "add a new key: a device, YubiKey, or backup key",
		Long:    "New key wizard: create a new key; works for devices, YubiKeys or backup keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNewKeyWizard(m, cmd, args)
		},
	}
	top.AddCommand(new)

	var lsOpts keyListOpts
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "list keys",
		Long:    "List keys for the currently active user, and all other users and keys on this machine",
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runKeyList(m, cmd, arg, &lsOpts)
		},
	}
	list.Flags().BoolVar(&lsOpts.currentUserKeys, "current-user-keys", false, "show all the curent user's keys")
	list.Flags().BoolVar(&lsOpts.otherProfiles, "other-profiles", false, "show all other profiles")
	top.AddCommand(list)

	revoke := &cobra.Command{
		Use:          "revoke",
		Short:        "revoke a key",
		Long:         "Revoke a key; supply a key ID; works for a device, backup key or yubikey",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runRevoke(m, cmd, arg)
		},
	}
	top.AddCommand(revoke)

	assist := &cobra.Command{
		Use:          "assist",
		Short:        "assist provisioning a new FOKS device",
		Long:         "Run on an existing, provisioned device to provision a new device",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runAssist(m, cmd, arg)
		},
	}
	top.AddCommand(assist)

	useYubi := yubiUseCmd(m, "use-yubikey", []string{"use-yubi"},
		"This command is a synonym for `foks yubi use`.")
	top.AddCommand(useYubi)

	useBkp := bkpUseCmd(m, "use-backup", []string{"use-bkp"},
		"This command is a synonym for `foks bkp use`.")
	top.AddCommand(useBkp)

	useBotKey := botTokenUseCmd(m, "use-bot-token", []string{"use-bot"},
		"This command is a synonym for `foks bot-token use`.")
	top.AddCommand(useBotKey)

	// Add device commands as subcommands
	dev := deviceCmd(m)
	top.AddCommand(dev)

	sw := switchCmd(m)
	top.AddCommand(sw)

	remove := removeCmd(m)
	top.AddCommand(remove)

	lock := keyLockCmd(m)
	top.AddCommand(lock)

	return top
}

func runAssist(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	err := agent.Startup(m, agent.StartupOpts{NeedUnlockedUser: true})
	if err != nil {
		return err
	}
	if m.G().Cfg().SimpleUI() {
		ass := assistState{}
		err = ass.runSimpleUI(m)
	} else {
		err = ui.RunAssist(m)
	}
	if err != nil {
		return err
	}
	return nil
}

func runNewKeyWizard(m libclient.MetaContext, cmd *cobra.Command, args []string) error {
	err := agent.Startup(m, agent.StartupOpts{})
	if err != nil {
		return err
	}
	return ui.RunNewKeyWizard(m)
}

func (o keyListOpts) doDefault() bool {
	return !o.currentUserKeys && !o.otherProfiles
}

func runKeyListTable(
	m libclient.MetaContext,
	ls lcl.KeyListRes,
	opts *keyListOpts,
) error {
	doCurrentUserKeys := opts.currentUserKeys || opts.doDefault()
	doOtherProfiles := opts.otherProfiles || opts.doDefault()
	doBoth := doCurrentUserKeys && doOtherProfiles

	if doCurrentUserKeys && len(ls.CurrUserAllKeys) > 0 {

		var title string
		if ls.CurrUser != nil && doBoth {
			u, err := common_ui.FormatUserInfoAsPromptItem(
				ls.CurrUser.Info,
				&common_ui.FormatUserInfoOpts{
					Avatar:       true,
					NoDeviceName: true,
				},
			)
			if err != nil {
				return err
			}
			title = fmt.Sprintf("All keys for %s", u)
		}

		err := outputKeyListTable(m,
			outputTableOpts{headers: true, title: title},
			ls.CurrUserAllKeys,
		)
		if err != nil {
			return err
		}
	}

	if doOtherProfiles && len(ls.AllUsers) > 0 {
		mode := userListTableModeDisk
		var title string
		if doBoth {
			title = "All profiles available on this machine"
		}
		err := outputUserListTable(m, outputTableOpts{headers: true, title: title}, ls.AllUsers, mode)
		if err != nil {
			return err
		}
	}

	return PartingConsoleMessage(m)
}

func runKeyList(m libclient.MetaContext, cmd *cobra.Command, arg []string, opts *keyListOpts) error {
	return quickStartLambda(
		m,
		&agent.StartupOpts{NeedUnlockedUser: true, NeedUser: true},
		func(cli lcl.KeyClient) error {
			ls, err := cli.KeyList(m.Ctx())
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, ls)
			}
			return runKeyListTable(m, ls, opts)
		},
	)
}

func runRevoke(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	if len(arg) != 1 {
		return ArgsError("expected exactly one argument, a key ID")
	}
	dkid, err := proto.ImportEntityIDFromString(arg[0])
	if err != nil {
		return err
	}
	return quickStartLambda(
		m,
		&agent.StartupOpts{NeedUnlockedUser: true, NeedUser: true},
		func(cli lcl.KeyClient) error {
			// Don't display nag here in case we're self-revoking (since after that
			// the nag warning will break on no active user available).
			return cli.KeyRevoke(m.Ctx(), dkid)
		},
	)
}

func (s *switchCmdCfg) parse() (*lcl.LocalUserIndexParsed, error) {
	var eid proto.EntityID
	if s.keyID != "" {
		tmp, err := proto.ImportEntityIDFromString(s.keyID)
		if err != nil {
			return nil, err
		}
		eid = tmp
	}

	fqu, err := parseFqu(s.fqu)
	if err != nil {
		return nil, err
	}
	if fqu == nil {
		if len(s.role) > 0 {
			return nil, ArgsError("can only use -r flag with -u flag")
		}
		if eid != nil {
			return nil, ArgsError("can only use --key-id flag with -u flag")
		}
		return nil, nil
	}

	role, err := parseRole(s.role, &proto.OwnerRole)
	if err != nil {
		return nil, err
	}
	var kg *proto.KeyGenus
	switch {
	case s.yubi:
		tmp := proto.KeyGenus_Yubi
		kg = &tmp
	case s.device:
		tmp := proto.KeyGenus_Device
		kg = &tmp
	case s.backup:
		tmp := proto.KeyGenus_Backup
		kg = &tmp
	case s.botToken:
		tmp := proto.KeyGenus_BotToken
		kg = &tmp
	}

	ret := lcl.LocalUserIndexParsed{
		Fqu:      *fqu,
		Role:     *role,
		KeyGenus: kg,
		KeyID:    eid,
	}
	return &ret, nil
}

func runRemove(m libclient.MetaContext, cmd *cobra.Command, cfg *switchCmdCfg, args []string) error {
	cli, clean, err := quickStart[lcl.UserClient](m, nil)
	if err != nil {
		return err
	}
	defer clean()
	swarg, err := cfg.parse()
	if err != nil {
		return err
	}
	if swarg == nil {
		return ui.RunRemove(m, cli)
	}
	if swarg.KeyGenus != nil && *swarg.KeyGenus == proto.KeyGenus_Device {
		return core.BadArgsError("cannot remove a device key; use `foks key revoke` instead")
	}
	return cli.RemoveKey(m.Ctx(), *swarg)
}

func runSwitch(m libclient.MetaContext, cmd *cobra.Command, cfg *switchCmdCfg, arg []string) error {
	cli, clean, err := quickStart[lcl.UserClient](m, nil)
	if err != nil {
		return err
	}
	defer clean()
	swarg, err := cfg.parse()
	if err != nil {
		return err
	}
	if swarg != nil {
		return cli.SwitchUser(m.Ctx(), *swarg)
	}
	err = ui.RunSwitch(m, cli)
	if err != nil {
		return err
	}
	return nil
}

func init() {
	AddCmd(keyCmd)
}
