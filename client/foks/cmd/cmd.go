// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libterm"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/spf13/cobra"
)

func rootCmdSwissArmyKnife() *cobra.Command {
	return &cobra.Command{
		Use:   "foks",
		Short: "Command-line interface to the Federated Open Key Service (FOKS)",
		Long: libterm.MustRewrapSense(`FOKS is a federated protocol that allows for online public key advertisement,
sharing, and rotation. It works for a user and their many devices, for many users who want
to form a group, for groups of groups etc. The core primitive is that several
private key holders can conveniently share a private key; and that private key
can simply correspond to another public/private key pair, which can be members
of a group one level up. This pattern can continue recursively forming a tree.

Crucially, if any private key is removed from a key share, all shares rooted at
that key must rotate. FOKS implements that rotation.

Like email or the Web, the world consists of multiple FOKS servers, administrated
independently and speaking the same protocol. Groups can span multiple federated
services.

Many applications can be built on top of this primitive but best suited are those
that share encrypted, persistent information across groups of users with multiple
devices. For instance, files and git hosting.`, 0),
		Version: core.CurrentSoftwareVersion.String(),
	}
}

type CommandBuilder func(m libclient.MetaContext) *cobra.Command

type Commands struct {
	cmds []CommandBuilder
}

func (c *Commands) push(f func(m libclient.MetaContext) *cobra.Command) {
	c.cmds = append(c.cmds, f)
}

func (c *Commands) init(m libclient.MetaContext, root *cobra.Command) {
	for _, cmd := range c.cmds {
		root.AddCommand(cmd(m))
	}
}

func versionCmd(m libclient.MetaContext) *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of foks",
		Long:  "Print the version number of foks",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("foks version %s\n", core.CurrentSoftwareVersion.String())
			if verbose {
				fmt.Printf(" - commit: %s\n", libclient.LinkerVersion)
				fmt.Printf(" - protocol compatibility version: %d\n", core.CurrentCompatibilityVersion)
				if libclient.LinkerPackaging != "" {
					fmt.Printf(" - packaging: %s\n", libclient.LinkerPackaging)
				}
			}
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show more version information")
	return cmd
}

func AddCmd(b CommandBuilder) {
	cmds.push(b)
}

var cmds Commands

func Main() {
	MainWithArgs(os.Args[0], nil)
}

func MainWithArgs(cmd string, args []string) {
	err := MainInnerWithCmd(cmd, args, nil)
	rc := 0
	if err != nil {
		rc = -1
	}
	os.Exit(rc)
}

func stripDirAndExtFromCommand(cmd string) string {
	ret := filepath.Base(cmd)
	if runtime.GOOS != "windows" {
		return ret
	}
	ext := filepath.Ext(ret)
	if ext == ".exe" {
		ret = ret[:len(ret)-len(ext)]
	}
	return ret
}

func rootCmdFromArgs(
	m libclient.MetaContext,
	cmd string,
	args []string,
) (
	*cobra.Command,
	error,
) {

	var ret *cobra.Command

	cmdBase := stripDirAndExtFromCommand(cmd)

	if cmdBase == GitRemoteHelper {
		ret = rootCmdGitRemoteHelper(m)
	} else {
		ret = rootCmdSwissArmyKnife()
		cmds.init(m, ret)
	}
	if args != nil {
		ret.SetArgs(args)
	}
	return ret, nil
}

func MainInner(args []string, testSetupHook func(m libclient.MetaContext) error) error {
	return MainInnerWithCmd("foks", args, testSetupHook)
}

func MainInnerWithCmd(cmd string, args []string, testSetupHook func(m libclient.MetaContext) error) error {

	core.DebugStop()

	m := libclient.NewMetaContextMain()
	defer m.Shutdown()

	root, err := rootCmdFromArgs(m, cmd, args)
	if err != nil {
		return err
	}
	err = m.Setup(root)
	if err != nil {
		return err
	}
	SetUIs(m)

	// Tests might want to substitue a mocked out UI for simulating user input/output.
	// That can happen here.
	if testSetupHook != nil {
		err = testSetupHook(m)
		if err != nil {
			return err
		}
	}
	ConfigureHelp(m, root)

	err = root.ExecuteContext(m.Ctx())
	if err != nil {
		s := libclient.ErrToStringCLI(err)
		fmt.Fprintf(os.Stderr, "Error: %s\n", s)
		return err
	}

	return nil
}

func init() {
	AddCmd(versionCmd)
}
