// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"errors"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

func passphraseCmd(m libclient.MetaContext) *cobra.Command {

	top := &cobra.Command{
		Use:          "passphrase",
		Aliases:      []string{"pp"},
		Short:        "passphrase commands",
		Long:         "manage passphrases, which are optionally used to encrypt local keys",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}

	top.AddCommand(&cobra.Command{
		Use:          "unlock",
		Short:        "unlock local credentials with a passphrase",
		Long:         "unlock local credentials with a passphrase",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runPassphraseUnlock(m, cmd, arg)
		},
	})

	top.AddCommand(&cobra.Command{
		Use:          "set",
		Short:        "set a new passphrase",
		Long:         "set a new passphrase; won't work if one is already set",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runPassphraseSet(m, cmd, arg, true)
		},
	})

	top.AddCommand(&cobra.Command{
		Use:          "change",
		Short:        "change passphrase",
		Long:         "change passphrase for local key encryption; will sync across machines",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return runPassphraseSet(m, cmd, arg, false)
		},
	})

	return top
}

func passphraseQuickStart(
	m libclient.MetaContext,
	fn func(lcl.UserClient, lcl.PassphraseClient) error,
) error {
	opts := agent.StartupOpts{NeedUser: true}
	err := agent.Startup(m, opts)
	if err != nil {
		return err
	}
	gcli, cleanFn, err := m.G().ConnectToAgentCli(m.Ctx())
	if err != nil {
		return err
	}
	defer cleanFn()

	ucli := newClient[lcl.UserClient](m, gcli)
	ppcli := lcl.PassphraseClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}

	return fn(ucli, ppcli)

}

func runPassphraseSet(m libclient.MetaContext, cmd *cobra.Command, arg []string, first bool) error {
	return passphraseQuickStart(
		m,
		func(ucli lcl.UserClient, ppcli lcl.PassphraseClient) error {
			au, err := ucli.ActiveUser(m.Ctx())
			if err != nil {
				return err
			}
			pp, err := pickNewPassphrase(m, 10, func(isConfirm bool, isRetry bool) (*proto.Passphrase, error) {
				return m.G().UIs().Passphrase.GetPassphrase(m, au.Info,
					libclient.GetPassphraseFlags{
						IsNew:     true,
						IsConfirm: isConfirm,
						IsRetry:   isRetry,
					},
				)
			})
			if err != nil {
				return err
			}
			return ppcli.PassphraseSet(m.Ctx(), lcl.PassphraseSetArg{
				Passphrase: *pp,
				First:      first,
			})
		},
	)
}

func pickNewPassphrase(
	m libclient.MetaContext,
	tries int,
	hook func(isConfirm bool, isRetry bool) (*proto.Passphrase, error),
) (
	*proto.Passphrase,
	error,
) {
	var confirmedPp *proto.Passphrase
	for i := 0; i < 10 && confirmedPp == nil; i++ {

		var pp [2]proto.Passphrase
		var fail bool

		for j := 0; j < 2; j++ {
			tmp, err := hook((j > 0), (i > 0))
			if err != nil {
				return nil, err
			}

			if tmp != nil {
				pp[j] = *tmp
			} else if j == 0 {
				return nil, nil
			} else {
				fail = true
			}
		}

		if !fail && pp[0] == pp[1] {
			confirmedPp = &pp[0]
		}
	}

	if confirmedPp == nil {
		return nil, core.TooManyTriesError{}
	}

	return confirmedPp, nil
}

func runPassphraseUnlock(m libclient.MetaContext, cmd *cobra.Command, arg []string) error {
	return passphraseQuickStart(
		m,
		func(ucli lcl.UserClient, ppcli lcl.PassphraseClient) error {
			res, err := ucli.ActiveUserCheckLocked(m.Ctx())
			if err != nil {
				return err
			}
			lres := core.StatusToError(res.LockStatus)
			if lres == nil {
				return nil
			}
			if !errors.Is(lres, core.PassphraseLockedError{}) {
				return lres
			}
			pp, err := m.G().UIs().Passphrase.GetPassphrase(
				m,
				res.User.Info,
				libclient.GetPassphraseFlags{},
			)
			if err != nil {
				return err
			}
			err = ppcli.PassphraseUnlock(m.Ctx(), *pp)
			return err
		},
	)
}

func init() {
	AddCmd(passphraseCmd)
}
