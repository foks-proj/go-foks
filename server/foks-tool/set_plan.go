// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type SetPlan struct {
	CLIAppBase
	fquStr    string
	planIDStr string

	fqu proto.FQUser
	pid proto.PlanID
}

func (s *SetPlan) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "set-plan",
		Short: "set a plan for a user",
	}
	ret.Flags().StringVar(&s.fquStr, "fqu", "", "Fully-qualified UID to set a plan on")
	ret.Flags().StringVar(&s.planIDStr, "plan-id", "", "The planID to set for the user")
	return ret
}

func (s *SetPlan) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	fqu, err := proto.ParseFQUser(s.fquStr)
	if err != nil {
		return err
	}
	i16, err := proto.ID16String(s.planIDStr).Parse()
	if err != nil {
		return err
	}
	pid, err := i16.ToPlanID()
	if err != nil {
		return err
	}

	s.fqu = *fqu
	s.pid = *pid

	return nil
}

func (s *SetPlan) Run(m shared.MetaContext) error {
	_, err := shared.SetPlanViaCli(m, s.fqu, s.pid, false)
	return err
}

func (s *SetPlan) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*SetPlan)(nil)

func init() {
	AddCmd(&SetPlan{})
}
