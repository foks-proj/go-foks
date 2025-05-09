// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

var teamOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

func teamCreate(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"create", []string{"mk"},
		"create a new team", "create a new team with one owner (the current user)",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team name")
			}
			nm := proto.NameUtf8(arg[0])
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				res, err := cli.TeamCreate(m.Ctx(), nm)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				s, err := res.Id.StringErr()
				if err != nil {
					return err
				}
				m.G().UIs().Terminal.Printf("TeamID: %s\n", s)
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamInvite(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"invite", []string{"inv"},
		"create a new team invite, or fetch one if it already exists",
		"create a new team invite or fetch an existing one; the output string can shared with multiple intended recipients",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team name")
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
				if err != nil {
					return err
				}
				res, err := cli.TeamCreateInvite(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				s, err := team.ExportTeamInvite(res)
				if err != nil {
					return err
				}
				m.G().UIs().Terminal.Printf("%s\n", s)
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamList(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"list", []string{"ls"},
		"list the memebers of a team",
		"list teams the members of a team",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team to list")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				res, err := cli.TeamList(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				err = outputTeamListTable(m, outputTableOpts{headers: true}, res)
				if err != nil {
					return err
				}
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamAll(m libclient.MetaContext, top *cobra.Command) {
	desc := "list the teams the current user is a member of"
	cmd := &cobra.Command{
		Use:          "list-memberships",
		Aliases:      []string{"all", "lm"},
		Short:        desc,
		Long:         desc,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				res, err := cli.TeamListMemberships(m.Ctx())
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				err = outputTeamListMembershipsTable(
					m,
					outputTableOpts{headers: true},
					res,
				)
				if err != nil {
					return err
				}
				return PartingConsoleMessage(m)
			})
		},
	}
	top.AddCommand(cmd)
}

func teamAccept(m libclient.MetaContext, top *cobra.Command) {
	var teamStr, roleStr string
	cmd := &cobra.Command{
		Use:          "accept",
		Aliases:      []string{"acc"},
		Short:        "accept a team invite",
		Long:         "accept a team invite in any of these 4 formats: {user,team} x {local,remote}",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			var fqt *proto.FQTeamParsed
			var srcRole *proto.Role
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team invite string")
			}
			if teamStr != "" {
				var err error
				fqt, err = core.ParseFQTeam(proto.FQTeamString(teamStr))
				if err != nil {
					return err
				}
			}
			if roleStr != "" {
				rs := proto.RoleString(roleStr)
				var err error
				srcRole, err = rs.Parse()
				if err != nil {
					return err
				}
			}
			if srcRole != nil && fqt == nil {
				return ArgsError("cannot specify source role without team")
			}
			if fqt != nil && srcRole == nil {
				tmp := proto.NewRoleWithMember(proto.VizLevel(0))
				srcRole = &tmp
			}
			var fqtr *lcl.FQTeamParsedAndRole
			if fqt != nil && srcRole != nil {
				tmp := lcl.FQTeamParsedAndRole{
					Fqtp: *fqt,
					Role: *srcRole,
				}
				fqtr = &tmp
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				invite, err := team.ImportTeamInvite(arg[0])
				if err != nil {
					return err
				}
				res, err := cli.TeamAcceptInvite(m.Ctx(),
					lcl.TeamAcceptInviteArg{
						I:        *invite,
						ActingAs: fqtr,
					},
				)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}

				teamId, err := res.Team.Id.Team.StringErr()
				if err != nil {
					return err
				}
				hostId, err := res.Team.Id.Host.StringErr()
				if err != nil {
					return err
				}

				m.G().UIs().Terminal.Printf(`Invite Accepted!
Team: %s (%s)
Host: %s (%s)
`,
					res.Team.Name.String(),
					teamId,
					res.Team.Host.String(),
					hostId,
				)
				if res.Tok != nil {
					m.G().UIs().Terminal.Printf("Token: %s\n", res.Tok.String())
				}
				return PartingConsoleMessage(m)
			})
		},
	}
	cmd.Flags().StringVarP(&teamStr, "team", "t", "", "team to accept invite for")
	cmd.Flags().StringVarP(&roleStr, "role", "r", "", "source role to accept team invte as (default=member/0)")
	top.AddCommand(cmd)
}

func teamInbox(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"inbox", []string{},
		"team join requests for the given team",
		"team join requests for the given team",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team to list")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				res, err := cli.TeamInbox(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				err = outputTeamInboxTable(m, outputTableOpts{headers: true}, res)
				if err != nil {
					return err
				}
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamAdd(m libclient.MetaContext, top *cobra.Command) {
	var roleStr string
	cmd := &cobra.Command{
		Use:          "add",
		Aliases:      nil,
		Short:        "add a user to a team (on an open-view host)",
		Long:         "add a user to a team (on an open-view host)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) < 2 {
				return ArgsError("expect two or more arguments -- team and user names (or UIDs)")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			var role *proto.Role

			if roleStr != "" {
				rs, err := proto.RoleString(roleStr).Parse()
				if err != nil {
					return err
				}
				role = rs
			}
			var members []lcl.FQPartyParsedAndRole

			for _, arg := range arg[1:] {
				p, err := core.ParseFQPartyAndRole(lcl.FQPartyAndRoleString(arg))
				if err != nil {
					return err
				}
				members = append(members, *p)
			}

			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				err := cli.TeamAdd(m.Ctx(), lcl.TeamAddArg{
					Team:    *fqt,
					DstRole: role,
					Members: members,
				})
				if err != nil {
					return err
				}
				return PartingConsoleMessage(m)
			})

		},
	}
	cmd.Flags().StringVarP(&roleStr, "role", "r", "", "destination role in the team")
	top.AddCommand(cmd)
}

func teamAdmit(m libclient.MetaContext, top *cobra.Command) {
	cmd := &cobra.Command{
		Use:          "admit",
		Aliases:      nil,
		Short:        "admit a user to a team (given an accept code)",
		Long:         "admit a user to a team (given an accept code)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) < 2 {
				return ArgsError("expect two or more arguments -- team and invite IDs")
			}
			fqt, err := core.ParseFQTeam((proto.FQTeamString(arg[0])))
			if err != nil {
				return err
			}
			var members []lcl.TokRole
			for _, s := range arg[1:] {
				tr, err := lcl.TokRoleString(s).Parse()
				if err != nil {
					return err
				}
				members = append(members, *tr)
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				err := cli.TeamAdmit(m.Ctx(), lcl.TeamAdmitArg{
					Team:    *fqt,
					Members: members,
				})
				if err != nil {
					return err
				}
				return PartingConsoleMessage(m)
			})
		},
	}
	top.AddCommand(cmd)
}

func teamIndexRangeSet(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"set", nil,
		"set a team's index range to the given value",
		"set a team's index range to the given value; old range must include new range",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 2 {
				return ArgsError("expected exactly two arguments -- the team name and the new value")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			rng, err := core.ParseRationalRange(arg[1])
			if err != nil {
				return err
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				res, err := cli.TeamIndexRangeSet(m.Ctx(),
					lcl.TeamIndexRangeSetArg{
						Team:  *fqt,
						Range: rng.Export(),
					},
				)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("New index range: %s\n", core.NewRationalRange(res).String())
				return PartingConsoleMessage(m)
			})
		},
	)

}

func teamIndexRangeGet(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"get", nil,
		"get a team's index range",
		"get and output a team's index range",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team name")
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
				if err != nil {
					return err
				}
				res, err := cli.TeamIndexRangeGet(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("%s\n", core.NewRationalRange(res).String())
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamIndexRangeLower(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"lower", []string{"rsh"},
		"lower a team's index range by a factor of 2; map inf to 0x80",
		"for a given range (a,b), lower it to (a,b/2)",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team name")
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
				if err != nil {
					return err
				}
				res, err := cli.TeamIndexRangeLower(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("New index range: %s\n", core.NewRationalRange(res).String())
				return PartingConsoleMessage(m)
			})
		},
	)
}

func teamIndexRangeRaise(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"raise", []string{"lsh"},
		"raise a team's index range by a factor of 2",
		"for a given range (a,b), raise it to (2a,b); map (1,∞) to (80,∞)",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the team name")
			}
			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
				if err != nil {
					return err
				}
				res, err := cli.TeamIndexRangeRaise(m.Ctx(), *fqt)
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("New index range: %s\n", core.NewRationalRange(res).String())
				return PartingConsoleMessage(m)
			})
		},
	)

}

func teamIndexRangeCmd(m libclient.MetaContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "index-range",
		Aliases:      []string{"ir"},
		Short:        "team index range management",
		Long:         "team index range management",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return cmd.Help()
		},
	}
	teamIndexRangeSet(m, cmd)
	teamIndexRangeGet(m, cmd)
	teamIndexRangeLower(m, cmd)
	teamIndexRangeRaise(m, cmd)
	return cmd
}

func teamCmd(m libclient.MetaContext) *cobra.Command {

	top := &cobra.Command{
		Use:          "team",
		Short:        "team management commands",
		Long:         "team management commands",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return cmd.Help()
		},
	}
	teamCreate(m, top)
	teamList(m, top)
	teamInvite(m, top)
	teamAccept(m, top)
	teamInbox(m, top)
	teamAdmit(m, top)
	teamAdd(m, top)
	teamAll(m, top)
	top.AddCommand(teamIndexRangeCmd(m))
	return top
}

func init() {
	AddCmd(teamCmd)
}
