// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
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
		"create <team-name>", []string{"mk"},
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
		"invite <team>", []string{"inv"},
		"create a new team invite, or fetch one if it already exists",
		libterm.MustRewrapSense(`create a new team invite or fetch an existing one; 
the output string can shared with multiple intended recipients, and can be shared
via any communication means available, like email or chat.

This command takes 1 argument, the team name (or ID) to make an invite for.
The operator must be admin or above to proceed.

Users can accept this invitation via the 'foks team accept' command.
`, 0),
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
		"list <name>", []string{"ls"},
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
		Use:     "accept <invite-code>",
		Aliases: []string{"acc"},
		Short:   "accept a team invite",
		Long: libterm.MustRewrapSense(`Accept a team invite given an invite code.
The invite code is good for exactly on team. By default, accept the invitation for
your user, at the role Owner. Optionally, you can specify a team and/or a 
source role, if you want to accept the invitation on behalf of a team, or with
a role other than the default.`, 0),
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
	cmd.Flags().StringVarP(&roleStr, "role", "r", "", "source role to accept team invite as (default=member/0)")
	top.AddCommand(cmd)
}

func teamInbox(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"inbox <team>", []string{},
		"team join requests for the given team",
		libterm.MustRewrapSense(`List all of the pending team join requests for the
given team, so they can be acted on with 'foks team accept'. You must be the 
admin or owner of the team to use this feature.`, 0),
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
		Use:     "add <team> <user1> <user2> ...",
		Aliases: nil,
		Short:   "add a user to a team (on an open-view host)",
		Long: libterm.MustRewrapSense(`Add a user to a team on an open-view host.

Recall that typically, adding a team (or user) to a team is a 3-way handshake, since
the intended party needs to allow the team admin first to view its sigchain. On an open-view
host, this permissioning is not needed, since anyone can see anyone. Therefore, it's also 
possible for an admin to add other members directly to a team. This command (`+"`foks team add`"+`)
does this addition.

Each user added can be specified with or without a source role. If source roles are not provided:
for users the default role is owner; for teams, the default role is member/0 
(meaning member at visibility level 0).

The destination role in the team is specified with the --role flag. If not provided, the default
role is member/0.

Note that this command does not work with teams and users that are homed on different 
hosts, since the admin running the command does not have open permission to view parties 
on other hosts.

See `+"`foks help roles`"+` for more information on roles -- how they work and how 
to specify them for CLI commands.
`, 0),
		Example: `
# Add to team acme at the admin level: (1) bob (source role is owner);
# and (2) the member/0 members of human-resources team; and (2) the 
# admins of the legal team.
foks team add acme --role=admin \
   bob t:human-resources/member t:legal/admin

# Add the members of the human-resources team at visibility level -8
# and above to the acme team at the member/-4 level.
foks team add acme --role=member/-4 t:human-resources/member/-8`,
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
	cmd.Flags().StringVarP(&roleStr, "role", "r", "", "destination role in the team (default=member/0)")
	top.AddCommand(cmd)
}

func teamChangeRoles(m libclient.MetaContext, top *cobra.Command) {
	cmd := &cobra.Command{
		Use:     "change-roles <team> <change1> <change2> ...",
		Aliases: nil,
		Short:   "change the roles of a set of users in a team",
		Long: libterm.MustRewrapSense(`Change the roles of a set of users in a team; or remove them if applicable.

Role changes are of the form: <party>[/<src-role>]→<new-role>. Party is specified as usual, in
<party>[@<host>] form. If no host is specified, then the current host is used. The 
role modifying the party is the *source role* of the party and is only needed to disambugiate
if the party is a member of the team multiple times. The new role is the new destination role
in the team, after the change. Use "n" or "none" to remove a party from the team.

See `+"`foks help roles`"+` for more information on roles -- how they work and how
to specify them for CLI commands.

Note that for this command, it's possible to use a two-character arrow ("->") instead of the 
unicode arrow ("→"), but on most shells, it must be written "-\>" to avoid being interpreted as 
an output redirection.`, 0),
		Example: `
# for team acme:
foks team change-roles acme alice/m→o   # change alice's role to owner
foks team change-roles acme alice→o     # change alice's role to owner
foks team change-roles acme t:hr→n      # remove team hr from acme

# Change alice and bob at the same time. Change alice to 
# member at visibility level 0. Remove remote user bob.
foks team change-roles acme alice/m/-4→m/0 bob@foks.mydomain.com→n`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) < 2 {
				return ArgsError("expect two or more arguments -- team and change(s)")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}

			var changes []lcl.RoleChange
			for _, s := range arg[1:] {
				rc, err := core.ParseRoleChangeString(lcl.RoleChangeString(s))
				if err != nil {
					return err
				}
				changes = append(changes, *rc)
			}

			return quickStartLambda(m, &teamOpts, func(cli lcl.TeamClient) error {
				err := cli.TeamChangeRoles(m.Ctx(), lcl.TeamChangeRolesArg{
					Team:    *fqt,
					Changes: changes,
				})
				if err != nil {
					return err
				}
				err = PartingConsoleMessage(m)
				if err != nil {
					return err
				}
				return nil
			})
		},
	}
	top.AddCommand(cmd)
}

func teamAdmit(m libclient.MetaContext, top *cobra.Command) {
	cmd := &cobra.Command{
		Use:     "admit <team> <rsvp1[/role1]> <rsvp2[/role2]> ...",
		Aliases: nil,
		Short:   "admit a party to a team",
		Long: libterm.MustRewrapSense(`Admit a party into a team. Specify
first the team, and then a series of RSVP x role pairs, where the role is 
optional. Get RSVP strings from the output of 'foks team inbox'; they should
correspond to users and/or teams who have accepted an invitation into the team.
For each, you can optionally specify the destination role they will have in the team.
If no role is spcified, the default is member/0 (meaning member at visibility level 0).

Here are some examples:`, 0) +
			`
# admit RSVP u1Lx6dV7HX48ezh47UqcIc as member/0
foks team admit my-team u1Lx6dV7HX48ezh47UqcIc 

# admit RSVP u1Qjei39jEv9ejKEem943j as member/-4
# admit RSVP u19ejeKeoome983KELqee as admin
foks team admit my-team u1Qjei39jEv9ejKEem943j/m/-4 u19ejeKeoome983KELqee/a
`,
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
			return subcommandHelp(cmd, arg)
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
		Use:   "team",
		Short: "team management commands",
		Long: libterm.MustRewrapSense(`Team management commands.
Create teams, change memberships, etc.

In FOKS, there are two strategies for adding users to teams, depending
on whether the host is an open-view host or not. On an open-view host,
admins can directly add users or teams to a team, as long as they
are on the same host. This is because the admin has the ability to
view those parties' sigchains without needing their permission.

On a closed host, or on an open-view host when interacting with remote parties,
the invitation sequence has three phases:

1. The admin creates an invite for the team via 'foks team invite'. This
operations yields an invititation code, which is about 100 characters long.
The admin can then share this code via email, chat, or any other 
means available. It can be used multiple times.

2. The target party 'accepts' the invite via 'foks team accept'. By accepting
the invite, the target party allows the team admin to view their sigchain.
Once they have accepted, they should use the same communication channel
used in step 1 to inform the admin.

3. The admin then 'admits' the party to the team. Here there are two
commands involved: (a) 'foks team inbox' to list the pending join requests;
and (b) 'foks team admit' to admit the party to the team. When admitting
a party into the team, the admin can specify the role of the party in the team.

For more information, see the variaous help articles on these individual
commands.`, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
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
	teamChangeRoles(m, top)
	top.AddCommand(teamIndexRangeCmd(m))
	return top
}

func init() {
	AddCmd(teamCmd)
}
