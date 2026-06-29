package cmd

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

func adhocCreate(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"create <user1>,<user2>,...", []string{"mk", "new"},
		"create a new adhoc team",
		"create a new adhoc team, specifying the other members of the team",
		func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return ArgsError("expected one or more other users")
			}
			members := core.Map(
				args,
				func(s string) lcl.FQPartyParsedAndRole {
					return lcl.FQPartyParsedAndRole{
						Role: &proto.OwnerRole,
						Fqp: proto.FQPartyParsed{
							Party: proto.NewParsedPartyWithTrue(
								proto.PartyName{
									Name:   proto.NameUtf8(s),
									IsTeam: false,
								},
							),
						},
					}
				},
			)
			return quickStartLambda(
				m,
				&teamOpts,
				func(cli lcl.TeamClient) error {
					res, err := cli.TeamCreateAdHoc(m.Ctx(), members)
					if err != nil {
						return err
					}
					return handleCreateRes(m, res)
				},
			)
		},
	)
}

func adhocCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:   "adhoc",
		Short: "commands for managing adhoc teams",
		Long: libterm.MustRewrapSense(`Adhoc team management commands.
Create adhoc teams, list memberships, etc.

Adhoc teams do not have names, and they do not allow membership changes.
They map to "DM"s in chat systems, where the group members might split 
into small breakouts. 

Adhoc teams can be addressed by participant list. So "alice,bob,charlie"
might name such a team (for other command families like kv and rt).

Eventually adhoc teams might allow for more rich combinations of teams
and users, local or remote, or users are different source roles. But for now, 
we're going to keep things simple and say that adhoc teams are lists of 
local users at the owner source role.
`, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	adhocCreate(m, top)
	return top
}

func init() {
	AddCmd(adhocCmd)
}
