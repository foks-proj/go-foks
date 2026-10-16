// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"strconv"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

var socialInviteOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

// fetch needs no account: the invitee reads the invitation before signing up.
var socialInviteGuestOpts = agent.StartupOpts{}

func printSocialInviteMsgs(m libclient.MetaContext, msgs []lcl.SocialInviteLocalMsg) error {
	for _, msg := range msgs {
		who := strings.ToLower(proto.SocialInvitePartyRevMap[msg.Sender])
		m.G().UIs().Terminal.Printf("  #%d %s: %s\n", msg.Seq, who, msg.Text)
		if msg.User != nil {
			s, err := msg.User.StringErr()
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("     user: %s\n", s)
		}
	}
	return nil
}

func socialInviteCreate(m libclient.MetaContext, top *cobra.Command) {
	var expire time.Duration
	cmd := &cobra.Command{
		Use:   "create <team> <message>",
		Short: "invite someone into a team",
		Long: libterm.MustRewrapSense(`Invite someone into a team, whether or not they
already have an account on this host.

Prints a seed. Send it, with this host's name, to the invitee over a channel
that is already end-to-end encrypted: anyone holding the seed can read the
exchange and answer it. The message is the opening turn the invitee reads.`, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 2 {
				return ArgsError("expected two arguments -- the team and the message")
			}
			fqt, err := core.ParseFQTeam(proto.FQTeamString(arg[0]))
			if err != nil {
				return err
			}
			var etime proto.Time
			if expire > 0 {
				etime = proto.ExportTime(time.Now().Add(expire))
			}
			return quickStartLambda(m, &socialInviteOpts, func(cli lcl.SocialInviteClient) error {
				res, err := cli.SocialInviteCreate(m.Ctx(), lcl.SocialInviteCreateArg{
					Team:  *fqt,
					Text:  arg[1],
					Etime: etime,
				})
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("Seed: %s\nID:   %s\n",
					core.ExportSocialInviteSeed(res.Seed), core.ExportSocialInviteID(res.Id))
				return nil
			})
		},
	}
	cmd.Flags().DurationVar(&expire, "expire", 0,
		"how long the invitation stays open (default: the host's maximum)")
	top.AddCommand(cmd)
}

func socialInviteList(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"list", []string{"ls"},
		"list the invitations you created, with their exchanges", "",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			return quickStartLambda(m, &socialInviteOpts, func(cli lcl.SocialInviteClient) error {
				res, err := cli.SocialInviteList(m.Ctx())
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				for _, row := range res {
					m.G().UIs().Terminal.Printf("%s %s (seed %s)\n",
						core.ExportSocialInviteID(row.Id),
						proto.SocialInviteStateRevMap[row.State],
						core.ExportSocialInviteSeed(row.Seed),
					)
					err = printSocialInviteMsgs(m, row.Msgs)
					if err != nil {
						return err
					}
				}
				return nil
			})
		},
	)
}

func socialInviteFetch(m libclient.MetaContext, top *cobra.Command) {
	var host string
	cmd := &cobra.Command{
		Use:          "fetch <seed>",
		Short:        "read an invitation; needs no account",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the seed")
			}
			seed, err := core.ImportSocialInviteSeed(arg[0])
			if err != nil {
				return err
			}
			return quickStartLambda(m, &socialInviteGuestOpts, func(cli lcl.SocialInviteClient) error {
				res, err := cli.SocialInviteFetch(m.Ctx(), lcl.SocialInviteFetchArg{
					Host: proto.TCPAddr(host),
					Seed: *seed,
				})
				if err != nil {
					return err
				}
				if m.G().Cfg().JSONOutput() {
					return JSONOutput(m, res)
				}
				m.G().UIs().Terminal.Printf("%s\n", proto.SocialInviteStateRevMap[res.State])
				return printSocialInviteMsgs(m, res.Msgs)
			})
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the host holding the invitation (default: the configured probe host)")
	top.AddCommand(cmd)
}

func socialInviteReply(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"reply <seed> <turn> <message>", nil,
		"answer an invitation as the current user",
		libterm.MustRewrapSense(`Answer the inviter's turn <turn> (its sequence number, as
shown by 'foks social-invite fetch') as the current user.

If the invitation names a team, this first grants that team permission to
view your user: on a closed-view host that is what lets the inviter add you.`, 0),
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 3 {
				return ArgsError("expected three arguments -- the seed, the turn, and the message")
			}
			seed, err := core.ImportSocialInviteSeed(arg[0])
			if err != nil {
				return err
			}
			turn, err := strconv.ParseUint(arg[1], 10, 64)
			if err != nil {
				return ArgsError("turn must be a sequence number")
			}
			return quickStartLambda(m, &socialInviteOpts, func(cli lcl.SocialInviteClient) error {
				return cli.SocialInviteReply(m.Ctx(), lcl.SocialInviteReplyArg{
					Seed:      *seed,
					InReplyTo: turn,
					Text:      arg[2],
				})
			})
		},
	)
}

func socialInviteAskAgain(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"ask-again <seed> <message>", nil,
		"ask the invitee for a different answer", "",
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 2 {
				return ArgsError("expected two arguments -- the seed and the message")
			}
			seed, err := core.ImportSocialInviteSeed(arg[0])
			if err != nil {
				return err
			}
			return quickStartLambda(m, &socialInviteOpts, func(cli lcl.SocialInviteClient) error {
				return cli.SocialInviteAskAgain(m.Ctx(), lcl.SocialInviteAskAgainArg{
					Seed: *seed,
					Text: arg[1],
				})
			})
		},
	)
}

func socialInviteClose(m libclient.MetaContext, top *cobra.Command) {
	quickCmd(m, top,
		"close <id> <accepted|declined|canceled>", nil,
		"record the decision on an invitation",
		libterm.MustRewrapSense(`Record the decision on an invitation. Accepting is
bookkeeping: add the invitee to the team first (by the user ID in their reply,
with 'foks team add'), then close the invitation as accepted.`, 0),
		func(cmd *cobra.Command, arg []string) error {
			if len(arg) != 2 {
				return ArgsError("expected two arguments -- the invitation ID and the decision")
			}
			id, err := core.ImportSocialInviteID(arg[0])
			if err != nil {
				return err
			}
			var st proto.SocialInviteState
			switch arg[1] {
			case "accepted":
				st = proto.SocialInviteState_Accepted
			case "declined":
				st = proto.SocialInviteState_Declined
			case "canceled":
				st = proto.SocialInviteState_Canceled
			default:
				return ArgsError("decision must be accepted, declined or canceled")
			}
			return quickStartLambda(m, &socialInviteOpts, func(cli lcl.SocialInviteClient) error {
				return cli.SocialInviteClose(m.Ctx(), lcl.SocialInviteCloseArg{Id: *id, St: st})
			})
		},
	)
}

func socialInviteCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:   "social-invite",
		Short: "invite people into a team, signing them up if needed",
		Long: libterm.MustRewrapSense(`Invite people into a team, whether or not they already
have an account (docs/social_signup_spec.md).

The inviter creates an invitation and sends its seed out of band. The invitee
reads it with 'fetch', signs up if needed, and answers with 'reply'. The
inviter reads answers with 'list', adds the invitee with 'foks team add', and
records the decision with 'close', or asks again with 'ask-again'.`, 0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return subcommandHelp(cmd, arg)
		},
	}
	socialInviteCreate(m, top)
	socialInviteList(m, top)
	socialInviteFetch(m, top)
	socialInviteReply(m, top)
	socialInviteAskAgain(m, top)
	socialInviteClose(m, top)
	return top
}

func init() {
	AddCmd(socialInviteCmd)
}
