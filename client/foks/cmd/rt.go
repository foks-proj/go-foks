package cmd

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type quickRTOpts struct {
	SupportReadRole  bool
	SupportWriteRole bool
	NoSupportTeam    bool
}

func quickRTCmd(
	m libclient.MetaContext,
	top *cobra.Command,
	name string,
	aliases []string,
	short string,
	long string,
	opts quickRTOpts,
	setup func(*cobra.Command),
	fn func([]string, lcl.RTConfig, lcl.RealTimeClient) error,
) {
	if long == "" {
		long = short
	}
	var teamStr string
	var rrs, wrs string
	var rr, wr *proto.Role
	run := func(cmd *cobra.Command, arg []string) error {
		var fqt *proto.FQTeamParsed
		if teamStr != "" {
			var err error
			fqt, err = core.ParseFQTeam(proto.FQTeamString(teamStr))
			if err != nil {
				return err
			}
		}
		if opts.SupportReadRole && rrs != "" {
			var err error
			rs := proto.RoleString(rrs)
			rr, err = rs.Parse()
			if err != nil {
				return err
			}
		}
		if opts.SupportWriteRole && wrs != "" {
			var err error
			rs := proto.RoleString(wrs)
			wr, err = rs.Parse()
			if err != nil {
				return err
			}
		}
		cfg := lcl.RTConfig{
			Team:  fqt,
			Roles: proto.RolePairOpt{Read: rr, Write: wr},
			AppID: proto.RTAppID_Chat,
		}
		return quickStartLambda(m, &kvOpts, func(cli lcl.RealTimeClient) error {
			err := fn(arg, cfg, cli)
			if err != nil {
				return err
			}
			return PartingConsoleMessage(m)
		})
	}

	cmd := &cobra.Command{
		Use:          name,
		Aliases:      aliases,
		Short:        short,
		Long:         long,
		SilenceUsage: true,
		RunE:         run,
	}
	if !opts.NoSupportTeam {
		actAsTeamOpt(cmd, &teamStr)
	}
	if opts.SupportReadRole {
		cmd.Flags().StringVarP(&rrs, "read-role", "r", "", "read role to create as (default depends on subcommand)")
	}
	if opts.SupportWriteRole {
		cmd.Flags().StringVarP(&wrs, "write-role", "w", "", "write role to create as (default depends on subcommand)")
	}
	if setup != nil {
		setup(cmd)
	}
	top.AddCommand(cmd)
}

func rtNewChannel(m libclient.MetaContext, top *cobra.Command) {
	var desc, nm string
	quickRTCmd(
		m, top,
		"new-channel", []string{"new"},
		"create a new channel",
		"create a new channel for a team or DM-style ad-hoc team",
		quickRTOpts{},
		func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&desc, "description", "", "channel description")
			cmd.Flags().StringVar(&nm, "name", "", "channel name")
		},
		func(args []string, cfg lcl.RTConfig, cli lcl.RealTimeClient) error {
			if cfg.Team == nil {
				return ArgsError("must provide a --team for chat stage 1a")
			}
			err := cfg.Channel.ParseFrom(nm)
			if err != nil {
				return err
			}
			var cd proto.RTChannelDesc
			err = cd.ParseFrom(desc)
			if err != nil {
				return err
			}
			if !cd.IsEmpty() && cfg.Channel.IsEmpty() {
				return ArgsError("can only specify a description if not the default channel")
			}
			ret, err := cli.ClientRTMakeChannel(m.Ctx(),
				lcl.ClientRTMakeChannelArg{
					Cfg:  cfg,
					Desc: cd,
				},
			)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, ret)
			}
			cid, err := ret.RTID().StringErr()
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("ChannelID: %s\n", cid)
			return PartingConsoleMessage(m)
		},
	)
}

func rtListChannels(m libclient.MetaContext, top *cobra.Command) {
	quickRTCmd(
		m, top,
		"list-channels", []string{"ls-channels", "channels"},
		"list the channels in a team",
		"list the channels in a team, sorted by channel class and name",
		quickRTOpts{},
		nil,
		func(args []string, cfg lcl.RTConfig, cli lcl.RealTimeClient) error {
			if cfg.Team == nil {
				return ArgsError("must provide a --team")
			}
			ret, err := cli.ClientRTListChannelsForTeam(m.Ctx(), cfg)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, ret)
			}
			return outputRTChannelListTable(m, outputTableOpts{headers: true}, ret)
		},
	)
}

func rtCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:     "rt",
		Aliases: []string{"real-time", "chat"},
		Short:   "real-time/chat commands",
		Long:    "real-time service for chat, notifications, etc; simple CLI interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			return subcommandHelp(cmd, args)
		},
	}
	rtNewChannel(m, top)
	rtListChannels(m, top)
	return top
}

func init() {
	AddCmd(rtCmd)
}
