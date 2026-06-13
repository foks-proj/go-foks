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
		quickRTOpts{SupportReadRole: true, SupportWriteRole: true},
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

func rtSend(m libclient.MetaContext, top *cobra.Command) {
	var ch string
	quickRTCmd(
		m, top,
		"send", []string{"s"},
		"send a message to a channel",
		"send a basic text message to a team channel; the message is the single positional argument",
		quickRTOpts{},
		func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&ch, "channel", "", "channel name (default channel if empty)")
		},
		func(args []string, cfg lcl.RTConfig, cli lcl.RealTimeClient) error {
			if cfg.Team == nil {
				return ArgsError("must provide a --team for chat stage 1a")
			}
			if len(args) != 1 {
				return ArgsError("must provide exactly one message argument (quote it)")
			}
			err := cfg.Channel.ParseFrom(ch)
			if err != nil {
				return err
			}
			seq, err := cli.ClientRTSend(m.Ctx(),
				lcl.ClientRTSendArg{
					Cfg:  cfg,
					Body: []byte(args[0]),
				},
			)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, seq)
			}
			m.G().UIs().Terminal.Printf("sent message #%d\n", seq)
			return nil
		},
	)
}

func rtRead(m libclient.MetaContext, top *cobra.Command) {
	var ch string
	var num uint
	var before uint64
	quickRTCmd(
		m, top,
		"read", []string{"thread", "get-thread", "r"},
		"read a page of messages from a channel",
		"fetch and decrypt a page of messages from a team channel, resolving sender "+
			"names. By default reads the most recent page; use --before to page back "+
			"through older messages.",
		quickRTOpts{},
		func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&ch, "channel", "", "channel name (default channel if empty)")
			cmd.Flags().UintVarP(&num, "num", "n", 0, "max number of messages in the page (0 = default)")
			cmd.Flags().Uint64Var(&before, "before", 0, "page messages older than this seq # (0 = most recent)")
		},
		func(args []string, cfg lcl.RTConfig, cli lcl.RealTimeClient) error {
			if cfg.Team == nil {
				return ArgsError("must provide a --team")
			}
			err := cfg.Channel.ParseFrom(ch)
			if err != nil {
				return err
			}
			thread, err := cli.ClientRTGetThread(m.Ctx(),
				lcl.ClientRTGetThreadArg{
					Cfg:    cfg,
					Num:    uint64(num),
					Before: proto.RTMsgSeq(before),
				},
			)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, thread)
			}
			return outputRTThread(m, thread)
		},
	)
}

// outputRTThread prints a thread oldest-first (the page comes back newest-first,
// so we iterate in reverse for chronological reading order) and, unless we've
// reached the start of the thread, prints how to page back to the previous page.
func outputRTThread(m libclient.MetaContext, thread lcl.RTThreadView) error {
	t := m.G().UIs().Terminal
	for i := len(thread.Msgs) - 1; i >= 0; i-- {
		msg := thread.Msgs[i]
		sender := "<system>"
		switch {
		case msg.SenderName != nil:
			sender = string(*msg.SenderName)
		case msg.Sender != nil:
			if s, err := msg.Sender.StringErr(); err == nil {
				sender = s
			}
		}
		when := msg.SentAtTime.Import().Local().Format("2006-01-02 15:04:05")
		t.Printf("#%d  %s  %s\n      %s\n", msg.Seq, when, sender, string(msg.Body))
	}
	switch {
	case thread.AtBeginning:
		t.Printf("(beginning of thread)\n")
	case len(thread.Msgs) > 0:
		// Oldest message in this page is the last one printed; page back from it.
		oldest := thread.Msgs[len(thread.Msgs)-1].Seq
		t.Printf("(older messages above; rerun with --before %d)\n", oldest)
	}
	return nil
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
	rtSend(m, top)
	rtRead(m, top)
	return top
}

func init() {
	AddCmd(rtCmd)
}
