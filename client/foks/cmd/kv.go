// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/foks-proj/go-foks/client/agent"
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

var kvOpts = agent.StartupOpts{
	NeedUser:         true,
	NeedUnlockedUser: true,
}

type quickKVOpts struct {
	SupportReadRole   bool
	SupportWriteRole  bool
	NoSupportMkdirP   bool
	SupportOverwrite  bool
	SupportMtimeLower bool
	SupportRecursive  bool
	NoSupportTeam     bool
}

func (q quickKVOpts) SupportsRoles() bool {
	return q.SupportReadRole || q.SupportWriteRole
}

func actAsTeamOpt(
	cmd *cobra.Command,
	teamStr *string,
) {
	cmd.Flags().StringVarP(teamStr, "team", "t", "", "team to work on behalf of (default is to operate as the logged in user)")
}

func makeKVPath(s string) proto.KVPath {
	// noop unless we are in a gitbash environment on windows
	return libclient.GitBashAbsPathInvert(proto.KVPath(s))
}

func quickKVCmd(
	m libclient.MetaContext,
	top *cobra.Command,
	name string,
	aliases []string,
	short string,
	long string,
	opts quickKVOpts,
	setup func(*cobra.Command),
	fn func([]string, lcl.KVConfig, lcl.KVClient) error,
) {
	if long == "" {
		long = short
	}
	var teamStr string
	var rrs, wrs string
	var rr, wr *proto.Role
	var mtimeStr string
	var mkdirP bool
	var force bool
	var recursive bool
	var mtime *proto.TimeMicro
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
		if opts.SupportMtimeLower && mtimeStr != "" {
			t, err := time.Parse(time.RFC3339, mtimeStr)
			if err != nil {
				return err
			}
			tmp := proto.ExportTimeMicro(t)
			mtime = &tmp
		}
		cfg := lcl.KVConfig{
			ActingAs:    fqt,
			Roles:       proto.RolePairOpt{Read: rr, Write: wr},
			MkdirP:      mkdirP,
			OverwriteOk: force,
			MtimeLower:  mtime,
			Recursive:   recursive,
		}
		return quickStartLambda(m, &kvOpts, func(cli lcl.KVClient) error {
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
	if !opts.NoSupportMkdirP {
		cmd.Flags().BoolVarP(&mkdirP, "mkdir-p", "p", false, "create parent directories if they do not exist")
	}
	if opts.SupportReadRole {
		cmd.Flags().StringVarP(&rrs, "read-role", "r", "", "read role to create as (default depends on subcommand)")
	}
	if opts.SupportWriteRole {
		cmd.Flags().StringVarP(&wrs, "write-role", "w", "", "write role to create as (default depends on subcommand)")
	}
	if opts.SupportOverwrite {
		cmd.Flags().BoolVar(&force, "force", false, "overwrite existing key-value store entry")
	}
	if opts.SupportMtimeLower {
		cmd.Flags().StringVar(&mtimeStr, "mtime-lower", "", "lower bound for modification time (RFC3339)")
	}
	if opts.SupportRecursive {
		cmd.Flags().BoolVarP(&recursive, "recursive", "R", false, "operate recursively")
	}
	if setup != nil {
		setup(cmd)
	}
	top.AddCommand(cmd)
}

func kvRest(m libclient.MetaContext, top *cobra.Command) {

	restTop := &cobra.Command{
		Use:   "rest",
		Short: "key-value store REST API commands",
		Long: libterm.MustRewrapSense(`Run a local loopback server that serves a REST API
into the key-value store.

Via options, specify a local port to bind to, an IP address to bind to,
and if desired, an authentication token to require of clients. This token
can be specified on the command line with the --auth-token flag, 
via the environment variable FOKS_KV_REST_AUTH_TOKEN, or with a file
via the --auth-token-file flag. If no token is specified, no authentication
is required.

Clients should send the "Authorization" HTTP header with the value "Basic <token>"
if using authentication.

The KV workspace exposed is dictated by the currently logged-in user,
and via the --team flag if it should act on beahlf of a team. If the
logged-in user changes, the REST loopback server will shutdown.

Rest commands are:

   GET /v0/-/path/to/a/key -- get a key-value store entry
   PUT /v0/-/path/to/a/key -- put a key-value store entry (value is in the body)
   DELETE /v0/-/path/to/a/key -- delete a key-value store entry

Specify '/v0' in all cases to version the API and to pin the API
to Version 0 (the current version). Future versions of the API
may change the semantics of the API.

The "/-" prefix is used to indicate that the path is for the current user.
You can specify a "t:<team-name>"-style identitifer to work on behalf of a team.
For instance:

   GET /v0/t:jets/mydir/file -- get a key-value store entry on behalf of team jets

For the case of GET, provide a trailing slash to get a directory listing,
and without a trailing slash, require that the key is a file. Directory
listings are returned in JSON format, with the document structure:

   { "entries" : entries, "next" : next, "parent" : parent }

The entries are a list of objects, each with the following fields:

	- name : the name of the directory entry
	- write : the write role for the entry
	- mtime : the modification time of the entry 
	    (note the ctime isn't readily available and is not currently exposed)
	- type : the entry type, one of: 'file', 'dir' or 'symlink'

The next field is pagination information, which is null if there are no 
more entries:

	next : { "dir_id" : dir_id, "pagination" : { "hmac" : hmac } }

To get the next page, issue the same GET request, but with
the "page_dir_id" and "page_hmac" query parameters set to the values
in the 'next' object. The "page_entries" query parameter can be used to
limit the number of entries returned in a single page.

For commands like PUT that do mutations, the --mkdir-p flag is assumed,
so all parent directories are created if they do not exist.
`, 0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return subcommandHelp(cmd, args)
		},
	}

	var port int
	var bindIP string
	var authToken string
	quickKVCmd(m, restTop,
		"start", nil,
		"start key-value store REST API",
		`Start a key-value store REST API server; the FOKS agent will run 
the server in the background, and this command will return immediately.`,
		quickKVOpts{
			NoSupportMkdirP: true,
			NoSupportTeam:   true,
		},
		func(cmd *cobra.Command) {
			cmd.Flags().IntVar(&port, "port", -1, "port to bind to (default 0=auto-assign random port)")
			cmd.Flags().StringVarP(&bindIP, "bind-ip", "b", "127.0.0.1", "address to bind to (default 127.0.0.1)")
			cmd.Flags().StringVar(&authToken, "auth-token", "", "authentication token to require of clients (default is no authentication)")
		},
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 0 {
				return ArgsError("expected no arguments")
			}
			err := PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			if bindIP != "" {
				ip := net.ParseIP(bindIP)
				if ip == nil {
					return ArgsError("invalid bind IP address")
				}
			}

			startArg := lcl.ClientKVRestStartArg{
				Cfg: cfg,
			}
			if port >= 0 {
				tmp := proto.Port(port)
				startArg.Port = &tmp
			}
			if bindIP != "" {
				tmp := proto.TCPAddr(bindIP)
				startArg.BindIP = &tmp
			}
			if authToken != "" {
				tmp := lcl.KVRestAuthToken(authToken)
				startArg.AuthToken = &tmp
			}
			info, err := cli.ClientKVRestStart(m.Ctx(), startArg)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, info)
			}
			m.G().UIs().Terminal.Printf("Listening...\nPort: %d\n", info.Port)
			return PartingConsoleMessage(m)
		},
	)

	quickKVCmd(m, restTop,
		"stop", nil,
		"stop key-value store REST API",
		`Stop the key-value store REST API server`,
		quickKVOpts{
			NoSupportMkdirP: true,
			NoSupportTeam:   true,
		},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			err := PartingConsoleMessage(m)
			if err != nil {
				return err
			}
			return cli.ClientKVRestStop(m.Ctx())
		},
	)

	top.AddCommand(restTop)
}

func kvCmd(m libclient.MetaContext) *cobra.Command {
	top := &cobra.Command{
		Use:          "kv",
		Short:        "key-value store commands",
		Long:         "key-value store put/get and management commands",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return subcommandHelp(cmd, args)
		},
	}
	kvMkdir(m, top)
	kvPut(m, top)
	kvGet(m, top)
	kvSymlink(m, top)
	kvMv(m, top)
	kvLs(m, top)
	kvRm(m, top)
	kvReadlink(m, top)
	kvGetUsage(m, top)
	kvRest(m, top)
	return top
}

func kvReadlink(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"readlink", nil,
		"read a key-value store symlink",
		"Read a key-value store symlink",
		quickKVOpts{},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the key-value store symlink")
			}
			path := makeKVPath(arg[0])
			res, err := cli.ClientKVReadlink(m.Ctx(), lcl.ClientKVReadlinkArg{
				Cfg:  cfg,
				Path: path,
			})
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, res)
			}
			m.G().UIs().Terminal.Printf("%s\n", res)
			return PartingConsoleMessage(m)
		},
	)
}

func kvMv(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"mv", []string{"move", "rename"},
		"move a key-value store entry",
		"Move a key-value store entry",
		quickKVOpts{SupportWriteRole: true, SupportReadRole: true},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 2 {
				return ArgsError("expected exactly 2 arguments -- the source and the destination")
			}
			src := makeKVPath(arg[0])
			dst := makeKVPath(arg[1])
			err := cli.ClientKVMv(m.Ctx(), lcl.ClientKVMvArg{
				Cfg: cfg,
				Src: src,
				Dst: dst,
			})
			if err != nil {
				return err
			}
			return PartingConsoleMessage(m)
		},
	)
}

func kvGetUsage(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"get-usage", []string{"du"},
		"get key-value store usage",
		"Get key-value store usage",
		quickKVOpts{},
		nil,
		func(args []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(args) != 0 {
				return ArgsError("expected no arguments")
			}
			res, err := cli.ClientKVUsage(m.Ctx(), cfg)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, res)
			}
			m.G().UIs().Terminal.Printf(
				"Num Files: %d\n"+
					"Total Size: %d\n",
				res.Small.Num+res.Large.Base.Num,
				res.Small.Sum+res.Large.Base.Sum,
			)
			return PartingConsoleMessage(m)
		},
	)
}

func kvRm(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"rm <key1> <key2> ....",
		[]string{"remove", "unlink", "delete"},
		"remove a key-value store entry",
		"Remove a key-value store entry; supply -r to remove directories",
		quickKVOpts{
			SupportReadRole:  true,
			SupportWriteRole: true,
			SupportRecursive: true,
		},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) < 1 {
				return ArgsError("expected at least one argument -- the key-value store entry to remove")
			}
			for _, a := range arg {
				err := cli.ClientKVRm(
					m.Ctx(),
					lcl.ClientKVRmArg{
						Cfg:  cfg,
						Path: makeKVPath(a),
					},
				)
				if err != nil {
					return err
				}
			}
			return PartingConsoleMessage(m)
		},
	)
}

func kvSymlink(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"symlink <key> <target>", []string{"ln"},
		"create a key-value store symlink",
		"Create a key-value store symlink",
		quickKVOpts{SupportWriteRole: true, SupportReadRole: true},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 2 {
				return ArgsError("expected exactly 2 arguments -- the key and the target")
			}
			path := makeKVPath(arg[0])
			target := makeKVPath(arg[1])
			res, err := cli.ClientKVSymlink(m.Ctx(), lcl.ClientKVSymlinkArg{
				Cfg:    cfg,
				Path:   path,
				Target: target,
			})
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, res)
			}
			resStr, err := res.StringErr()
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("NodeID: %s\n", resStr)
			return PartingConsoleMessage(m)
		},
	)
}

func kvGet(m libclient.MetaContext, top *cobra.Command) {
	var mode int
	var force bool
	var forceOutput bool
	quickKVCmd(m, top,
		"get <key> [<output-file>]", nil,
		"get a key-value store entry",
		libterm.MustRewrapSense(
			`Get a key-value store entry. Supply a key and an optional output file. If
no output file is given, or if the output file is '-', then the value is printed to standard output.
If standard output is a terminal, and the file is probably binary, an error is returned.
This behavior can be overridden by specifying the --force-output flag. `, 0),
		quickKVOpts{},
		func(cmd *cobra.Command) {
			cmd.Flags().IntVarP(&mode, "mode", "", -1, "file mode to use when writing to a file")
			cmd.Flags().BoolVarP(&force, "force", "", false, "overwrite existing file")
			cmd.Flags().BoolVarP(&forceOutput, "force-output", "", false, "force output to terminal even if it looks like binary data")
		},
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 2 && len(arg) != 1 {
				return ArgsError("expected 1 or 2 arguments -- the key and the file to write to (or '-' for stdout)")
			}
			out := "-"
			if len(arg) == 2 {
				out = arg[1]
			}
			if mode != -1 && (mode < 0 || mode > 0o777) {
				return ArgsError("mode must be between 0 and 0o777")
			}
			if out == "-" && mode >= 0 {
				return ArgsError("cannot specify file mode when writing to stdout")
			}
			path := makeKVPath(arg[0])
			err := kvGetWithArgs(m, cfg, cli, path, out, mode, force, forceOutput)
			if err != nil {
				return err
			}
			return PartingConsoleMessage(m)
		},
	)
}

func kvPut(m libclient.MetaContext, top *cobra.Command) {
	var isFile bool
	quickKVCmd(m, top,
		"put <key> [<value>]", nil,
		"put a key-value store entry",
		libterm.MustRewrapSense(
			`Put a key-value pair to the store. Supply a key and an option value.
If no value is given, one is read from standard input. If a value is given, it is
interpreted as a string to insert into the store, unless the --file flag is specified.
In that case, the value is interepreted as a file, whose content is read and then
stored under the given key.`,
			0,
		),
		quickKVOpts{SupportWriteRole: true, SupportReadRole: true, SupportOverwrite: true},
		func(cmd *cobra.Command) {
			cmd.Flags().BoolVarP(&isFile, "file", "f", false, "read value from file (or - if from stdin)")
		},
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 2 && len(arg) != 1 {
				return ArgsError("expected exactly 1 or 2 arguments -- the key and an optional value")
			}
			var val string
			if len(arg) == 1 {
				isFile = true
				val = "-"
			} else {
				val = arg[1]
			}
			path := makeKVPath(arg[0])
			err := kvPutWithArgs(m, cfg, cli, path, val, isFile)

			// Transform the error to a write error for better online eduction / documentation
			// for remediation (since it might seem weird that a write fails with a read error)
			err = core.ErrorAsWriteError(err)

			if err != nil {
				return err
			}
			return PartingConsoleMessage(m)
		},
	)
}

func openReader(m libclient.MetaContext, value string, isFile bool) (io.Reader, error) {
	if !isFile {
		buf := bytes.NewBufferString(value)
		return buf, nil
	}
	if value == "-" {
		return os.Stdin, nil
	}
	f, err := os.Open(value)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type terminalOutputWrapper struct {
	io.WriteCloser
	didFirst bool
}

func isProbablyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if !utf8.Valid(data) {
		return true
	}
	for _, b := range data {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			return true
		}
	}
	return false
}

type TerminalError string

func (e TerminalError) Error() string {
	return string(e)
}

func (t *terminalOutputWrapper) Write(p []byte) (n int, err error) {
	if !t.didFirst {
		t.didFirst = true
		if isProbablyBinary(p) {
			return 0, TerminalError(
				"refusing to output binary data to terminal; use --force-output to override",
			)
		}
	}
	return t.WriteCloser.Write(p)
}

var _ io.WriteCloser = (*terminalOutputWrapper)(nil)

func (t *terminalOutputWrapper) Close() error {
	return t.WriteCloser.Close()
}

func openWriter(
	m libclient.MetaContext,
	dest string,
	mode int,
	force bool,
	forceOutput bool,
) (io.WriteCloser, error) {

	if dest == "-" {
		tui := m.G().UIs().Terminal
		stdout := tui.OutputStream()
		if tui.IsOutputTTY() && !forceOutput {
			return &terminalOutputWrapper{
				WriteCloser: stdout,
				didFirst:    false,
			}, nil
		}
		return stdout, nil
	}

	if mode < 0 {
		mode = 0o600
	}
	flags := os.O_CREATE | os.O_WRONLY
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	return os.OpenFile(dest, flags, os.FileMode(mode))
}

func kvGetWithArgs(
	m libclient.MetaContext,
	cfg lcl.KVConfig,
	cli lcl.KVClient,
	path proto.KVPath,
	dest string,
	mode int,
	force bool,
	forceOutput bool,
) error {
	wrt, err := openWriter(m, dest, mode, force, forceOutput)
	if err != nil {
		return err
	}
	defer wrt.Close()

	return libkv.GetFile(
		wrt,
		func() (lcl.GetFileRes, error) {
			return cli.ClientKVGetFile(m.Ctx(), lcl.ClientKVGetFileArg{
				Cfg:  cfg,
				Path: path,
			})
		},
		func(id proto.FileID, offset proto.Offset) (lcl.GetFileChunkRes, error) {
			return cli.ClientKVGetFileChunk(m.Ctx(), lcl.ClientKVGetFileChunkArg{
				Id:     id,
				Cfg:    cfg,
				Offset: offset,
			})

		},
	)
}

func kvLs(
	m libclient.MetaContext,
	top *cobra.Command,
) {
	var optF bool // append '/' to directory names
	var optL bool // long listing format (with mtime and type)
	var optU bool // print time as unix time in milliseconds since epoch
	quickKVCmd(m, top,
		"ls <key>", []string{"list"},
		"list a key-value store directory",
		"List a key-value store directory, will come back in random order",
		quickKVOpts{
			SupportMtimeLower: true,
		},
		func(cmd *cobra.Command) {
			cmd.Flags().BoolVarP(&optF, "classify", "F", false, "append '/' to directory names")
			cmd.Flags().BoolVarP(&optL, "long", "l", false, "use long listing format (with mtime and type)")
			cmd.Flags().BoolVarP(&optU, "unix-time", "U", false, "print time as unix time in milliseconds since epoch")
		},
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the directory to list")
			}
			path := makeKVPath(arg[0])
			num := m.G().Cfg().KVListPageSize()
			keepGoing := true
			var json []lcl.KVListEntry
			var prefix proto.KVPath
			var dirID *proto.DirID
			nxt := proto.NewKVListPaginationWithNone()
			if cfg.MtimeLower != nil {
				nxt = proto.NewKVListPaginationWithTime(*cfg.MtimeLower)
			}
			for keepGoing {
				res, err := cli.ClientKVList(m.Ctx(), lcl.ClientKVListArg{
					Cfg:   cfg,
					Path:  path,
					Num:   num,
					Nxt:   nxt,
					DirID: dirID,
				})
				if err != nil {
					return err
				}
				if len(prefix) == 0 {
					prefix = res.Parent
				}
				if m.G().Cfg().JSONOutput() {
					json = append(json, res.Ents...)
				} else {
					for _, ent := range res.Ents {
						out := ent.Name.String()
						if optF && ent.Typ == proto.KVNodeType_Dir {
							out += "/"
						}
						out = prefix.String() + out
						if optL {
							var typ string
							switch ent.Typ {
							case proto.KVNodeType_File, proto.KVNodeType_SmallFile:
								typ = "f"
							case proto.KVNodeType_Dir:
								typ = "d"
							case proto.KVNodeType_Symlink:
								typ = "s"
							default:
								typ = "-"
							}
							var date string
							if optU {
								date = fmt.Sprintf("%d", ent.Mtime.Import().UnixMilli())
							} else {
								date = ent.Mtime.Import().Local().Format("2006-01-02 15:04:05")
							}
							parts := []string{typ, out, date}
							out = strings.Join(parts, "\t")
						}

						m.G().UIs().Terminal.Printf("%s\n", out)
					}
				}
				if res.Nxt != nil {
					dirID = &res.Nxt.Id
					nxt = res.Nxt.Nxt
				} else {
					keepGoing = false
				}
			}

			if len(json) != 0 {
				ret := lcl.CliKVListRes{
					Ents:   json,
					Parent: prefix,
				}
				err := JSONOutput(m, ret)
				if err != nil {
					return err
				}
				return nil
			}

			return PartingConsoleMessage(m)
		},
	)
}

func kvPutWithArgs(
	m libclient.MetaContext,
	cfg lcl.KVConfig,
	cli lcl.KVClient,
	path proto.KVPath,
	value string,
	isFile bool,
) error {
	rdr, err := openReader(m, value, isFile)
	if err != nil {
		return err
	}
	ctx := m.Ctx()
	return libkv.PutFile(
		rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			arg := lcl.ClientKVPutFirstArg{
				Cfg:   cfg,
				Path:  path,
				Chunk: data,
				Final: isFinal,
			}
			return cli.ClientKVPutFirst(ctx, arg)
		},
		func(id proto.FileID, data []byte, offset proto.Offset, final bool) error {
			arg := lcl.ClientKVPutChunkArg{
				Cfg:    cfg,
				Id:     id,
				Chunk:  data,
				Offset: offset,
				Final:  final,
			}
			return cli.ClientKVPutChunk(m.Ctx(), arg)
		},
		0,
	)
}

func kvMkdir(m libclient.MetaContext, top *cobra.Command) {
	quickKVCmd(m, top,
		"mkdir <key>", nil,
		"make a new key-value store directory",
		"Make a new key-value store directory (and parents with -p)",
		quickKVOpts{SupportReadRole: true, SupportWriteRole: true},
		nil,
		func(arg []string, cfg lcl.KVConfig, cli lcl.KVClient) error {
			if len(arg) != 1 {
				return ArgsError("expected exactly one argument -- the key-value store directory name")
			}
			path := makeKVPath(arg[0])
			res, err := cli.ClientKVMkdir(m.Ctx(), lcl.ClientKVMkdirArg{
				Cfg:  cfg,
				Path: path,
			})

			// See comment in kvPut for why we do this
			err = core.ErrorAsWriteError(err)
			if err != nil {
				return err
			}
			if m.G().Cfg().JSONOutput() {
				return JSONOutput(m, res)
			}
			did, err := res.KVNodeID().StringErr()
			if err != nil {
				return err
			}
			m.G().UIs().Terminal.Printf("DirID: %s\n", did)
			return PartingConsoleMessage(m)
		},
	)
}

func init() {
	AddCmd(kvCmd)
}
