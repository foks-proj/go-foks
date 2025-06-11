// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libterm"
	"github.com/spf13/cobra"
)

var templateFuncs = template.FuncMap{
	"trim":                    strings.TrimSpace,
	"trimRightSpace":          trimRightSpace,
	"trimTrailingWhitespaces": trimRightSpace,
	"rpad":                    rpad,
	"gt":                      Gt,
	"eq":                      Eq,
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// rpad adds padding to the right of a string.
func rpad(s string, padding int) string {
	formattedString := fmt.Sprintf("%%-%ds", padding)
	return fmt.Sprintf(formattedString, s)
}

// tmpl executes the given template text on data, writing the result to w.
func Tmpl(w io.Writer, text string, data interface{}) error {
	t := template.New("top")
	t.Funcs(templateFuncs)
	template.Must(t.Parse(text))
	return t.Execute(w, data)
}

func Gt(a interface{}, b interface{}) bool {
	var left, right int64
	av := reflect.ValueOf(a)

	switch av.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		left = int64(av.Len())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		left = av.Int()
	case reflect.String:
		left, _ = strconv.ParseInt(av.String(), 10, 64)
	}

	bv := reflect.ValueOf(b)

	switch bv.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		right = int64(bv.Len())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		right = bv.Int()
	case reflect.String:
		right, _ = strconv.ParseInt(bv.String(), 10, 64)
	}

	return left > right
}

// FIXME Eq is unused by cobra and should be removed in a version 2. It exists only for compatibility with users of cobra.

// Eq takes two types and checks whether they are equal. Supported types are int and string. Unsupported types will panic.
func Eq(a interface{}, b interface{}) bool {
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)

	switch av.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		panic("Eq called on unsupported type")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return av.Int() == bv.Int()
	case reflect.String:
		return av.String() == bv.String()
	}
	return false
}

func ConfigureHelp(
	m libclient.MetaContext,
	cmd *cobra.Command,
) {
	var showGlobal bool

	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	cmd.PersistentFlags().BoolVar(&showGlobal, "show-global", false, "show global flags help")

	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {

		type helpData struct {
			*cobra.Command
			ShowGlobal          bool
			ShowFlags           bool
			EducateGlobalInSub  bool
			EducateGlobalInRoot bool
			UsageString         string
		}
		hd := helpData{
			Command:             c,
			ShowFlags:           showGlobal || c.HasParent(),
			ShowGlobal:          showGlobal && c.HasParent(),
			EducateGlobalInSub:  !showGlobal && c.HasParent(),
			EducateGlobalInRoot: !showGlobal && !c.HasParent(),
		}
		usage := `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if (and .HasAvailableLocalFlags .ShowFlags)}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{else}}{{if .EducateGlobalInRoot}}

Flags: 
  --show-global   Show verbose help for global flags
{{end}}{{end}}{{if (and .HasAvailableInheritedFlags .ShowGlobal)}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{else}}{{if .EducateGlobalInSub}}

  (global flags shown with the --show-global flag)
{{end}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
		var usageBuf bytes.Buffer
		_ = Tmpl(&usageBuf, usage, hd)

		hd.UsageString = usageBuf.String()

		help := `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

		_ = Tmpl(c.OutOrStdout(), help, hd)
	})
}

func helpRoles(m libclient.MetaContext) *cobra.Command {
	return &cobra.Command{
		Use:   "roles",
		Short: "Help about how roles work in FOKS",
		Long: libterm.MustRewrapSense(`
There are four roles in FOKS. From most privileged to least: owner, admin,
member, and none. First consider roles in the context of a team. The user that
creates a team starts as its sole owner. Owners have the ability to later delete
the team. Every team must have at least one owner at any given time. Owners also
have admin privileges. Admins have the ability to add and remove members from
the teams. Members get the abiilty to decrypt data encrypted for the team's
encryption keys, but otherwise have no team modification privileges.  And the
special role "none" is used to indicate removal of a member from a team.

Each non-none level has its own set of encryption and signing keys. The owner
gets access to all keys, from owner on down. Admins get access to all admin
and member keys. And members just get access to member keys.

Within the member role, there can be further stratification, known as "visibility 
level." The default member has visibility level 0, but other members can have 
visibilty levels up to 32,767 and as low as -32,768. A member with visibiilty level
n can see the keys for all visibility levels m, where m <= n. And admins and
owners can see keys with member roles at all visibilty levels.

In the FOKS CLI, roles can be specified with their full names -- "owner", "admin"
or "member" -- or with their first letter, "o", "a", or "m". To specify a visibility
level, use the "/" delimiter. For example, "m/1", "m/-200", and "m" are all valid
visibility levels, and "m" is equivalent to "m/0".

Some commands like `+"`foks team add`"+` need to specify a team member along
with a role. The "/" delimiter is used here as well. For example, "bob/a",
"alice/o", and "charlie/m/1" are all valid user+role combinations.

Roles also can be applied to the concept of a user. By default, user keys
are at the "owner" level. Meaning, they can add new keys, or revoke existing
keys. In the future, we are leaving room open to have lesser-privileged user
keys. One can imagine an "m/3" user key that might be used to encrypt and decrypt
data but not to make changes to the user's set of keys and devices. We so far
have not implemented this, so it's currently safe to assume that all user keys
are at the owner level.
`, 0),
	}
}

func init() {
	AddCmd(helpRoles)
}
