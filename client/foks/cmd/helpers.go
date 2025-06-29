package cmd

import "github.com/spf13/cobra"

func subcommandHelp(cmd *cobra.Command, arg []string) error {
	if len(arg) == 0 || (len(arg) == 1 && arg[0] == "help") {
		return cmd.Help()
	}
	_ = cmd.Help()
	return BadSubCommandError(arg[0])
}
