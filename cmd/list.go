package cmd

import "github.com/spf13/cobra"

// listCmd is a top-level shortcut for `tvault tokens list` — tokens are the
// primary resource, so `tvault list` lists them.
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens (shortcut for `tvault tokens list`)",
	Args:  cobra.NoArgs,
	RunE:  runTokensList,
}

func init() { rootCmd.AddCommand(listCmd) }
