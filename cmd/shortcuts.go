package cmd

import (
	"github.com/spf13/cobra"
)

// Top-level shortcut verbs. Tokens are the primary resource, so the most
// common token operations get a flat verb at the root level — `tvault get
// SVC` instead of `tvault tokens get SVC`. Each shortcut delegates to the
// same RunE as its `tokens …` sibling.

var getShortCmd = &cobra.Command{
	Use:               "get <service>",
	Short:             "Print a credential value (shortcut for `tvault tokens get`)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensGet,
}

var setShortCmd = &cobra.Command{
	Use:               "set <service>",
	Short:             "Rotate a credential value (shortcut for `tvault tokens set`)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensSet,
}

var showShortCmd = &cobra.Command{
	Use:               "show <service>",
	Short:             "Show token metadata (shortcut for `tvault tokens show`)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensShow,
}

var rmShortCmd = &cobra.Command{
	Use:               "rm <service> [<service>...]",
	Short:             "Delete tokens (shortcut for `tvault tokens rm`)",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensRm,
}

// addCmd lifts the most common create form — name + value — to a positional
// shortcut: `tvault add SVC --value SECRET`. Defaults --type to PlainText
// (matches the wizard's default). For non-PlainText (SSHKey, JWT, …), users
// can pass --type explicitly or fall back to the full wizard.
var addCmd = &cobra.Command{
	Use:   "add <service>",
	Short: "Create a token (shortcut for `tvault tokens create`)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Forward the positional service into the underlying create handler
		// via its --service flag. runTokensCreate already reads --type and
		// --value off the same FlagSet.
		_ = cmd.Flags().Set("service", args[0])
		return runTokensCreate(cmd, nil)
	},
}

// useCmd is a top-level shortcut for `tvault ctx use <name>`.
var useCmd = &cobra.Command{
	Use:               "use <name>",
	Short:             "Switch the active context (shortcut for `tvault ctx use`)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeContexts,
	RunE:              contextUseCmd.RunE,
}

// grantCmd is a top-level shortcut for `tvault agents grants add <agent> <svc>`.
// Resolves agent by name or ID, then delegates to AddGrants.
var grantCmd = &cobra.Command{
	Use:               "grant <agent> <service> [<service>...]",
	Short:             "Grant an agent access to one or more services (shortcut for `tvault ag gr add`)",
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completeAgentThenServices,
	RunE:              grantsAddCmd.RunE,
}

func init() {
	// Add inherits the same flag surface as `tokens create`.
	addCmd.Flags().String("type", "", "token type (defaults to PlainText)")
	addCmd.Flags().String("service", "", "")
	_ = addCmd.Flags().MarkHidden("service")
	addCmd.Flags().String("value", "", "credential value")

	setShortCmd.Flags().String("value", "", "new credential value")
	rmShortCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	getShortCmd.Flags().Bool("check", false, "exit 0 if the token has a value, 6 if empty; never prints the secret")

	// `tvault list` already exists in list.go — give it an `ls` alias too.
	listCmd.Aliases = append(listCmd.Aliases, "ls")

	rootCmd.AddCommand(getShortCmd, setShortCmd, showShortCmd, rmShortCmd, addCmd, useCmd, grantCmd)
}
