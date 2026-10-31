package cmd

import (
	"errors"
	"fmt"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
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
	Long: `Stores a credential: the value goes straight to your webhook, never through
Token Vault.

--for <agent> then grants it to that agent (created if missing). Append =<uses>
to choose what the grant is for, as in ` + "`tvault grant`" + `: --for my-agent=tools or
--for my-agent=value,tools:github. Plain --for <agent> grants the value.

--mcp <preset> then attaches that MCP server preset to the credential (see
` + "`tvault mcp-servers templates`" + `), so agents granted "tools" can call it. If
attaching fails the value stays stored and the retry command is printed.`,
	Example: `  printf %s "$SECRET" | tvault add stripe
  tvault add stripe --for my-agent --yes   # store, then grant to my-agent (created if missing)
  printf %s "$PAT" | tvault add github --mcp github --for my-agent=tools --yes`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Forward the positional service into the underlying create handler
		// via its --service flag. runTokensCreate already reads --type and
		// --value off the same FlagSet.
		_ = cmd.Flags().Set("service", args[0])
		forFlag, _ := cmd.Flags().GetString("for")
		mcpPreset, _ := cmd.Flags().GetString("mcp")
		if forFlag == "" && mcpPreset == "" {
			return runTokensCreate(cmd, nil)
		}
		agentRef, grantArg := splitForFlag(forFlag, args[0])
		var specs []api.GrantSpec
		if forFlag != "" {
			spec, err := parseGrantSpec(grantArg, "add")
			if err != nil {
				return err
			}
			specs = []api.GrantSpec{spec}
		}
		yes, _ := cmd.Flags().GetBool("yes")
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		// Settle the agent and the preset before asking for the secret, so a
		// refused agent or a typo'd preset never costs the user a typed value.
		var agent resolved
		if forFlag != "" {
			if agent, err = ensureAgent(cmd, cc, agentRef, "add", yes); err != nil {
				return enrich(cmd, cc, err)
			}
		}
		var tpl *api.MCPTemplate
		if mcpPreset != "" {
			if tpl, err = presetByID(cc, mcpPreset, "add"); err != nil {
				return enrich(cmd, cc, err)
			}
		}
		if err := runTokensCreate(cmd, nil); err != nil {
			return err
		}
		if tpl != nil {
			if err := attachMCPPreset(cmd, cc, args[0], tpl); err != nil {
				if forFlag != "" {
					var ce *clierr.CLIError
					if errors.As(err, &ce) {
						ce.Hint += fmt.Sprintf(", then: tvault grant %s %s", agentRef, grantArg)
					}
				}
				return enrich(cmd, cc, err)
			}
		}
		if err := grantSpecs(cmd, cc, agent, specs, "add"); err != nil {
			return enrich(cmd, cc, err)
		}
		return nil
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
	Use:               "grant <agent> <service>[=<uses>[:<server>,...]] [...]",
	Short:             "Grant an agent access to one or more services (shortcut for `tvault ag gr add`)",
	Long:              grantsAddCmd.Long,
	Example:           grantsAddCmd.Example,
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completeAgentThenServices,
	RunE:              grantsAddCmd.RunE,
}

func init() {
	// Add inherits the same flag surface as `tokens create`.
	addCmd.Flags().String("type", "", "token type (defaults to PlainText)")
	addCmd.Flags().String("service", "", "")
	_ = addCmd.Flags().MarkHidden("service")
	addValueFlags(addCmd, "credential value")
	addCmd.Flags().String("for", "", "after storing, grant the credential to this agent (name or id); created if missing. <agent>=<uses>[:<server>,...] grants tools and/or value, e.g. my-agent=tools")
	addCmd.Flags().String("mcp", "", "after storing, attach this MCP server preset to the credential (see `tvault mcp-servers templates`)")
	addCmd.Flags().Bool("yes", false, "with --for: create the agent without asking if it does not exist")

	addValueFlags(setShortCmd, "new credential value")
	rmShortCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	getShortCmd.Flags().Bool("check", false, "exit 0 if the token has a value, 6 if empty; never prints the secret")

	// `tvault list` already exists in list.go — give it an `ls` alias too.
	listCmd.Aliases = append(listCmd.Aliases, "ls")

	rootCmd.AddCommand(getShortCmd, setShortCmd, showShortCmd, rmShortCmd, addCmd, useCmd, grantCmd)
}
