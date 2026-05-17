package cmd

import (
	"os"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/c-lgrant/tvault/internal/tui"
	"github.com/spf13/cobra"
)

var tokensCmd = &cobra.Command{
	Use:     "tokens",
	Aliases: []string{"tk"},
	Short:   "Manage credentials",
}

var tokensListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List tokens",
	Args:    cobra.NoArgs,
	RunE:    runTokensList,
}

// runTokensList renders the token list. It backs both `tvault tokens list` and
// the top-level `tvault list` shortcut.
func runTokensList(cmd *cobra.Command, _ []string) error {
	cc, err := resolve(cmd, false)
	if err != nil {
		return err
	}
	toks, err := cc.Client.ListTokens()
	if err != nil {
		return enrich(cmd, cc, err)
	}
	if len(toks) == 0 {
		cmd.PrintErrln("No tokens. Create one with `tvault tk new`.")
		return nil
	}
	rows := make([]map[string]string, len(toks))
	for i, t := range toks {
		rows[i] = map[string]string{
			"service": t.ServiceName, "type": t.Type,
		}
	}
	return output.Render(os.Stdout, cc.Format,
		[]string{"service", "type"}, rows)
}

var tokensGetCmd = &cobra.Command{
	Use:               "get <service>",
	Short:             "Print a credential value (stdout only — safe for $(...))",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, false)
		if err != nil {
			return err
		}
		val, err := cc.Client.GetTokenValue(args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.Println(val)
		return nil
	},
}

var tokensShowCmd = &cobra.Command{
	Use:               "show <service>",
	Aliases:           []string{"info"},
	Short:             "Show token metadata (no secret)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, false)
		if err != nil {
			return err
		}
		t, err := cc.Client.GetToken(args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		rows := []map[string]string{{
			"service": t.ServiceName, "type": t.Type,
			"display_name": t.DisplayName, "notes": t.Notes,
			"tags": strings.Join(t.Tags, ","),
		}}
		return output.Render(os.Stdout, cc.Format,
			[]string{"service", "type", "display_name", "notes", "tags"}, rows)
	},
}

var tokensSetCmd = &cobra.Command{
	Use:               "set <service>",
	Aliases:           []string{"up"},
	Short:             "Rotate a credential value",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		value, _ := cmd.Flags().GetString("value")
		if value == "" {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens set", Message: "--value is required"}
		}
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if err := cc.Client.SetTokenValue(args[0], value); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Updated credential for %q.\n", args[0])
		return nil
	},
}

var tokensEditCmd = &cobra.Command{
	Use:               "edit <service>",
	Short:             "Edit token metadata (display name, notes, tags) — no secret",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		var md api.TokenMetadata
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			md.DisplayName = &v
		}
		if cmd.Flags().Changed("notes") {
			v, _ := cmd.Flags().GetString("notes")
			md.Notes = &v
		}
		if cmd.Flags().Changed("tags") {
			v, _ := cmd.Flags().GetStringSlice("tags")
			md.Tags = &v
		}
		if md.DisplayName == nil && md.Notes == nil && md.Tags == nil {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens edit", Message: "nothing to edit — pass --name, --notes, or --tags"}
		}
		if err := cc.Client.UpdateTokenMetadata(args[0], md); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Updated metadata for %q.\n", args[0])
		return nil
	},
}

var tokensRmCmd = &cobra.Command{
	Use:               "rm <service> [<service>...]",
	Aliases:           []string{"del", "d"},
	Short:             "Delete one or more tokens",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if !confirmDestructive(cmd, cc, "delete token(s)", args, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens rm", Message: "aborted"}
		}
		if err := cc.Client.DeleteTokens(args); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Deleted %d token(s).\n", len(args))
		return nil
	},
}

var tokensRefreshCmd = &cobra.Command{
	Use:               "refresh <service>",
	Aliases:           []string{"ref"},
	Short:             "Force an OAuth token refresh",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if err := cc.Client.RefreshToken_OAuth(args[0]); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Refreshed %q.\n", args[0])
		return nil
	},
}

var tokensHistoryCmd = &cobra.Command{
	Use:               "history <service>",
	Aliases:           []string{"hist"},
	ValidArgsFunction: completeServices,
	Short:             "Show a token's usage history",
	Args:              cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, false)
		if err != nil {
			return err
		}
		hist, err := cc.Client.TokenHistory(args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(hist) == 0 {
			cmd.PrintErrln("No history for this token.")
			return nil
		}
		// Audit events use camelCase keys (timestamp/eventType/source);
		// fall back to agentName for the actor when source is "agent".
		rows := make([]map[string]string, len(hist))
		for i, h := range hist {
			actor := toStr(h["source"])
			if name := toStr(h["agentName"]); name != "" {
				actor = name
			}
			rows[i] = map[string]string{
				"timestamp": toStr(h["timestamp"]),
				"event":     toStr(h["eventType"]),
				"actor":     actor,
			}
		}
		return output.Render(os.Stdout, cc.Format,
			[]string{"timestamp", "event", "actor"}, rows)
	},
}

var tokensCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a token (interactive wizard, or fully flag-driven)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}

		typ, _ := cmd.Flags().GetString("type")
		service, _ := cmd.Flags().GetString("service")
		value, _ := cmd.Flags().GetString("value")

		var req *api.CreateTokenRequest
		if typ != "" && service != "" {
			req = &api.CreateTokenRequest{Type: typ, ServiceName: service, Credential: value}
		} else {
			if !cc.IsTTY {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens create",
					Message: "non-interactive shell needs --type and --service (and --value)"}
			}
			req, err = tui.RunTokenWizard()
			if err != nil {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens create", Message: err.Error()}
			}
		}
		if err := cc.Client.CreateToken(*req); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Created token %q.\n", req.ServiceName)
		return nil
	},
}

func init() {
	tokensSetCmd.Flags().String("value", "", "new credential value")
	tokensEditCmd.Flags().String("name", "", "display name")
	tokensEditCmd.Flags().String("notes", "", "freeform notes")
	tokensEditCmd.Flags().StringSlice("tags", nil, "comma-separated tags")
	tokensRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	tokensCreateCmd.Flags().String("type", "", "token type (JWT, PlainText, Certificate, SSHKey, RawCredential, TOTP)")
	tokensCreateCmd.Flags().String("service", "", "service name")
	tokensCreateCmd.Flags().String("value", "", "credential value")

	tokensCmd.AddCommand(
		tokensListCmd, tokensGetCmd, tokensShowCmd,
		tokensSetCmd, tokensEditCmd, tokensRmCmd,
		tokensRefreshCmd, tokensHistoryCmd, tokensCreateCmd,
	)
	rootCmd.AddCommand(tokensCmd)
}
