package cmd

import (
	"fmt"
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
	RunE:              runTokensGet,
}

func runTokensGet(cmd *cobra.Command, args []string) error {
	cc, err := resolve(cmd, false)
	if err != nil {
		return err
	}
	check, _ := cmd.Flags().GetBool("check")
	val, err := cc.Client.GetTokenValue(args[0])
	if check {
		// --check / --exists: presence-only probe. Exit 0 if the token has
		// a value, 6 (KindEmpty) if it doesn't, never print the secret.
		if err == nil {
			return nil
		}
		var ce *clierr.CLIError
		if asCLIErr(err, &ce) && ce.Kind == clierr.KindEmpty {
			// Reshape: suppress the noisy stderr message but preserve the
			// exit code by returning the CLIError shell (with empty Message
			// so Execute's Fprintln writes only a newline). Callers usually
			// pipe this through `>/dev/null 2>&1`.
			return &clierr.CLIError{Kind: clierr.KindEmpty}
		}
		return enrich(cmd, cc, err)
	}
	if err != nil {
		return enrich(cmd, cc, err)
	}
	// Use os.Stdout directly: Cobra's cmd.Println writes to OutOrStderr,
	// which breaks $(tvault tokens get X) capture. The same footgun was
	// fixed for `tvault version` in be6f4fe.
	fmt.Println(val)
	return nil
}

var tokensShowCmd = &cobra.Command{
	Use:               "show <service>",
	Aliases:           []string{"info"},
	Short:             "Show token metadata (no secret)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensShow,
}

func runTokensShow(cmd *cobra.Command, args []string) error {
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
}

var tokensSetCmd = &cobra.Command{
	Use:               "set <service>",
	Aliases:           []string{"up"},
	Short:             "Rotate a credential value",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              runTokensSet,
}

func runTokensSet(cmd *cobra.Command, args []string) error {
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
	RunE:              runTokensRm,
}

func runTokensRm(cmd *cobra.Command, args []string) error {
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
	RunE:    runTokensCreate,
}

func runTokensCreate(cmd *cobra.Command, _ []string) error {
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
	} else if service != "" {
		// Service known but type missing → default to PlainText. This makes
		// `tvault add foo --value bar` work without a --type flag for the
		// most common case; explicit --type still overrides.
		req = &api.CreateTokenRequest{Type: "PlainText", ServiceName: service, Credential: value}
	} else {
		if !cc.IsTTY {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens create",
				Message: "non-interactive shell needs --service (and optional --type/--value)"}
		}
		req, err = tui.RunTokenWizard()
		if err != nil {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "tokens create", Message: err.Error()}
		}
	}
	if err := cc.Client.CreateToken(*req); err != nil {
		return enrich(cmd, cc, err)
	}
	if req.Credential == "" {
		cmd.PrintErrf("Created token %q (no value stored).\n", req.ServiceName)
		cmd.PrintErrf("  fill with: tvault tokens set %s --value <secret>\n", req.ServiceName)
	} else {
		cmd.PrintErrf("Created token %q.\n", req.ServiceName)
	}
	return nil
}

// tokensStoreTicketCmd implements webhook-mode store via the ticket flow.
// In webhook (zero-knowledge) mode the backend will not accept plaintext
// POSTs to /api/tokens. The browser dashboard uses a signed store ticket
// to push the secret directly to the user's webhook, bypassing TV. This
// subcommand makes that same flow available to scripts.
//
// With --value: full one-shot store. Without: print the ticket envelope
// as JSON for advanced workflows (e.g. piping into curl or a sibling tool).
var tokensStoreTicketCmd = &cobra.Command{
	Use:               "store-ticket <service>",
	Short:             "Store a secret directly on the webhook (webhook-mode vaults)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		value, _ := cmd.Flags().GetString("value")
		typ, _ := cmd.Flags().GetString("type")
		if typ == "" {
			typ = "PlainText"
		}

		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}

		if value == "" {
			// Print the ticket envelope so the caller can use it elsewhere.
			ticket, err := cc.Client.VaultStoreTicket(args[0])
			if err != nil {
				return enrich(cmd, cc, err)
			}
			rows := []map[string]string{{
				"service":    args[0],
				"webhookUrl": ticket.WebhookURL,
				"ticket":     ticket.Ticket,
				"expiresIn":  fmt.Sprintf("%d", ticket.ExpiresIn),
			}}
			return output.Render(os.Stdout, cc.Format,
				[]string{"service", "webhookUrl", "ticket", "expiresIn"}, rows)
		}

		if err := cc.Client.StoreTokenViaWebhook(args[0], typ, value); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Stored %q via webhook.\n", args[0])
		return nil
	},
}

func init() {
	tokensGetCmd.Flags().Bool("check", false, "exit 0 if the token has a value, 6 if empty; never prints the secret")
	tokensSetCmd.Flags().String("value", "", "new credential value")
	tokensEditCmd.Flags().String("name", "", "display name")
	tokensEditCmd.Flags().String("notes", "", "freeform notes")
	tokensEditCmd.Flags().StringSlice("tags", nil, "comma-separated tags")
	tokensRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	tokensCreateCmd.Flags().String("type", "", "token type (JWT, PlainText, Certificate, SSHKey, RawCredential, TOTP)")
	tokensCreateCmd.Flags().String("service", "", "service name")
	tokensCreateCmd.Flags().String("value", "", "credential value")
	tokensStoreTicketCmd.Flags().String("value", "", "secret to store on the webhook (omit to print ticket envelope only)")
	tokensStoreTicketCmd.Flags().String("type", "PlainText", "token type when --value is set")

	tokensCmd.AddCommand(
		tokensListCmd, tokensGetCmd, tokensShowCmd,
		tokensSetCmd, tokensEditCmd, tokensRmCmd,
		tokensRefreshCmd, tokensHistoryCmd, tokensCreateCmd,
		tokensStoreTicketCmd,
	)
	rootCmd.AddCommand(tokensCmd)
}
