package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
)

// defaultKeyExpiry is applied when `keys create` is run without --expires.
// A forgotten flag should never mint an immortal key.
const defaultKeyExpiry = "90d"

// parseExpiry turns an --expires value into the API's expiresAt: nil for
// "never", otherwise an RFC 3339 UTC timestamp. Accepted forms are "never",
// a day count like 30d / 90d / 365d, or a calendar date YYYY-MM-DD (expires
// at the end of that day, UTC).
func parseExpiry(s string, now time.Time) (*string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	bad := func() error {
		return &clierr.CLIError{Kind: clierr.KindUser,
			Message: fmt.Sprintf("invalid --expires %q — use 30d, 90d, 365d, YYYY-MM-DD, or never", s)}
	}
	var at time.Time
	switch {
	case s == "never":
		return nil, nil
	case strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return nil, bad()
		}
		at = now.UTC().AddDate(0, 0, n)
	default:
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			return nil, bad()
		}
		at = d.Add(24*time.Hour - time.Second)
		if !at.After(now) {
			return nil, &clierr.CLIError{Kind: clierr.KindUser,
				Message: fmt.Sprintf("--expires %s is in the past", s)}
		}
	}
	out := at.UTC().Format(time.RFC3339)
	return &out, nil
}

// resolveKeyRef accepts a key ID or name and returns the ID. IDs win; a name
// that matches exactly one key is resolved via ListKeys; anything else passes
// through unchanged so the server produces the not-found error.
func resolveKeyRef(client *api.Client, ref string) (string, error) {
	keys, err := client.ListKeys()
	if err != nil {
		return "", err
	}
	var byName []string
	for _, k := range keys {
		if k.ID == ref {
			return ref, nil
		}
		if k.Name == ref {
			byName = append(byName, k.ID)
		}
	}
	switch len(byName) {
	case 0:
		return ref, nil
	case 1:
		return byName[0], nil
	default:
		return "", &clierr.CLIError{Kind: clierr.KindUser,
			Message: fmt.Sprintf("%d keys are named %q — use the key ID (tvault keys ls)", len(byName), ref)}
	}
}

var keysCmd = &cobra.Command{
	Use:     "keys",
	Aliases: []string{"key"},
	Short:   "Manage scoped API keys (tvkey_*)",
	Long: `Scoped keys are API keys limited to an explicit list of scopes, with an
optional expiry. The key secret is printed once, on stdout; everything else
goes to stderr, so KEY=$(tvault keys create ...) captures only the secret.`,
}

var keysCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a scoped key (the secret is printed once, to stdout)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		scopes, _ := cmd.Flags().GetStringSlice("scopes")
		expires, _ := cmd.Flags().GetString("expires")
		if name == "" {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "keys create", Message: "--name is required"}
		}
		if len(scopes) == 0 {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "keys create",
				Message: "--scopes is required (comma-separated, e.g. credentials:read,tokens:list)"}
		}
		expiresAt, err := parseExpiry(expires, time.Now())
		if err != nil {
			return enrichCmd(cmd, err)
		}
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		res, err := cc.Client.CreateKey(name, scopes, expiresAt)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if res.Key == "" { // --dry-run: nothing was sent, so no secret exists
			return nil
		}
		cmd.PrintErrf("Created key %q (id %s).\n", res.Name, res.ID)
		cmd.PrintErrf("  scopes : %s\n", strings.Join(res.Scopes, ","))
		cmd.PrintErrf("  expires: %s\n", expiryLabel(res.ExpiresAt))
		cmd.PrintErrln("Key (shown once — store it now):")
		// stdout: scripts capture KEY=$(tvault keys create ...).
		fmt.Println(res.Key)
		return nil
	},
}

var keysListCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List scoped keys",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		keys, err := cc.Client.ListKeys()
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(keys) == 0 {
			cmd.PrintErrln("No keys. Create one with `tvault keys create`.")
			return nil
		}
		rows := make([]map[string]string, len(keys))
		for i, k := range keys {
			last := "never"
			if k.LastUsedAt != nil && *k.LastUsedAt != "" {
				last = *k.LastUsedAt
			}
			rows[i] = map[string]string{
				"id": k.ID, "name": k.Name, "status": k.Status,
				"scopes":  strings.Join(k.Scopes, ","),
				"expires": expiryLabel(k.ExpiresAt),
				"created": k.CreatedAt, "last_used": last,
				"created_by": k.CreatedBy.Type + ":" + k.CreatedBy.ID,
			}
		}
		return output.Render(os.Stdout, cc.Format,
			[]string{"id", "name", "status", "scopes", "expires", "last_used"}, rows)
	},
}

var keysRotateCmd = &cobra.Command{
	Use:   "rotate <id-or-name> | --self",
	Short: "Rotate a key (the new secret is printed once, to stdout)",
	Long: `Rotate a key. Rotating another key needs a signed-in human; any key can
rotate itself with --self, which also switches the active context to the new key.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		self, _ := cmd.Flags().GetBool("self")
		if self == (len(args) == 1) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "keys rotate", Message: "pass either a key id/name or --self"}
		}
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		var id string
		if self {
			id, err = selfPrincipalID(cc, "key", "keys rotate")
		} else {
			id, err = resolveKeyRef(cc.Client, args[0])
		}
		if err != nil {
			return enrich(cmd, cc, err)
		}
		res, err := cc.Client.RotateKey(id)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if res.Key == "" { // --dry-run
			return nil
		}
		cmd.PrintErrf("Rotated key %s — the old secret no longer works.\n", res.ID)
		if self {
			if err := storeRotatedKey(cc, res.Key); err != nil {
				fmt.Println(res.Key)
				return err
			}
			cmd.PrintErrf("Context %q now uses the new key.\n", cc.ContextName)
		}
		cmd.PrintErrln("New key (shown once — store it now):")
		fmt.Println(res.Key)
		return nil
	},
}

var keysRevokeCmd = &cobra.Command{
	Use:     "revoke <id-or-name>",
	Aliases: []string{"rm"},
	Short:   "Permanently revoke a key",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		force, _ := cmd.Flags().GetBool("force")
		yes = yes || force
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		if !confirmDestructive(cmd, cc, "revoke key", args, yes) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "keys revoke", Message: "aborted — pass --force to confirm"}
		}
		id, err := resolveKeyRef(cc.Client, args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if err := cc.Client.RevokeKey(id); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Revoked key %s.\n", id)
		return nil
	},
}

var keysShowCmd = &cobra.Command{
	Use:     "show <id-or-name>",
	Aliases: []string{"info"},
	Short:   "Show a key's details and grants",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		id, err := resolveKeyRef(cc.Client, args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		k, err := cc.Client.GetKey(id)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		last := "never"
		if k.LastUsedAt != nil && *k.LastUsedAt != "" {
			last = *k.LastUsedAt
		}
		grants := make([]string, len(k.Grants))
		for i, g := range k.Grants {
			grants[i] = g.ServiceName
			if g.Source != "" {
				grants[i] += " (" + g.Source + ")"
			}
			if g.GrantExpiresAt != nil && *g.GrantExpiresAt != "" {
				grants[i] += " until " + *g.GrantExpiresAt
			}
		}
		rows := []map[string]string{{
			"id": k.ID, "name": k.Name, "status": k.Status,
			"scopes":  strings.Join(k.Scopes, ","),
			"expires": expiryLabel(k.ExpiresAt), "last_used": last,
			"created_by": k.CreatedBy.Type + ":" + k.CreatedBy.ID,
			"grants":     strings.Join(grants, ", "),
		}}
		return output.Render(os.Stdout, cc.Format,
			[]string{"id", "name", "status", "scopes", "expires", "last_used", "created_by", "grants"}, rows)
	},
}

var keysGrantCmd = &cobra.Command{
	Use:   "grant <key> <service>",
	Short: "Grant a service to a key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		hours, _ := cmd.Flags().GetInt("expires-in-hours")
		if hours < 0 {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "keys grant", Message: "--expires-in-hours must be positive"}
		}
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		id, err := resolveKeyRef(cc.Client, args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		res, err := cc.Client.GrantKey(id, args[1], hours)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		msg := fmt.Sprintf("Granted %q to key %s", args[1], id)
		if res.GrantExpiresAt != nil && *res.GrantExpiresAt != "" {
			msg += " until " + *res.GrantExpiresAt
		}
		cmd.PrintErrln(msg + ".")
		return nil
	},
}

var keysUngrantCmd = &cobra.Command{
	Use:   "ungrant <key> <service>",
	Short: "Remove a service grant from a key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		id, err := resolveKeyRef(cc.Client, args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if err := cc.Client.UngrantKey(id, args[1]); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Removed grant %q from key %s.\n", args[1], id)
		return nil
	},
}

// enrichCmd fills in the command path on a CLIError raised before a context
// was resolved (flag validation).
func enrichCmd(cmd *cobra.Command, err error) error {
	return enrich(cmd, nil, err)
}

func init() {
	keysCreateCmd.Flags().String("name", "", "key name (required)")
	keysCreateCmd.Flags().StringSlice("scopes", nil, "comma-separated scopes, e.g. credentials:read,tokens:list (required)")
	keysCreateCmd.Flags().String("expires", defaultKeyExpiry, "expiry: 30d | 90d | 365d | YYYY-MM-DD | never")
	keysRotateCmd.Flags().Bool("self", false, "rotate the key this context is logged in with, and switch the context to the new key")
	keysRevokeCmd.Flags().Bool("force", false, "skip the confirmation prompt (required in a non-interactive shell)")
	keysRevokeCmd.Flags().BoolP("yes", "y", false, "alias for --force")

	keysGrantCmd.Flags().Int("expires-in-hours", 0, "expire the grant after N hours (default: no grant expiry)")

	keysCmd.AddCommand(keysCreateCmd, keysListCmd, keysShowCmd, keysGrantCmd, keysUngrantCmd, keysRotateCmd, keysRevokeCmd)
	rootCmd.AddCommand(keysCmd)
}
