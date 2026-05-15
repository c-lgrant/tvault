package cmd

import (
	"sort"
	"strings"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
)

var errorExplanations = map[string]struct {
	What string
	Fix  string
}{
	"VAULT_LOCKED": {
		What: "The vault is locked, so all mutating operations are blocked.",
		Fix:  "Run `tvault vault unlock` (admin only). Agents must wait for the owner to unlock.",
	},
	"POLICY_DENIED": {
		What: "An ABAC policy attached to this entity rejected the request.",
		Fix:  "Inspect the policy named in the error footer; the request must satisfy every rule.",
	},
	"GRANT_EXPIRED": {
		What: "The agent's grant for this service has expired and was removed.",
		Fix:  "Have an admin re-grant access: `tvault ag gr add <agent> <service>`.",
	},
	"DECRYPTION_FAILED": {
		What: "The stored token could not be decrypted — the vault key does not match.",
		Fix:  "Re-save the credential under the current vault key: `tvault tk set <service>`.",
	},
	"STORAGE_ERROR": {
		What: "The vault's storage backend failed while retrieving the token.",
		Fix:  "Transient — retry. If it persists, check the storage backend (Firestore/webhook) health.",
	},
	"TOKEN_EMPTY": {
		What: "The token exists but has no credential data, or was not found in the vault.",
		Fix:  "Re-save the credential with `tvault tk set <service>`.",
	},
	"TOKEN_ERROR": {
		What: "The proxy failed to retrieve a token for the upstream request.",
		Fix:  "Confirm the token exists (`tvault tk show <service>`) and the vault is unlocked.",
	},
	"WEBHOOK_NOT_CONFIGURED": {
		What: "The vault is in webhook mode but no webhook URL is configured.",
		Fix:  "Set the webhook URL in vault settings before storing or proxying tokens.",
	},
	"WEBHOOK_UNAVAILABLE": {
		What: "Token Vault could not reach the user's webhook.",
		Fix:  "Check that the webhook service is running and reachable from Token Vault.",
	},
	"WEBHOOK_AUTH_FAILED": {
		What: "The webhook rejected Token Vault's HMAC authentication.",
		Fix:  "The HMAC secret is out of sync — re-run the vault webhook setup to rotate it.",
	},
}

var explainCmd = &cobra.Command{
	Use:   "explain <error-code>",
	Short: "Explain a Token Vault error code and how to fix it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code := strings.ToUpper(args[0])
		info, ok := errorExplanations[code]
		if !ok {
			known := make([]string, 0, len(errorExplanations))
			for k := range errorExplanations {
				known = append(known, k)
			}
			sort.Strings(known)
			return &clierr.CLIError{
				Kind:    clierr.KindUser,
				Command: "explain",
				Message: "unknown error code " + code + " — known codes: " + strings.Join(known, ", "),
			}
		}
		cmd.Printf("%s\n\n  what: %s\n  fix : %s\n", code, info.What, info.Fix)
		return nil
	},
}

func init() { rootCmd.AddCommand(explainCmd) }
