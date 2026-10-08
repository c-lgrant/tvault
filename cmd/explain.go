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
	"SCOPE_DENIED": {
		What: "The API key is valid but lacks a scope this operation requires (exit code 8). The error names the missing scope.",
		Fix:  "Create or rotate a key that includes the scope: `tvault keys create --scopes <scope>,...`.",
	},
	"HUMAN_ONLY": {
		What: "This operation is reserved for a signed-in human and cannot be done with an API key (exit code 9).",
		Fix:  "Run `tvault login` (browser) and use the admin context: `tvault ctx use <admin-ctx>`.",
	},
	"KEY_EXPIRED": {
		What: "The API key is past its expiry (exit code 10).",
		Fix:  "An expired key can't rotate itself (--self is refused too). Rotate it from an admin context (`tvault keys rotate <id>` / `tvault agents rotate-key <agent>`) or log in with a new key.",
	},
	"AGENT_INACTIVE": {
		What: "The agent is suspended and refused until it is resumed (exit code 11).",
		Fix:  "Resume it from an admin context: `tvault agents resume <agent>`.",
	},
	"KEY_SUSPENDED": {
		What: "The API key is suspended and refused until it is resumed (exit code 11).",
		Fix:  "Ask the key's owner to resume it, or use a different key.",
	},
	"INVALID_KEY": {
		What: "The API key is unknown, malformed, or already revoked (exit code 12).",
		Fix:  "Check the key value; log in with a valid one: `printf %s \"$TVAULT_KEY\" | tvault login --key-stdin --as <name>`.",
	},
	"NOT_OWNER": {
		What: "Only the owner of this key or agent may perform this action.",
		Fix:  "Switch to the owning account/context (`tvault ctx use <ctx>`).",
	},
	"GRANT_REQUIRED": {
		What: "A principal can only hand out access it already holds, and it lacks the grant it tried to pass on.",
		Fix:  "Grant the service to the acting principal first (`tvault keys grant <key> <service>`), then retry.",
	},
	"NO_GRANT": {
		What: "This key or agent has no grant for that service.",
		Fix:  "Ask the owner to grant it: `tvault grant <agent> <service>` or `tvault keys grant <key> <service>`.",
	},
	"SCOPE_NOT_DELEGABLE": {
		What: "Only a signed-in human can give this scope to a key or agent (keys:manage, keys:revoke, agents:manage, agents:delete, policies:write, grants:write, tokens:update, tokens:delete, proxies:write).",
		Fix:  "Create or edit the key/agent from the console, or from an admin context (`tvault ctx use <admin-ctx>`).",
	},
	"AUTO_GRANT_IN_PLACE": {
		What: "The target holds a grant that came from tokens:create-read; a regular grant can't silently replace it.",
		Fix:  "Remove the target's grant first, then grant again, or have a human replace it.",
	},
	"MANUAL_GRANT_IN_PLACE": {
		What: "The target holds a regular grant; a key or agent can't replace it with a copy of its tokens:create-read grant.",
		Fix:  "Leave the existing grant in place, or have a human replace it.",
	},
	"SELF_CHANGE_FORBIDDEN": {
		What: "A key or agent can't loosen its own controls: its own scopes, MCP switch, status, grants, or the policies attached to it.",
		Fix:  "Make the change from the console or an admin context. A key may still rotate itself (`--self`), suspend itself, or add a policy to itself.",
	},
	"ROTATION_CONFLICT": {
		What: "Two rotations of the same key ran at once and this one lost; no new key was issued by it.",
		Fix:  "Use the key the winning rotation returned, or rotate again.",
	},
	"UNKNOWN_SCOPE": {
		What: "A requested scope name is not recognised.",
		Fix:  "Use scopes from the README's Keys section, e.g. credentials:read,tokens:list.",
	},
	"INVALID_EXPIRY": {
		What: "The requested expiry is malformed or not in the future.",
		Fix:  "Use --expires 30d|90d|365d|YYYY-MM-DD|never.",
	},
	"REAUTH_REQUIRED": {
		What: "Creating a key as a human needs a fresh browser sign-in (exit code 2).",
		Fix:  "Run `tvault login` again, then retry the command.",
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
