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
		What: "A policy rejected the request. The CLI says which rule (rate limit, allowed hours, lifetime cap, country, IP allowlist or channel), which policy, and what it is attached to (an agent, key, credential or label). Your own login sees all of that; an agent or key sees the policy name and, when it clears by itself, how long to wait, plus an event id to look up.",
		Fix:  "Detach or loosen the policy: `tvault policy detach <policy-id> --label <label>` (or --credential, --agent, --key), or edit it in the web console. From an agent or key, ask the owner to look up the event id in Activity.",
	},
	"RATE_LIMITED": {
		What: "Token Vault's own safety limit: this caller is asking faster than allowed, or was locked out briefly after too many refusals. It is not one of your policies (exit code 7).",
		Fix:  "Wait for the retry time in the hint and slow down. It clears by itself.",
	},
	"WEBHOOK_CIRCUIT_OPEN": {
		What: "Your webhook has been failing, so Token Vault stopped calling it to avoid hammering a broken service.",
		Fix:  "Fix the webhook (`tvault webhook status`); calls resume after a successful check.",
	},
	"WEB_CONSOLE_REQUIRED": {
		What: "An access channel policy restricts who can read this token, and this change could widen that (a grant, a folder change, a proxy, a key hand-over, or loosening the policy). Only the web console may do that; the CLI, agents and API keys may not.",
		Fix:  "Make the change in the web console. The policy names the channels that may read the token.",
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
		Fix:  "Run `tvault login` again, then retry the command. (`agents create`, `add --for`, `mcp-servers add` and `connect` do this inline in an interactive admin context.)",
	},
	"MCP_SERVER_LITERAL_CREDENTIAL": {
		What: "A header whose name looks like a credential (Authorization, Cookie, X-Api-Key, anything with key/token/secret/auth) holds a literal value. Token Vault never stores a credential, so such a header may hold only the placeholder ${TOKEN}.",
		Fix:  "Use --header 'Authorization: Bearer ${TOKEN}' (single quotes, so your shell does not expand it). Your webhook substitutes the credential.",
	},
	"MCP_SERVER_HEADERS_REQUIRED": {
		What: "None of the server's headers contains ${TOKEN}, so the credential would not be sent to the upstream.",
		Fix:  "Add a header such as --header 'Authorization: Bearer ${TOKEN}', or start from a preset: `tvault mcp-servers add <service> --preset <id>`.",
	},
	"SERVICE_NOT_HOSTABLE": {
		What: "The credential's name is part of its MCP server URL, so it must be made of letters, digits and . _ ~ - and start with a letter or digit.",
		Fix:  "Rename the credential (store it under a plain name), then attach the server. Removing servers is always allowed.",
	},
	"MCP_SERVERS_CAP": {
		What: "A credential can have at most five MCP servers.",
		Fix:  "Remove one first: `tvault mcp-servers rm <service> <name>`.",
	},
	"INVALID_GRANT_USES": {
		What: "A grant's uses must be \"value\" and/or \"tools\", and tools needs a credential with at least one MCP server.",
		Fix:  "Attach a server first (`tvault mcp-servers add <service> --preset <id>`), then `tvault grant <agent> <service>=tools`.",
	},
	"INVALID_GRANT_SERVERS": {
		What: "A grant names MCP servers that the credential does not have, or names servers without the tools use.",
		Fix:  "Check the names with `tvault mcp-servers ls <service>`; the syntax is <service>=tools:<server>,<server>.",
	},
	"GRANT_USES_EXCEEDED": {
		What: "A key or agent can only pass on a grant no wider than its own, and the uses requested are not covered by the grant it holds (a value grant cannot be passed on as tools).",
		Fix:  "Request only uses the acting principal holds, or have a person make the grant.",
	},
	"GRANT_SERVERS_EXCEEDED": {
		What: "A key or agent can only pass on MCP servers its own grant covers, and none of the requested servers are covered.",
		Fix:  "Name servers within the acting principal's own grant, or have a person make the grant.",
	},
	"GRANT_TOOLS_ONLY": {
		What: "The acting key or agent holds only a tools grant on this credential, which does not allow reading the value or changing its MCP servers.",
		Fix:  "Have a person make the change, or give the principal a value grant.",
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
