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
		What: "A policy rejected the request (exit code 13; 7 when a policy's rate limit answers with 429). The CLI says which rule (rate limit, allowed hours, lifetime cap, country, IP allowlist or channel), which policy, and what it is attached to (an agent, key, credential or label). Your own login sees all of that; an agent or key sees the policy name and, when it clears by itself, how long to wait, plus an event id to look up.",
		Fix:  "Detach or loosen the policy: `tvault policy detach <policy-id> --label <label>` (or --credential, --agent, --key), or edit it in the web app. From an agent or key, ask the owner to look up the event id in Activity.",
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
		What: "An access channel policy restricts who can read this token, and this change could widen that (a grant, a folder change, a proxy, a key hand-over, or loosening the policy). Only the web app may do that; the CLI, agents and API keys may not.",
		Fix:  "Make the change in the web app. The policy names the channels that may read the token.",
	},
	"GRANT_EXPIRED": {
		What: "The agent's grant for this service has expired and was removed (exit code 14).",
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
		What: "This key or agent has no grant for that service (exit code 14).",
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
		What: "A grant's uses must be \"value\" and/or \"mcp\", and mcp needs a credential with at least one MCP server.",
		Fix:  "Attach a server first (`tvault mcp-servers add <service> --preset <id>`), then `tvault grant <agent> <service>=mcp`.",
	},
	"INVALID_GRANT_SERVERS": {
		What: "A grant names MCP servers that the credential does not have, or names servers without MCP access.",
		Fix:  "Check the names with `tvault mcp-servers ls <service>`; the syntax is <service>=mcp:<server>,<server>.",
	},
	"GRANT_USES_EXCEEDED": {
		What: "A key or agent can only pass on a grant no wider than its own, and the uses requested are not covered by the grant it holds (a value grant cannot be passed on as MCP access).",
		Fix:  "Request only uses the acting principal holds, or have a person make the grant.",
	},
	"GRANT_SERVERS_EXCEEDED": {
		What: "A key or agent can only pass on MCP servers its own grant covers, and none of the requested servers are covered.",
		Fix:  "Name servers within the acting principal's own grant, or have a person make the grant.",
	},
	"GRANT_TOOLS_ONLY": {
		What: "The acting key or agent holds only MCP access to this credential, which does not allow reading the value or changing its MCP servers.",
		Fix:  "Have a person make the change, or give the principal a value grant.",
	},
	"SIGNIN_NO_VALUE": {
		What: "A Token Vault sign-in credential has no value, so there is nothing to read, rotate, store or connect through OAuth (exit code 6).",
		Fix:  "Agents use it through its MCP server: `tvault grant <agent> <name>=mcp`. To change where it signs in, edit its MCP server with `tvault mcp-servers add <name> --name <mcp-server> --url <url> --header 'Authorization: Bearer ${AGENT_SESSION}'`.",
	},
	"SIGNIN_TOOLS_ONLY": {
		What: "A Token Vault sign-in credential can only be granted MCP access, to an agent. It has no value to hand out, and a key cannot hold it.",
		Fix:  "Grant MCP access only: `tvault grant <agent> <name>=mcp` (or `tvault add <name> --sign-in <url> --for <agent>=mcp`).",
	},
	"SIGNIN_URL_ON_TOKEN_VAULT": {
		What: "The URL of a Token Vault sign-in MCP server must be a different service. It cannot point back at Token Vault itself.",
		Fix:  "Use the https URL of your own MCP server: `tvault add <name> --sign-in https://mcp.example.com/mcp`.",
	},
	"USE_SIGNIN_ROUTE": {
		What: "The request tried to create a Token Vault sign-in credential through the ordinary add route, which only stores credentials with a value.",
		Fix:  "Create it with `tvault add <name> --sign-in <url>`.",
	},
	"SIGNIN_SESSION_REFUSED": {
		What: "Token Vault refused to issue the agent a sign-in pass for this MCP server: the agent is suspended, expired or gone, its MCP access is switched off, or the MCP server entry is no longer valid.",
		Fix:  "Resume the agent (`tvault agents resume <agent>`), check its access (`tvault grant <agent> <name>=mcp`), and check the MCP server with `tvault mcp-servers ls <name>`.",
	},
	"SIGNIN_SESSION_UNAVAILABLE": {
		What: "Token Vault could not issue a sign-in pass just now: the account is locked, or Token Vault could not read its lock state.",
		Fix:  "If you locked the account, unlock it in the web app. Otherwise retry after the Retry-After delay.",
	},
	"MCP_KEY_RETIRED": {
		What: "This old app key (an mcp_ key for an old MCP connection) has been switched off. Old app keys stopped working 90 days after the connection was converted.",
		Fix:  "Point the app at the MCP server's own URL, /api/mcp/<name>/<mcp-server> (see `tvault mcp-servers ls <name>`), and sign in as the agent. Old connection URLs keep working with an agent sign-in.",
	},
	"PROXY_CREATE_REMOVED": {
		What: "You can no longer create old-style MCP connections (proxies).",
		Fix:  "Attach an MCP server to a credential instead: `tvault mcp-servers add <name> --preset <id>`, or `tvault add <name> --sign-in <url>` for an MCP server that signs the agent in itself.",
	},
	"PROXY_FROZEN": {
		What: "This old MCP connection was converted to an MCP server and is frozen: it can be suspended or deleted but no longer edited.",
		Fix:  "Change the MCP server it became: `tvault mcp-servers ls <name>` and `tvault mcp-servers add <name> ...`.",
	},
	"PROXY_GROUPS_REMOVED": {
		What: "Old MCP connection groups (proxy groups) can no longer be created or changed.",
		Fix:  "Use labels to organise credentials and their MCP servers: `tvault label --help`.",
	},
	"MCP_TOGGLE_REMOVED": {
		What: "There is no per-agent MCP switch any more, so it cannot be turned off. (An agent that still carries an old off-switch can be cleared with `tvault agents mcp-on <agent>`.)",
		Fix:  "Remove the agent's MCP grant (`tvault ag gr rm <agent> <name>`) or suspend the agent (`tvault agents suspend <agent>`).",
	},
	"SCOPE_RETIRED": {
		What: "That scope is retired and can no longer be given to a new key or agent. Keys that already hold it keep it, to delete or suspend old MCP connections.",
		Fix:  "Create the key without it: `tvault keys create --scopes mcp:use,...`. Use `mcp:use` for MCP servers.",
	},
	"WEBHOOK_AUTH_FAILED": {
		What: "The webhook rejected Token Vault's HMAC authentication.",
		Fix:  "The HMAC secret is out of sync — re-run the vault webhook setup to rotate it.",
	},
	"MCP_SERVER_NAME_INVALID": {
		What: "An MCP server name is not allowed: it must be 1-32 lowercase letters, digits, '-' or '_', starting with a letter or digit.",
		Fix:  "Pick another name: `tvault mcp-servers add <service> --name <name> ...`.",
	},
	"MCP_SERVER_NAME_DUPLICATE": {
		What: "Two MCP servers on the same credential share a name; names are unique within a credential.",
		Fix:  "Use a different --name, or remove the existing server first: `tvault mcp-servers ls <service>`, then `tvault mcp-servers rm <service> <name>`.",
	},
	"MCP_SERVER_CREDENTIAL_TYPE_UNSUPPORTED": {
		What: "MCP servers can only be attached to PlainText or JWT credentials, because ${TOKEN} substitution needs a single-value credential. SSH keys, certificates and other structured types are refused.",
		Fix:  "Attach the server to a PlainText or JWT credential instead (`tvault tokens show <service>` shows the type).",
	},
	"MCP_SERVER_HEADER_INVALID": {
		What: "A header on the MCP server is refused: a bad header name, control characters in a value, or the wrong placeholder for the credential. A stored credential uses ${TOKEN} (not ${AGENT_SESSION}); a Token Vault sign-in credential uses ${AGENT_SESSION} (not ${TOKEN}) and cannot set certain headers.",
		Fix:  "Fix the --header value, for example --header 'Authorization: Bearer ${TOKEN}' in single quotes so your shell does not expand it.",
	},
	"MCP_SERVER_INVALID": {
		What: "The MCP server definition is malformed; typically the template id is not a short slug such as 'github'.",
		Fix:  "Use a preset id from `tvault mcp-servers templates` with --preset, or drop --preset and give --name, --url and --header.",
	},
	"UPSTREAM_REDIRECT_BLOCKED": {
		What: "The MCP server answered with a redirect to another address. Your webhook does not carry the credential there, and Token Vault does not pass the redirect on.",
		Fix:  "Set the MCP server's URL to its final address (in the web app, or `tvault mcp-servers rm` then `add` from an admin context).",
	},
	"AUTO_GRANT_CANNOT_SET_SERVERS": {
		What: "This key or agent can read the credential only through an automatic grant that lapses with the token, so it may not attach MCP servers (they would outlive the grant and point the next owner's credential at its URL).",
		Fix:  "Ask a person to attach the servers, or have the key's owner grant the credential explicitly first.",
	},
	"TOKEN_EXISTS": {
		What: "`tvault add` named a credential that already exists. Nothing was replaced: add only ever creates.",
		Fix:  "To replace the value, rotate it: `tvault set <service>`. To start again, remove it first (`tvault rm <service>`) or pick another name.",
	},
	"NAME_TAKEN": {
		What: "A credential with that name already exists, so a Token Vault sign-in credential (or a converted one) cannot take it.",
		Fix:  "Pick another name, or remove the existing credential first (`tvault rm <service>`).",
	},
	"INVALID_LABELS": {
		What: "A label is not allowed: labels are lowercase letters, digits and '-', 1-32 characters, at most 10 per object.",
		Fix:  "Fix the label: `tvault label set <credential|agent|key> <id> <label>...`.",
	},
	"INVALID_ENTITY_TYPE": {
		What: "Labels can only be set on a credential, an agent or an API key.",
		Fix:  "Use one of `credential`, `agent` or `key` as the first argument of `tvault label`.",
	},
	"SIGNIN_SERVER_NOT_AGGREGATED": {
		What: "A Token Vault sign-in credential's MCP server is reached only through its own URL, never through the combined tool list.",
		Fix:  "Register the server's own entry: `tvault connect <agent> <service>=mcp --server <service>/<server>`, and use that entry in your MCP client.",
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
