package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

// A key or agent never adds a grant to itself. It can ask the owner for one
// (`access request`, approved on a console page) and it can drop grants it
// holds (`access drop`, no scope: that only reduces its own access).

// requestPollInterval is how often `access request --wait` checks the request.
var requestPollInterval = 5 * time.Second

// maxRequestWait caps --wait: a request expires after an hour on the server.
const maxRequestWait = time.Hour

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Ask the owner for access, or drop your own access",
	Long: `For a key or agent context. A key or agent cannot grant itself access.

  tvault access request <service>... --reason "..."   ask the owner; prints a link to approve
  tvault access plan <file|->                         ask for a list of changes (create agent, grant, ...)
  tvault access claim-key <request-id> <action-id>    collect a created agent's key, once
  tvault access status <request-id>                   check a request
  tvault access drop <service>...                     remove grants this key or agent holds`,
}

// parseGrantHours turns --expires (12h, 7d, never) into the request's
// expiresInHours; 0 means the grant never expires.
func parseGrantHours(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	bad := &clierr.CLIError{Kind: clierr.KindUser, Command: "access request",
		Message: fmt.Sprintf("invalid --expires %q: use 12h, 7d or never", safeText(s))}
	if s == "" || s == "never" {
		return 0, nil
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, bad
	}
	switch unit {
	case 'h':
		return n, nil
	case 'd':
		return n * 24, nil
	}
	return 0, bad
}

// parseRequestUses maps --uses (value, mcp) to the API's words (value, tools).
func parseRequestUses(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, u := range strings.Split(s, ",") {
		u = strings.ToLower(strings.TrimSpace(u))
		if u == "mcp" {
			u = "tools"
		}
		if u != "value" && u != "tools" {
			return nil, &clierr.CLIError{Kind: clierr.KindUser, Command: "access request",
				Message: fmt.Sprintf("invalid --uses %q: use value and/or mcp", safeText(u))}
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// splitList splits a comma-separated flag value, dropping blanks and repeats.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// requestTerms reads the services and the access asked for. A service may
// carry its uses and servers as in `tvault grant` (home-hub=mcp:otto), or the
// --uses / --servers flags set them for all services; not both. One request
// carries one set of uses and servers, so every service must ask for the same.
func requestTerms(args []string, usesFlag, serversFlag string) (services, uses, servers []string, err error) {
	user := func(msg string) error {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: "access request", Message: msg}
	}
	specs, err := parseGrantSpecs(args, "access request")
	if err != nil {
		return nil, nil, nil, err
	}
	inline := false
	for _, s := range specs {
		services = append(services, s.Service)
		inline = inline || s.Uses != nil
	}
	if inline {
		if strings.TrimSpace(usesFlag) != "" || strings.TrimSpace(serversFlag) != "" {
			return nil, nil, nil, user("give uses and servers in the name (" + grantSpecSyntax + ") or with --uses/--servers, not both")
		}
		for _, s := range specs[1:] {
			if !slices.Equal(s.Uses, specs[0].Uses) || !slices.Equal(s.Servers, specs[0].Servers) {
				return nil, nil, nil, user("every credential in one request must ask for the same uses and servers; send one request per kind of access")
			}
		}
		return services, specs[0].Uses, specs[0].Servers, nil
	}
	if uses, err = parseRequestUses(usesFlag); err != nil {
		return nil, nil, nil, err
	}
	servers = splitList(serversFlag)
	if len(servers) > 0 {
		if uses == nil {
			uses = []string{"tools"} // --servers alone asks for MCP on those servers
		} else if !slices.Contains(uses, "tools") {
			return nil, nil, nil, user("--servers needs --uses mcp: servers limit an MCP grant")
		}
	}
	return services, uses, servers, nil
}

// resolveSelf resolves the active context and refuses an admin one before any
// network call: only a key or agent asks for or drops its own grants.
func resolveSelf(cmd *cobra.Command, command string) (*cmdContext, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	ctx, name, err := cfg.ActiveContext(contextOverride(cmd))
	if err != nil {
		return nil, err
	}
	if ctx.Type != "agent" && ctx.Type != "key" {
		return nil, &clierr.CLIError{Kind: clierr.KindUser, Command: command,
			Message: command + " is for a key or agent context, but " + name + " is not one",
			Hint:    "as the owner, grant access directly: `tvault grant <agent> <service>`"}
	}
	return resolve(cmd)
}

// waitForDecision polls the request until the owner decides, it expires, or
// the wait runs out. Bounded: at most `wait`, never more than maxRequestWait.
func waitForDecision(cmd *cobra.Command, cc *cmdContext, id string, wait time.Duration) (*api.GrantRequest, error) {
	if wait > maxRequestWait {
		wait = maxRequestWait
	}
	deadline := time.Now().Add(wait)
	for {
		req, err := cc.Client.GetGrantRequest(id)
		if err != nil {
			return nil, err
		}
		if req.Status != "pending" {
			return req, nil
		}
		if !time.Now().Add(requestPollInterval).Before(deadline) {
			return req, nil
		}
		time.Sleep(requestPollInterval)
	}
}

// decisionError is nil for an approved request and a distinct exit code otherwise.
func decisionError(req *api.GrantRequest) error {
	switch req.Status {
	case "approved":
		return nil
	case "denied":
		return &clierr.CLIError{Kind: clierr.KindRequestDenied, Command: "access request",
			Message: "the owner denied request " + req.RequestID}
	case "expired":
		return &clierr.CLIError{Kind: clierr.KindRequestExpired, Command: "access request",
			Message: "request " + req.RequestID + " expired before the owner decided",
			Hint:    "send a new request"}
	default:
		return &clierr.CLIError{Kind: clierr.KindRequestExpired, Command: "access request",
			Message: "stopped waiting; request " + req.RequestID + " is still " + req.Status,
			Hint:    "check it later with `tvault access status " + req.RequestID + "`"}
	}
}

func printDecision(cmd *cobra.Command, req *api.GrantRequest) {
	switch req.Status {
	case "approved":
		if req.Kind == "changes" {
			done := 0
			for _, r := range req.Results {
				if r.Status == "done" {
					done++
				}
			}
			cmd.PrintErrf("Approved. %d of %d actions done.\n", done, len(req.Results))
			for _, r := range req.Results {
				line := fmt.Sprintf("  %s %s: %s", r.ID, r.Type, r.Status)
				if r.Message != "" {
					line += " (" + r.Message + ")"
				}
				if r.Type == "create_agent" && r.Status == "done" && r.KeyClaimedAt == "" {
					line += "; collect its key: tvault access claim-key " + req.RequestID + " " + r.ID
				}
				cmd.PrintErrln(line)
			}
			return
		}
		granted := "nothing"
		if len(req.Granted) > 0 {
			granted = strings.Join(req.Granted, ", ")
		}
		cmd.PrintErrf("Approved. Granted: %s\n", granted)
		for _, s := range req.Skipped {
			cmd.PrintErrf("  skipped %s: %s\n", s.Service, safeText(s.Reason))
		}
	case "pending":
		cmd.PrintErrf("Waiting for the owner. Expires %s.\n", req.ExpiresAt)
	default:
		cmd.PrintErrf("Request is %s.\n", req.Status)
	}
}

var accessRequestCmd = &cobra.Command{
	Use:   "request <service> [<service>...] --reason \"...\"",
	Short: "Ask the owner for access to services; prints the approval link",
	Long: `Sends a grant request for this key or agent. The link printed on stdout opens
the request in the console, where the owner approves or denies it. The link
grants nothing by itself. A request expires after one hour.

With --wait, the command waits for the decision (bounded) and exits 0 when
approved, 15 when denied, and 16 when the request expires or the wait runs out.`,
	Example: `  tvault access request openai --reason "summarise the build logs"
  tvault access request github --uses mcp --expires 7d --reason "triage issues" --wait 10m
  tvault access request home-hub=mcp:otto --reason "use the otto tools only"
  tvault access request home-hub --servers otto --reason "the same, with flags"

A service takes the same form as in tvault grant: <service>[=<uses>[:<servers>]].
MCP access with no servers named covers every server of the credential,
including servers added later. Name only credentials and MCP servers that exist (tvault list, tvault
mcp-servers list <credential>): the request is refused otherwise.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, _ := cmd.Flags().GetString("reason")
		usesFlag, _ := cmd.Flags().GetString("uses")
		expires, _ := cmd.Flags().GetString("expires")
		wait, _ := cmd.Flags().GetDuration("wait")
		if strings.TrimSpace(reason) == "" {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "access request",
				Message: "--reason is required: the owner reads it before approving"}
		}
		serversFlag, _ := cmd.Flags().GetString("servers")
		services, uses, servers, err := requestTerms(args, usesFlag, serversFlag)
		if err != nil {
			return err
		}
		hours, err := parseGrantHours(expires)
		if err != nil {
			return err
		}
		cc, err := resolveSelf(cmd, "access request")
		if err != nil {
			return err
		}
		req, err := cc.Client.CreateGrantRequest(api.NewGrantRequest{
			Services: services, Reason: reason, Uses: uses, Servers: servers, ExpiresInHours: hours})
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if cc.Client.DryRun {
			cmd.PrintErrln("Dry run: nothing was sent, so there is no request and no approval link.")
			return nil
		}
		if req.URL == "" { // missing, or not a plain http(s) link (api.GrantRequest.sanitize)
			return &clierr.CLIError{Kind: clierr.KindServer, Command: "access request",
				Message: "request " + req.RequestID + " was sent, but the server returned no usable approval link",
				Hint:    "the owner can find it in the console inbox"}
		}
		fmt.Fprintln(os.Stdout, req.URL)
		cmd.PrintErrf("Request %s sent for %s. Open the link above to approve. It expires %s.\n",
			req.RequestID, strings.Join(services, ", "), req.ExpiresAt)
		if wait <= 0 {
			return nil
		}
		final, err := waitForDecision(cmd, cc, req.RequestID, wait)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		printDecision(cmd, final)
		return decisionError(final)
	},
}

// maxPlanBytes caps a plan file: 25 actions never come close.
const maxPlanBytes = 256 << 10

// readPlan reads a change-request plan from a file or stdin ("-"): either a
// JSON array of actions, or an object {"reason": "...", "actions": [...]}.
// The actions are sent as written; the server checks them.
func readPlan(cmd *cobra.Command, path string) (string, json.RawMessage, error) {
	bad := func(msg string) error {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: "access plan", Message: msg}
	}
	var r io.Reader
	if path == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", nil, bad("cannot read the plan: " + safeText(err.Error()))
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPlanBytes+1))
	if err != nil {
		return "", nil, bad("cannot read the plan: " + safeText(err.Error()))
	}
	if len(data) > maxPlanBytes {
		return "", nil, bad("the plan is larger than 256 KB")
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		return "", json.RawMessage(trimmed), nil
	}
	var obj struct {
		Reason  string          `json:"reason"`
		Actions json.RawMessage `json:"actions"`
	}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil || len(obj.Actions) == 0 {
		return "", nil, bad(`the plan must be a JSON array of actions, or {"reason": "...", "actions": [...]}`)
	}
	return obj.Reason, obj.Actions, nil
}

var accessPlanCmd = &cobra.Command{
	Use:   "plan <file|->",
	Short: "Ask the owner to approve a list of changes; prints the approval link",
	Long: `Sends a change request: a list of actions the owner ticks on one page. The
owner may allow all, some or none. Actions:

  grant               to (agent name or "self"), service, uses?, servers?, expiresInMinutes?
                      servers: with uses ["tools"], only these MCP servers; each must exist
                      or be added by an add_mcp_server in the grant's parent chain. No
                      servers = every server, including ones added later.
  revoke             to (agent name), services
  create_agent        name, kind?, scopes?
  delete_agents       names        (starts unticked for the owner)
  delete_credentials  names        (starts unticked for the owner)
  suspend, resume     to (agent name)
  add_mcp_server      service, name, url (https), headers ({"Authorization": "Bearer ${TOKEN}"};
                      each value only a placeholder, never a secret)
  remove_mcp_server   service, name

Each action has an "id"; "parent" names an earlier action it needs (it runs
only if the parent ran). Never put a secret value in a plan.

With --wait, exits 0 when approved, 15 when denied, 16 when it expires or the
wait runs out. Collect a created agent's key with ` + "`tvault access claim-key`" + `.`,
	Example: `  tvault access plan setup-ci.json --wait 10m
  echo '[{"id":"a1","type":"grant","to":"self","service":"github","expiresInMinutes":1}]' \
    | tvault access plan - --reason "check one issue"
  echo '[{"id":"g1","type":"grant","to":"self","service":"home-hub","uses":["tools"],"servers":["otto"]}]' \
    | tvault access plan - --reason "otto tools only"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, _ := cmd.Flags().GetString("reason")
		wait, _ := cmd.Flags().GetDuration("wait")
		planReason, actions, err := readPlan(cmd, args[0])
		if err != nil {
			return err
		}
		if strings.TrimSpace(reason) == "" {
			reason = planReason
		}
		if strings.TrimSpace(reason) == "" {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "access plan",
				Message: "a reason is required (--reason, or \"reason\" in the plan): the owner reads it"}
		}
		cc, err := resolveSelf(cmd, "access plan")
		if err != nil {
			return err
		}
		req, err := cc.Client.CreateGrantRequest(api.NewGrantRequest{Actions: actions, Reason: reason})
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if cc.Client.DryRun {
			cmd.PrintErrln("Dry run: nothing was sent, so there is no request and no approval link.")
			return nil
		}
		if req.URL == "" {
			return &clierr.CLIError{Kind: clierr.KindServer, Command: "access plan",
				Message: "request " + req.RequestID + " was sent, but the server returned no usable approval link",
				Hint:    "the owner can find it in the console inbox"}
		}
		fmt.Fprintln(os.Stdout, req.URL)
		cmd.PrintErrf("Request %s sent. Open the link above to review it. It expires %s.\n", req.RequestID, req.ExpiresAt)
		if wait <= 0 {
			return nil
		}
		final, err := waitForDecision(cmd, cc, req.RequestID, wait)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		printDecision(cmd, final)
		return decisionError(final)
	},
}

var accessClaimKeyCmd = &cobra.Command{
	Use:   "claim-key <request-id> <action-id>",
	Short: "Collect the key of an agent your approved change request created",
	Long: `Prints the new agent's key on stdout, once. Works within one hour of the
approval. The server issues a fresh key at this moment. Pipe it straight into
storage; never print it:

  tvault access claim-key <request-id> a1 | tvault add ci-bot --value-stdin`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolveSelf(cmd, "access claim-key")
		if err != nil {
			return err
		}
		res, err := cc.Client.ClaimAgentKey(args[0], args[1])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if !strings.HasPrefix(res.APIKey, "tvagent_") || safeText(res.APIKey) != res.APIKey {
			return &clierr.CLIError{Kind: clierr.KindServer, Command: "access claim-key",
				Message: "the server returned something that is not an agent key"}
		}
		return printNewKey(cmd, res.APIKey, map[string]any{"agentId": res.AgentID})
	},
}

var accessStatusCmd = &cobra.Command{
	Use:   "status <request-id>",
	Short: "Show a grant request's status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		req, err := cc.Client.GetGrantRequest(args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		fmt.Fprintln(os.Stdout, req.Status)
		printDecision(cmd, req)
		return nil
	},
}

var accessDropCmd = &cobra.Command{
	Use:   "drop <service> [<service>...]",
	Short: "Remove grants this key or agent holds",
	Long: `Removes grants from the key or agent of the active context. No scope is
needed: it only reduces this key or agent's own access. To get a grant back,
use ` + "`tvault access request`" + `.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		cc, err := resolveSelf(cmd, "access drop")
		if err != nil {
			return err
		}
		items := append([]string{"from " + cc.label() + ":"}, args...)
		if !confirmDestructive(cmd, cc, "drop grant(s)", items, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "access drop", Message: "aborted"}
		}
		res, err := cc.Client.DropGrants(args)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Dropped %d grant(s).", len(res.Dropped))
		if len(res.NotHeld) > 0 {
			cmd.PrintErrf(" Not held: %s.", strings.Join(res.NotHeld, ", "))
		}
		cmd.PrintErrln()
		return nil
	},
}

func init() {
	accessRequestCmd.Flags().String("reason", "", "why this key or agent needs the access (the owner reads it)")
	accessRequestCmd.Flags().String("uses", "", "what the grant is for: value, mcp, or value,mcp (agents only)")
	accessRequestCmd.Flags().String("servers", "", "MCP grant on these servers only, comma-separated (implies --uses mcp)")
	accessRequestCmd.Flags().String("expires", "never", "when the grant ends: 12h, 7d or never")
	accessRequestCmd.Flags().Duration("wait", 0, "wait up to this long for the owner's decision, e.g. 10m (max 1h)")
	accessDropCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	accessPlanCmd.Flags().String("reason", "", "why (the owner reads it); overrides \"reason\" in the plan")
	accessPlanCmd.Flags().Duration("wait", 0, "wait up to this long for the owner's decision, e.g. 10m (max 1h)")
	accessCmd.AddCommand(accessRequestCmd, accessPlanCmd, accessClaimKeyCmd, accessStatusCmd, accessDropCmd)
	rootCmd.AddCommand(accessCmd)
}
