package cmd

import (
	"fmt"
	"os"
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
  tvault access request github --uses mcp --expires 7d --reason "triage issues" --wait 10m`,
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
		uses, err := parseRequestUses(usesFlag)
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
			Services: args, Reason: reason, Uses: uses, ExpiresInHours: hours})
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if req.URL == "" { // missing, or not a plain http(s) link (api.GrantRequest.sanitize)
			return &clierr.CLIError{Kind: clierr.KindServer, Command: "access request",
				Message: "request " + req.RequestID + " was sent, but the server returned no usable approval link",
				Hint:    "the owner can find it in the console inbox"}
		}
		fmt.Fprintln(os.Stdout, req.URL)
		cmd.PrintErrf("Request %s sent for %s. Open the link above to approve. It expires %s.\n",
			req.RequestID, strings.Join(args, ", "), req.ExpiresAt)
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
	accessRequestCmd.Flags().String("expires", "never", "when the grant ends: 12h, 7d or never")
	accessRequestCmd.Flags().Duration("wait", 0, "wait up to this long for the owner's decision, e.g. 10m (max 1h)")
	accessDropCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	accessCmd.AddCommand(accessRequestCmd, accessStatusCmd, accessDropCmd)
	rootCmd.AddCommand(accessCmd)
}
