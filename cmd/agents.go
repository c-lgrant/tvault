package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/c-lgrant/tvault/internal/tui"
	"github.com/spf13/cobra"
)

// Agent refs (names or IDs) are resolved in refs.go; see pickRef for the rules.

// agentIDPattern matches the IDs the backend issues for agents: Firestore
// auto-IDs, 20 alphanumeric characters.
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{20}$`)

var agentsCmd = &cobra.Command{
	Use:     "agents",
	Aliases: []string{"ag"},
	Short:   "Manage agents",
}

var agentsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List agents",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		agents, err := cc.Client.ListAgents()
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(agents) == 0 {
			cmd.PrintErrln("No agents. Create one with `tvault ag new`.")
			return nil
		}
		rows := make([]map[string]string, len(agents))
		for i, a := range agents {
			rows[i] = map[string]string{"id": a.ID, "name": a.Name, "status": a.Status}
		}
		return output.Render(os.Stdout, cc.Format, []string{"name", "status", "id"}, rows)
	},
}

var agentsShowCmd = &cobra.Command{
	Use:               "show <name-or-id>",
	Aliases:           []string{"info"},
	Short:             "Show agent details",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeAgents,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		rs, err := resolveAgents(cc.Client, args[:1], false)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		a, err := cc.Client.GetAgent(rs[0].ID)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		grants := make([]string, 0, len(a.Grants))
		for _, g := range a.Grants {
			grants = append(grants, g.ServiceName)
		}
		rows := []map[string]string{{
			"name": a.Name, "status": a.Status, "id": a.ID,
			"grants": joinComma(grants),
		}}
		return output.Render(os.Stdout, cc.Format, []string{"name", "status", "id", "grants"}, rows)
	},
}

var agentsCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create an agent (interactive wizard, or flag-driven)",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		name, _ := cmd.Flags().GetString("name")
		grants, _ := cmd.Flags().GetStringSlice("grants")
		nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
		kind, _ := cmd.Flags().GetString("kind")
		scopes, _ := cmd.Flags().GetStringSlice("scopes")

		switch kind {
		case "", "classic":
			if len(scopes) > 0 {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create",
					Message: "--scopes only applies to --kind scoped"}
			}
		case "scoped":
			if len(scopes) == 0 {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create",
					Message: "--kind scoped needs --scopes (comma-separated, e.g. credentials:read)"}
			}
		default:
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create",
				Message: fmt.Sprintf("invalid --kind %q — use classic or scoped", kind)}
		}

		if name == "" {
			if nonInteractive || !cc.IsTTY {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create",
					Message: "non-interactive shell needs --name (and optional --grants)"}
			}
			toks, terr := cc.Client.ListTokens()
			if terr != nil {
				return enrich(cmd, cc, terr)
			}
			services := make([]string, len(toks))
			for i, t := range toks {
				services[i] = t.ServiceName
			}
			name, grants, err = tui.RunAgentWizard(services)
			if err != nil {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create", Message: err.Error()}
			}
		}

		// The backend has no grants field on POST /api/agents — create the
		// agent first, then apply grants via the grants endpoint.
		res, err := cc.Client.CreateAgentWithKind(name, kind, scopes)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		// A server that predates scoped agents silently drops kind/scopes and
		// mints a classic agent, which can read credentials — not what was
		// asked for. Refuse, print no key, and clean up the stray agent.
		if kind == "scoped" && res.Kind != "scoped" && !cc.Client.DryRun {
			msg := "this server doesn't support scoped agents yet; an unscoped agent was NOT what you asked for"
			hint := ""
			if derr := cc.Client.DeleteAgents([]string{res.ID}); derr != nil {
				msg += " — delete it with `tvault agents rm " + res.ID + "`"
				hint = "automatic cleanup failed: " + api.BriefError(derr)
			} else {
				hint = "the unscoped agent that was just created has been deleted again"
			}
			return enrich(cmd, cc, &clierr.CLIError{Kind: clierr.KindUser, Command: "agents create",
				Message: msg, Hint: hint})
		}
		cmd.PrintErrf("Created agent %q.\n", res.Name)
		var gr api.GrantResult
		var grantErr error
		if len(grants) > 0 {
			gr = cc.Client.AddGrants(res.ID, grants)
			if grantErr = gr.Err(); grantErr == nil {
				cmd.PrintErrf("Granted %d service(s).\n", len(gr.OK))
			}
		}
		cmd.PrintErrln("API key (shown once — store it now):")
		// stdout: scripts capture KEY=$(tvault agents create ... | tail -1).
		fmt.Println(res.APIKey)
		if grantErr != nil {
			// The key is already printed (it is never shown again), but a
			// half-granted agent must not exit 0: scripts would assume access.
			// Keep the first failure's kind so e.g. SCOPE_DENIED still exits 8.
			kind := clierr.KindUser
			for _, e := range gr.Failed {
				var ce *clierr.CLIError
				if errors.As(e, &ce) {
					kind = ce.Kind
					break
				}
			}
			return &clierr.CLIError{Kind: kind, Command: "agents create",
				Message: "agent created (key printed above), but granting services failed: " + grantErr.Error(),
				Hint:    "retry with `tvault grant " + res.ID + " <service>` once the cause is fixed"}
		}
		return nil
	},
}

var agentsRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <name-or-id> | --self",
	Short: "Rotate an agent's API key (the new key is printed once, to stdout)",
	Long: `Rotate an agent's key. Rotating another agent's key needs a signed-in human;
an agent can rotate itself with --self, which also switches the active context to the new key.`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeAgents,
	RunE: func(cmd *cobra.Command, args []string) error {
		self, _ := cmd.Flags().GetBool("self")
		if self == (len(args) == 1) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents rotate-key", Message: "pass either an agent name/id or --self"}
		}
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		var id, label string
		if self {
			id, label, err = selfPrincipal(cc, "agent", "agents rotate-key")
		} else {
			var rs []resolved
			rs, err = resolveAgents(cc.Client, args[:1], true)
			if err == nil {
				id, label = rs[0].ID, rs[0].label()
			}
		}
		if err != nil {
			return enrich(cmd, cc, err)
		}
		res, err := cc.Client.RotateAgentKey(id)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if res.APIKey == "" { // --dry-run
			return nil
		}
		cmd.PrintErrf("Rotated key for agent %s —the old key no longer works.\n", label)
		if self {
			if err := storeRotatedKey(cc, res.APIKey); err != nil {
				fmt.Println(res.APIKey)
				return err
			}
			cmd.PrintErrf("Context %q now uses the new key.\n", cc.ContextName)
		}
		cmd.PrintErrln("API key (shown once — store it now):")
		// stdout: scripts capture KEY=$(tvault agents rotate-key ...).
		fmt.Println(res.APIKey)
		return nil
	},
}

var agentsRmCmd = &cobra.Command{
	Use:               "rm <name-or-id> [<name-or-id>...]",
	Aliases:           []string{"del", "d"},
	Short:             "Delete one or more agents",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeAgents,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		rs, err := resolveAgents(cc.Client, args, true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if !confirmDestructive(cmd, cc, "delete agent(s)", labels(rs), force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents rm", Message: "aborted"}
		}
		if force {
			cmd.PrintErrf("Deleting agent(s): %s\n", strings.Join(labels(rs), ", "))
		}
		if err := cc.Client.DeleteAgents(idsOf(rs)); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Deleted %d agent(s).\n", len(rs))
		return nil
	},
}

func agentStatusCmd(use, alias, status, verb string) *cobra.Command {
	return &cobra.Command{
		Use:               use + " <name-or-id>",
		Aliases:           []string{alias},
		Short:             verb + " an agent",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeAgents,
		RunE: func(cmd *cobra.Command, args []string) error {
			cc, err := resolve(cmd)
			if err != nil {
				return err
			}
			rs, err := resolveAgents(cc.Client, args[:1], true)
			if err != nil {
				return enrich(cmd, cc, err)
			}
			if err := cc.Client.SetAgentStatus(rs[0].ID, status); err != nil {
				return enrich(cmd, cc, err)
			}
			cmd.PrintErrf("%s agent %s.\n", strings.TrimSuffix(verb, "e")+"ed", rs[0].label())
			return nil
		},
	}
}

func init() {
	agentsRotateKeyCmd.Flags().Bool("self", false, "rotate the key this agent context is logged in with, and switch the context to the new key")
	agentsCreateCmd.Flags().String("name", "", "agent name")
	agentsCreateCmd.Flags().StringSlice("grants", nil, "comma-separated services to grant")
	agentsCreateCmd.Flags().Bool("non-interactive", false, "fail instead of prompting")
	agentsCreateCmd.Flags().String("kind", "", "agent kind: classic (default) or scoped")
	agentsCreateCmd.Flags().StringSlice("scopes", nil, "comma-separated scopes for --kind scoped, e.g. credentials:read")
	agentsRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")

	agentsCmd.AddCommand(
		agentsListCmd, agentsShowCmd, agentsCreateCmd, agentsRotateKeyCmd, agentsRmCmd,
		agentStatusCmd("suspend", "off", "suspended", "Suspend"),
		agentStatusCmd("resume", "on", "active", "Resume"),
	)
	rootCmd.AddCommand(agentsCmd)
}
