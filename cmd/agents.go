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

// resolveAgentRefs accepts a mix of agent IDs and names and returns the
// corresponding IDs in input order. The backend's /api/agents/{id} routes
// expect an ID. A ref shaped like a backend agent ID (a 20-character
// Firestore auto-ID) is used as-is with no lookup — listing agents needs the
// agents:read scope, which a key limited to e.g. grants:write doesn't have.
// Any other ref is treated as a name and resolved via ListAgents; a name that
// matches nothing passes through unchanged so the server reports not-found.
//
// Edge case: a human name that is exactly 20 alphanumeric characters is
// indistinguishable from an ID and is treated as one first; commands retry it
// as a name if the server answers 404 (see withNameFallback).
func resolveAgentRefs(client *api.Client, refs []string) ([]string, error) {
	out := make([]string, len(refs))
	var byName map[string]string
	for i, r := range refs {
		if agentIDPattern.MatchString(r) {
			out[i] = r
			continue
		}
		if byName == nil {
			agents, err := client.ListAgents()
			if err != nil {
				var ce *clierr.CLIError
				if asCLIErr(err, &ce) && ce.Kind == clierr.KindScopeDenied {
					return nil, &clierr.CLIError{
						Kind:    clierr.KindScopeDenied,
						Code:    ce.Code,
						Scope:   ce.Scope,
						Request: ce.Request,
						Message: fmt.Sprintf("cannot look up agent %q by name — listing agents needs the agents:read scope; pass the agent ID instead", r),
						Hint:    "use the agent's ID (shown by `tvault agents ls` in an admin context) in place of its name",
					}
				}
				return nil, err
			}
			byName = make(map[string]string, len(agents))
			for _, a := range agents {
				byName[a.Name] = a.ID
			}
		}
		if id, ok := byName[r]; ok {
			out[i] = id
		} else {
			out[i] = r
		}
	}
	return out, nil
}

// isNotFound reports whether err is the server's 404 for a missing resource.
func isNotFound(err error) bool {
	var ce *clierr.CLIError
	return asCLIErr(err, &ce) && strings.HasPrefix(ce.Response, "404")
}

// withNameFallback runs op(id). When ref was used as an ID without a lookup
// (id == ref) and the server answers 404, ref may instead be an agent name
// that happens to look like an ID (exactly 20 letters/digits): look it up by
// name and retry once. Any lookup failure returns the original error.
func withNameFallback(client *api.Client, ref, id string, op func(id string) error) error {
	err := op(id)
	if err == nil || id != ref || !agentIDPattern.MatchString(ref) || !isNotFound(err) {
		return err
	}
	agents, lerr := client.ListAgents()
	if lerr != nil {
		return err
	}
	for _, a := range agents {
		if a.Name == ref && a.ID != id {
			return op(a.ID)
		}
	}
	return err
}

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
		ids, err := resolveAgentRefs(cc.Client, args[:1])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		var a *api.Agent
		err = withNameFallback(cc.Client, args[0], ids[0], func(id string) (e error) {
			a, e = cc.Client.GetAgent(id)
			return e
		})
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
			var ids []string
			ids, err = resolveAgentRefs(cc.Client, args[:1])
			if err == nil {
				id, label = ids[0], args[0]
			}
		}
		if err != nil {
			return enrich(cmd, cc, err)
		}
		var res *api.RotateAgentKeyResult
		err = withNameFallback(cc.Client, label, id, func(id string) (e error) {
			res, e = cc.Client.RotateAgentKey(id)
			return e
		})
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if res.APIKey == "" { // --dry-run
			return nil
		}
		cmd.PrintErrf("Rotated key for agent %q — the old key no longer works.\n", label)
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
		if !confirmDestructive(cmd, cc, "delete agent(s)", args, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents rm", Message: "aborted"}
		}
		ids, err := resolveAgentRefs(cc.Client, args)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(ids) == 1 {
			err = withNameFallback(cc.Client, args[0], ids[0], func(id string) error {
				return cc.Client.DeleteAgents([]string{id})
			})
		} else {
			err = cc.Client.DeleteAgents(ids)
		}
		if err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Deleted %d agent(s).\n", len(args))
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
			ids, err := resolveAgentRefs(cc.Client, args[:1])
			if err != nil {
				return enrich(cmd, cc, err)
			}
			if err := withNameFallback(cc.Client, args[0], ids[0], func(id string) error {
				return cc.Client.SetAgentStatus(id, status)
			}); err != nil {
				return enrich(cmd, cc, err)
			}
			cmd.PrintErrf("%s agent %q.\n", strings.TrimSuffix(verb, "e")+"ed", args[0])
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
