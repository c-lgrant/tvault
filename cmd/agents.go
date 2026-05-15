package cmd

import (
	"os"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/c-lgrant/tvault/internal/tui"
	"github.com/spf13/cobra"
)

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
		cc, err := resolve(cmd, true)
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
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		a, err := cc.Client.GetAgent(args[0])
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
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		name, _ := cmd.Flags().GetString("name")
		grants, _ := cmd.Flags().GetStringSlice("grants")
		nonInteractive, _ := cmd.Flags().GetBool("non-interactive")

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
		res, err := cc.Client.CreateAgent(name)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Created agent %q.\n", res.Name)
		if len(grants) > 0 {
			gr := cc.Client.AddGrants(res.ID, grants)
			if err := gr.Err(); err != nil {
				cmd.PrintErrf("Agent created, but granting services failed: %v\n", err)
			} else {
				cmd.PrintErrf("Granted %d service(s).\n", len(gr.OK))
			}
		}
		cmd.PrintErrln("API key (shown once — store it now):")
		cmd.Println(res.APIKey)
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
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if !confirmDestructive(cmd, cc, "delete agent(s)", args, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents rm", Message: "aborted"}
		}
		if err := cc.Client.DeleteAgents(args); err != nil {
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
			cc, err := resolve(cmd, true)
			if err != nil {
				return err
			}
			if err := cc.Client.SetAgentStatus(args[0], status); err != nil {
				return enrich(cmd, cc, err)
			}
			cmd.PrintErrf("%s agent %q.\n", verb+"d", args[0])
			return nil
		},
	}
}

func init() {
	agentsCreateCmd.Flags().String("name", "", "agent name")
	agentsCreateCmd.Flags().StringSlice("grants", nil, "comma-separated services to grant")
	agentsCreateCmd.Flags().Bool("non-interactive", false, "fail instead of prompting")
	agentsRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")

	agentsCmd.AddCommand(
		agentsListCmd, agentsShowCmd, agentsCreateCmd, agentsRmCmd,
		agentStatusCmd("suspend", "off", "suspended", "Suspend"),
		agentStatusCmd("resume", "on", "active", "Resume"),
	)
	rootCmd.AddCommand(agentsCmd)
}
