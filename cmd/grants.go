package cmd

import (
	"os"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
)

var grantsCmd = &cobra.Command{
	Use:     "grants",
	Aliases: []string{"gr"},
	Short:   "Manage an agent's token grants",
}

var grantsListCmd = &cobra.Command{
	Use:               "list <agent>",
	Aliases:           []string{"ls"},
	Short:             "List an agent's grants",
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
		grants, err := cc.Client.ListGrantDetails(rs[0].ID)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(grants) == 0 {
			cmd.PrintErrf("No grants. Add one with `tvault ag gr add %s <service>`.\n", args[0])
			return nil
		}
		// One row per entry (the value, each MCP server), each with its own end.
		var rows []map[string]string
		for _, g := range grants {
			if len(g.Entries) == 0 { // a server that predates entries: one row for the grant
				rows = append(rows, map[string]string{"service": g.ServiceName, "entry": "",
					"expires": expiresText(g.GrantExpiresAt)})
				continue
			}
			for _, e := range g.Entries {
				rows = append(rows, map[string]string{"service": g.ServiceName, "entry": e.Key,
					"expires": expiresText(e.ExpiresAt)})
			}
		}
		return output.Render(os.Stdout, cc.Format, []string{"service", "entry", "expires"}, rows)
	},
}

var grantsAddCmd = &cobra.Command{
	Use:   "add <agent> <service>[=<uses>[:<server>,...]] [...]",
	Short: "Grant an agent access to one or more services",
	Long: `Grants an agent access to credentials. A plain <service> grants the value
(today's meaning). Append =<uses> to choose what the grant may be used for:

  value   the agent may read the credential value
  mcp     the agent may call the credential's MCP servers through Token Vault
          and is never handed the value (see ` + "`tvault mcp-servers`" + `);
          "tools" is accepted as another spelling of mcp

<uses> is a comma list. After a colon, name the MCP servers an mcp grant covers;
without it, the credential's servers as they are now (never ones added later).
A grant adds to what the agent holds and never shortens an entry it has.`,
	Example: `  tvault grant claude-code github            # value grant
  tvault grant claude-code github=mcp        # MCP access only, every server it has now
  tvault grant claude-code github=value,mcp:github
  tvault grant claude-code github=mcp:github linear=mcp`,
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completeAgentThenServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		specs, err := parseGrantSpecs(args[1:], "agents grants add")
		if err != nil {
			return err
		}
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		rs, err := resolveAgents(cc.Client, args[:1], true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		res := cc.Client.AddGrantSpecs(rs[0].ID, specs)
		if err := res.Err(); err != nil {
			if len(res.OK) > 0 {
				cmd.PrintErrf("Granted %d service(s) to %s before the failure.\n", len(res.OK), rs[0].label())
			}
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Granted %d service(s) to %s.\n", len(res.OK), rs[0].label())
		printAlreadyHeld(cmd, res)
		return nil
	},
}

// printAlreadyHeld names the entries a grant kept because the agent already
// held them for as long or longer. A grant adds and never narrows or shortens:
// to cut access, remove the grant or change an entry.
func printAlreadyHeld(cmd *cobra.Command, res api.GrantResult) {
	if len(res.AlreadyHeld) == 0 {
		return
	}
	for _, svc := range res.OK {
		if kept := res.AlreadyHeld[svc]; len(kept) > 0 {
			cmd.PrintErrf("  %s: already held for as long or longer: %s\n", svc, strings.Join(kept, ", "))
		}
	}
	cmd.PrintErrln("  A grant never narrows or shortens access. To cut it, remove the grant (tvault ag gr rm) " +
		"or ask for a change_grant.")
}

var grantsRmCmd = &cobra.Command{
	Use:               "rm <agent> <service> [<service>...]",
	Short:             "Revoke an agent's access to one or more services",
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completeAgentThenServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		rs, err := resolveAgents(cc.Client, args[:1], true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		items := append([]string{"from agent " + rs[0].label() + ":"}, args[1:]...)
		if !confirmDestructive(cmd, cc, "revoke grant(s)", items, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents grants rm", Message: "aborted"}
		}
		if force {
			cmd.PrintErrf("Revoking %s from agent %s\n", strings.Join(args[1:], ", "), rs[0].label())
		}
		res := cc.Client.RemoveGrants(rs[0].ID, args[1:])
		if err := res.Err(); err != nil {
			if len(res.OK) > 0 {
				cmd.PrintErrf("Revoked %d grant(s) from %s before the failure.\n", len(res.OK), rs[0].label())
			}
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Revoked %d grant(s) from %s.\n", len(res.OK), rs[0].label())
		return nil
	},
}

func init() {
	grantsRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	grantsCmd.AddCommand(grantsListCmd, grantsAddCmd, grantsRmCmd)
	agentsCmd.AddCommand(grantsCmd)
}

// expiresText is the end of a grant entry for display: "never" when it has none.
func expiresText(at string) string {
	if at == "" {
		return "never"
	}
	return at
}

// grantSummary is "github (value, tools:main until <time>)": the service and each entry's end.
func grantSummary(g api.Grant) string {
	if len(g.Entries) == 0 {
		return g.ServiceName
	}
	parts := make([]string, len(g.Entries))
	for i, e := range g.Entries {
		parts[i] = e.Key
		if e.ExpiresAt != "" {
			parts[i] += " until " + e.ExpiresAt
		}
	}
	return g.ServiceName + " (" + strings.Join(parts, ", ") + ")"
}
