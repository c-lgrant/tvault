package cmd

import (
	"os"
	"strings"

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
		grants, err := cc.Client.ListGrants(rs[0].ID)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if len(grants) == 0 {
			cmd.PrintErrf("No grants. Add one with `tvault ag gr add %s <service>`.\n", args[0])
			return nil
		}
		rows := make([]map[string]string, len(grants))
		for i, g := range grants {
			rows[i] = map[string]string{"service": g}
		}
		return output.Render(os.Stdout, cc.Format, []string{"service"}, rows)
	},
}

var grantsAddCmd = &cobra.Command{
	Use:               "add <agent> <service> [<service>...]",
	Short:             "Grant an agent access to one or more services",
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completeAgentThenServices,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		rs, err := resolveAgents(cc.Client, args[:1], true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		res := cc.Client.AddGrants(rs[0].ID, args[1:])
		if err := res.Err(); err != nil {
			if len(res.OK) > 0 {
				cmd.PrintErrf("Granted %d service(s) to %s before the failure.\n", len(res.OK), rs[0].label())
			}
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Granted %d service(s) to %s.\n", len(res.OK), rs[0].label())
		return nil
	},
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
