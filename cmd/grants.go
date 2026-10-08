package cmd

import (
	"os"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
)

// grantNotFound returns the first 404 among a grant operation's failures (so
// withNameFallback can retry), or the aggregate error otherwise.
func grantNotFound(res api.GrantResult) error {
	for _, e := range res.Failed {
		if isNotFound(e) {
			return e
		}
	}
	return res.Err()
}

var grantsCmd =&cobra.Command{
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
		ids, err := resolveAgentRefs(cc.Client, args[:1])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		var grants []string
		err = withNameFallback(cc.Client, args[0], ids[0], func(id string) (e error) {
			grants, e = cc.Client.ListGrants(id)
			return e
		})
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
		ids, err := resolveAgentRefs(cc.Client, args[:1])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		var res api.GrantResult
		_ = withNameFallback(cc.Client, args[0], ids[0], func(id string) error {
			res = cc.Client.AddGrants(id, args[1:])
			return grantNotFound(res)
		})
		if err := res.Err(); err != nil {
			if len(res.OK) > 0 {
				cmd.PrintErrf("Granted %d service(s) to %q before the failure.\n", len(res.OK), args[0])
			}
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Granted %d service(s) to %q.\n", len(res.OK), args[0])
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
		if !confirmDestructive(cmd, cc, "revoke grant(s)", args[1:], force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "agents grants rm", Message: "aborted"}
		}
		ids, err := resolveAgentRefs(cc.Client, args[:1])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		var res api.GrantResult
		_ = withNameFallback(cc.Client, args[0], ids[0], func(id string) error {
			res = cc.Client.RemoveGrants(id, args[1:])
			return grantNotFound(res)
		})
		if err := res.Err(); err != nil {
			if len(res.OK) > 0 {
				cmd.PrintErrf("Revoked %d grant(s) from %q before the failure.\n", len(res.OK), args[0])
			}
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrf("Revoked %d grant(s) from %q.\n", len(res.OK), args[0])
		return nil
	},
}

func init() {
	grantsRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	grantsCmd.AddCommand(grantsListCmd, grantsAddCmd, grantsRmCmd)
	agentsCmd.AddCommand(grantsCmd)
}
