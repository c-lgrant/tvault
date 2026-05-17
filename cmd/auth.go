package cmd

import (
	"fmt"

	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Low-level auth helpers",
}

var authPrintTokenCmd = &cobra.Command{
	Use:   "print-token",
	Short: "Print the raw bearer ID token for the active admin context",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		override, _ := cmd.Flags().GetString("context")
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		ctx, name, err := cfg.ActiveContext(override)
		if err != nil {
			return err
		}
		if ctx.Type != "admin" {
			return &clierr.CLIError{
				Kind:    clierr.KindUser,
				Command: "auth print-token",
				Message: "print-token requires an admin context; " + name + " is an agent context",
			}
		}
		client, err := auth.ClientFor(ctx, false)
		if err != nil {
			return err
		}
		cmd.PrintErrln("warning: this token grants full account access — avoid saving it to shell history or exporting/persisting it. Prefer `$(tvault tk get <svc>)` where possible.")
		// stdout: callers do `BEARER=$(tvault auth print-token)`.
		fmt.Println(client.BearerToken)
		return nil
	},
}

func init() {
	authCmd.AddCommand(authPrintTokenCmd)
	rootCmd.AddCommand(authCmd)
}
