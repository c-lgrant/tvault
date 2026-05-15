package cmd

import (
	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and drop a stored context",
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

		// Admin contexts: revoke the refresh token server-side first.
		if ctx.Type == "admin" {
			client, err := auth.ClientFor(ctx, false)
			if err != nil {
				cmd.PrintErrf("warning: could not build an authenticated client (%v) — skipping server-side revoke, dropping the local context anyway\n", err)
			} else {
				if rerr := client.Revoke(); rerr != nil {
					cmd.PrintErrf("warning: server-side revoke failed (%v) — dropping the local context anyway\n", rerr)
				}
			}
		}

		delete(cfg.Contexts, name)
		if cfg.Current == name {
			cfg.Current = ""
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		cmd.Printf("Logged out — context %q removed.\n", name)
		return nil
	},
}
