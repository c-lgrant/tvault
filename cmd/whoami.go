package cmd

import (
	"time"

	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"who"},
	Short:   "Show the active context, identity, and token expiry",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		override := contextOverride(cmd)
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		ctx, name, err := cfg.ActiveContext(override)
		if err != nil {
			return err
		}

		cmd.Printf("context : %s\n", name)
		cmd.Printf("type    : %s\n", ctx.Type)
		cmd.Printf("identity: %s\n", ctx.Identity)
		cmd.Printf("api_url : %s\n", ctx.APIURL)

		if ctx.Type == "admin" {
			// Refresh so we can show a real expiry.
			if _, err := auth.ClientFor(ctx, false); err != nil {
				return err
			}
			_, expiresAt := ctx.IDToken()
			cmd.Printf("token   : expires in %s\n", time.Until(time.Unix(expiresAt, 0)).Round(time.Second))
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(whoamiCmd) }
