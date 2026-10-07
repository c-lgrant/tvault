package cmd

import (
	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/spf13/cobra"
)

const (
	defaultAPIURL      = "https://api.tokenvault.uk"
	defaultFrontendURL = "https://tokenvault.uk"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to Token Vault (browser-based admin login, or --key for a tvagent_/tvkey_ key)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		asName, _ := cmd.Flags().GetString("as")
		apiKey, _ := cmd.Flags().GetString("key")
		noBrowser, _ := cmd.Flags().GetBool("no-launch-browser")
		apiURL, _ := cmd.Flags().GetString("api-url")
		frontendURL, _ := cmd.Flags().GetString("frontend-url")

		if apiKey != "" {
			if err := auth.LoginKey(asName, apiURL, apiKey); err != nil {
				return err
			}
			cmd.Printf("Logged in as %s — context %q is now active.\n", auth.KeyContextType(apiKey), asName)
			return nil
		}

		err := auth.Login(auth.LoginOptions{
			ContextName: asName,
			APIURL:      apiURL,
			FrontendURL: frontendURL,
			ForceManual: noBrowser,
		})
		if err != nil {
			return err
		}
		name := asName
		if name == "" {
			name = "default"
		}
		cmd.Printf("Logged in — context %q is now active.\n", name)
		return nil
	},
}

func init() {
	loginCmd.Flags().String("as", "", "context name to store the login under")
	loginCmd.Flags().String("key", "", "tvagent_* (agent) or tvkey_* (scoped key) for non-interactive login; the type is detected from the prefix")
	loginCmd.Flags().Bool("no-launch-browser", false, "use the manual code-paste flow instead of the loopback browser redirect (for SSH/headless sessions)")
	loginCmd.Flags().String("api-url", defaultAPIURL, "API base URL")
	loginCmd.Flags().String("frontend-url", defaultFrontendURL, "frontend base URL (hosts /cli/auth)")
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}
