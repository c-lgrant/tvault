package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/webhook"
	"github.com/spf13/cobra"
)

// webhookHTTP is package-level so tests can substitute a fake client.
var webhookHTTP = &http.Client{Timeout: 15 * time.Second}

var webhookCmd = &cobra.Command{
	Use:     "webhook",
	Aliases: []string{"wh"},
	Short:   "Connect your own Token Vault webhook",
	// Runnable only to give removed subcommands (init, up, down) cobra's usual
	// unknown-command error; a group command otherwise swallows them and
	// prints help.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
				Message: fmt.Sprintf("unknown command %q for %q", args[0], cmd.CommandPath()),
				Hint:    "available: bind, status. To run the reference webhook, see examples/webhook"}
		}
		return cmd.Help()
	},
}

var webhookBindCmd = &cobra.Command{
	Use:   "bind",
	Short: "Bind a running webhook to your vault (no browser)",
	Long: `Fetches the one-time registration code from the webhook at --url and binds
it to your vault. Deploy the reference webhook first (see examples/webhook).`,
	Args: cobra.NoArgs,
	RunE: runWebhookBind,
}

// normalizeWebhookURL trims whitespace and trailing slashes and assumes https
// when the user typed a bare hostname.
func normalizeWebhookURL(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s != "" && !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return s
}

func runWebhookBind(cmd *cobra.Command, _ []string) error {
	rawURL, _ := cmd.Flags().GetString("url")
	whURL := normalizeWebhookURL(rawURL)
	if whURL == "" {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: "--url is required: the public URL of your running webhook"}
	}
	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	if err := webhook.CheckHealth(webhookHTTP, whURL); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: "webhook is not reachable — is it running? " + err.Error()}
	}
	info, err := webhook.FetchRegisterURL(webhookHTTP, whURL)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	res, err := cc.Client.WebhookBind(info.Code, info.WebhookURL, info.HMACSecretHash)
	if err != nil {
		return enrich(cmd, cc, err)
	}
	cmd.PrintErrf("Webhook bound. Vault mode: %s. Capabilities: %s\n",
		res.VaultMode, strings.Join(res.WebhookCapabilities, ", "))
	return nil
}

var webhookStatusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"stat"},
	Short:   "Show the control plane's view of your webhook",
	Args:    cobra.NoArgs,
	RunE:    runWebhookStatus,
}

func runWebhookStatus(cmd *cobra.Command, _ []string) error {
	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	st, err := cc.Client.VaultWebhookInfo()
	if err != nil {
		return enrich(cmd, cc, err)
	}
	cmd.Printf("vault mode: %s\n", st.VaultMode)
	if st.Webhook == nil {
		cmd.Println("webhook   : not bound — run `tvault webhook bind --url <webhook-url>`")
		return nil
	}
	cmd.Printf("url       : %s\n", st.Webhook.URL)
	cmd.Printf("status    : %s\n", st.Webhook.Status)
	cmd.Printf("last check: %s (%s)\n", st.Webhook.LastHealthCheck, st.Webhook.LastHealthStatus)
	// Direct probe from this machine, independent of the control plane's check.
	if err := webhook.CheckHealth(webhookHTTP, st.Webhook.URL); err != nil {
		cmd.Printf("probe     : unreachable (%s)\n", err)
	} else {
		cmd.Printf("probe     : healthy\n")
	}
	if len(st.Capabilities) > 0 {
		cmd.Printf("caps      : %s\n", strings.Join(st.Capabilities, ", "))
	}
	return nil
}

func init() {
	webhookBindCmd.Flags().String("url", "", "public URL of your running webhook (required)")
	webhookCmd.AddCommand(webhookBindCmd, webhookStatusCmd)
	rootCmd.AddCommand(webhookCmd)
}
