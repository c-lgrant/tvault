package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/webhook"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// confirmOverwrite is a package var so tests can stub it out without a TTY.
// Returns true to proceed with overwrite, false to abort. On non-interactive
// stdin it never prompts and returns false — preserving script-safety.
var confirmOverwrite = func(cmd *cobra.Command, dir string, conflicts []string) bool {
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return false
	}
	cmd.PrintErrf("These files in %s would be overwritten:\n", dir)
	for _, n := range conflicts {
		cmd.PrintErrf("  - %s\n", n)
	}
	cmd.PrintErr("Overwrite? [y/N]: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

var webhookCmd = &cobra.Command{
	Use:     "webhook",
	Aliases: []string{"wh"},
	Short:   "Deploy and connect your own Token Vault webhook",
}

var webhookInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a Docker Compose project for a webhook deployment",
	Args:  cobra.NoArgs,
	RunE:  runWebhookInit,
}

func runWebhookInit(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	image, _ := cmd.Flags().GetString("image")
	force, _ := cmd.Flags().GetBool("force")
	methodID, _ := cmd.Flags().GetString("method")
	sets, _ := cmd.Flags().GetStringArray("set")

	var m webhook.Method
	var values map[string]string

	if methodID != "" {
		var ok bool
		m, ok = webhook.MethodByID(methodID)
		if !ok {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
				Message: fmt.Sprintf("unknown method %q — one of: ngrok, cloudflare, tailscale, custom", methodID)}
		}
		values = map[string]string{}
		for _, kv := range sets {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
					Message: fmt.Sprintf("--set %q must be KEY=VALUE", kv)}
			}
			k = strings.TrimSpace(k)
			if k == "" {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
					Message: fmt.Sprintf("--set %q: key must not be empty", kv)}
			}
			values[k] = strings.TrimSpace(v)
		}
		for _, p := range m.Params {
			if p.Normalize != nil {
				values[p.Key] = p.Normalize(values[p.Key])
			}
			if values[p.Key] == "" {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
					Message: fmt.Sprintf("method %q needs --set %s=...", m.ID, p.Key)}
			}
		}
	} else {
		wiz := &webhook.Wizard{In: cmd.InOrStdin(), Out: cmd.ErrOrStderr()}
		var err error
		m, values, err = wiz.Run()
		if err != nil {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
		}
	}

	files, err := webhook.Generate(m, values, image)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
				Message: "could not determine current directory: " + err.Error()}
		}
		dir = cwd
	}
	if !force {
		if conflicts := webhook.Conflicts(dir, files); len(conflicts) > 0 {
			if !confirmOverwrite(cmd, dir, conflicts) {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
					Message: fmt.Sprintf("would overwrite existing files in %s: %s — re-run with --force or pick a different --dir",
						dir, strings.Join(conflicts, ", "))}
			}
			force = true
		}
	}
	if err := webhook.WriteProject(dir, files, force); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}

	cmd.PrintErrf("Generated %s webhook project in %s\n", m.Label, dir)
	cmd.PrintErrf("Next:  cd %s && tvault webhook up\n", dir)
	return nil
}

// composeRunner and webhookHTTP are package-level so tests can substitute
// fakes; production uses the real Docker CLI and a plain HTTP client.
var (
	composeRunner webhook.ComposeRunner = webhook.ExecRunner{}
	webhookHTTP                         = &http.Client{Timeout: 15 * time.Second}
)

var webhookUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the webhook container + tunnel and wait for it to be healthy",
	Args:  cobra.NoArgs,
	RunE:  runWebhookUp,
}

func runWebhookUp(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	proj, err := webhook.LoadProject(dir)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	if err := composeRunner.Up(proj.Dir); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	cmd.PrintErrln("Containers started — waiting for the webhook to become healthy...")
	if err := webhook.WaitHealthy(webhookHTTP, proj.ExternalURL, 90*time.Second); err != nil {
		logs, _ := composeRunner.Logs(proj.Dir, 20)
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: err.Error() + "\n--- docker compose logs (tail) ---\n" + logs}
	}
	cmd.PrintErrf("Webhook healthy at %s\n", proj.ExternalURL)
	cmd.PrintErrln("Next:  tvault webhook bind")
	return nil
}

var webhookDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the webhook container + tunnel",
	Args:  cobra.NoArgs,
	RunE:  runWebhookDown,
}

func runWebhookDown(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	proj, err := webhook.LoadProject(dir)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	if err := composeRunner.Down(proj.Dir); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	cmd.PrintErrln("Webhook stopped.")
	return nil
}

var webhookBindCmd = &cobra.Command{
	Use:   "bind",
	Short: "Bind the running webhook to your vault (no browser)",
	Args:  cobra.NoArgs,
	RunE:  runWebhookBind,
}

func runWebhookBind(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	cc, err := resolve(cmd, true)
	if err != nil {
		return err
	}
	proj, err := webhook.LoadProject(dir)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(), Message: err.Error()}
	}
	if err := webhook.CheckHealth(webhookHTTP, proj.ExternalURL); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: "webhook is not reachable — run `tvault webhook up` first: " + err.Error()}
	}
	info, err := webhook.FetchRegisterURL(webhookHTTP, proj.ExternalURL)
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
	Short:   "Show local container state and the backend's view of the webhook",
	Args:    cobra.NoArgs,
	RunE:    runWebhookStatus,
}

func runWebhookStatus(cmd *cobra.Command, _ []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	cc, err := resolve(cmd, true)
	if err != nil {
		return err
	}

	cmd.Println("Local:")
	proj, projErr := webhook.LoadProject(dir)
	if projErr != nil {
		cmd.Printf("  project   : %s\n", projErr)
	} else {
		cmd.Printf("  directory : %s\n", proj.Dir)
		cmd.Printf("  url       : %s\n", proj.ExternalURL)
		if err := webhook.CheckHealth(webhookHTTP, proj.ExternalURL); err != nil {
			cmd.Printf("  health    : unreachable (%s)\n", err)
		} else {
			cmd.Printf("  health    : healthy\n")
		}
	}

	st, err := cc.Client.VaultWebhookInfo()
	if err != nil {
		return enrich(cmd, cc, err)
	}
	cmd.Println("Backend:")
	cmd.Printf("  vault mode: %s\n", st.VaultMode)
	if st.Webhook == nil {
		cmd.Println("  webhook   : not bound — run `tvault webhook bind`")
	} else {
		cmd.Printf("  url       : %s\n", st.Webhook.URL)
		cmd.Printf("  status    : %s\n", st.Webhook.Status)
		cmd.Printf("  last check: %s (%s)\n", st.Webhook.LastHealthCheck, st.Webhook.LastHealthStatus)
		if projErr == nil && proj.ExternalURL != st.Webhook.URL {
			cmd.Println("  note      : backend URL differs from local — run `tvault webhook bind` to re-point")
		}
	}
	if len(st.Capabilities) > 0 {
		cmd.Printf("  caps      : %s\n", strings.Join(st.Capabilities, ", "))
	}
	return nil
}

func init() {
	webhookInitCmd.Flags().String("dir", "", "target directory (default: current working directory)")
	webhookInitCmd.Flags().String("image", "", "override the webhook container image")
	webhookInitCmd.Flags().Bool("force", false, "overwrite an existing docker-compose.yml")
	webhookInitCmd.Flags().String("method", "", "non-interactive: ngrok|cloudflare|tailscale|custom")
	webhookInitCmd.Flags().StringArray("set", nil, "non-interactive: KEY=VALUE param (repeatable)")

	for _, c := range []*cobra.Command{webhookUpCmd, webhookDownCmd, webhookBindCmd, webhookStatusCmd} {
		c.Flags().String("dir", "", "project directory (default current directory)")
	}

	webhookCmd.AddCommand(webhookInitCmd, webhookUpCmd, webhookDownCmd, webhookBindCmd, webhookStatusCmd)
	rootCmd.AddCommand(webhookCmd)
}
