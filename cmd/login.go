package cmd

import (
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	defaultAPIURL      = "https://api.tokenvault.uk"
	defaultFrontendURL = "https://tokenvault.uk"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to Token Vault (browser-based admin login, or --key-stdin for a tvagent_/tvkey_ key)",
	Example: `  # non-interactive key login without touching shell history
  printf %s "$TVAULT_KEY" | tvault login --key-stdin --as ci`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		asName, _ := cmd.Flags().GetString("as")
		apiKey, _ := cmd.Flags().GetString("key")
		noBrowser, _ := cmd.Flags().GetBool("no-launch-browser")
		apiURL, _ := cmd.Flags().GetString("api-url")
		frontendURL, _ := cmd.Flags().GetString("frontend-url")
		keyStdin, _ := cmd.Flags().GetBool("key-stdin")

		if keyStdin {
			if apiKey != "" {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "login", Message: "--key and --key-stdin are mutually exclusive"}
			}
			k, err := readKeyFromStdin()
			if err != nil {
				return err
			}
			apiKey = k
		}

		if apiKey != "" {
			if err := auth.LoginKey(asName, apiURL, apiKey); err != nil {
				return err
			}
			cmd.Printf("Logged in as %s — context %q is now active.\n", auth.KeyContextType(apiKey), asName)
			return nil
		}

		if cmd.Flags().Changed("api-url") && !cmd.Flags().Changed("frontend-url") {
			derived, ok := deriveFrontendURL(apiURL)
			if !ok {
				return &clierr.CLIError{Kind: clierr.KindUser, Command: "login",
					Message: "cannot derive the frontend URL from --api-url " + apiURL,
					Hint:    "pass --frontend-url too (the site that hosts /cli/auth)"}
			}
			frontendURL = derived
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

// deriveFrontendURL maps an API base URL to the frontend that issued its login
// codes (https://api.tokenvault.one → https://tokenvault.one). A code minted by
// one environment is rejected by another, so a custom --api-url must never
// fall back to the prod frontend.
func deriveFrontendURL(apiURL string) (string, bool) {
	u, err := url.Parse(strings.TrimRight(apiURL, "/"))
	if err != nil || u.Host == "" || !strings.HasPrefix(u.Host, "api.") {
		return "", false
	}
	return u.Scheme + "://" + strings.TrimPrefix(u.Host, "api."), true
}

// Seams for tests: where --key-stdin reads from, and whether that is a TTY.
var (
	loginStdin      io.Reader = os.Stdin
	loginStdinIsTTY           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
)

// readKeyFromStdin reads an API key piped on stdin, trimming surrounding
// whitespace. It refuses an interactive terminal rather than silently waiting
// on (and echoing) a pasted secret.
func readKeyFromStdin() (string, error) {
	if loginStdinIsTTY() {
		return "", &clierr.CLIError{
			Kind:    clierr.KindUser,
			Command: "login",
			Message: "--key-stdin expects the key on a pipe, but stdin is a terminal",
			Hint:    `printf %s "$TVAULT_KEY" | tvault login --key-stdin --as <name>`,
		}
	}
	b, err := io.ReadAll(io.LimitReader(loginStdin, 64*1024))
	if err != nil {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Command: "login", Message: "reading key from stdin: " + err.Error()}
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Command: "login", Message: "--key-stdin: no key on stdin",
			Hint: `printf %s "$TVAULT_KEY" | tvault login --key-stdin --as <name>`}
	}
	return k, nil
}

func init() {
	loginCmd.Flags().Bool("key-stdin", false, "read the tvagent_*/tvkey_* key from stdin (preferred over --key: keeps it out of shell history)")
	loginCmd.Flags().String("as", "", "context name to store the login under")
	loginCmd.Flags().String("key", "", "tvagent_* (agent) or tvkey_* (scoped key) for non-interactive login; the type is detected from the prefix. Note: the value lands in your shell history and process list — prefer --key-stdin")
	loginCmd.Flags().Bool("no-launch-browser", false, "use the manual code-paste flow instead of the loopback browser redirect (for SSH/headless sessions)")
	loginCmd.Flags().String("api-url", defaultAPIURL, "API base URL")
	loginCmd.Flags().String("frontend-url", defaultFrontendURL, "frontend base URL (hosts /cli/auth)")
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}
