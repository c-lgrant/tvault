package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Build-time variables, set via -ldflags by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "tvault",
	Short: "Token Vault CLI — manage credentials, agents, and grants",
	Long: `tvault is the command-line interface for Token Vault.

It mirrors the web console: manage tokens, agents, grants, and the vault lock,
with a browser-based login and kubectl-style contexts for switching between
admin and agent personas.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Bare `tvault [service...]` is the legacy back-compat shim: with args it
	// prints that service's credential, with none it shows help. Cobra still
	// dispatches to real subcommands first; RunE only fires when no subcommand
	// matches.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runShim(cmd, args)
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip the migration prompt for commands that should never block on it.
		if cmd.Name() == "version" || cmd.Name() == "completion" || cmd.Name() == "help" {
			return nil
		}
		_, err := config.MigrateLegacy(func(prompt string) bool {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return false // never block scripts on a prompt
			}
			fmt.Fprint(os.Stderr, prompt)
			var answer string
			if n, err := fmt.Scanln(&answer); err != nil && n == 0 {
				return false
			}
			answer = strings.ToLower(strings.TrimSpace(answer))
			return answer == "" || answer == "y" || answer == "yes"
		})
		return err
	},
}

// errShowedHelp is returned by an Args validator after it has already printed
// the command's help text — Execute() then exits cleanly without printing it.
var errShowedHelp = errors.New("help shown")

// helpOnMissingArgs wraps every command's Args validator so an argument-count
// failure prints that command's help instead of a terse "accepts N arg(s)"
// error. Applied to the whole tree once, in Execute().
func helpOnMissingArgs(cmd *cobra.Command) {
	for _, c := range cmd.Commands() {
		helpOnMissingArgs(c)
	}
	orig := cmd.Args
	if orig == nil {
		return // nil Args means ArbitraryArgs — nothing to fail on
	}
	cmd.Args = func(c *cobra.Command, args []string) error {
		if err := orig(c, args); err != nil {
			_ = c.Help()
			return errShowedHelp
		}
		return nil
	}
}

// Execute runs the root command and maps returned errors to exit codes.
func Execute() {
	helpOnMissingArgs(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errShowedHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(clierr.ExitCode(err))
	}
}

func init() {
	rootCmd.PersistentFlags().String("context", "", "override the active context for this command")
	// --ctx mirrors --context (Cobra has no long-flag aliases, so a parallel
	// flag is the cleanest path). resolve() prefers whichever was set.
	rootCmd.PersistentFlags().String("ctx", "", "alias for --context")
	rootCmd.PersistentFlags().String("format", "", "output format: json|table|wide|name")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	rootCmd.PersistentFlags().Bool("debug", false, "print HTTP request/response diagnostics to stderr")
	rootCmd.PersistentFlags().Bool("dry-run", false, "print the request a write command would send, without sending it")
}
