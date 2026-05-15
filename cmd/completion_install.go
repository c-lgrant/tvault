package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// installPlan describes where a shell's completion script lands and what (if
// anything) the user must do after the file is written.
type installPlan struct {
	shell        string
	path         string // absolute target file
	autoDiscover bool   // shell auto-loads from path; no rc edit needed
	enableHint   string // one-liner to print when !autoDiscover
}

// resolveInstallPlan returns the install plan for shell using XDG-aware paths
// rooted at home. xdgData and xdgConfig override XDG_DATA_HOME / XDG_CONFIG_HOME
// when non-empty (the caller already resolved them with the env-var fallback).
func resolveInstallPlan(shell, home, xdgData, xdgConfig string) (*installPlan, error) {
	if xdgData == "" {
		xdgData = filepath.Join(home, ".local", "share")
	}
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	switch shell {
	case "bash":
		return &installPlan{
			shell:        "bash",
			path:         filepath.Join(xdgData, "bash-completion", "completions", "tvault"),
			autoDiscover: true,
		}, nil
	case "fish":
		return &installPlan{
			shell:        "fish",
			path:         filepath.Join(xdgConfig, "fish", "completions", "tvault.fish"),
			autoDiscover: true,
		}, nil
	case "zsh":
		dir := filepath.Join(xdgData, "zsh", "site-functions")
		return &installPlan{
			shell:        "zsh",
			path:         filepath.Join(dir, "_tvault"),
			autoDiscover: false,
			enableHint: fmt.Sprintf(
				"Add the following to your ~/.zshrc, then start a new shell:\n"+
					"  fpath=(%q $fpath)\n"+
					"  autoload -Uz compinit && compinit",
				dir,
			),
		}, nil
	case "powershell":
		return nil, fmt.Errorf("powershell install isn't supported; use `tvault completion powershell` and dot-source the output from your $PROFILE")
	default:
		return nil, fmt.Errorf("unknown shell %q", shell)
	}
}

// resolveHomeAndXDG centralises the env lookups so tests can override via
// t.Setenv.
func resolveHomeAndXDG() (home, xdgData, xdgConfig string, err error) {
	home, err = os.UserHomeDir()
	if err != nil {
		return "", "", "", err
	}
	return home, os.Getenv("XDG_DATA_HOME"), os.Getenv("XDG_CONFIG_HOME"), nil
}

// generateScript writes the completion script for shell into out using the same
// generators as the top-level `completion` command.
func generateScript(out io.Writer, shell string) error {
	switch shell {
	case "bash":
		return rootCmd.GenBashCompletionV2(out, true)
	case "zsh":
		return rootCmd.GenZshCompletion(out)
	case "fish":
		return rootCmd.GenFishCompletion(out, true)
	}
	return fmt.Errorf("no generator for shell %q", shell)
}

// writeAtomic writes data to path with mode 0o644 via a temp file + rename so a
// half-written file can never replace a working completion script.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tvault-completion-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// runInstall handles `tvault completion install <shell>` and the --print-only
// flag. It writes nothing to shared shell rc files; for shells that don't
// auto-discover (zsh) it prints the one-liner the user must add to their rc.
func runInstall(cmd *cobra.Command, shell string, printOnly bool) error {
	home, xdgData, xdgConfig, err := resolveHomeAndXDG()
	if err != nil {
		return err
	}
	plan, err := resolveInstallPlan(shell, home, xdgData, xdgConfig)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if printOnly {
		fmt.Fprintf(out, "Would install %s completion to: %s\n", plan.shell, plan.path)
		if plan.autoDiscover {
			fmt.Fprintf(out, "Auto-discovered by %s after restart — no rc changes needed.\n", plan.shell)
		} else {
			fmt.Fprintln(out, plan.enableHint)
		}
		return nil
	}
	var buf bytes.Buffer
	if err := generateScript(&buf, plan.shell); err != nil {
		return err
	}
	if err := writeAtomic(plan.path, buf.Bytes()); err != nil {
		return fmt.Errorf("writing %s: %w", plan.path, err)
	}
	fmt.Fprintf(out, "Installed %s completion to: %s\n", plan.shell, plan.path)
	if plan.autoDiscover {
		fmt.Fprintf(out, "Restart your shell — %s will pick it up automatically.\n", plan.shell)
	} else {
		fmt.Fprintln(out, plan.enableHint)
	}
	return nil
}

// runUninstall removes the completion file for shell. Missing file is success
// (idempotent) so the command is safe to re-run.
func runUninstall(cmd *cobra.Command, shell string) error {
	home, xdgData, xdgConfig, err := resolveHomeAndXDG()
	if err != nil {
		return err
	}
	plan, err := resolveInstallPlan(shell, home, xdgData, xdgConfig)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if err := os.Remove(plan.path); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(out, "No %s completion file at %s — nothing to remove.\n", plan.shell, plan.path)
			return nil
		}
		return fmt.Errorf("removing %s: %w", plan.path, err)
	}
	fmt.Fprintf(out, "Removed %s completion: %s\n", plan.shell, plan.path)
	if !plan.autoDiscover {
		fmt.Fprintln(out, "If you added an `fpath=(...)` line for this in your ~/.zshrc, remove it too.")
	}
	return nil
}

var validInstallShells = []string{"bash", "zsh", "fish", "powershell"}

func newCompletionInstallCmd() *cobra.Command {
	var printOnly bool
	c := &cobra.Command{
		Use:       "install [bash|zsh|fish|powershell]",
		Short:     "Install the completion script into a self-contained file",
		Long:      "Install writes the shell completion script to a tvault-managed file under XDG paths. It never edits your shell rc; for shells that need an fpath line (zsh) it prints the exact one-liner you can paste.",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: validInstallShells,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, args[0], printOnly)
		},
	}
	c.Flags().BoolVar(&printOnly, "print-only", false, "Print the path and instructions without writing anything")
	return c
}

func newCompletionUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "uninstall [bash|zsh|fish|powershell]",
		Short:     "Remove the installed completion file",
		Long:      "Uninstall removes the file written by `completion install`. Idempotent — missing file is reported and exits 0.",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: validInstallShells,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd, args[0])
		},
	}
}

func init() {
	completionCmd.AddCommand(newCompletionInstallCmd(), newCompletionUninstallCmd())
}
