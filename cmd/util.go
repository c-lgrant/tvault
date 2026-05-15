package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func toStr(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func joinComma(ss []string) string { return strings.Join(ss, ",") }

// confirmDestructive gates a destructive action behind --force or an
// interactive y/N prompt. In a non-interactive shell without --force it
// refuses outright rather than hanging on stdin.
func confirmDestructive(cmd *cobra.Command, cc *cmdContext, action string, items []string, force bool) bool {
	if force {
		return true
	}
	if cc == nil || !term.IsTerminal(int(os.Stdin.Fd())) {
		cmd.PrintErrln("refusing to " + action + " without --force in a non-interactive shell")
		return false
	}
	cmd.PrintErrf("About to %s: %s\n", action, strings.Join(items, ", "))
	cmd.PrintErr("Continue? [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}
