package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

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

// safeText makes server-supplied text (agent/key names, which any principal
// holding agents:create can choose) safe to print in a prompt: anything with
// control, escape or invisible formatting characters (ANSI sequences,
// newlines, bidi overrides) is shown quoted with those characters escaped, so
// a name can't repaint or spoof what the user is confirming.
func safeText(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r != ' ' && !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(s)
	}
	return s
}

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
	safe := make([]string, len(items))
	for i, it := range items {
		safe[i] = safeText(it)
	}
	cmd.PrintErrf("About to %s: %s\n", action, strings.Join(safe, ", "))
	cmd.PrintErr("Continue? [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}
