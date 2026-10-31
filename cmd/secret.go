package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Seams for tests: whether stdin is a terminal, and the hidden prompt.
var (
	stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// readHidden prompts on stderr and reads one line without echo.
	readHidden = func(prompt string) (string, error) {
		os.Stderr.WriteString(prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		os.Stderr.WriteString("\n")
		return string(b), err
	}
)

const maxSecretBytes = 1 << 20

// addValueFlags registers the secret-input flags shared by add/create/set.
func addValueFlags(c *cobra.Command, valueHelp string) {
	c.Flags().String("value", "", valueHelp+" (lands in shell history — prefer the prompt or --value-stdin)")
	c.Flags().Bool("value-stdin", false, "read the value from stdin (also the default when stdin is not a terminal)")
}

// readSecretValue resolves a credential value without putting it on the
// command line:
//
//	--value               used as given, with a shell-history warning on stderr
//	--value-stdin or a    read from stdin; one trailing newline is trimmed
//	non-terminal stdin
//	terminal stdin        hidden prompt
//
// An empty value is returned as "" with a nil error only when allowEmpty is
// set and the source was implicit (piped without --value-stdin, or an empty
// prompt answer); an empty value from --value-stdin is always an error.
func readSecretValue(cmd *cobra.Command, command string, allowEmpty bool) (string, error) {
	if cmd.Flags().Changed("value") {
		v, _ := cmd.Flags().GetString("value")
		cmd.PrintErrln("warning: --value puts the secret in your shell history and process list; prefer the prompt or --value-stdin")
		return v, nil
	}
	explicit, _ := cmd.Flags().GetBool("value-stdin")
	if explicit || !stdinIsTTY() {
		b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxSecretBytes))
		if err != nil {
			return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "reading value from stdin: " + err.Error()}
		}
		v := trimOneNewline(string(b))
		if v == "" && (explicit || !allowEmpty) {
			return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "no value on stdin",
				Hint: `printf %s "$SECRET" | tvault ` + map[string]string{"tokens create": "add", "tokens set": "set"}[command] + ` <service> --value-stdin`}
		}
		return v, nil
	}
	prompt := "Value (hidden): "
	if allowEmpty {
		prompt = "Value (hidden; empty creates the token without one): "
	}
	v, err := readHidden(prompt)
	if err != nil {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "reading value: " + err.Error()}
	}
	if v == "" && !allowEmpty {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "empty value"}
	}
	return v, nil
}

// trimOneNewline drops a single trailing "\n" or "\r\n", nothing else.
func trimOneNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
		s = strings.TrimSuffix(s, "\r")
	}
	return s
}
