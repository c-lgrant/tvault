package cmd

import (
	"bufio"
	"io"
	"os"
	"strings"
	"time"

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

// Seams for tests: the file mode of stdin, and how long an implicit read
// waits for a pipe to produce its first byte.
var (
	stdinMode = func() os.FileMode {
		fi, err := os.Stdin.Stat()
		if err != nil {
			return os.ModeIrregular
		}
		return fi.Mode()
	}
	stdinFirstByteWait = 2 * time.Second
)

// readImplicitStdin reads stdin when --value-stdin was NOT given. A regular
// file or /dev/null is read to EOF. A pipe or socket may be an open pipe
// nobody writes to (docker exec -i, harnesses), so it is read only if its
// first byte arrives within stdinFirstByteWait; otherwise got is false and
// the caller treats it as "no value". Anything else is treated as no value.
func readImplicitStdin(in io.Reader) (b []byte, got bool, err error) {
	mode := stdinMode()
	switch {
	case mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0:
		br := bufio.NewReader(in)
		peeked := make(chan error, 1)
		go func() { _, e := br.Peek(1); peeked <- e }()
		select {
		case e := <-peeked:
			if e != nil && e != io.EOF {
				return nil, false, e
			}
		case <-time.After(stdinFirstByteWait):
			return nil, false, nil
		}
		in = br
	case mode.IsRegular() || mode&os.ModeCharDevice != 0:
	default:
		return nil, false, nil
	}
	b, err = io.ReadAll(io.LimitReader(in, maxSecretBytes))
	return b, len(b) > 0, err
}

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
		hint := `printf %s "$SECRET" | tvault ` + map[string]string{"tokens create": "add", "tokens set": "set"}[command] + ` <service> --value-stdin`
		var b []byte
		var err error
		if explicit {
			b, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxSecretBytes))
		} else {
			var got bool
			b, got, err = readImplicitStdin(cmd.InOrStdin())
			if err == nil && !got && !allowEmpty {
				return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command,
					Message: "no value: stdin is not a terminal but sent no data", Hint: hint}
			}
		}
		if err != nil {
			return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "reading value from stdin: " + err.Error()}
		}
		v := trimOneNewline(string(b))
		if v == "" && (explicit || !allowEmpty) {
			return "", &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "no value on stdin", Hint: hint}
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
