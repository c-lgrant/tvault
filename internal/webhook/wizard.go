package webhook

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Wizard runs the interactive `tvault webhook init` prompts against arbitrary
// streams so it can be tested without a TTY.
type Wizard struct {
	In  io.Reader
	Out io.Writer
}

// isTerminalFD and readPasswordFD are package vars so tests can simulate a TTY
// without needing one. Production paths call term.IsTerminal and
// term.ReadPassword unchanged.
var (
	isTerminalFD   = term.IsTerminal
	readPasswordFD = term.ReadPassword
)

// secretFromTerminal returns the masked-read value if In is a TTY-backed
// *os.File, plus a bool indicating whether the masked path was taken. When
// false the caller falls back to the non-secret line read.
func (w *Wizard) secretFromTerminal() (string, bool, error) {
	f, ok := w.In.(*os.File)
	if !ok {
		return "", false, nil
	}
	fd := int(f.Fd())
	if !isTerminalFD(fd) {
		return "", false, nil
	}
	b, err := readPasswordFD(fd)
	if err != nil {
		return "", true, err
	}
	// ReadPassword swallows the user's Enter — emit a newline so subsequent
	// prompts don't run together on the same line.
	fmt.Fprintln(w.Out)
	return strings.TrimSpace(string(b)), true, nil
}

// Run prompts for an exposure method and its params, returning the chosen
// method and the collected values. An empty method line selects the first
// method; any required param left blank is an error.
func (w *Wizard) Run() (Method, map[string]string, error) {
	r := bufio.NewReader(w.In)
	ms := Methods()

	fmt.Fprintln(w.Out, "Choose an exposure method:")
	for i, m := range ms {
		fmt.Fprintf(w.Out, "  %d) %s — %s\n", i+1, m.Label, m.Description)
		fmt.Fprintf(w.Out, "       help: %s\n", m.HelpURL)
	}
	fmt.Fprint(w.Out, "Method [1]: ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return Method{}, nil, fmt.Errorf("reading method choice: %w", err)
	}
	line = strings.TrimSpace(line)
	idx := 1
	if line != "" {
		idx, err = strconv.Atoi(line)
		if err != nil || idx < 1 || idx > len(ms) {
			return Method{}, nil, fmt.Errorf("invalid choice %q", line)
		}
	}
	m := ms[idx-1]

	values := map[string]string{}
	for _, p := range m.Params {
		fmt.Fprintf(w.Out, "%s (%s): ", p.Prompt, p.Help)
		v, err := w.readParam(r, p)
		if err != nil {
			return Method{}, nil, err
		}
		if v == "" {
			return Method{}, nil, fmt.Errorf("%s is required", p.Key)
		}
		values[p.Key] = v
	}
	return m, values, nil
}

// readParam reads one param: masked when it's a secret over a TTY, plain line
// otherwise.
func (w *Wizard) readParam(r *bufio.Reader, p Param) (string, error) {
	if p.Secret {
		v, ok, err := w.secretFromTerminal()
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", p.Key, err)
		}
		if ok {
			return v, nil
		}
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading %s: %w", p.Key, err)
	}
	return strings.TrimSpace(line), nil
}
