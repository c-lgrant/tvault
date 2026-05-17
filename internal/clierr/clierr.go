// Package clierr defines the CLI's structured error type, its exit-code
// mapping, and the multi-line error footer format used across commands.
package clierr

import (
	"errors"
	"fmt"
	"strings"
)

type Kind int

const (
	KindUser        Kind = iota // 1 — bad args, validation, not found
	KindAuth                    // 2 — no context, expired, refresh failed
	KindNetwork                 // 3 — connect timeout, DNS, no route
	KindServer                  // 4 — 5xx
	KindVaultLocked             // 5 — 423 VAULT_LOCKED
	KindEmpty                   // 6 — token exists but has no credential value
)

func (k Kind) exitCode() int {
	switch k {
	case KindUser:
		return 1
	case KindAuth:
		return 2
	case KindNetwork:
		return 3
	case KindServer:
		return 4
	case KindVaultLocked:
		return 5
	case KindEmpty:
		return 6
	default:
		return 1
	}
}

// CLIError is the canonical error returned by every command. Fields beyond
// Kind/Message are optional and only render when set.
type CLIError struct {
	Kind     Kind
	Command  string // e.g. "agents create"
	Message  string // human-readable summary
	Context  string // e.g. "nuc-admin (admin · conor@example.com)"
	Request  string // e.g. "POST /api/agents"
	Response string // e.g. "403 POLICY_DENIED — agent quota exceeded"
	Hint     string // a likely fix; rendered only when known
}

func (e *CLIError) Error() string {
	var b strings.Builder
	cmd := e.Command
	if cmd == "" {
		cmd = "error"
	}
	fmt.Fprintf(&b, "tvault: %s: %s", cmd, e.Message)
	if e.Context != "" {
		fmt.Fprintf(&b, "\n  context : %s", e.Context)
	}
	if e.Request != "" {
		fmt.Fprintf(&b, "\n  request : %s", e.Request)
	}
	if e.Response != "" {
		fmt.Fprintf(&b, "\n  response: %s", e.Response)
	}
	if e.Hint != "" {
		fmt.Fprintf(&b, "\n  hint    : %s", e.Hint)
	}
	return b.String()
}

// ExitCode maps any error to a process exit code. nil → 0, *CLIError → its
// Kind's code, anything else → 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ce *CLIError
	if errors.As(err, &ce) {
		return ce.Kind.exitCode()
	}
	return 1
}
