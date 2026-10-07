// Package clierr defines the CLI's structured error type, its exit-code
// mapping, and the multi-line error footer format used across commands.
package clierr

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Kind int

const (
	KindUser         Kind = iota // 1 — bad args, validation, not found
	KindAuth                     // 2 — no context, expired, refresh failed
	KindNetwork                  // 3 — connect timeout, DNS, no route
	KindServer                   // 4 — 5xx
	KindVaultLocked              // 5 — 423 VAULT_LOCKED
	KindEmpty                    // 6 — token exists but has no credential value
	KindRateLimited              // 7 — 429 rate limited / penalty-boxed
	KindScopeDenied              // 8 — 403 SCOPE_DENIED: the key lacks a required scope
	KindHumanOnly                // 9 — 403 HUMAN_ONLY: operation needs a signed-in human
	KindKeyExpired               // 10 — 401 KEY_EXPIRED: the API key is past its expiry
	KindKeySuspended             // 11 — 403 KEY_SUSPENDED: the key is suspended
	KindInvalidKey               // 12 — 401 INVALID_KEY: the key is unknown or malformed
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
	case KindRateLimited:
		return 7
	case KindScopeDenied:
		return 8
	case KindHumanOnly:
		return 9
	case KindKeyExpired:
		return 10
	case KindKeySuspended:
		return 11
	case KindInvalidKey:
		return 12
	default:
		return 1
	}
}

// CLIError is the canonical error returned by every command. Fields beyond
// Kind/Message are optional and only render when set.
type CLIError struct {
	Kind       Kind
	Code       string        // server error code, e.g. "SCOPE_DENIED"; empty when none
	Scope      string        // missing scope for SCOPE_DENIED, e.g. "tokens:create"
	Command    string        // e.g. "agents create"
	Message    string        // human-readable summary
	Context    string        // e.g. "nuc-admin (admin · conor@example.com)"
	Request    string        // e.g. "POST /api/agents"
	Response   string        // e.g. "403 POLICY_DENIED — agent quota exceeded"
	Hint       string        // a likely fix; rendered only when known
	RetryAfter time.Duration // server-provided backoff (429 Retry-After); 0 = unknown
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
