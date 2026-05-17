package clierr

import (
	"errors"
	"strings"
	"testing"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{&CLIError{Kind: KindUser}, 1},
		{&CLIError{Kind: KindAuth}, 2},
		{&CLIError{Kind: KindNetwork}, 3},
		{&CLIError{Kind: KindServer}, 4},
		{&CLIError{Kind: KindVaultLocked}, 5},
		{&CLIError{Kind: KindEmpty}, 6},
		{errors.New("plain error"), 1},
	}
	for _, c := range cases {
		if got := ExitCode(c.err); got != c.want {
			t.Errorf("ExitCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestErrorFooter(t *testing.T) {
	e := &CLIError{
		Kind:    KindServer,
		Command: "agents create",
		Message: "agent quota exceeded",
		Context: "nuc-admin (admin · conor@example.com)",
		Request: "POST /api/agents",
		Hint:    "tvault vault unlock",
	}
	out := e.Error()
	for _, want := range []string{
		"tvault: agents create: agent quota exceeded",
		"context : nuc-admin",
		"request : POST /api/agents",
		"hint    : tvault vault unlock",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Error() missing %q; got:\n%s", want, out)
		}
	}
}
