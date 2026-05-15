package webhook

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestWizardNgrok(t *testing.T) {
	in := strings.NewReader("1\nmy-token\nfoo.ngrok-free.app\n")
	w := &Wizard{In: in, Out: io.Discard}
	m, vals, err := w.Run()
	if err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	if m.ID != "ngrok" {
		t.Errorf("method = %q, want ngrok", m.ID)
	}
	if vals["NGROK_AUTHTOKEN"] != "my-token" || vals["NGROK_URL"] != "foo.ngrok-free.app" {
		t.Errorf("values = %v", vals)
	}
}

func TestWizardDefaultChoice(t *testing.T) {
	// Empty method line selects method 1 (ngrok).
	in := strings.NewReader("\ntok\ndomain\n")
	w := &Wizard{In: in, Out: io.Discard}
	m, _, err := w.Run()
	if err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	if m.ID != "ngrok" {
		t.Errorf("default method = %q, want ngrok", m.ID)
	}
}

func TestWizardInvalidChoice(t *testing.T) {
	for _, in := range []string{"99\n", "0\n", "abc\n", "-1\n"} {
		w := &Wizard{In: strings.NewReader(in), Out: io.Discard}
		if _, _, err := w.Run(); err == nil {
			t.Errorf("choice %q should error", in)
		}
	}
}

func TestWizardPrintsMenuAndPrompts(t *testing.T) {
	var out strings.Builder
	w := &Wizard{In: strings.NewReader("1\ntok\ndomain\n"), Out: &out}
	if _, _, err := w.Run(); err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	s := out.String()
	for _, want := range []string{
		"Choose an exposure method:", "ngrok", "Method [1]:", "ngrok authtoken",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("wizard output missing %q\n%s", want, s)
		}
	}
}

func TestWizardTailscaleThreeParams(t *testing.T) {
	in := strings.NewReader("3\nauth-key\ntv-host\nhttps://tv-host.ts.net\n")
	w := &Wizard{In: in, Out: io.Discard}
	m, vals, err := w.Run()
	if err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	if m.ID != "tailscale" {
		t.Errorf("method = %q, want tailscale", m.ID)
	}
	if vals["TS_AUTHKEY"] != "auth-key" || vals["TS_HOSTNAME"] != "tv-host" || vals["WEBHOOK_EXTERNAL_URL"] != "https://tv-host.ts.net" {
		t.Errorf("values = %v", vals)
	}
}

func TestWizardMissingParam(t *testing.T) {
	// Method 4 (custom) then an empty required URL line.
	w := &Wizard{In: strings.NewReader("4\n\n"), Out: io.Discard}
	if _, _, err := w.Run(); err == nil {
		t.Error("empty required param should error")
	}
}

// fakeTerminal swaps the package-level TTY hooks for the duration of the test.
// Calls to readPasswordFD return successive entries from secrets.
func fakeTerminal(t *testing.T, secrets ...string) {
	t.Helper()
	prevIsTTY := isTerminalFD
	prevRead := readPasswordFD
	calls := 0
	isTerminalFD = func(int) bool { return true }
	readPasswordFD = func(int) ([]byte, error) {
		if calls >= len(secrets) {
			return nil, errors.New("readPasswordFD called more times than secrets supplied")
		}
		s := secrets[calls]
		calls++
		return []byte(s), nil
	}
	t.Cleanup(func() {
		isTerminalFD = prevIsTTY
		readPasswordFD = prevRead
	})
}

func TestWizardSecretMaskedOnTerminal(t *testing.T) {
	fakeTerminal(t, "super-secret-token")

	// Pipe read end is *os.File so the type-assert in secretFromTerminal
	// succeeds; the fake isTerminalFD then forces the masked branch for the
	// secret param. Non-secret lines (method choice, NGROK_URL) flow through
	// bufio from the same pipe.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()
	if _, err := pw.WriteString("\nfoo.ngrok-free.app\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	pw.Close()

	w := &Wizard{In: pr, Out: io.Discard}
	m, vals, err := w.Run()
	if err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	if m.ID != "ngrok" {
		t.Fatalf("method = %q, want ngrok", m.ID)
	}
	if vals["NGROK_AUTHTOKEN"] != "super-secret-token" {
		t.Errorf("masked secret = %q, want %q", vals["NGROK_AUTHTOKEN"], "super-secret-token")
	}
	if vals["NGROK_URL"] != "foo.ngrok-free.app" {
		t.Errorf("non-secret = %q", vals["NGROK_URL"])
	}
}

func TestWizardSecretEmptyMaskedIsRequired(t *testing.T) {
	// User hits Enter at the masked prompt → empty value → required-error.
	fakeTerminal(t, "")

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()
	pw.WriteString("\n")
	pw.Close()

	w := &Wizard{In: pr, Out: io.Discard}
	_, _, err = w.Run()
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("empty masked secret = %v, want required error", err)
	}
}

func TestWizardSecretFallsBackWithoutTerminal(t *testing.T) {
	// strings.Reader is not *os.File → masked path skipped → secret read via
	// bufio. Existing TestWizardNgrok covers the happy value-path; this test
	// asserts the gating path explicitly via fakeTerminal not being engaged.
	in := strings.NewReader("1\nplain-token\nfoo.ngrok-free.app\n")
	w := &Wizard{In: in, Out: io.Discard}
	_, vals, err := w.Run()
	if err != nil {
		t.Fatalf("wizard errored: %v", err)
	}
	if vals["NGROK_AUTHTOKEN"] != "plain-token" {
		t.Errorf("fallback secret = %q", vals["NGROK_AUTHTOKEN"])
	}
}
