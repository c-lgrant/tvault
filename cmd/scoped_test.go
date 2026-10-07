package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

// setupContext writes a single active context pointing at apiURL into an
// isolated config dir.
func setupContext(t *testing.T, ctx *config.Context) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	cfg := &config.Config{Current: "t", Contexts: map[string]*config.Context{"t": ctx}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

// runCLI executes the root command with args, returning captured stdout,
// stderr and the command error. Stdout is captured at the os.Stdout level
// because key-printing commands write to it directly.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })

	origOut := os.Stdout
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()

	errBuf := new(bytes.Buffer)
	rootCmd.SetErr(errBuf)
	rootCmd.SetOut(errBuf)
	rootCmd.SetArgs(args)
	err = rootCmd.Execute()

	w.Close()
	os.Stdout = origOut
	stdout = <-done
	return stdout, errBuf.String(), err
}

func TestKeysCreate_KeyOnlyOnStdout(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.Method != "POST" || r.URL.Path != "/api/keys" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"k1","key":"tvkey_secret123","name":"ci","scopes":["credentials:read","tokens:list"],"expiresAt":"2027-01-01T00:00:00Z","createdAt":"2026-10-07T00:00:00Z"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "ci", APIKey: "tvkey_admin"})

	stdout, stderr, err := runCLI(t, "keys", "create", "--name", "ci",
		"--scopes", "credentials:read,tokens:list", "--expires", "30d")
	if err != nil {
		t.Fatalf("keys create errored: %v", err)
	}
	if stdout != "tvkey_secret123\n" {
		t.Errorf("stdout = %q, want only the key", stdout)
	}
	if strings.Contains(stderr, "tvkey_secret123") {
		t.Errorf("key leaked to stderr: %q", stderr)
	}
	if !strings.Contains(stderr, "credentials:read,tokens:list") {
		t.Errorf("metadata missing from stderr: %q", stderr)
	}
	if auth != "Bearer tvkey_admin" {
		t.Errorf("Authorization = %q", auth)
	}
	if got["name"] != "ci" {
		t.Errorf("body name = %v", got["name"])
	}
	if scopes, _ := got["scopes"].([]any); len(scopes) != 2 {
		t.Errorf("body scopes = %v", got["scopes"])
	}
	if s, _ := got["expiresAt"].(string); s == "" {
		t.Errorf("30d should send an expiresAt timestamp, got %v", got["expiresAt"])
	}
}

// An agent context must no longer be refused client-side: the request goes to
// the server, which is the sole enforcer.
func TestTokensCreate_AgentContextSendsRequest(t *testing.T) {
	var hit bool
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		auth = r.Header.Get("Authorization")
		if r.Method != "POST" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"key lacks scope","missingScope":"tokens:create"}}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})

	_, _, err := runCLI(t, "tokens", "create", "--service", "github")
	if !hit {
		t.Fatalf("no request reached the server — still refused client-side? err=%v", err)
	}
	if auth != "Bearer tvagent_abc" {
		t.Errorf("Authorization = %q", auth)
	}
	// The server's refusal surfaces as the distinct scope exit code, naming
	// the missing scope.
	if code := clierr.ExitCode(err); code != 8 {
		t.Errorf("exit code = %d, want 8 (err=%v)", code, err)
	}
	if err == nil || !strings.Contains(err.Error(), "tokens:create") {
		t.Errorf("error should name the missing scope: %v", err)
	}
}

func TestWhoami_KeyContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/whoami" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"principal":{"type":"key","id":"k1","name":"ci"},"userId":"u1","kind":"scoped","scopes":["credentials:read"],"expiresAt":"2027-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "ci", APIKey: "tvkey_x"})

	stdout, stderr, err := runCLI(t, "whoami", "--format", "json")
	if err != nil {
		t.Fatalf("whoami errored: %v (%s)", err, stderr)
	}
	var doc map[string]any
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("whoami --format json not JSON: %v\n%s", jerr, stdout)
	}
	if doc["kind"] != "scoped" || doc["expiresAt"] != "2027-01-01T00:00:00Z" {
		t.Errorf("unexpected whoami json: %v", doc)
	}
}

func TestParseExpiry(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	got, err := parseExpiry("30d", now)
	if err != nil || got == nil || *got != "2026-11-06T12:00:00Z" {
		t.Errorf("30d = %v, %v", got, err)
	}
	if got, err := parseExpiry("never", now); err != nil || got != nil {
		t.Errorf("never = %v, %v", got, err)
	}
	got, err = parseExpiry("2027-01-01", now)
	if err != nil || got == nil || *got != "2027-01-01T23:59:59Z" {
		t.Errorf("date = %v, %v", got, err)
	}
	for _, bad := range []string{"", "soon", "0d", "-5d", "2020-01-01", "2026-13-40"} {
		if _, err := parseExpiry(bad, now); err == nil {
			t.Errorf("parseExpiry(%q) should fail", bad)
		} else {
			var ce *clierr.CLIError
			if !errors.As(err, &ce) || ce.Kind != clierr.KindUser {
				t.Errorf("parseExpiry(%q) error kind wrong: %v", bad, err)
			}
		}
	}
}
