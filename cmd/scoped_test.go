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

	"github.com/c-lgrant/tvault/internal/api"
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

// A key limited to grants:write must be able to grant by agent ID without the
// CLI listing agents (which needs agents:read).
func TestGrantsAdd_AgentIDSkipsAgentList(t *testing.T) {
	const agentID = "aB3dE5gH7jK9mN1pQ2rS" // 20-char Firestore-style ID
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == "GET" && r.URL.Path == "/api/agents" {
			w.WriteHeader(403)
			w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"denied","missingScope":"agents:read"}}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "k", APIKey: "tvkey_gw"})

	_, stderr, err := runCLI(t, "agents", "grants", "add", agentID, "github")
	if err != nil {
		t.Fatalf("grants add errored: %v", err)
	}
	if len(calls) != 1 || calls[0] != "POST /api/agents/"+agentID+"/grants" {
		t.Errorf("calls = %v, want a single POST (no GET /api/agents)", calls)
	}
	if !strings.Contains(stderr, "Granted 1") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestResolveAgentRefs_NameLookupScopeDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"denied","missingScope":"agents:read"}}`))
	}))
	defer srv.Close()
	client := &api.Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_gw"}

	_, err := resolveAgentRefs(client, []string{"my-agent"})
	if err == nil || clierr.ExitCode(err) != 8 {
		t.Fatalf("want scope-denied exit 8, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent ID") {
		t.Errorf("error should suggest passing the agent ID: %v", err)
	}
}

func TestLoginKeyStdin(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"principal":{"type":"key","id":"k1","name":"ci-key"},"userId":"u","kind":"scoped","scopes":[],"expiresAt":null}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	origIn, origTTY := loginStdin, loginStdinIsTTY
	t.Cleanup(func() { loginStdin, loginStdinIsTTY = origIn, origTTY })

	// Piped key with surrounding whitespace/newline: trimmed, prefix-detected.
	loginStdin, loginStdinIsTTY = strings.NewReader("  tvkey_piped\n"), func() bool { return false }
	_, _, err := runCLI(t, "login", "--key-stdin", "--as", "k", "--api-url", srv.URL)
	if err != nil {
		t.Fatalf("login --key-stdin errored: %v", err)
	}
	if auth != "Bearer tvkey_piped" {
		t.Errorf("validated with Authorization %q, want the trimmed key", auth)
	}
	cfg, _ := config.Load()
	if c := cfg.Contexts["k"]; c == nil || c.Type != "key" || c.APIKey != "tvkey_piped" {
		t.Errorf("stored context wrong: %+v", c)
	}

	// Empty pipe.
	loginStdin = strings.NewReader("\n")
	if _, _, err := runCLI(t, "login", "--key-stdin", "--as", "e", "--api-url", srv.URL); err == nil || !strings.Contains(err.Error(), "no key on stdin") {
		t.Errorf("empty stdin should error, got %v", err)
	}

	// Interactive terminal: refuse with a pipe hint.
	loginStdinIsTTY = func() bool { return true }
	_, _, err = runCLI(t, "login", "--key-stdin", "--as", "t", "--api-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "terminal") || !strings.Contains(err.Error(), "--key-stdin") {
		t.Errorf("TTY stdin should be refused with a hint, got %v", err)
	}
	if clierr.ExitCode(err) != 1 {
		t.Errorf("exit = %d", clierr.ExitCode(err))
	}

	// --key and --key-stdin together.
	loginStdinIsTTY = func() bool { return false }
	if _, _, err := runCLI(t, "login", "--key-stdin", "--key", "tvkey_x", "--as", "m", "--api-url", srv.URL); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("want mutual-exclusion error, got %v", err)
	}
}

// Admin whoami against a server that predates scoped keys falls back to the
// local report instead of failing.
func TestWhoami_AdminFallsBackOnLegacyServer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"403 INVALID_KEY", 403, `{"detail":{"code":"INVALID_KEY","message":"Invalid agent API key format"}}`},
		{"401 INVALID_KEY", 401, `{"detail":{"code":"INVALID_KEY","message":"Invalid agent API key format"}}`},
		{"404", 404, `{"detail":"Not Found"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// ID tokens are never persisted, so resolve() refreshes first.
				if r.URL.Path == "/api/cli/auth/refresh" {
					w.Write([]byte(`{"id_token":"idt","expires_in":3600}`))
					return
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			setupContext(t, &config.Context{Type: "admin", APIURL: srv.URL, Identity: "me@example.com", RefreshToken: "rt"})

			stdout, stderr, err := runCLI(t, "whoami", "--format", "table")
			if err != nil {
				t.Fatalf("whoami should fall back, got %v", err)
			}
			out := stdout + stderr
			for _, want := range []string{"me@example.com", "user (server predates scoped keys)", "scopes   : none", "token    : expires in"} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// Key contexts never fall back: INVALID_KEY is a real answer for them.
func TestWhoami_KeyContextInvalidKeyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"detail":{"code":"INVALID_KEY","message":"bad key"}}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "k", APIKey: "tvkey_bad"})
	_, _, err := runCLI(t, "whoami", "--format", "table")
	if clierr.ExitCode(err) != 12 {
		t.Errorf("exit = %d, want 12 (%v)", clierr.ExitCode(err), err)
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

// A grant refused after the agent is created must not exit 0: the key is
// still printed (it is shown only once), but the scope refusal keeps exit 8.
func TestAgentsCreate_GrantFailureIsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/agents":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"a1","name":"child","apiKey":"tvagent_child","kind":"scoped"}`))
		case r.Method == "POST" && r.URL.Path == "/api/agents/a1/grants":
			w.WriteHeader(403)
			w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"no","missingScope":"grants:write"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "ci", APIKey: "tvkey_k"})

	stdout, _, err := runCLI(t, "agents", "create", "--kind", "scoped", "--name", "child",
		"--scopes", "credentials:read", "--grants", "github", "--non-interactive")
	if stdout != "tvagent_child\n" {
		t.Errorf("stdout = %q, want the key even when grants fail", stdout)
	}
	if code := clierr.ExitCode(err); code != 8 {
		t.Errorf("exit code = %d, want 8 (err=%v)", code, err)
	}
}

// --self rotates the context's own key (found via whoami, no keys:manage
// lookup) and switches the stored context to the new key.
func TestKeysRotateSelf_UpdatesContext(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/agents/whoami":
			w.Write([]byte(`{"principal":{"type":"api_key","id":"k1","name":"ci"},"kind":"api_key","scopes":["tokens:list"]}`))
		case r.Method == "POST" && r.URL.Path == "/api/keys/k1/rotate":
			w.Write([]byte(`{"id":"k1","key":"tvkey_new"}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "ci", APIKey: "tvkey_old"})

	stdout, _, err := runCLI(t, "keys", "rotate", "--self")
	if err != nil {
		t.Fatalf("rotate --self errored: %v (requests %v)", err, paths)
	}
	if stdout != "tvkey_new\n" {
		t.Errorf("stdout = %q", stdout)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Contexts["t"].APIKey; got != "tvkey_new" {
		t.Errorf("context key = %q, want the rotated key", got)
	}
}

func TestKeysRotate_NeedsArgOrSelf(t *testing.T) {
	setupContext(t, &config.Context{Type: "key", APIURL: "http://127.0.0.1:1", Identity: "ci", APIKey: "tvkey_k"})
	for _, args := range [][]string{{"keys", "rotate"}, {"keys", "rotate", "k1", "--self"}} {
		keysRotateCmd.Flags().Set("self", "false") // cobra keeps flag values between Execute calls
		if _, _, err := runCLI(t, args...); clierr.ExitCode(err) != 1 {
			t.Errorf("%v: want a usage error, got %v", args, err)
		}
	}
}
