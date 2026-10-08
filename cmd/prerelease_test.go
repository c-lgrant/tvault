package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cobra keeps flag values between Execute calls in one process; put every
// flag these tests touch back to its default before each CLI run.
func resetFlags(t *testing.T) {
	t.Helper()
	reset := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				_ = sv.Replace(nil)
			} else {
				_ = f.Value.Set(f.DefValue)
			}
			f.Changed = false
		})
	}
	reset(rootCmd.PersistentFlags())
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		reset(c.Flags())
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// recorder is a test server that records "METHOD /path" for every request and
// answers through h.
type recorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []string
}

func newRecorder(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *recorder {
	t.Helper()
	rec := &recorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.calls = append(rec.calls, r.Method+" "+r.URL.Path)
		rec.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *recorder) has(call string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == call {
			return true
		}
	}
	return false
}

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	resetFlags(t)
	return runCLI(t, args...)
}

const (
	keyID   = "kA1bC2dE3fG4hI5jK6lM" // 20-char auto-ID shape
	agentID = "aB3dE5gH7jK9mN1pQ2rS"
)

// ---- agents rotate-key ----

func TestAgentsRotateKey_ByNameResolvesAndPrintsKeyOnce(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + agentID + `","name":"bot","status":"active"}]`))
		case "POST /api/agents/" + agentID + "/rotate-key":
			w.Write([]byte(`{"apiKey":"tvagent_fresh","agentId":"` + agentID + `"}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, stderr, err := run(t, "agents", "rotate-key", "bot")
	if err != nil {
		t.Fatalf("rotate-key errored: %v (calls %v)", err, rec.calls)
	}
	if stdout != "tvagent_fresh\n" {
		t.Errorf("stdout = %q, want only the key", stdout)
	}
	if strings.Contains(stderr, "tvagent_fresh") {
		t.Errorf("secret leaked to stderr: %q", stderr)
	}
}

func TestAgentsRotateKeySelf_UpdatesAgentContext(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents/whoami":
			w.Write([]byte(`{"principal":{"type":"agent","id":"` + agentID + `","name":"bot"},"kind":"scoped","scopes":["credentials:read"]}`))
		case "POST /api/agents/" + agentID + "/rotate-key":
			w.Write([]byte(`{"apiKey":"tvagent_new"}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "agent", APIURL: rec.srv.URL, Identity: "bot", AgentKey: "tvagent_old"})

	stdout, stderr, err := run(t, "agents", "rotate-key", "--self")
	if err != nil {
		t.Fatalf("rotate-key --self errored: %v", err)
	}
	if stdout != "tvagent_new\n" || strings.Contains(stderr, "tvagent_new") {
		t.Errorf("stdout=%q stderr=%q", stdout, stderr)
	}
	cfg, _ := config.Load()
	if got := cfg.Contexts["t"].AgentKey; got != "tvagent_new" {
		t.Errorf("context agent key = %q, want the rotated key", got)
	}
}

// An agent whose name is exactly 20 letters/digits is first tried as an ID;
// the 404 makes the CLI retry it as a name.
func TestAgentsShow_TwentyCharNameFallsBackToNameLookup(t *testing.T) {
	const name = "abcdefghij0123456789"
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents/" + name:
			w.WriteHeader(404)
			w.Write([]byte(`{"detail":"Agent not found"}`))
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + agentID + `","name":"` + name + `","status":"active"}]`))
		case "GET /api/agents/" + agentID:
			w.Write([]byte(`{"id":"` + agentID + `","name":"` + name + `","status":"active","grants":[]}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, _, err := run(t, "agents", "show", name, "--format", "json")
	if err != nil {
		t.Fatalf("show errored: %v (calls %v)", err, rec.calls)
	}
	if !strings.Contains(stdout, agentID) {
		t.Errorf("stdout = %q, want the resolved agent", stdout)
	}
}

// ---- agents create against a server without scoped agents ----

func TestAgentsCreateScoped_OldServerFailsAndCleansUp(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/agents":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"a1","name":"child","apiKey":"tvagent_classic"}`)) // no "kind"
		case "DELETE /api/agents/a1":
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, stderr, err := run(t, "agents", "create", "--kind", "scoped", "--name", "child",
		"--scopes", "grants:write", "--grants", "github", "--non-interactive")
	if clierr.ExitCode(err) != 1 {
		t.Fatalf("exit = %d, want 1 (%v)", clierr.ExitCode(err), err)
	}
	if !strings.Contains(err.Error(), "doesn't support scoped agents") {
		t.Errorf("error = %v", err)
	}
	if stdout != "" || strings.Contains(stderr, "tvagent_classic") || strings.Contains(err.Error(), "tvagent_classic") {
		t.Errorf("key must not be printed: stdout=%q stderr=%q", stdout, stderr)
	}
	if !rec.has("DELETE /api/agents/a1") {
		t.Errorf("the stray agent was not deleted: %v", rec.calls)
	}
	if rec.has("POST /api/agents/a1/grants") {
		t.Errorf("grants must not be applied to the stray agent: %v", rec.calls)
	}
}

func TestAgentsCreateScoped_OldServerCleanupFailureTellsUserToDelete(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"a1","name":"child","apiKey":"tvagent_classic"}`))
			return
		}
		w.WriteHeader(500)
		w.Write([]byte(`{"detail":"boom"}`))
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, _, err := run(t, "agents", "create", "--kind", "scoped", "--name", "child",
		"--scopes", "grants:write", "--non-interactive")
	if clierr.ExitCode(err) != 1 || stdout != "" {
		t.Fatalf("exit=%d stdout=%q err=%v", clierr.ExitCode(err), stdout, err)
	}
	if !strings.Contains(err.Error(), "tvault agents rm a1") {
		t.Errorf("error should name the manual cleanup command: %v", err)
	}
}

func TestAgentsCreateScoped_NewServerSucceeds(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"a1","name":"child","apiKey":"tvagent_scoped","kind":"scoped"}`))
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, stderr, err := run(t, "agents", "create", "--kind", "scoped", "--name", "child",
		"--scopes", "credentials:read", "--non-interactive")
	if err != nil || stdout != "tvagent_scoped\n" || strings.Contains(stderr, "tvagent_scoped") {
		t.Errorf("err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
}

// ---- keys ----

const keyJSON = `{"id":"` + keyID + `","name":"ci","status":"active","scopes":["credentials:read"],"expiresAt":null,"createdAt":"2026-10-01T00:00:00Z","lastUsedAt":null,"createdBy":{"type":"user","id":"u1"}}`

func TestKeysRevoke_NonTTYWithoutForceAborts(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`{"keys":[` + keyJSON + `]}`))
			return
		}
		w.WriteHeader(500)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, _, err := run(t, "keys", "revoke", keyID)
	if clierr.ExitCode(err) != 1 || err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("want an abort mentioning --force, got %v", err)
	}
	if rec.has("DELETE /api/keys/" + keyID) {
		t.Errorf("nothing may be revoked without confirmation: %v", rec.calls)
	}
}

// A key holding only keys:revoke can revoke by ID: the listing is denied, so
// the ID-shaped ref is used as an ID and the server decides.
func TestKeysRevoke_ForceByIDWhenListingDenied(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(403)
			w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"denied","missingScope":"keys:manage"}}`))
			return
		}
		w.Write([]byte(`{}`))
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, stderr, err := run(t, "keys", "revoke", keyID, "--force")
	if err != nil {
		t.Fatalf("revoke errored: %v (calls %v)", err, rec.calls)
	}
	if len(rec.calls) != 2 || rec.calls[1] != "DELETE /api/keys/"+keyID {
		t.Errorf("calls = %v, want a denied listing then the DELETE", rec.calls)
	}
	if !strings.Contains(stderr, "Revoked key") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestKeysByName_ListingDeniedExplainsAndExits8(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"denied","missingScope":"keys:manage"}}`))
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, _, err := run(t, "keys", "revoke", "ci-key", "--force")
	if clierr.ExitCode(err) != 8 || !strings.Contains(err.Error(), "key ID") {
		t.Errorf("want exit 8 suggesting the key ID, got %v", err)
	}
}

func TestKeysGrantUngrantShowLs_CommandLevel(t *testing.T) {
	var grantBody map[string]any
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/keys/" + keyID + "/grants":
			json.NewDecoder(r.Body).Decode(&grantBody)
			w.WriteHeader(201)
			w.Write([]byte(`{"serviceName":"github","grantExpiresAt":"2027-01-01T00:00:00Z"}`))
		case "DELETE /api/keys/" + keyID + "/grants/github":
			w.Write([]byte(`{}`))
		case "GET /api/keys/" + keyID:
			w.Write([]byte(`{"id":"` + keyID + `","name":"ci","status":"active","scopes":["credentials:read"],"expiresAt":null,"createdAt":"2026-10-01T00:00:00Z","lastUsedAt":null,"createdBy":{"type":"user","id":"u1"},"grants":[{"serviceName":"github","source":"auto:create"}]}`))
		case "GET /api/keys":
			w.Write([]byte(`{"keys":[` + keyJSON + `]}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, stderr, err := run(t, "keys", "grant", keyID, "github", "--expires-in-hours", "24")
	if err != nil || !strings.Contains(stderr, `Granted "github"`) {
		t.Fatalf("grant: err=%v stderr=%q", err, stderr)
	}
	if grantBody["serviceName"] != "github" {
		t.Errorf("grant body = %v", grantBody)
	}

	_, stderr, err = run(t, "keys", "ungrant", keyID, "github")
	if err != nil || !strings.Contains(stderr, "Removed grant") {
		t.Fatalf("ungrant: err=%v stderr=%q", err, stderr)
	}

	stdout, _, err := run(t, "keys", "show", keyID, "--format", "json")
	if err != nil || !strings.Contains(stdout, "github (auto:create)") {
		t.Fatalf("show: err=%v stdout=%q", err, stdout)
	}

	stdout, _, err = run(t, "keys", "ls", "--format", "json")
	if err != nil || !strings.Contains(stdout, keyID) {
		t.Fatalf("ls: err=%v stdout=%q", err, stdout)
	}
}

func TestKeysDryRun_DoesNotClaimSuccess(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`{"keys":[` + keyJSON + `]}`))
			return
		}
		w.WriteHeader(500)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	for _, args := range [][]string{
		{"keys", "revoke", keyID, "--force", "--dry-run"},
		{"keys", "grant", keyID, "github", "--dry-run"},
		{"keys", "ungrant", keyID, "github", "--dry-run"},
	} {
		_, stderr, err := run(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, bad := range []string{"Revoked", "Granted", "Removed"} {
			if strings.Contains(stderr, bad) {
				t.Errorf("%v: dry run printed %q: %s", args, bad, stderr)
			}
		}
	}
	for _, c := range rec.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("dry run sent a mutation: %v", rec.calls)
		}
	}
}

func TestKeysCreateAndRotate_SecretNeverOnStderr(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/keys":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"k1","key":"tvkey_created","name":"ci","scopes":["tokens:list"],"expiresAt":null,"createdAt":"2026-10-07T00:00:00Z"}`))
		case "GET /api/keys":
			w.Write([]byte(`{"keys":[` + keyJSON + `]}`))
		case "POST /api/keys/" + keyID + "/rotate":
			w.Write([]byte(`{"id":"` + keyID + `","key":"tvkey_rotated"}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, stderr, err := run(t, "keys", "create", "--name", "ci", "--scopes", "tokens:list", "--expires", "never")
	if err != nil || stdout != "tvkey_created\n" || strings.Contains(stderr, "tvkey_created") {
		t.Errorf("create: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	stdout, stderr, err = run(t, "keys", "rotate", keyID)
	if err != nil || stdout != "tvkey_rotated\n" || strings.Contains(stderr, "tvkey_rotated") {
		t.Errorf("rotate: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
}

// If the new key can't be saved, the key still reaches stdout and the error
// says the rotation itself succeeded.
func TestKeysRotateSelf_SaveFailureExplainsAndKeepsKeyOnStdout(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents/whoami":
			w.Write([]byte(`{"principal":{"type":"api_key","id":"k1","name":"ci"},"kind":"api_key","scopes":[]}`))
		case "POST /api/keys/k1/rotate":
			w.Write([]byte(`{"id":"k1","key":"tvkey_new"}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "ci", APIKey: "tvkey_old"})

	// Make the config directory read-only so Save (a temp file + rename) fails
	// while Load (a read) still works.
	var cfgDir string
	filepath.WalkDir(os.Getenv("XDG_CONFIG_HOME"), func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && d.Name() == "contexts.yaml" {
			cfgDir = filepath.Dir(p)
		}
		return nil
	})
	if cfgDir == "" {
		t.Fatal("could not locate the config dir")
	}
	if err := os.Chmod(cfgDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cfgDir, 0o700) })
	if f, err := os.CreateTemp(cfgDir, "probe-*"); err == nil { // running as root: chmod doesn't bind
		f.Close()
		t.Skip("config dir stays writable in this environment")
	}

	stdout, _, err := run(t, "keys", "rotate", "--self")
	if stdout != "tvkey_new\n" {
		t.Errorf("stdout = %q, want the new key even though saving failed", stdout)
	}
	if err == nil || !strings.Contains(err.Error(), "rotation succeeded") || !strings.Contains(err.Error(), "stdout") {
		t.Errorf("error should say the rotation succeeded and the key is on stdout: %v", err)
	}
}

// ---- old servers / classic agents ----

func TestAgentWhoami_OldServerFlatShape(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"` + agentID + `","name":"bot","status":"active"}`))
	})
	setupContext(t, &config.Context{Type: "agent", APIURL: rec.srv.URL, Identity: "bot", AgentKey: "tvagent_x"})

	stdout, _, err := run(t, "whoami", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Principal struct{ ID, Name string }
		Kind      string
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if doc.Principal.ID != agentID || doc.Principal.Name != "bot" || doc.Kind != "classic" {
		t.Errorf("whoami = %+v", doc)
	}

	_, stderr, err := run(t, "whoami", "--format", "table")
	if err != nil || !strings.Contains(stderr+stdout, "agent bot ("+agentID+")") {
		t.Errorf("text output missing the principal: err=%v %q", err, stderr)
	}
}

func TestClassicAgentOnManagementRoute_ExitsHumanOnly(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"detail":"Invalid or expired token"}`))
	})
	setupContext(t, &config.Context{Type: "agent", APIURL: rec.srv.URL, Identity: "bot", AgentKey: "tvagent_x"})

	for _, args := range [][]string{{"agents", "ls"}, {"keys", "ls"}} {
		_, _, err := run(t, args...)
		if code := clierr.ExitCode(err); code != 9 {
			t.Fatalf("%v: exit = %d, want 9 (%v)", args, code, err)
		}
		if !strings.Contains(err.Error(), "classic agents can only read credentials") {
			t.Errorf("%v: message = %v", args, err)
		}
		if strings.Contains(err.Error(), "expired") && !strings.Contains(err.Error(), "classic agents") {
			t.Errorf("must not claim the login expired: %v", err)
		}
	}
}

func TestSuspendedClassicAgent_ExitsEleven(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"detail":{"code":"AGENT_INACTIVE","message":"Agent is suspended"}}`))
	})
	setupContext(t, &config.Context{Type: "agent", APIURL: rec.srv.URL, Identity: "bot", AgentKey: "tvagent_x"})

	_, _, err := run(t, "whoami")
	if clierr.ExitCode(err) != 11 {
		t.Errorf("exit = %d, want 11 (%v)", clierr.ExitCode(err), err)
	}
}

func TestOldServer_MissingRoutesHintAtScopedKeys(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"detail":"Not Found"}`))
	})
	setupContext(t, &config.Context{Type: "admin", APIURL: rec.srv.URL, Identity: "me", RefreshToken: "rt"})
	// admin contexts refresh their ID token first; answer that path normally.
	rec.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cli/auth/refresh" {
			w.Write([]byte(`{"id_token":"idt","expires_in":3600}`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"detail":"Not Found"}`))
	})

	_, _, err := run(t, "keys", "ls")
	if err == nil || !strings.Contains(err.Error(), "predates scoped keys") {
		t.Errorf("keys ls: want a hint about old servers, got %v", err)
	}
}
