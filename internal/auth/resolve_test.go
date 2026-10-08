package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/config"
)

func TestResolveAgentContextAttachesKey(t *testing.T) {
	ctx := &config.Context{Type: "agent", APIURL: "https://x", AgentKey: "tvagent_abc"}
	client, err := ClientFor(ctx, false)
	if err != nil {
		t.Fatalf("ClientFor errored: %v", err)
	}
	if client.AgentKey != "tvagent_abc" || client.BearerToken != "" {
		t.Errorf("agent client wrong: %+v", client)
	}
}

func TestResolveKeyContextUsesBearerKeyWithoutRefresh(t *testing.T) {
	ctx := &config.Context{Type: "key", APIURL: "https://x", APIKey: "tvkey_abc", RefreshToken: "must-not-be-used"}
	client, err := ClientFor(ctx, false)
	if err != nil {
		t.Fatalf("ClientFor errored: %v", err)
	}
	if client.APIKey != "tvkey_abc" || client.BearerToken != "" || client.AgentKey != "" {
		t.Errorf("key client wrong: %+v", client)
	}
}

func TestLoginKeyDetectsPrefix(t *testing.T) {
	var paths []string
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		auths = append(auths, r.Header.Get("Authorization"))
		if r.URL.Path == "/api/agents/whoami" {
			w.Write([]byte(`{"principal":{"type":"key","id":"k1","name":"ci-key"},"userId":"u","kind":"scoped","scopes":[],"expiresAt":null}`))
			return
		}
		w.Write([]byte(`{"grants":[]}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := LoginKey("k", srv.URL, "tvkey_abc"); err != nil {
		t.Fatalf("LoginKey(tvkey_) errored: %v", err)
	}
	if err := LoginKey("a", srv.URL, "tvagent_xyz"); err != nil {
		t.Fatalf("LoginKey(tvagent_) errored: %v", err)
	}
	cfg, _ := config.Load()
	k, a := cfg.Contexts["k"], cfg.Contexts["a"]
	if k == nil || k.Type != "key" || k.APIKey != "tvkey_abc" || k.AgentKey != "" || k.Identity != "ci-key" {
		t.Errorf("key context wrong: %+v", k)
	}
	if a == nil || a.Type != "agent" || a.AgentKey != "tvagent_xyz" || a.APIKey != "" {
		t.Errorf("agent context wrong: %+v", a)
	}
	if paths[0] != "/api/agents/whoami" || auths[0] != "Bearer tvkey_abc" {
		t.Errorf("key login validated via %s with %q", paths[0], auths[0])
	}

	if err := LoginKey("bad", srv.URL, "sk-nope"); err == nil {
		t.Error("unrecognized prefix should be rejected")
	}
	if cfg2, _ := config.Load(); cfg2.Contexts["bad"] != nil {
		t.Error("rejected key must not be persisted")
	}
}

// #15: a scoped agent without credentials:read must still log in. Agent keys
// are validated through whoami (no scope needed), not the credentials list.
func TestLoginKeyAgentValidatesViaWhoami(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/api/agents/whoami" {
			w.Write([]byte(`{"principal":{"type":"agent","id":"a1","name":"script-mint"},"userId":"u","kind":"scoped","scopes":["tokens:create"],"expiresAt":null}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","missingScope":"credentials:read","message":"Missing required scope: credentials:read"}}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := LoginKey("a", srv.URL, "tvagent_xyz"); err != nil {
		t.Fatalf("scoped agent without credentials:read could not log in: %v", err)
	}
	cfg, _ := config.Load()
	if a := cfg.Contexts["a"]; a == nil || a.Type != "agent" || a.AgentKey != "tvagent_xyz" || a.Identity != "script-mint" {
		t.Errorf("agent context wrong: %+v", a)
	}
	if len(paths) != 1 || paths[0] != "/api/agents/whoami" {
		t.Errorf("agent login called %v, want only /api/agents/whoami", paths)
	}
}

// A server without /api/agents/whoami (404) still accepts a classic agent key
// through the credentials endpoint, as before.
func TestLoginKeyAgentFallsBackOnOldServer(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/api/agents/whoami" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"Not Found"}`))
			return
		}
		w.Write([]byte(`{"grants":[]}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := LoginKey("a", srv.URL, "tvagent_xyz"); err != nil {
		t.Fatalf("old-server agent login errored: %v", err)
	}
	cfg, _ := config.Load()
	if a := cfg.Contexts["a"]; a == nil || a.Identity != "agent" {
		t.Errorf("agent context wrong: %+v", a)
	}
	if len(paths) != 2 || paths[1] != "/api/agents/credentials" {
		t.Errorf("old-server agent login called %v", paths)
	}
}

// An invalid agent key is refused by whoami and never persisted.
func TestLoginKeyAgentInvalidIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":{"code":"INVALID_KEY","message":"Invalid agent API key"}}`))
	}))
	defer srv.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := LoginKey("a", srv.URL, "tvagent_xyz"); err == nil {
		t.Fatal("invalid agent key should be rejected")
	}
	if cfg, _ := config.Load(); cfg.Contexts["a"] != nil {
		t.Error("rejected key must not be persisted")
	}
}

func TestResolveAdminContextRefreshesWhenStale(t *testing.T) {
	var refreshCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalls++
		w.Write([]byte(`{"id_token":"fresh-idt","expires_in":3600}`))
	}))
	defer srv.Close()

	ctx := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}
	// No cached token → must refresh.
	client, err := ClientFor(ctx, false)
	if err != nil {
		t.Fatalf("ClientFor errored: %v", err)
	}
	if client.BearerToken != "fresh-idt" {
		t.Errorf("BearerToken = %q, want fresh-idt", client.BearerToken)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1", refreshCalls)
	}

	// Cached token still valid for an hour → no second refresh.
	if _, err := ClientFor(ctx, false); err != nil {
		t.Fatalf("second ClientFor errored: %v", err)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d after cached call, want 1", refreshCalls)
	}

	// Force staleness → refresh again.
	ctx.SetIDToken("stale", time.Now().Add(2*time.Minute).Unix())
	if _, err := ClientFor(ctx, false); err != nil {
		t.Fatalf("third ClientFor errored: %v", err)
	}
	if refreshCalls != 2 {
		t.Errorf("refreshCalls = %d after stale call, want 2", refreshCalls)
	}
}
