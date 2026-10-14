package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/config"
)

func TestLoginAdminPersistsContext(t *testing.T) {
	forceLoopbackEnv(t)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// exchange endpoint
		w.Write([]byte(`{"id_token":"idt","refresh_token":"rt","expires_in":3600,"identity":"conor@x.y"}`))
	}))
	defer srv.Close()

	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(rawURL string) error {
		go func() {
			u := mustParseQuery(t, rawURL)
			postCallback(t, u["port"], "code-1", u["state"])
		}()
		return nil
	}

	err := Login(LoginOptions{
		ContextName: "nuc-admin",
		APIURL:      srv.URL,
		FrontendURL: srv.URL, // unused by the fake browser
		Timeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Login errored: %v", err)
	}

	cfg, _ := config.Load()
	if cfg.Current != "nuc-admin" {
		t.Errorf("Current = %q", cfg.Current)
	}
	ctx := cfg.Contexts["nuc-admin"]
	if ctx == nil || ctx.Type != "admin" || ctx.RefreshToken != "rt" || ctx.Identity != "conor@x.y" {
		t.Errorf("stored context wrong: %+v", ctx)
	}
	// The refresh token must be the only secret in contexts.yaml — no id_token.
	raw, _ := os.ReadFile(filepath.Join(dir, "tvault", "contexts.yaml"))
	if string(raw) != "" && contains(raw, "idt") {
		t.Error("id_token was written to contexts.yaml")
	}
}

// Logging in over an existing admin context drops the old session's cached
// ID token, so it does not stay on disk until it expires.
func TestLoginOverAdminContextForgetsOldIDToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"principal":{"type":"key","id":"k1","name":"ci-key"},"kind":"scoped","scopes":[]}`))
	}))
	defer srv.Close()

	old := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "old-rt"}
	cfg, _ := config.Load()
	cfg.Contexts["work"] = old
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := config.StoreIDToken(old, "old-idt", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	if err := LoginKey("work", srv.URL, "tvkey_abc"); err != nil {
		t.Fatalf("LoginKey: %v", err)
	}
	if token, _ := config.CachedIDToken(old); token != "" {
		t.Errorf("old session's ID token still cached: %q", token)
	}
}
