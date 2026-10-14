package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/config"
)

// refreshServer counts refresh calls and hands out numbered ID tokens.
func refreshServer(t *testing.T, expiresIn int) (*httptest.Server, *int64) {
	t.Helper()
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cli/auth/refresh" {
			w.WriteHeader(404)
			return
		}
		n := atomic.AddInt64(&calls, 1)
		// Slow enough that parallel callers overlap with the first refresh.
		time.Sleep(50 * time.Millisecond)
		fmt.Fprintf(w, `{"id_token":"idt-%d","expires_in":%d}`, n, expiresIn)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// Each tvault invocation is a new process with a fresh Context; a token
// minted by one must be reused by the next instead of refreshing again.
func TestAdminIDTokenSharedAcrossProcesses(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv, calls := refreshServer(t, 3600)

	for i := 0; i < 3; i++ {
		ctx := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}
		client, err := ClientFor(ctx, false)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if client.BearerToken != "idt-1" {
			t.Errorf("call %d: BearerToken = %q, want idt-1", i, client.BearerToken)
		}
	}
	if got := atomic.LoadInt64(calls); got != 1 {
		t.Errorf("refresh calls = %d, want 1", got)
	}
}

// A burst of parallel calls with nothing cached makes one refresh, not one each.
func TestAdminIDTokenBurstRefreshesOnce(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv, calls := refreshServer(t, 3600)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}
			if _, err := ClientFor(ctx, false); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("ClientFor: %v", err)
	}
	if got := atomic.LoadInt64(calls); got != 1 {
		t.Errorf("refresh calls = %d, want 1", got)
	}
}

// A cached token inside the refresh skew is not reused.
func TestAdminIDTokenNearExpiryRefreshes(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// expires_in below refreshSkew: every call must refresh.
	srv, calls := refreshServer(t, 60)

	for i := 0; i < 2; i++ {
		ctx := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}
		if _, err := ClientFor(ctx, false); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt64(calls); got != 2 {
		t.Errorf("refresh calls = %d, want 2", got)
	}
}

// A different refresh token (a new login, or another account) never picks
// up someone else's cached token.
func TestAdminIDTokenKeyedByRefreshToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv, calls := refreshServer(t, 3600)

	a, err := ClientFor(&config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt-a"}, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ClientFor(&config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt-b"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.BearerToken == b.BearerToken {
		t.Errorf("both contexts got %q", a.BearerToken)
	}
	if got := atomic.LoadInt64(calls); got != 2 {
		t.Errorf("refresh calls = %d, want 2", got)
	}
}

func TestAdminIDTokenCacheFileModeAndForget(t *testing.T) {
	cfgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	srv, calls := refreshServer(t, 3600)
	ctx := &config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}

	if _, err := ClientFor(ctx, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(cfgHome, "tvault", "idtokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("idtokens.json mode = %o, want 600", mode)
	}

	if err := config.ForgetIDToken(ctx); err != nil {
		t.Fatal(err)
	}
	if token, _ := config.CachedIDToken(ctx); token != "" {
		t.Errorf("token still cached after forget: %q", token)
	}
	if _, err := ClientFor(&config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}, false); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(calls); got != 2 {
		t.Errorf("refresh calls = %d, want 2 after forget", got)
	}
}

// Expired entries are dropped whenever the cache is written.
func TestStoreIDTokenPrunesExpired(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	old := &config.Context{APIURL: "https://x", RefreshToken: "old"}
	cur := &config.Context{APIURL: "https://x", RefreshToken: "cur"}

	if err := config.StoreIDToken(old, "old-idt", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := config.StoreIDToken(cur, "cur-idt", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if token, _ := config.CachedIDToken(old); token != "" {
		t.Errorf("expired entry kept: %q", token)
	}
	if token, _ := config.CachedIDToken(cur); token != "cur-idt" {
		t.Errorf("current entry = %q, want cur-idt", token)
	}
}

// If the cache cannot be written the command still works; it just refreshes.
func TestAdminIDTokenUnwritableCacheStillWorks(t *testing.T) {
	cfgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	d := filepath.Join(cfgHome, "tvault")
	if err := os.MkdirAll(d, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d, 0o700) })
	if f, err := os.CreateTemp(d, "probe-*"); err == nil { // running as root: chmod doesn't bind
		f.Close()
		t.Skip("config dir stays writable in this environment")
	}
	srv, _ := refreshServer(t, 3600)

	client, err := ClientFor(&config.Context{Type: "admin", APIURL: srv.URL, RefreshToken: "rt"}, false)
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	if client.BearerToken != "idt-1" {
		t.Errorf("BearerToken = %q, want idt-1", client.BearerToken)
	}
}
