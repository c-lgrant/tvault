package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

func TestScopedErrorCodesMapToExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantExit int
		wantMsg  string // substring of the error text
	}{
		{"scope denied", 403, `{"detail":{"code":"SCOPE_DENIED","message":"nope","missingScope":"tokens:create"}}`, 8, "tokens:create"},
		{"scope denied null scope", 403, `{"detail":{"code":"SCOPE_DENIED","message":"nope","missingScope":null}}`, 8, "nope"},
		{"human only", 403, `{"detail":{"code":"HUMAN_ONLY","message":"humans only"}}`, 9, "humans only"},
		{"key expired", 401, `{"detail":{"code":"KEY_EXPIRED","message":"key expired"}}`, 10, "key expired"},
		{"plain 403 stays user error", 403, `{"detail":"forbidden"}`, 1, "forbidden"},
		{"plain 401 stays auth error", 401, `{"detail":"bad token"}`, 2, "bad token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_x"}
			_, err := c.ListKeys()
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := clierr.ExitCode(err); got != tc.wantExit {
				t.Errorf("exit code = %d, want %d (%v)", got, tc.wantExit, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestKeyBearerHeader(t *testing.T) {
	var auth, legacy string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, legacy = r.Header.Get("Authorization"), r.Header.Get("X-Agent-Key")
		w.Write([]byte(`{"keys":[{"id":"k1","name":"ci","scopes":["a"],"status":"active","expiresAt":null,"createdAt":"x","lastUsedAt":null,"createdBy":{"type":"user","id":"u"}}]}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_abc"}
	keys, err := c.ListKeys()
	if err != nil || len(keys) != 1 || keys[0].ExpiresAt != nil {
		t.Fatalf("ListKeys = %+v, %v", keys, err)
	}
	if auth != "Bearer tvkey_abc" || legacy != "" {
		t.Errorf("Authorization = %q, X-Agent-Key = %q", auth, legacy)
	}
}
