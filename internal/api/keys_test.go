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
		{"key suspended", 403, `{"detail":{"code":"KEY_SUSPENDED","message":"key suspended"}}`, 11, "key suspended"},
		{"invalid key", 401, `{"detail":{"code":"INVALID_KEY","message":"bad key"}}`, 12, "bad key"},
		{"vault locked by code", 423, `{"detail":{"code":"VAULT_LOCKED","message":"locked"}}`, 5, "locked"},
		{"reauth required", 401, `{"detail":{"code":"REAUTH_REQUIRED","message":"sign in again"}}`, 2, "tvault login"},
		{"not owner", 403, `{"detail":{"code":"NOT_OWNER","message":"not yours"}}`, 1, "owner"},
		{"grant required", 403, `{"detail":{"code":"GRANT_REQUIRED","message":"no grant"}}`, 1, "keys grant"},
		{"no grant", 404, `{"detail":{"code":"NO_GRANT","message":"missing"}}`, 1, "keys show"},
		{"unknown scope 422", 422, `{"detail":{"code":"UNKNOWN_SCOPE","message":"bad scope"}}`, 1, "bad scope"},
		{"invalid expiry 400", 400, `{"detail":{"code":"INVALID_EXPIRY","message":"bad expiry"}}`, 1, "--expires"},
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

func TestKeyGrantsAndShow(t *testing.T) {
	var calls []string
	var grantBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "POST":
			b := make([]byte, 200)
			n, _ := r.Body.Read(b)
			grantBody = string(b[:n])
			w.WriteHeader(201)
			w.Write([]byte(`{}`))
		case r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{"id":"k1","name":"ci","scopes":["a"],"status":"active","expiresAt":null,"createdAt":"x","lastUsedAt":null,"createdBy":{"type":"user","id":"u"},"grants":[{"serviceName":"github","source":"direct","expiresAt":null}]}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_x"}

	if err := c.GrantKey("k1", "github", 24); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grantBody, `"serviceName":"github"`) || !strings.Contains(grantBody, `"expiresInHours":24`) {
		t.Errorf("grant body = %s", grantBody)
	}
	if err := c.GrantKey("k1", "github", 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(grantBody, "expiresInHours") {
		t.Errorf("expiresInHours should be omitted when 0, body = %s", grantBody)
	}
	if err := c.UngrantKey("k1", "github"); err != nil {
		t.Fatal(err)
	}
	d, err := c.GetKey("k1")
	if err != nil || len(d.Grants) != 1 || d.Grants[0].Source != "direct" || d.Name != "ci" {
		t.Fatalf("GetKey = %+v, %v", d, err)
	}
	want := []string{"POST /api/keys/k1/grants", "POST /api/keys/k1/grants", "DELETE /api/keys/k1/grants/github", "GET /api/keys/k1"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", calls)
	}
}
