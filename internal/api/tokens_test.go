package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tokens" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Backend list shape: tokenId + serviceName + tokenType.
		w.Write([]byte(`[{"serviceName":"github","tokenType":"JWT","status":"active"},
		                 {"serviceName":"stripe","tokenType":"PlainText","status":"active"}]`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	toks, err := client.ListTokens()
	if err != nil {
		t.Fatalf("ListTokens errored: %v", err)
	}
	if len(toks) != 2 || toks[0].ServiceName != "github" {
		t.Errorf("tokens = %+v", toks)
	}
	if toks[0].Type != "JWT" {
		t.Errorf("type = %q, want JWT", toks[0].Type)
	}
}

func TestGetTokenValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tokens/github" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Backend returns the full token doc; the secret lives in accessToken.
		w.Write([]byte(`{"serviceName":"github","accessToken":"ghp_secret123","tokenType":"pat"}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	val, err := client.GetTokenValue("github")
	if err != nil {
		t.Fatalf("GetTokenValue errored: %v", err)
	}
	if val != "ghp_secret123" {
		t.Errorf("value = %q", val)
	}
}

func TestDeleteTokensBulkVsSingle(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}

	if err := client.DeleteTokens([]string{"github"}); err != nil {
		t.Fatalf("single delete errored: %v", err)
	}
	if err := client.DeleteTokens([]string{"github", "stripe"}); err != nil {
		t.Fatalf("bulk delete errored: %v", err)
	}
	if paths[0] != "DELETE /api/tokens/github" {
		t.Errorf("single delete path = %s", paths[0])
	}
	if paths[1] != "DELETE /api/tokens/bulk" {
		t.Errorf("bulk delete path = %s", paths[1])
	}
}

func TestUpdateTokenMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/api/tokens/github/metadata" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["notes"] != "rotated quarterly" {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	err := client.UpdateTokenMetadata("github", TokenMetadata{Notes: strPtr("rotated quarterly")})
	if err != nil {
		t.Fatalf("UpdateTokenMetadata errored: %v", err)
	}
}

func TestCreateToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/tokens" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		// Backend POST shape: {serviceName, tokenData:{accessToken,tokenType}}.
		if body["serviceName"] != "github" {
			t.Errorf("serviceName = %v", body["serviceName"])
		}
		td, ok := body["tokenData"].(map[string]any)
		if !ok {
			t.Fatalf("tokenData not an object: %v", body["tokenData"])
		}
		if td["accessToken"] != "ghp_x" {
			t.Errorf("tokenData.accessToken = %v", td["accessToken"])
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	err := client.CreateToken(CreateTokenRequest{ServiceName: "github", Type: "pat", Credential: "ghp_x"})
	if err != nil {
		t.Fatalf("CreateToken errored: %v", err)
	}
}

// TestCreateTokenTypeSpecificField verifies that CreateToken routes the
// credential into the backend's type-specific tokenData field rather than
// always using accessToken (see credentialFieldForType).
func TestCreateTokenTypeSpecificField(t *testing.T) {
	cases := []struct {
		typ   string
		field string
	}{
		{"SSHKey", "sshPrivateKey"},
		{"Certificate", "certificateData"},
		{"TOTP", "totpSecret"},
		{"PlainText", "accessToken"},
		{"JWT", "accessToken"},
		{"RawCredential", "accessToken"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.typ, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				var body map[string]any
				json.Unmarshal(raw, &body)
				td, ok := body["tokenData"].(map[string]any)
				if !ok {
					t.Fatalf("tokenData not an object: %v", body["tokenData"])
				}
				if td[tc.field] != "the-secret" {
					t.Errorf("tokenData.%s = %v, want the-secret", tc.field, td[tc.field])
				}
				// The credential must not leak into accessToken for non-bearer types.
				if tc.field != "accessToken" && td["accessToken"] != nil {
					t.Errorf("credential leaked into accessToken: %v", td["accessToken"])
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
			err := client.CreateToken(CreateTokenRequest{
				ServiceName: "svc", Type: tc.typ, Credential: "the-secret",
			})
			if err != nil {
				t.Fatalf("CreateToken errored: %v", err)
			}
		})
	}
}

func TestTokenHistory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Backend exposes per-service history via the audit-log endpoint.
		if r.URL.Path != "/api/tokens/audit-log" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("serviceName") != "github" {
			t.Errorf("serviceName query = %q", r.URL.Query().Get("serviceName"))
		}
		w.Write([]byte(`{"events":[{"timestamp":"2026-05-14T00:00:00Z","eventType":"SECRET_ACCESS"}]}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	hist, err := client.TokenHistory("github")
	if err != nil {
		t.Fatalf("TokenHistory errored: %v", err)
	}
	if len(hist) != 1 {
		t.Errorf("history = %+v", hist)
	}
}

func strPtr(s string) *string { return &s }
