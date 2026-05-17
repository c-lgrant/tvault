package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
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

// TestGetTokenValue_WebhookFallback exercises the zero-knowledge fallback:
// /api/tokens/{svc} returns metadata only (no secret fields), so the CLI
// fetches a ticket from /api/vault/credential-ticket then GETs the
// plaintext from <webhook>/v1/credential.
func TestGetTokenValue_WebhookFallback(t *testing.T) {
	// Stand up the fake webhook first so we can hand its URL to the TV stub.
	webhookHits := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits++
		if r.URL.Path != "/v1/credential" {
			t.Errorf("webhook path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("service") != "spotify" {
			t.Errorf("service query = %q", r.URL.Query().Get("service"))
		}
		if r.URL.Query().Get("ticket") == "" {
			t.Errorf("ticket query missing")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token":{"accessToken":"plaintext-from-webhook","tokenType":"JWT"}}`))
	}))
	defer webhook.Close()

	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens/spotify":
			// Webhook-mode: backend strips secrets, returns metadata only.
			w.Write([]byte(`{"serviceName":"spotify","tokenType":"JWT"}`))
		case "/api/vault/credential-ticket":
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			json.Unmarshal(raw, &body)
			if body["serviceName"] != "spotify" {
				t.Errorf("ticket serviceName = %v", body["serviceName"])
			}
			if body["purpose"] != "user_reveal" {
				t.Errorf("ticket purpose = %v", body["purpose"])
			}
			w.Write([]byte(`{"ticket":"abc.sig","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
		default:
			t.Errorf("unexpected TV path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	val, err := client.GetTokenValue("spotify")
	if err != nil {
		t.Fatalf("GetTokenValue errored: %v", err)
	}
	if val != "plaintext-from-webhook" {
		t.Errorf("value = %q, want plaintext-from-webhook", val)
	}
	if webhookHits != 1 {
		t.Errorf("webhook hits = %d, want 1", webhookHits)
	}
}

// TestGetTokenValue_EmptyTokenReturnsKindEmpty verifies the distinct exit
// code path for an existing-but-empty token. Backend strips secrets (webhook
// mode), webhook returns 200 with no credential field — must surface as
// KindEmpty so scripts can branch on "empty" vs "auth" vs "server".
func TestGetTokenValue_EmptyTokenReturnsKindEmpty(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token doc exists, has metadata, no accessToken.
		w.Write([]byte(`{"token":{"serviceName":"empty","tokenType":"PlainText"}}`))
	}))
	defer webhook.Close()

	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens/empty":
			w.Write([]byte(`{"serviceName":"empty","tokenType":"PlainText"}`))
		case "/api/vault/credential-ticket":
			w.Write([]byte(`{"ticket":"abc.sig","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
		default:
			t.Errorf("unexpected TV path: %s", r.URL.Path)
		}
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	val, err := client.GetTokenValue("empty")
	if err == nil {
		t.Fatalf("expected error, got val=%q", val)
	}
	if val != "" {
		t.Errorf("value should be empty on error, got %q", val)
	}
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a *CLIError: %T %v", err, err)
	}
	if ce.Kind != clierr.KindEmpty {
		t.Errorf("Kind = %v, want KindEmpty (so exit code is 6)", ce.Kind)
	}
	if !strings.Contains(ce.Message, "empty") {
		t.Errorf("message should mention empty: %q", ce.Message)
	}
}

// TestGetTokenValue_TopLevelTokenShape handles webhooks that return the
// token doc at the top level instead of nested under "token". The fallback
// in fetchWebhookCredential's else-branch covers this.
func TestGetTokenValue_TopLevelTokenShape(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accessToken":"top-level-secret","serviceName":"x"}`))
	}))
	defer webhook.Close()

	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens/x":
			w.Write([]byte(`{"serviceName":"x","tokenType":"PlainText"}`))
		case "/api/vault/credential-ticket":
			w.Write([]byte(`{"ticket":"t","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
		}
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	val, err := client.GetTokenValue("x")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if val != "top-level-secret" {
		t.Errorf("value = %q", val)
	}
}

// TestVaultStoreTicket verifies the POST shape and response unmarshal.
func TestVaultStoreTicket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/vault/store-ticket" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["serviceName"] != "github" {
			t.Errorf("serviceName = %v", body["serviceName"])
		}
		w.Write([]byte(`{"ticket":"signed.ticket","webhookUrl":"https://hook.example/","expiresIn":60}`))
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	tkt, err := client.VaultStoreTicket("github")
	if err != nil {
		t.Fatalf("VaultStoreTicket errored: %v", err)
	}
	if tkt.Ticket != "signed.ticket" || tkt.WebhookURL != "https://hook.example/" || tkt.ExpiresIn != 60 {
		t.Errorf("ticket = %+v", tkt)
	}
}

// TestStoreTokenViaWebhook covers the full webhook-mode store flow:
// CLI fetches a ticket from TV, POSTs the token doc directly to the user's
// webhook at /v1/store. Verifies the type-specific credential field is set
// correctly and TV does not see the secret.
func TestStoreTokenViaWebhook(t *testing.T) {
	webhookHits := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits++
		if r.Method != "POST" || r.URL.Path != "/v1/store" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["ticket"] != "the-ticket" {
			t.Errorf("ticket = %v", body["ticket"])
		}
		if body["service"] != "ssh-cred" {
			t.Errorf("service = %v", body["service"])
		}
		td, ok := body["tokenData"].(map[string]any)
		if !ok {
			t.Fatalf("tokenData not an object: %v", body["tokenData"])
		}
		// SSHKey → sshPrivateKey, never accessToken.
		if td["sshPrivateKey"] != "PRIVATE-KEY-BODY" {
			t.Errorf("sshPrivateKey = %v", td["sshPrivateKey"])
		}
		if td["accessToken"] != nil {
			t.Errorf("accessToken leaked: %v", td["accessToken"])
		}
		if td["tokenType"] != "SSHKey" {
			t.Errorf("tokenType = %v", td["tokenType"])
		}
		w.WriteHeader(200)
	}))
	defer webhook.Close()

	tvHits := map[string]int{}
	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tvHits[r.URL.Path]++
		// TV must NEVER receive the plaintext secret.
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "PRIVATE-KEY-BODY") {
			t.Errorf("PLAINTEXT LEAKED TO TV: %s body=%s", r.URL.Path, raw)
		}
		w.Write([]byte(`{"ticket":"the-ticket","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	if err := client.StoreTokenViaWebhook("ssh-cred", "SSHKey", "PRIVATE-KEY-BODY"); err != nil {
		t.Fatalf("StoreTokenViaWebhook errored: %v", err)
	}
	if webhookHits != 1 {
		t.Errorf("webhook hits = %d, want 1", webhookHits)
	}
	if tvHits["/api/vault/store-ticket"] != 1 {
		t.Errorf("TV /api/vault/store-ticket hits = %d, want 1", tvHits["/api/vault/store-ticket"])
	}
	// TV must NOT have been called for /api/tokens (the plaintext-rejecting path).
	if tvHits["/api/tokens"] != 0 {
		t.Errorf("TV /api/tokens was hit %d times; secret may have leaked", tvHits["/api/tokens"])
	}
}

// TestStoreTokenViaWebhook_WebhookError propagates webhook errors as
// CLIErrors with the correct kind (so scripts can branch on them).
func TestStoreTokenViaWebhook_WebhookError(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"detail":"ticket_invalid"}`))
	}))
	defer webhook.Close()

	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ticket":"t","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	err := client.StoreTokenViaWebhook("svc", "PlainText", "v")
	if err == nil {
		t.Fatalf("expected error from 401 webhook")
	}
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("not a CLIError: %T", err)
	}
	if ce.Kind != clierr.KindAuth {
		t.Errorf("Kind = %v, want KindAuth (401 → 2)", ce.Kind)
	}
}
