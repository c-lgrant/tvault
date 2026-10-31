package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestTokenNotesReadsDescription(t *testing.T) {
	cases := map[string]string{
		`{"serviceName":"a","description":"current"}`:                  "current",
		`{"serviceName":"a","notes":"legacy"}`:                         "legacy",
		`{"serviceName":"a","description":"current","notes":"legacy"}`: "current",
		`{"serviceName":"a"}`:                                          "",
	}
	for body, want := range cases {
		var tok Token
		if err := json.Unmarshal([]byte(body), &tok); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if tok.Notes != want {
			t.Errorf("%s: Notes = %q, want %q", body, tok.Notes, want)
		}
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
		// The backend's field is "description"; it only re-reads legacy "notes"
		// when no description exists, so a "notes" write can be invisible.
		if body["description"] != "rotated quarterly" {
			t.Errorf("body = %v", body)
		}
		if _, ok := body["notes"]; ok {
			t.Errorf("body still sends legacy notes: %v", body)
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

// TestCreateToken: a create with a value goes ticket-first. The value goes
// only to the webhook; TV sees one store-ticket request and never /api/tokens.
func TestCreateToken(t *testing.T) {
	h := newTicketHarness(t, "ghp_x")
	err := h.client().CreateToken(CreateTokenRequest{ServiceName: "github", Type: "PlainText", Credential: "ghp_x"})
	if err != nil {
		t.Fatalf("CreateToken errored: %v", err)
	}
	if h.stored["service"] != "github" {
		t.Errorf("service = %v", h.stored["service"])
	}
	td := h.tokenData(t)
	if td["accessToken"] != "ghp_x" || td["tokenType"] != "PlainText" {
		t.Errorf("tokenData = %v", td)
	}
	if h.tvHits["/api/tokens"] != 0 || h.tvHits["/api/vault/store-ticket"] != 1 {
		t.Errorf("tv hits = %+v, want only one store-ticket", h.tvHits)
	}
}

// TestCreateTokenTypeSpecificField verifies that CreateToken routes the
// credential into the type-specific tokenData field rather than always
// using accessToken (see credentialFieldForType), on the webhook.
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
			h := newTicketHarness(t, "the-secret")
			err := h.client().CreateToken(CreateTokenRequest{
				ServiceName: "svc", Type: tc.typ, Credential: "the-secret",
			})
			if err != nil {
				t.Fatalf("CreateToken errored: %v", err)
			}
			td := h.tokenData(t)
			if td[tc.field] != "the-secret" {
				t.Errorf("tokenData.%s = %v, want the-secret", tc.field, td[tc.field])
			}
			// The credential must not leak into accessToken for non-bearer types.
			if tc.field != "accessToken" && td["accessToken"] != nil {
				t.Errorf("credential leaked into accessToken: %v", td["accessToken"])
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

// webhookRetryRig is a TV stub plus a webhook that hangs for the first
// `hangs` calls. Each ticket is unique, as TV's are (the webhook rejects a
// reused nonce), and the webhook records which tickets it was shown. The
// handlers run on server goroutines, so the counters sit behind a mutex.
type retryRig struct {
	mu     sync.Mutex
	shown  []string
	minted int
}

func (g *retryRig) seen() ([]string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.shown...), g.minted
}

func webhookRetryRig(t *testing.T, hangs int) (*Client, *retryRig) {
	t.Helper()
	g := &retryRig{}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.shown = append(g.shown, r.URL.Query().Get("ticket"))
		n := len(g.shown)
		g.mu.Unlock()
		if n <= hangs {
			select { // hold the response until the client gives up
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		w.Write([]byte(`{"token":{"accessToken":"plaintext"}}`))
	}))
	t.Cleanup(webhook.Close)
	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens/svc":
			w.Write([]byte(`{"serviceName":"svc"}`))
		case "/api/vault/credential-ticket":
			g.mu.Lock()
			g.minted++
			n := g.minted
			g.mu.Unlock()
			w.Write([]byte(`{"ticket":"t` + strings.Repeat("x", n) + `","webhookUrl":"` + webhook.URL + `"}`))
		}
	}))
	t.Cleanup(tv.Close)
	return &Client{BaseURL: tv.URL, HTTP: tv.Client(), WebhookTimeout: 100 * time.Millisecond}, g
}

func TestGetTokenValue_WebhookTimeoutRetriesWithFreshTicket(t *testing.T) {
	client, rig := webhookRetryRig(t, 1)
	val, err := client.GetTokenValue("svc")
	if err != nil {
		t.Fatalf("GetTokenValue errored: %v", err)
	}
	if val != "plaintext" {
		t.Errorf("value = %q", val)
	}
	shown, minted := rig.seen()
	if minted != 2 || len(shown) != 2 || shown[0] == shown[1] {
		t.Errorf("minted %d tickets, webhook saw %v; want 2 distinct", minted, shown)
	}
}

func TestGetTokenValue_WebhookTimeoutGivesUpWithTimeoutInMessage(t *testing.T) {
	client, rig := webhookRetryRig(t, 99)
	start := time.Now()
	_, err := client.GetTokenValue("svc")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Kind != clierr.KindNetwork {
		t.Fatalf("err = %v, want a KindNetwork CLIError", err)
	}
	if !strings.Contains(ce.Message, "100ms") {
		t.Errorf("message %q does not name the timeout", ce.Message)
	}
	if shown, _ := rig.seen(); len(shown) != 2 {
		t.Errorf("webhook attempts = %d, want 2", len(shown))
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %s; the per-attempt webhook timeout was not applied", time.Since(start))
	}
}

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

// TestGetTokenValue_AgentPath verifies an agent-persona client routes to
// /api/agents/credentials (not /api/tokens/{svc}, which requires admin auth
// and returns 422 for agents) and sends the key as a Bearer token.
func TestGetTokenValue_AgentPath(t *testing.T) {
	var sawAuth, sawAgentKey string
	var sawPath, sawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawAgentKey = r.Header.Get("X-Agent-Key")
		sawPath = r.URL.Path
		sawQuery = r.URL.Query().Get("service")
		w.Write([]byte(`{"accessToken":"agent-creds","serviceName":"svc","tokenType":"PlainText"}`))
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), AgentKey: "tvagent_abc"}
	val, err := client.GetTokenValue("svc")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if val != "agent-creds" {
		t.Errorf("value = %q, want agent-creds", val)
	}
	if sawPath != "/api/agents/credentials" {
		t.Errorf("path = %q, want /api/agents/credentials (admin path won't work for agents)", sawPath)
	}
	if sawQuery != "svc" {
		t.Errorf("service query = %q", sawQuery)
	}
	if sawAuth != "Bearer tvagent_abc" {
		t.Errorf("Authorization = %q, want Bearer tvagent_abc", sawAuth)
	}
	if sawAgentKey != "" {
		t.Errorf("legacy X-Agent-Key header still sent (%q)", sawAgentKey)
	}
}

// TestGetTokenValue_AgentWebhookRedirect: webhook-mode agents 307 from
// /api/agents/credentials to <webhook>/v1/credential, which returns
// {"token": {accessToken, ...}} (nested, not top-level). Go's HTTP client
// follows the redirect transparently; we need to unwrap the nested shape.
func TestGetTokenValue_AgentWebhookRedirect(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/credential" {
			t.Errorf("webhook path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"token":{"accessToken":"redirected-secret","serviceName":"svc"}}`))
	}))
	defer webhook.Close()

	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, webhook.URL+"/v1/credential?ticket=t&service=svc", http.StatusTemporaryRedirect)
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client(), AgentKey: "tvagent_k"}
	val, err := client.GetTokenValue("svc")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if val != "redirected-secret" {
		t.Errorf("value = %q, want redirected-secret", val)
	}
}

// TestGetTokenValue_AgentEmpty pins KindEmpty when the agent endpoint
// returns 200 with no credential (grant exists but token has no value).
func TestGetTokenValue_AgentEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"serviceName":"svc","tokenType":"PlainText"}`))
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), AgentKey: "tvagent_x"}
	_, err := client.GetTokenValue("svc")
	if err == nil {
		t.Fatalf("expected error on empty credential")
	}
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("not CLIError: %T", err)
	}
	if ce.Kind != clierr.KindEmpty {
		t.Errorf("Kind = %v, want KindEmpty", ce.Kind)
	}
}

// ticketHarness is a fake TV plus a fake webhook. TV only issues store
// tickets and fails the test if any request body carries the secret; the
// webhook records the token document it was sent.
type ticketHarness struct {
	tv, webhook *httptest.Server
	tvHits      map[string]int
	stored      map[string]any // the last /v1/store body
}

func newTicketHarness(t *testing.T, secret string) *ticketHarness {
	t.Helper()
	h := &ticketHarness{tvHits: map[string]int{}}
	h.webhook = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/store" {
			t.Errorf("unexpected webhook path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &h.stored)
		w.WriteHeader(200)
	}))
	h.tv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.tvHits[r.URL.Path]++
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), secret) {
			t.Errorf("PLAINTEXT SENT TO TV: %s %s body=%s", r.Method, r.URL.Path, raw)
		}
		if r.URL.Path != "/api/vault/store-ticket" {
			t.Errorf("unexpected TV path %s", r.URL.Path)
		}
		w.Write([]byte(`{"ticket":"t","webhookUrl":"` + h.webhook.URL + `","expiresIn":60}`))
	}))
	t.Cleanup(func() { h.tv.Close(); h.webhook.Close() })
	return h
}

func (h *ticketHarness) client() *Client {
	return &Client{BaseURL: h.tv.URL, HTTP: h.tv.Client()}
}

func (h *ticketHarness) tokenData(t *testing.T) map[string]any {
	t.Helper()
	td, ok := h.stored["tokenData"].(map[string]any)
	if !ok {
		t.Fatalf("webhook got no tokenData: %v", h.stored)
	}
	return td
}

// TestSetTokenValue_TicketFirst: a rotate sends the new value only to the
// webhook. TV sees one store-ticket request and never /api/tokens.
func TestSetTokenValue_TicketFirst(t *testing.T) {
	h := newTicketHarness(t, "rotated-v2")
	if err := h.client().SetTokenValue("svc", "rotated-v2"); err != nil {
		t.Fatalf("SetTokenValue errored: %v", err)
	}
	if got := h.tokenData(t)["accessToken"]; got != "rotated-v2" {
		t.Errorf("webhook accessToken = %v, want rotated-v2", got)
	}
	if h.tvHits["/api/tokens"] != 0 || h.tvHits["/api/vault/store-ticket"] != 1 {
		t.Errorf("tv hits = %+v, want only one store-ticket", h.tvHits)
	}
}

// TestCreateToken_EmptyCredentialPassesThrough: a placeholder create (no
// credential) carries no secret, so the backend's webhook-mode reject doesn't
// apply. The original error should propagate — no spurious webhook call.
func TestCreateToken_EmptyCredentialPassesThrough(t *testing.T) {
	tvHits := map[string]int{}
	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tvHits[r.URL.Path]++
		// Backend won't actually 400 on empty payloads, but if it ever did
		// with the webhook-mode wording we must NOT call store-ticket
		// because there's nothing to store.
		w.WriteHeader(400)
		w.Write([]byte(`{"detail":"Webhook mode: plaintext secrets must not transit Token Vault."}`))
	}))
	defer tv.Close()

	client := &Client{BaseURL: tv.URL, HTTP: tv.Client()}
	err := client.CreateToken(CreateTokenRequest{
		Type:        "PlainText",
		ServiceName: "svc",
		Credential:  "",
	})
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	if tvHits["/api/vault/store-ticket"] != 0 {
		t.Errorf("store-ticket called for empty placeholder (%d times)", tvHits["/api/vault/store-ticket"])
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
