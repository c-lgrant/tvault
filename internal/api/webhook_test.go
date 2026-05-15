package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookBind(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"status":"configured","vaultMode":"webhook","webhookRegistered":true,"webhookCapabilities":["store","credential"]}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res, err := client.WebhookBind("code-123", "https://wh.example.com", "abc123hash")
	if err != nil {
		t.Fatalf("WebhookBind errored: %v", err)
	}
	if gotPath != "POST /api/vault/webhook-bind" {
		t.Errorf("path = %q", gotPath)
	}
	for _, want := range []string{`"code":"code-123"`, `"webhookUrl":"https://wh.example.com"`, `"hmacSecretHash":"abc123hash"`} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("body %q missing %q", gotBody, want)
		}
	}
	if res.Status != "configured" || !res.WebhookRegistered || len(res.WebhookCapabilities) != 2 {
		t.Errorf("res = %+v", res)
	}
}

func TestVaultWebhookInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vaultMode":"webhook","webhookCapabilities":["store"],"webhook":{"url":"https://wh.example.com","status":"active","lastHealthCheck":"2026-05-14T10:00:00Z","lastHealthStatus":"healthy"}}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	st, err := client.VaultWebhookInfo()
	if err != nil {
		t.Fatalf("VaultWebhookInfo errored: %v", err)
	}
	if st.VaultMode != "webhook" || st.Webhook == nil || st.Webhook.URL != "https://wh.example.com" {
		t.Errorf("status = %+v", st)
	}
}
