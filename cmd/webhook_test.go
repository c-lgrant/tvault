package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/config"
)

// fakeWebhook serves the two endpoints the CLI probes on a running webhook.
func fakeWebhook(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/health":
			w.Write([]byte(`{"status":"healthy"}`))
		case "/v1/register-url":
			w.Write([]byte(`{"registrationUrl":"https://tv.example/register?hmac_hash=h1","code":"c1","expiresIn":60,"webhookUrl":"https://wh.example.com"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWebhookBind(t *testing.T) {
	wh := fakeWebhook(t)
	var bound string
	cp := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/vault/webhook-bind" {
			bound = r.Method
			w.Write([]byte(`{"status":"ok","vaultMode":"webhook","webhookCapabilities":["tv-store"]}`))
			return
		}
		w.WriteHeader(404)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: cp.srv.URL, APIKey: "tvkey_k", Identity: "me"})
	origHTTP := webhookHTTP
	defer func() { webhookHTTP = origHTTP }()
	webhookHTTP = wh.Client()

	stdout, stderr, err := run(t, "webhook", "bind", "--url", wh.URL)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if bound != "POST" {
		t.Errorf("control plane bind not called")
	}
	if stdout != "" || !strings.Contains(stderr, "Webhook bound") {
		t.Errorf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestWebhookBindNeedsURL(t *testing.T) {
	setupContext(t, &config.Context{Type: "key", APIURL: "http://127.0.0.1:1", APIKey: "tvkey_k", Identity: "me"})
	if _, _, err := run(t, "webhook", "bind"); err == nil || !strings.Contains(err.Error(), "--url") {
		t.Errorf("err = %v", err)
	}
}

func TestWebhookStatus(t *testing.T) {
	wh := fakeWebhook(t)
	cp := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/vault/status" {
			w.Write([]byte(`{"vaultMode":"webhook","webhook":{"url":"` + wh.URL + `","status":"active","lastHealthCheck":"t","lastHealthStatus":"healthy"},"webhookCapabilities":["tv-store"]}`))
			return
		}
		w.WriteHeader(404)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: cp.srv.URL, APIKey: "tvkey_k", Identity: "me"})
	origHTTP := webhookHTTP
	defer func() { webhookHTTP = origHTTP }()
	webhookHTTP = wh.Client()

	stdout, stderr, err := run(t, "webhook", "status")
	if err != nil {
		t.Fatal(err)
	}
	out := stdout + stderr
	for _, want := range []string{"vault mode: webhook", "probe     : healthy", "tv-store"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, "Local:") {
		t.Errorf("local container state must be gone: %q", out)
	}
}

// The init/up/down subcommands were removed; cobra's unknown-command error
// is the whole story for old scripts.
func TestWebhookRemovedCommands(t *testing.T) {
	setupContext(t, &config.Context{Type: "key", APIURL: "http://127.0.0.1:1", APIKey: "tvkey_k", Identity: "me"})
	for _, sub := range []string{"init", "up", "down"} {
		_, _, err := run(t, "webhook", sub)
		if err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("webhook %s: err = %v, want unknown command", sub, err)
		}
	}
}
