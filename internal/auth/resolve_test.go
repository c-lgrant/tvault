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
