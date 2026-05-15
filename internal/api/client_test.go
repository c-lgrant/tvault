package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// countingTransport tallies calls and always returns a connection-level
// error, so doRequest sees a retriable failure on every attempt.
type countingTransport struct{ calls int }

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("simulated connection failure")
}

// TestDoRequestRetriesGetButNotPost proves the connection-error retry is
// restricted to idempotent GETs: a GET makes 2 attempts, a POST makes 1.
func TestDoRequestRetriesGetButNotPost(t *testing.T) {
	t.Run("GET retries once", func(t *testing.T) {
		rt := &countingTransport{}
		client := &Client{BaseURL: "http://example.invalid", HTTP: &http.Client{Transport: rt}}
		if _, err := client.doRequest("GET", "/x", nil, nil); err == nil {
			t.Fatal("expected error")
		}
		if rt.calls != 2 {
			t.Errorf("GET attempts = %d, want 2", rt.calls)
		}
	})
	t.Run("POST does not retry", func(t *testing.T) {
		rt := &countingTransport{}
		client := &Client{BaseURL: "http://example.invalid", HTTP: &http.Client{Transport: rt}}
		if _, err := client.doRequest("POST", "/x", map[string]string{"k": "v"}, nil); err == nil {
			t.Fatal("expected error")
		}
		if rt.calls != 1 {
			t.Errorf("POST attempts = %d, want 1", rt.calls)
		}
	})
}

func TestDoRequestMapsStatusToErrorKind(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   clierr.Kind
	}{
		{423, `{"detail":{"code":"VAULT_LOCKED","message":"locked"}}`, clierr.KindVaultLocked},
		{401, `{"detail":"bad token"}`, clierr.KindAuth},
		{403, `{"detail":"forbidden"}`, clierr.KindUser},
		{404, `{"detail":"missing"}`, clierr.KindUser},
		{500, `{"detail":"boom"}`, clierr.KindServer},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
		_, err := client.doRequest("GET", "/x", nil, nil)
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected error", c.status)
		}
		var ce *clierr.CLIError
		if !errorsAs(err, &ce) {
			t.Fatalf("status %d: error is not *CLIError: %v", c.status, err)
		}
		if ce.Kind != c.want {
			t.Errorf("status %d: Kind = %v, want %v", c.status, ce.Kind, c.want)
		}
	}
}

func TestDoRequestSuccessReturnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer id-tok" {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), BearerToken: "id-tok"}
	body, err := client.doRequest("GET", "/x", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %s", body)
	}
}

// errorsAs is a thin wrapper so the test file does not import errors twice.
func errorsAs(err error, target any) bool { return errorsAsImpl(err, target) }
