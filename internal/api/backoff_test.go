package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// rateLimitedServer always answers 429, optionally with a Retry-After header,
// and tallies how many requests it saw.
func rateLimitedServer(t *testing.T, retryAfter string, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"detail":{"code":"RATE_LIMITED","message":"slow down"}}`))
	}))
}

// TestGet429RetriesWithBackoff proves a GET hitting 429 backs off (honoring a
// small Retry-After) and retries up to maxAttempts, then surfaces
// KindRateLimited with the server's Retry-After recorded.
func TestGet429RetriesWithBackoff(t *testing.T) {
	var calls int
	srv := rateLimitedServer(t, "1", &calls)
	defer srv.Close()

	var slept []time.Duration
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), sleep: func(d time.Duration) { slept = append(slept, d) }}

	_, err := client.doRequest("GET", "/x", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *clierr.CLIError
	if !errorsAs(err, &ce) {
		t.Fatalf("error is not *CLIError: %v", err)
	}
	if ce.Kind != clierr.KindRateLimited {
		t.Errorf("Kind = %v, want KindRateLimited", ce.Kind)
	}
	if ce.RetryAfter != time.Second {
		t.Errorf("RetryAfter = %v, want 1s", ce.RetryAfter)
	}
	if calls != maxGetAttempts {
		t.Errorf("attempts = %d, want %d", calls, maxGetAttempts)
	}
	if len(slept) != maxGetAttempts-1 {
		t.Fatalf("sleeps = %d, want %d", len(slept), maxGetAttempts-1)
	}
	for i, d := range slept {
		if d < time.Second {
			t.Errorf("sleep %d = %v, want >= Retry-After (1s)", i, d)
		}
	}
}

// TestGet429LargeRetryAfterFailsFast proves that a Retry-After beyond the
// sleep cap fails immediately instead of blocking the CLI.
func TestGet429LargeRetryAfterFailsFast(t *testing.T) {
	var calls int
	srv := rateLimitedServer(t, "600", &calls)
	defer srv.Close()

	var slept []time.Duration
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), sleep: func(d time.Duration) { slept = append(slept, d) }}

	_, err := client.doRequest("GET", "/x", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *clierr.CLIError
	if !errorsAs(err, &ce) {
		t.Fatalf("error is not *CLIError: %v", err)
	}
	if ce.Kind != clierr.KindRateLimited {
		t.Errorf("Kind = %v, want KindRateLimited", ce.Kind)
	}
	if calls != 1 {
		t.Errorf("attempts = %d, want 1 (fail fast)", calls)
	}
	if len(slept) != 0 {
		t.Errorf("slept %v, want no sleeps", slept)
	}
}

// TestPost429DoesNotRetry keeps the POST single-attempt guarantee for 429s.
func TestPost429DoesNotRetry(t *testing.T) {
	var calls int
	srv := rateLimitedServer(t, "1", &calls)
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), sleep: func(time.Duration) {}}
	_, err := client.doRequest("POST", "/x", map[string]string{"k": "v"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("attempts = %d, want 1", calls)
	}
}

// TestConnectionErrorBackoffGrows proves connection-error GET retries use a
// growing non-zero backoff between attempts.
func TestConnectionErrorBackoffGrows(t *testing.T) {
	rt := &countingTransport{}
	var slept []time.Duration
	client := &Client{BaseURL: "http://example.invalid", HTTP: &http.Client{Transport: rt},
		sleep: func(d time.Duration) { slept = append(slept, d) }}

	if _, err := client.doRequest("GET", "/x", nil, nil); err == nil {
		t.Fatal("expected error")
	}
	if rt.calls != maxGetAttempts {
		t.Errorf("attempts = %d, want %d", rt.calls, maxGetAttempts)
	}
	if len(slept) != maxGetAttempts-1 {
		t.Fatalf("sleeps = %d, want %d", len(slept), maxGetAttempts-1)
	}
	for i, d := range slept {
		if d <= 0 {
			t.Errorf("sleep %d = %v, want > 0", i, d)
		}
	}
	if len(slept) >= 2 && slept[1] < slept[0] {
		t.Errorf("backoff did not grow: %v", slept)
	}
}
