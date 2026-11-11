package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// A control plane that predates grant uses drops `uses` and makes a value
// grant; the client must revoke it and say so.
func TestAddGrantSpecs_ServerWithoutUsesRevokes(t *testing.T) {
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		w.Write([]byte(`{"success":true,"serviceName":"github"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res := c.AddGrantSpecs("a1", []GrantSpec{{Service: "github", Uses: []string{"tools"}}, {Service: "x"}})
	err := res.Err()
	if err == nil || !strings.Contains(err.Error(), "predates grant uses") || !strings.Contains(err.Error(), "the grant was removed") {
		t.Fatalf("err = %v", err)
	}
	if len(reqs) != 2 || reqs[1] != "DELETE /api/agents/a1/grants/github" {
		t.Errorf("reqs = %v, want the grant revoked", reqs)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "x" {
		t.Errorf("skipped = %v", res.Skipped)
	}
}

func TestAddGrantSpecs_RevokeFailureGivesManualCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	err := c.AddGrantSpecs("a1", []GrantSpec{{Service: "github", Uses: []string{"tools"}}}).Err()
	if err == nil || !strings.Contains(err.Error(), "could not be removed") || !strings.Contains(err.Error(), "tvault ag gr rm a1 github") {
		t.Errorf("err = %v", err)
	}
}

func TestAddGrantSpecs_UsesEchoedShapes(t *testing.T) {
	for _, body := range []string{
		`{"success":true,"uses":["tools"]}`,
		`{"grant":{"serviceName":"github","uses":["tools"]}}`,
		`{"grants":[{"serviceName":"github","uses":["tools"]}]}`,
	} {
		var deletes int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" {
				deletes++
			}
			w.Write([]byte(body))
		}))
		c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
		if err := c.AddGrantSpecs("a1", []GrantSpec{{Service: "github", Uses: []string{"tools"}}}).Err(); err != nil || deletes != 0 {
			t.Errorf("body %s: err=%v deletes=%d", body, err, deletes)
		}
		srv.Close()
	}
}

func TestParseErrorBody_TopLevelCode(t *testing.T) {
	er := parseErrorBody([]byte(`{"error":"slow down","code":"RATE_LIMITED","retryAfter":5}`))
	if er.Code != "RATE_LIMITED" || er.Message != "slow down" || er.Denial == nil || er.Denial.RetryAfter == nil || *er.Denial.RetryAfter != 5 {
		t.Errorf("er = %+v", er)
	}
	// Without a Retry-After header the body's retryAfter drives the hint.
	err := denyOnce(t, 429, nil, `{"error":"slow down","code":"RATE_LIMITED","retryAfter":5}`)
	if !strings.Contains(err.Error(), "retry in 5s") {
		t.Errorf("err = %v", err)
	}
}

func TestBareNotFoundAndNotAllowedHints(t *testing.T) {
	for _, status := range []int{404, 405} {
		msg := map[int]string{404: "Not Found", 405: "Method Not Allowed"}[status]
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"detail":"` + msg + `"}`))
		}))
		c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
		_, err := c.ListAgents()
		srv.Close()
		s := ""
		if err != nil {
			s = err.Error()
		}
		if !strings.Contains(s, "does not have this command yet") || strings.Contains(s, "scoped keys") || strings.Contains(s, "tokenvault.one") {
			t.Errorf("status %d: %q", status, s)
		}
	}
}

// A transport error must not print the one-shot ticket from the query string.
func TestFetchWebhookCredential_ErrorHidesTicket(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused
	c := &Client{HTTP: &http.Client{Timeout: time.Second}}
	_, err := c.fetchWebhookCredential(url, "SECRET-TICKET", "github")
	if err == nil {
		t.Fatal("expected an error")
	}
	if s := err.Error(); strings.Contains(s, "SECRET-TICKET") || strings.Contains(s, "ticket=") {
		t.Errorf("error leaks the ticket: %q", s)
	}
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Kind != clierr.KindNetwork {
		t.Errorf("err = %v, want a network error", err)
	}
}

func TestDenialSentenceEscapesServerText(t *testing.T) {
	err := denyOnce(t, 403, nil, wrap(`{"code":"POLICY_DENIED","message":"m","policy":"evil\u001b[2J","rule":"max_usage",
		"appliedVia":{"type":"agent","id":"a\nb"},"ruleSettings":{"max":1,"used":1}}`))
	if s := err.Error(); strings.ContainsAny(s, "\x1b") || strings.Contains(s, "a\nb") {
		t.Errorf("raw control characters reached the output: %q", s)
	}
}

func TestWebhookURLMustBeHTTPS(t *testing.T) {
	c := &Client{}
	if _, err := c.fetchWebhookCredential("http://wh.example.com", "t", "github"); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("fetch: err = %v", err)
	}
	if err := c.postWebhookStore("http://wh.example.com", map[string]string{"a": "b"}); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("store: err = %v", err)
	}
}

func TestRefuseInsecureRedirect(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	for raw, ok := range map[string]bool{
		"https://example.com/x":  true,
		"http://127.0.0.1:9/x":   true,
		"http://localhost/x":     true,
		"http://[::1]:9/x":       true,
		"http://example.com/x":   false,
		"http://127.0.0.1.evil/": false,
	} {
		err := refuseInsecureRedirect(mk(raw), nil)
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", raw, err, ok)
		}
	}
	if New("https://x", 0).HTTP.CheckRedirect == nil {
		t.Error("New must set CheckRedirect")
	}
}
