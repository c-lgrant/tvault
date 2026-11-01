package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// denyOnce serves one canned error and returns what the client made of it.
func denyOnce(t *testing.T, status int, header map[string]string, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_x", sleep: func(time.Duration) {}}
	_, err := c.ListKeys()
	if err == nil {
		t.Fatal("expected an error")
	}
	return err
}

func wrap(inner string) string { return `{"detail":` + inner + `}` }

func TestPolicyDenialSentences(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		header   map[string]string
		body     string
		wantExit int
		want     []string // all must appear in err.Error()
	}{
		{
			"rate limit via label", 429, map[string]string{"Retry-After": "12"},
			wrap(`{"code":"POLICY_DENIED","message":"limit","policy":"burst-60","rule":"rate_limit","retryAfter":12,
				"appliedVia":{"type":"label","id":"ai","carriedBy":["token"]},"ruleSettings":{"limit":60,"windowSeconds":60}}`),
			7,
			[]string{"denied: rate limit 60 requests per minute (policy burst-60, on label ai). Try again in 12s. The label is on the credential.",
				"hint: ", "tvault policy detach <policy-id> --label ai"},
		},
		{
			"time window", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"closed","policy":"office-hours","rule":"time_window",
				"appliedVia":{"type":"agent","id":"cursor"},
				"ruleSettings":{"days":[1,2,3,4,5],"start":"08:00","end":"19:00","timezone":"Europe/London"}}`),
			1,
			[]string{"denied: outside allowed hours Mon–Fri 08:00–19:00 Europe/London (policy office-hours, on agent cursor).",
				"--agent cursor"},
		},
		{
			"time window opens again", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"closed","policy":"p","rule":"time_window","retryAfter":7200,
				"appliedVia":{"type":"token","id":"github"},"ruleSettings":{"days":[1,3,6],"start":"09:00","end":"17:00"}}`),
			1,
			[]string{"outside allowed hours Mon, Wed, Sat 09:00–17:00 (policy p, on credential github). Opens again in 2 h.", "--credential github"},
		},
		{
			"lifetime cap", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"cap","policy":"cap-100","rule":"max_usage",
				"appliedVia":{"type":"api_key","id":"k1"},"ruleSettings":{"max":100,"used":100}}`),
			1,
			[]string{"lifetime cap reached: used 100 of 100 (policy cap-100, on key k1). It does not reset by itself.", "--key k1"},
		},
		{
			"geo allow", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"geo","policy":"eu","rule":"geo_restrict",
				"appliedVia":{"type":"token","id":"x"},"ruleSettings":{"mode":"allow","countryCodes":["GB","IE"]}}`),
			1,
			[]string{"country not allowed: only GB and IE may use this (policy eu, on credential x)."},
		},
		{
			"geo deny", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"geo","policy":"eu","rule":"geo_restrict",
				"appliedVia":{"type":"token","id":"x"},"ruleSettings":{"mode":"deny","countryCodes":["RU"]}}`),
			1,
			[]string{"requests from RU are refused"},
		},
		{
			"channel", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"ch","policy":"web-only","rule":"access_channel",
				"appliedVia":{"type":"token_group","id":"prod"},"ruleSettings":{"mode":"allow","channels":["web"]}}`),
			1,
			[]string{"only the web console may read this (policy web-only, on folder prod).", "web console (Policies)"},
		},
		{
			"ip allowlist", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"ip","policy":"office","rule":"ip_allowlist",
				"appliedVia":{"type":"agent","id":"a"},"ruleSettings":{"cidrCount":3}}`),
			1,
			[]string{"address not on the IP allowlist (policy office, on agent a)."},
		},
		{
			"ip allowlist empty", 403, nil,
			wrap(`{"code":"POLICY_DENIED","message":"ip","policy":"office","rule":"ip_allowlist",
				"appliedVia":{"type":"agent","id":"a"},"ruleSettings":{"cidrCount":0}}`),
			1,
			[]string{"the IP allowlist is empty, so nobody gets in"},
		},
		{
			"top-level body (REST shape)", 403, nil,
			`{"error":"Access denied by policy","policy":"cap","rule":"max_usage","reason":"cap","code":"POLICY_DENIED",
				"appliedVia":{"type":"label","id":"ai"},"ruleSettings":{"max":5,"used":5}}`,
			1,
			[]string{"denied: lifetime cap reached: used 5 of 5 (policy cap, on label ai)."},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := denyOnce(t, tc.status, tc.header, tc.body)
			if got := clierr.ExitCode(err); got != tc.wantExit {
				t.Errorf("exit = %d, want %d", got, tc.wantExit)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q should contain %q", err.Error(), w)
				}
			}
		})
	}
}

// Agents and scoped keys never get appliedVia/ruleSettings: the message stays
// as it was, plus the wait and a pointer to the event.
func TestPolicyDenialAgentShapedBody(t *testing.T) {
	err := denyOnce(t, 429, map[string]string{"Retry-After": "30"},
		wrap(`{"code":"POLICY_DENIED","message":"Rate limit exceeded","policy":"burst","rule":"rate_limit","retryAfter":30,"eventId":"evt_9"}`))
	s := err.Error()
	if strings.HasPrefix(s, "denied:") {
		t.Errorf("agent-shaped body should keep the old format, got %q", s)
	}
	for _, w := range []string{"Rate limit exceeded Try again in 30s.", "ask the owner to look up event evt_9 in Activity"} {
		if !strings.Contains(s, w) {
			t.Errorf("error %q should contain %q", s, w)
		}
	}
	if got := clierr.ExitCode(err); got != 7 {
		t.Errorf("exit = %d, want 7", got)
	}

	err = denyOnce(t, 403, nil, wrap(`{"code":"POLICY_DENIED","message":"Outside hours","policy":"office","rule":"time_window","retryAfter":3600,"eventId":"evt_1"}`))
	s = err.Error()
	for _, w := range []string{"Outside hours Try again in 60 min.", "look up event evt_1 in Activity"} {
		if !strings.Contains(s, w) {
			t.Errorf("error %q should contain %q", s, w)
		}
	}
	if got := clierr.ExitCode(err); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestPolicyDenialOldServerBody(t *testing.T) {
	err := denyOnce(t, 403, nil, wrap(`{"code":"POLICY_DENIED","message":"Access denied by policy","policy":"p","rule":"time_window"}`))
	s := err.Error()
	if strings.Contains(s, "denied:") || strings.Contains(s, "hint") {
		t.Errorf("old body should print today's message, got %q", s)
	}
	if !strings.Contains(s, "Access denied by policy") || !strings.Contains(s, "403 POLICY_DENIED") {
		t.Errorf("unexpected old-server output %q", s)
	}
	if got := clierr.ExitCode(err); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestAccessRefusalsExplained(t *testing.T) {
	cases := []struct {
		code     string
		status   int
		wantExit int
		sentence string
		hint     string
	}{
		{"NO_GRANT", 404, 1, "no access to that credential", "tvault grant <agent> <credential>=value"},
		{"GRANT_EXPIRED", 403, 1, "has expired", "tvault grant <agent> <credential>=value"},
		{"GRANT_TOOLS_ONLY", 403, 1, "tool calls only", "=value"},
		{"AGENT_INACTIVE", 403, 11, "agent is suspended", "tvault agents resume <agent>"},
		{"VAULT_LOCKED", 423, 5, "vault is locked", "tvault vault unlock"},
		{"SCOPE_DENIED", 403, 8, "lacks a permission", "tvault keys create --scopes x:y"},
		{"RATE_LIMITED", 429, 7, "faster than Token Vault allows", "retry in 5s"},
		{"WEBHOOK_CIRCUIT_OPEN", 503, 4, "webhook has been failing", "tvault webhook status"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			body := wrap(`{"code":"` + tc.code + `","message":"m","missingScope":"x:y"}`)
			err := denyOnce(t, tc.status, map[string]string{"Retry-After": "5"}, body)
			s := err.Error()
			if !strings.HasPrefix(s, "denied: ") || !strings.Contains(s, tc.sentence) {
				t.Errorf("error %q should start with 'denied: ' and contain %q", s, tc.sentence)
			}
			if !strings.Contains(s, "\nhint: ") || !strings.Contains(s, tc.hint) {
				t.Errorf("error %q should carry hint containing %q", s, tc.hint)
			}
			if got := clierr.ExitCode(err); got != tc.wantExit {
				t.Errorf("exit = %d, want %d", got, tc.wantExit)
			}
		})
	}
}
