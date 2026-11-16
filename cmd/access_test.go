package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

func TestParseGrantHours(t *testing.T) {
	cases := map[string]int{"never": 0, "": 0, "12h": 12, "7d": 168}
	for in, want := range cases {
		got, err := parseGrantHours(in)
		if err != nil || got != want {
			t.Errorf("parseGrantHours(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"0h", "-1d", "3w", "d", "abc"} {
		if _, err := parseGrantHours(in); err == nil {
			t.Errorf("parseGrantHours(%q) should fail", in)
		}
	}
}

func TestParseRequestUses(t *testing.T) {
	got, err := parseRequestUses("value, mcp,tools")
	if err != nil || strings.Join(got, ",") != "value,tools" {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := parseRequestUses("read"); err == nil {
		t.Error("an unknown use should fail")
	}
}

func TestAccessRequest_PrintsLinkOnStdout(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/grant-requests" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending","expiresAt":"soon"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})

	out, errOut, err := runCLI(t, "access", "request", "openai", "github", "--reason", "summarise logs",
		"--uses", "mcp", "--expires", "7d", "--wait", "0s")
	if err != nil {
		t.Fatalf("err = %v (%s)", err, errOut)
	}
	if strings.TrimSpace(out) != "https://tv.example/requests/r1" {
		t.Errorf("stdout = %q, want only the link", out)
	}
	if body["reason"] != "summarise logs" || body["expiresInHours"] != float64(168) {
		t.Errorf("body = %v", body)
	}
	if uses, _ := body["uses"].([]any); len(uses) != 1 || uses[0] != "tools" {
		t.Errorf("uses = %v, want [tools]", body["uses"])
	}
}

func TestAccessRequest_NeedsReason(t *testing.T) {
	setupContext(t, &config.Context{Type: "agent", APIURL: "http://127.0.0.1:1", Identity: "bot", AgentKey: "tvagent_abc"})
	_, _, err := runCLI(t, "access", "request", "openai", "--reason", " ", "--uses", "", "--expires", "never", "--wait", "0s")
	if err == nil || !strings.Contains(err.Error(), "--reason") {
		t.Errorf("err = %v, want a --reason error", err)
	}
}

func TestAccessRequest_RefusesAdminContext(t *testing.T) {
	setupContext(t, &config.Context{Type: "admin", APIURL: "http://127.0.0.1:1", Identity: "me"})
	_, _, err := runCLI(t, "access", "request", "openai", "--reason", "x", "--uses", "", "--expires", "never", "--wait", "0s")
	if err == nil || !strings.Contains(err.Error(), "key or agent context") {
		t.Errorf("err = %v", err)
	}
}

func TestAccessRequest_WaitExitCodes(t *testing.T) {
	old := requestPollInterval
	requestPollInterval = time.Millisecond
	defer func() { requestPollInterval = old }()

	for status, want := range map[string]int{"approved": 0, "denied": 15, "expired": 16} {
		t.Run(status, func(t *testing.T) {
			var polls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending"}`))
					return
				}
				// Pending on the first poll, decided on the second.
				s := "pending"
				if atomic.AddInt32(&polls, 1) > 1 {
					s = status
				}
				w.Write([]byte(`{"requestId":"r1","status":"` + s + `","granted":["openai"]}`))
			}))
			defer srv.Close()
			setupContext(t, &config.Context{Type: "key", APIURL: srv.URL, Identity: "ci", APIKey: "tvkey_abc"})
			_, _, err := runCLI(t, "access", "request", "openai", "--reason", "x", "--uses", "", "--expires", "never",
				"--wait", "1m")
			if got := clierr.ExitCode(err); got != want {
				t.Errorf("exit = %d, want %d (err=%v)", got, want, err)
			}
		})
	}
}

func TestAccessRequest_WaitRunsOut(t *testing.T) {
	old := requestPollInterval
	requestPollInterval = 20 * time.Millisecond
	defer func() { requestPollInterval = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"requestId":"r1","url":"u","status":"pending"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	_, _, err := runCLI(t, "access", "request", "openai", "--reason", "x", "--uses", "", "--expires", "never",
		"--wait", "50ms")
	if got := clierr.ExitCode(err); got != 16 {
		t.Errorf("exit = %d, want 16 (err=%v)", got, err)
	}
}

func TestAccessDrop_SendsServicesAndReports(t *testing.T) {
	var body map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/grants/drop" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"dropped":["github"],"notHeld":["nope"]}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	_, errOut, err := runCLI(t, "access", "drop", "github", "nope", "--force")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(body["services"], ",") != "github,nope" {
		t.Errorf("body = %v", body)
	}
	if !strings.Contains(errOut, "Dropped 1 grant(s). Not held: nope.") {
		t.Errorf("stderr = %q", errOut)
	}
}
