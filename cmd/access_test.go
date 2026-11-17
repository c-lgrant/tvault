package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestAccessRequest_ServersAskForMCPOnThoseServers(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending","expiresAt":"soon"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	t.Cleanup(func() { accessRequestCmd.Flags().Set("servers", "") })

	_, errOut, err := runCLI(t, "access", "request", "home-hub", "--reason", "otto tools", "--uses", "",
		"--servers", "otto", "--expires", "never", "--wait", "0s")
	if err != nil {
		t.Fatalf("err = %v (%s)", err, errOut)
	}
	if fmt.Sprint(body["uses"]) != "[tools]" || fmt.Sprint(body["servers"]) != "[otto]" {
		t.Errorf("body = %v, want uses [tools] and servers [otto]", body)
	}
	if _, ok := body["expiresInHours"]; ok {
		t.Errorf("never should send no expiresInHours, got %v", body["expiresInHours"])
	}
}

func TestAccessRequest_ParsesTheGrantForm(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending","expiresAt":"soon"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})

	_, errOut, err := runCLI(t, "access", "request", "home-hub=mcp:otto", "--reason", "x", "--uses", "",
		"--expires", "never", "--wait", "0s")
	if err != nil {
		t.Fatalf("err = %v (%s)", err, errOut)
	}
	if fmt.Sprint(body["services"]) != "[home-hub]" || fmt.Sprint(body["uses"]) != "[tools]" ||
		fmt.Sprint(body["servers"]) != "[otto]" {
		t.Errorf("body = %v, want services [home-hub], uses [tools], servers [otto]", body)
	}
}

func TestRequestTerms(t *testing.T) {
	cases := []struct {
		args          []string
		uses, servers string
		wantErr       string
	}{
		{[]string{"a=mcp:x", "b=mcp:y"}, "", "", "same uses and servers"},
		{[]string{"a=mcp:x"}, "mcp", "", "not both"},
		{[]string{"a=value:x"}, "", "", "only be named with mcp"},
		{[]string{"a"}, "value", "x", "--servers needs --uses mcp"},
	}
	for _, c := range cases {
		_, _, _, err := requestTerms(c.args, c.uses, c.servers)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%v: err = %v, want %q", c.args, err, c.wantErr)
		}
	}
	svcs, uses, servers, err := requestTerms([]string{"a=mcp:x,y", "b=mcp:x,y"}, "", "")
	if err != nil || fmt.Sprint(svcs, uses, servers) != "[a b] [tools] [x y]" {
		t.Errorf("got %v %v %v %v", svcs, uses, servers, err)
	}
}

func TestAccessRequest_DryRunSaysNothingWasSent(t *testing.T) {
	setupContext(t, &config.Context{Type: "agent", APIURL: "http://127.0.0.1:1", Identity: "bot", AgentKey: "tvagent_abc"})
	_, errOut, err := runCLI(t, "access", "request", "openai", "--reason", "x", "--uses", "",
		"--expires", "never", "--wait", "0s", "--dry-run")
	t.Cleanup(func() { rootCmd.PersistentFlags().Set("dry-run", "false") })
	if err != nil {
		t.Fatalf("err = %v (%s)", err, errOut)
	}
	if !strings.Contains(errOut, "nothing was sent") || strings.Contains(errOut, "no usable approval link") {
		t.Errorf("stderr = %q", errOut)
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
		w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	_, _, err := runCLI(t, "access", "request", "openai", "--reason", "x", "--uses", "", "--expires", "never",
		"--wait", "50ms")
	if got := clierr.ExitCode(err); got != 16 {
		t.Errorf("exit = %d, want 16 (err=%v)", got, err)
	}
}

func writePlan(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/plan.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAccessPlan_SendsActionsAndPrintsLink(t *testing.T) {
	var body map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending","expiresAt":"soon"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	plan := writePlan(t, `{"reason":"set up ci","actions":[{"id":"a1","type":"create_agent","name":"ci-bot"},
		{"id":"a2","parent":"a1","type":"grant","to":"ci-bot","service":"github"}]}`)

	out, errOut, err := runCLI(t, "access", "plan", plan, "--reason", "", "--wait", "0s")
	if err != nil {
		t.Fatalf("err = %v (%s)", err, errOut)
	}
	if strings.TrimSpace(out) != "https://tv.example/requests/r1" {
		t.Errorf("stdout = %q", out)
	}
	if string(body["reason"]) != `"set up ci"` || !strings.Contains(string(body["actions"]), `"parent":"a1"`) {
		t.Errorf("body = %s / %s", body["reason"], body["actions"])
	}
	if _, has := body["services"]; has {
		t.Error("a plan must not send services")
	}
}

func TestAccessPlan_ArrayNeedsReason(t *testing.T) {
	setupContext(t, &config.Context{Type: "agent", APIURL: "http://127.0.0.1:1", Identity: "bot", AgentKey: "tvagent_abc"})
	plan := writePlan(t, `[{"id":"a1","type":"grant","to":"self","service":"github"}]`)
	_, _, err := runCLI(t, "access", "plan", plan, "--reason", "", "--wait", "0s")
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Errorf("err = %v", err)
	}
}

func TestAccessPlan_RefusesBadJSON(t *testing.T) {
	setupContext(t, &config.Context{Type: "agent", APIURL: "http://127.0.0.1:1", Identity: "bot", AgentKey: "tvagent_abc"})
	_, _, err := runCLI(t, "access", "plan", writePlan(t, `{"nope":1}`), "--reason", "x", "--wait", "0s")
	if clierr.ExitCode(err) != 1 || !strings.Contains(err.Error(), "JSON array of actions") {
		t.Errorf("err = %v", err)
	}
}

func TestAccessPlan_WaitPrintsResults(t *testing.T) {
	old := requestPollInterval
	requestPollInterval = time.Millisecond
	defer func() { requestPollInterval = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte(`{"requestId":"r1","url":"https://tv.example/requests/r1","status":"pending"}`))
			return
		}
		w.Write([]byte(`{"requestId":"r1","status":"approved","kind":"changes","results":[
			{"id":"a1","type":"create_agent","status":"done","agentId":"ag1"},
			{"id":"a2","type":"grant","status":"skipped","message":"not approved"}]}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	plan := writePlan(t, `[{"id":"a1","type":"create_agent","name":"ci-bot"}]`)
	_, errOut, err := runCLI(t, "access", "plan", plan, "--reason", "x", "--wait", "1m")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 of 2 actions done", "a2 grant: skipped (not approved)",
		"tvault access claim-key r1 a1"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut)
		}
	}
}

func TestAccessClaimKey_PrintsOnlyTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/grant-requests/r1/actions/a1/claim-key" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{"agentId":"ag1","apiKey":"tvagent_newkey"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	out, _, err := runCLI(t, "access", "claim-key", "r1", "a1", "--format", "")
	if err != nil {
		t.Fatal(err)
	}
	if out != "tvagent_newkey\n" {
		t.Errorf("stdout = %q, want only the key", out)
	}
}

func TestAccessClaimKey_RefusesANonKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"agentId":"ag1","apiKey":"\u001b[2Jgotcha"}`))
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "agent", APIURL: srv.URL, Identity: "bot", AgentKey: "tvagent_abc"})
	out, _, err := runCLI(t, "access", "claim-key", "r1", "a1", "--format", "")
	if err == nil || out != "" {
		t.Errorf("err = %v, stdout = %q; want an error and nothing printed", err, out)
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
