package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

func keyCtx(t *testing.T, url string) {
	t.Helper()
	setupContext(t, &config.Context{Type: "key", APIURL: url, Identity: "k", APIKey: "tvkey_k"})
}

// `tvault credentials` and `tvault history` are the same commands as
// `tvault tokens list` / `tvault tokens history`.
func TestCredentialsAndHistoryAliases(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens":
			w.Write([]byte(`[{"serviceName":"github","tokenType":"PlainText","status":"active"}]`))
		case "/api/tokens/audit-log":
			if r.URL.Query().Get("serviceName") != "github" {
				t.Errorf("history query = %q", r.URL.RawQuery)
			}
			w.Write([]byte(`{"events":[{"timestamp":"2026-10-01T00:00:00Z","eventType":"read","source":"agent","agentName":"bot"}]}`))
		default:
			w.WriteHeader(500)
		}
	})
	keyCtx(t, rec.srv.URL)

	viaAlias, _, err := run(t, "credentials", "--format", "table")
	if err != nil {
		t.Fatal(err)
	}
	viaTokens, _, _ := run(t, "tokens", "list", "--format", "table")
	if viaAlias != viaTokens || !strings.Contains(viaAlias, "github") {
		t.Errorf("credentials = %q, tokens list = %q", viaAlias, viaTokens)
	}

	h1, _, err := run(t, "history", "github", "--format", "table")
	if err != nil {
		t.Fatal(err)
	}
	h2, _, _ := run(t, "tokens", "history", "github", "--format", "table")
	if h1 != h2 || !strings.Contains(h1, "bot") {
		t.Errorf("history = %q, tokens history = %q", h1, h2)
	}
}

func TestLabelLs(t *testing.T) {
	const body = `{"labels":[{"label":"prod","credentials":2,"agents":1,"keys":0,"policyIds":["p1","p2"]}]}`
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
	keyCtx(t, rec.srv.URL)

	table, _, err := run(t, "label", "ls", "--format", "table")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LABEL", "CREDENTIALS", "prod", "p1,p2"} {
		if !strings.Contains(table, want) {
			t.Errorf("table missing %q: %q", want, table)
		}
	}
	js, _, err := run(t, "label", "ls", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Labels []map[string]any `json:"labels"`
	}
	if err := json.Unmarshal([]byte(js), &got); err != nil || len(got.Labels) != 1 || got.Labels[0]["label"] != "prod" {
		t.Errorf("--json = %q (%v)", js, err)
	}
}

// labelServer serves the list endpoints with labels and records PUT bodies.
func labelServer(t *testing.T, putStatus int, putBody string) (*recorder, *[]string) {
	var puts []string
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/tokens":
			w.Write([]byte(`[{"serviceName":"github","tokenType":"PlainText","labels":["prod","ai"]}]`))
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + agentID + `","name":"bot","status":"active","labels":["ci"]}]`))
		case "GET /api/keys":
			w.Write([]byte(`{"keys":[` + strings.Replace(keyJSON, `"createdBy"`, `"labels":["old"],"createdBy"`, 1) + `]}`))
		default:
			if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/api/labels/") {
				raw, _ := io.ReadAll(r.Body)
				puts = append(puts, r.URL.Path+" "+string(raw))
				w.WriteHeader(putStatus)
				w.Write([]byte(putBody))
				return
			}
			w.WriteHeader(500)
		}
	})
	return rec, &puts
}

func TestLabelSetAddRm(t *testing.T) {
	const ok = `{"entityType":"x","entityId":"y","labels":["a"],"policies":[{"id":"p1","label":"a","enabled":true,"name":"Night only"}]}`
	rec, puts := labelServer(t, 200, ok)
	keyCtx(t, rec.srv.URL)

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"label", "set", "credential", "github", "Work", " AI "}, `/api/labels/credential/github {"labels":["work","ai"]}`},
		{[]string{"label", "add", "credential", "github", "work"}, `/api/labels/credential/github {"labels":["prod","ai","work"]}`},
		{[]string{"label", "rm", "credential", "github", "prod"}, `/api/labels/credential/github {"labels":["ai"]}`},
		{[]string{"label", "add", "agent", "bot", "x"}, `/api/labels/agent/` + agentID + ` {"labels":["ci","x"]}`},
		{[]string{"label", "rm", "key", keyID, "old"}, `/api/labels/api_key/` + keyID + ` {"labels":[]}`},
		{[]string{"label", "set", "key", keyID, "z"}, `/api/labels/api_key/` + keyID + ` {"labels":["z"]}`},
	}
	for _, c := range cases {
		*puts = nil
		stdout, stderr, err := run(t, c.args...)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if len(*puts) != 1 || strings.TrimSpace((*puts)[0]) != c.want {
			t.Errorf("%v: puts = %q, want %q", c.args, *puts, c.want)
		}
		if stdout != "a\n" || !strings.Contains(stderr, "Night only") {
			t.Errorf("%v: stdout=%q stderr=%q", c.args, stdout, stderr)
		}
	}
}

func TestLabelAddNoChangeSendsNothing(t *testing.T) {
	rec, puts := labelServer(t, 200, `{}`)
	keyCtx(t, rec.srv.URL)
	stdout, _, err := run(t, "label", "add", "credential", "github", "prod")
	if err != nil || len(*puts) != 0 || stdout != "prod\nai\n" {
		t.Errorf("err=%v puts=%q stdout=%q", err, *puts, stdout)
	}
	if _, _, err := run(t, "label", "add", "credential", "nope", "x"); err == nil || clierr.ExitCode(err) != userExit {
		t.Errorf("unknown credential: err = %v", err)
	}
	if _, _, err := run(t, "label", "set", "folder", "x", "y"); err == nil || clierr.ExitCode(err) != userExit {
		t.Errorf("unknown kind: err = %v", err)
	}
}

// Removing a label that carries a policy needs policies:write; the server's
// SCOPE_DENIED maps to the permission-denied exit code (8).
func TestLabelRmNeedsPolicyScope(t *testing.T) {
	rec, _ := labelServer(t, 403,
		`{"detail":{"code":"SCOPE_DENIED","message":"Missing required scope: policies:write","missingScope":"policies:write"}}`)
	keyCtx(t, rec.srv.URL)
	_, _, err := run(t, "label", "rm", "credential", "github", "prod")
	if err == nil || clierr.ExitCode(err) != 8 || !strings.Contains(err.Error(), "policies:write") {
		t.Fatalf("err = %v (exit %d), want exit 8 naming policies:write", err, clierr.ExitCode(err))
	}
}

func TestPolicyAttachDetachLabel(t *testing.T) {
	var got []string
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(raw))
		w.Write([]byte(`{}`))
	})
	keyCtx(t, rec.srv.URL)

	if _, _, err := run(t, "policy", "attach", "pol1", "--label", "Prod", "--credential", "github"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, "policy", "detach", "pol1", "--label", "prod"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /api/policies/pol1/attach {"attachments":[{"entityType":"label","entityId":"prod"},{"entityType":"token","entityId":"github"}]}`,
		`POST /api/policies/pol1/detach {"attachments":[{"entityType":"label","entityId":"prod"}]}`,
	}
	for i := range want {
		if i >= len(got) || strings.TrimSpace(got[i]) != want[i] {
			t.Errorf("call %d = %q, want %q", i, got, want[i])
		}
	}
	if _, _, err := run(t, "policy", "attach", "pol1"); err == nil || clierr.ExitCode(err) != userExit {
		t.Errorf("no target: err = %v", err)
	}
}

// ---- tvault add: repeatable --for and --labels ----

func TestAddForRepeatable(t *testing.T) {
	two := `[{"id":"abcdefghij0123456789","name":"claude-code","status":"active"},{"id":"bbbbbbbbbbbbbbbbbbbb","name":"cursor","status":"active"}]`
	b := newAgentBackend(t, two)
	withStdin(t, "s3cret\n", false, "")
	_, _, err := runCLI(t, "add", "github", "--for", "claude-code=tools", "--for", "cursor=value,tools:github")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.stored) != 1 {
		t.Errorf("stored = %q, want one value", b.stored)
	}
	want := []string{"abcdefghij0123456789/github", "bbbbbbbbbbbbbbbbbbbb/github"}
	if strings.Join(b.grants, ",") != strings.Join(want, ",") {
		t.Errorf("grants = %q, want %q", b.grants, want)
	}
}

func TestAddLabels(t *testing.T) {
	b := newAgentBackend(t, existingAgent)
	withStdin(t, "s3cret\n", false, "")
	_, _, err := runCLI(t, "add", "github", "--labels", "Work,ai", "--labels", "work")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.stored) != 1 || len(b.labelPuts) != 1 || b.labelPuts[0] != "/api/labels/credential/github work,ai" {
		t.Errorf("stored=%q labelPuts=%q", b.stored, b.labelPuts)
	}
}

func TestAddLabelsFailureKeepsCredential(t *testing.T) {
	b := newAgentBackend(t, existingAgent)
	b.labelFail = true
	withStdin(t, "s3cret\n", false, "")
	_, _, err := runCLI(t, "add", "github", "--for", "my-agent", "--labels", "bad_label")
	if err == nil || clierr.ExitCode(err) != userExit {
		t.Fatalf("err = %v, want a user error", err)
	}
	if !strings.Contains(err.Error(), "tvault label set credential github") {
		t.Errorf("error should print the retry command: %v", err)
	}
	if len(b.stored) != 1 || len(b.grants) != 1 {
		t.Errorf("credential and grant must still happen: stored=%q grants=%q", b.stored, b.grants)
	}
}
