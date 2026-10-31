package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

// agentBackend is a fake control plane with a fixed agent list, recording
// creates, grants and stored values.
type agentBackend struct {
	srv     *httptest.Server
	mu      sync.Mutex
	agents  string // JSON array served by GET /api/agents
	creates []map[string]any
	grants  []string // "agentID/service"
	stored  []string
}

func newAgentBackend(t *testing.T, agentsJSON string) *agentBackend {
	t.Helper()
	b := &agentBackend{agents: agentsJSON}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/agents":
			w.Write([]byte(b.agents))
		case r.Method == "POST" && r.URL.Path == "/api/agents":
			b.creates = append(b.creates, body)
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"newagent","name":"` + body["name"].(string) + `","apiKey":"tvagent_secretkey"}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/grants"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agents/"), "/grants")
			b.grants = append(b.grants, id+"/"+body["serviceName"].(string))
			w.Write([]byte(`{}`))
		case r.Method == "POST" && r.URL.Path == "/api/vault/store-ticket":
			w.Write([]byte(`{"ticket":"tk","webhookUrl":"` + b.srv.URL + `/wh","expiresIn":60}`))
		case r.Method == "POST" && r.URL.Path == "/wh/v1/store":
			td, _ := body["tokenData"].(map[string]any)
			b.stored = append(b.stored, td["accessToken"].(string))
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(b.srv.Close)
	setupContext(t, &config.Context{Type: "key", APIURL: b.srv.URL, Identity: "ci", APIKey: "tvkey_k"})
	return b
}

const existingAgent = `[{"id":"abcdefghij0123456789","name":"my-agent","status":"active"}]`

func TestAddFor_ExistingAgentStoresThenGrants(t *testing.T) {
	b := newAgentBackend(t, existingAgent)
	withStdin(t, "s3cret\n", false, "")
	stdout, _, err := runCLI(t, "add", "stripe", "--for", "my-agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.stored) != 1 || b.stored[0] != "s3cret" {
		t.Errorf("stored = %q", b.stored)
	}
	if len(b.grants) != 1 || b.grants[0] != "abcdefghij0123456789/stripe" {
		t.Errorf("grants = %q", b.grants)
	}
	if len(b.creates) != 0 {
		t.Errorf("must not create an existing agent")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestAddFor_MissingAgentWithYesCreatesMCPEnabled(t *testing.T) {
	b := newAgentBackend(t, `[]`)
	withStdin(t, "v\n", false, "")
	stdout, _, err := runCLI(t, "add", "stripe", "--for", "fresh", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.creates) != 1 || b.creates[0]["name"] != "fresh" || b.creates[0]["mcpEnabled"] != true {
		t.Errorf("creates = %v", b.creates)
	}
	if len(b.grants) != 1 || b.grants[0] != "newagent/stripe" || len(b.stored) != 1 {
		t.Errorf("grants=%q stored=%q", b.grants, b.stored)
	}
	if strings.Contains(stdout, "tvagent_") {
		t.Errorf("the new agent's key must not be printed: %q", stdout)
	}
}

func TestAddFor_MissingAgentNonInteractiveWithoutYesRefuses(t *testing.T) {
	b := newAgentBackend(t, `[]`)
	withStdin(t, "v\n", false, "")
	_, _, err := runCLI(t, "add", "stripe", "--for", "fresh")
	if err == nil || clierr.ExitCode(err) != userExit || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("err = %v, want a user error pointing at --yes", err)
	}
	if len(b.creates)+len(b.stored)+len(b.grants) != 0 {
		t.Errorf("nothing should happen: %+v", b)
	}
}

func TestAddFor_PromptsOnTTY(t *testing.T) {
	for _, c := range []struct {
		answer  string
		created int
	}{{"y\n", 1}, {"n\n", 0}, {"\n", 0}} {
		b := newAgentBackend(t, `[]`)
		withStdin(t, c.answer, true, "typed")
		_, stderr, err := runCLI(t, "add", "stripe", "--for", "fresh")
		if !strings.Contains(stderr, `Create agent "fresh"? [y/N]`) {
			t.Errorf("no prompt on stderr: %q", stderr)
		}
		if len(b.creates) != c.created {
			t.Errorf("answer %q: creates = %d, want %d (err=%v)", c.answer, len(b.creates), c.created, err)
		}
		if c.created == 0 && (err == nil || len(b.stored) != 0) {
			t.Errorf("declined: want an error and no stored value, err=%v stored=%q", err, b.stored)
		}
	}
}

// fakeClaude stubs the Claude Code seams. getErr is what `claude mcp get`
// returns; ran records every invocation.
func fakeClaude(t *testing.T, onPath bool, getErr error) *[]string {
	t.Helper()
	var ran []string
	origLook, origRun := claudeLookPath, claudeRun
	claudeLookPath = func() (string, error) {
		if onPath {
			return "/usr/bin/claude", nil
		}
		return "", errors.New("not found")
	}
	claudeRun = func(args ...string) error {
		ran = append(ran, strings.Join(args, " "))
		if len(args) > 1 && args[1] == "get" {
			return getErr
		}
		return nil
	}
	t.Cleanup(func() { claudeLookPath, claudeRun = origLook, origRun })
	return &ran
}

func TestConnect_GrantsAndRegistersWithClaude(t *testing.T) {
	b := newAgentBackend(t, existingAgent)
	withStdin(t, "", false, "")
	ran := fakeClaude(t, true, errors.New("exit status 1"))
	stdout, stderr, err := runCLI(t, "connect", "my-agent", "github", "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.grants) != 2 {
		t.Errorf("grants = %q", b.grants)
	}
	want := "mcp add --transport http tokenvault " + b.srv.URL + "/api/agents/mcp"
	if len(*ran) != 2 || (*ran)[0] != "mcp get tokenvault" || (*ran)[1] != want {
		t.Errorf("claude invocations = %q, want get then %q", *ran, want)
	}
	if !strings.Contains(stderr, "claude "+want) {
		t.Errorf("the command should be shown first: %q", stderr)
	}
	if !strings.Contains(stderr, "In Claude Code, run /mcp, sign in, and pick my-agent.") {
		t.Errorf("missing next-step line: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestConnect_AlreadyRegisteredDoesNotAdd(t *testing.T) {
	newAgentBackend(t, existingAgent)
	withStdin(t, "", false, "")
	ran := fakeClaude(t, true, nil)
	if _, _, err := runCLI(t, "connect", "my-agent", "github"); err != nil {
		t.Fatal(err)
	}
	if len(*ran) != 1 || (*ran)[0] != "mcp get tokenvault" {
		t.Errorf("claude invocations = %q", *ran)
	}
}

func TestConnect_PrintAndNoClaudeRunNothing(t *testing.T) {
	for _, flag := range []string{"--print", "--no-claude"} {
		newAgentBackend(t, existingAgent)
		withStdin(t, "", false, "")
		ran := fakeClaude(t, true, errors.New("x"))
		_, stderr, err := runCLI(t, "connect", "my-agent", "github", flag)
		if err != nil {
			t.Fatal(err)
		}
		if len(*ran) != 0 {
			t.Errorf("%s: ran claude: %q", flag, *ran)
		}
		if flag == "--print" && !strings.Contains(stderr, "claude mcp add --transport http tokenvault") {
			t.Errorf("--print should show the command: %q", stderr)
		}
		if flag == "--no-claude" && strings.Contains(stderr, "claude mcp add") {
			t.Errorf("--no-claude should not mention it: %q", stderr)
		}
	}
}

func TestConnect_NoClaudeOnPathPrintsCommand(t *testing.T) {
	newAgentBackend(t, existingAgent)
	withStdin(t, "", false, "")
	ran := fakeClaude(t, false, nil)
	_, stderr, err := runCLI(t, "connect", "my-agent", "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(*ran) != 0 || !strings.Contains(stderr, "not on PATH") || !strings.Contains(stderr, "claude mcp add") {
		t.Errorf("ran=%q stderr=%q", *ran, stderr)
	}
}

func TestConnect_MissingAgentNeedsYes(t *testing.T) {
	b := newAgentBackend(t, `[]`)
	withStdin(t, "", false, "")
	fakeClaude(t, false, nil)
	if _, _, err := runCLI(t, "connect", "fresh", "github"); err == nil || clierr.ExitCode(err) != userExit {
		t.Fatalf("err = %v, want a user error", err)
	}
	if _, _, err := runCLI(t, "connect", "fresh", "github", "--yes"); err != nil {
		t.Fatal(err)
	}
	if len(b.creates) != 1 || len(b.grants) != 1 {
		t.Errorf("creates=%v grants=%q", b.creates, b.grants)
	}
}

// --- inline re-sign-in -----------------------------------------------------

func reauthServer(t *testing.T, failures int) (*httptest.Server, *int) {
	t.Helper()
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= failures {
			w.WriteHeader(401)
			w.Write([]byte(`{"detail":{"code":"REAUTH_REQUIRED","message":"sign in again"}}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"a1","name":"x","apiKey":"tvagent_k"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func withReauthStub(t *testing.T, tty bool, srvURL string) *int {
	t.Helper()
	var logins int
	origTTY, origLogin := stdinIsTTY, reauthLogin
	stdinIsTTY = func() bool { return tty }
	reauthLogin = func(_ *cobra.Command, cc *cmdContext) error {
		logins++
		cc.Client = &api.Client{BaseURL: srvURL, HTTP: http.DefaultClient}
		return nil
	}
	t.Cleanup(func() { stdinIsTTY, reauthLogin = origTTY, origLogin })
	return &logins
}

func TestWithReauth_AdminTTYSignsInAndRetriesOnce(t *testing.T) {
	srv, calls := reauthServer(t, 1)
	logins := withReauthStub(t, true, srv.URL)
	cc := &cmdContext{Ctx: &config.Context{Type: "admin"}, Client: &api.Client{BaseURL: srv.URL, HTTP: srv.Client()}}
	var res *api.CreateAgentResult
	err := withReauth(rootCmd, cc, func() (e error) { res, e = cc.Client.CreateAgent("x"); return e })
	if err != nil || res == nil || res.ID != "a1" {
		t.Fatalf("err=%v res=%v", err, res)
	}
	if *logins != 1 || *calls != 2 {
		t.Errorf("logins=%d calls=%d, want 1 and 2", *logins, *calls)
	}
}

func TestWithReauth_RetriesOnlyOnce(t *testing.T) {
	srv, calls := reauthServer(t, 5)
	logins := withReauthStub(t, true, srv.URL)
	cc := &cmdContext{Ctx: &config.Context{Type: "admin"}, Client: &api.Client{BaseURL: srv.URL, HTTP: srv.Client()}}
	err := withReauth(rootCmd, cc, func() error { _, e := cc.Client.CreateAgent("x"); return e })
	if !isReauthRequired(err) || *logins != 1 || *calls != 2 {
		t.Errorf("err=%v logins=%d calls=%d", err, *logins, *calls)
	}
}

func TestWithReauth_NonTTYAndKeyContextsKeepTheError(t *testing.T) {
	for name, c := range map[string]struct {
		typ string
		tty bool
	}{"non-tty admin": {"admin", false}, "tty key": {"key", true}, "tty agent": {"agent", true}} {
		srv, calls := reauthServer(t, 1)
		logins := withReauthStub(t, c.tty, srv.URL)
		cc := &cmdContext{Ctx: &config.Context{Type: c.typ}, Client: &api.Client{BaseURL: srv.URL, HTTP: srv.Client()}}
		err := withReauth(rootCmd, cc, func() error { _, e := cc.Client.CreateAgent("x"); return e })
		if !isReauthRequired(err) || *logins != 0 || *calls != 1 {
			t.Errorf("%s: err=%v logins=%d calls=%d", name, err, *logins, *calls)
		}
		if code := clierr.ExitCode(err); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
	}
}
