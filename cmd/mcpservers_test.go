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

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

const tplJSON = `{"templates":[
 {"id":"github","name":"GitHub","url":"https://api.githubcopilot.com/mcp/","headers":{"Authorization":"Bearer ${TOKEN}","Accept":"application/json, text/event-stream"},"docsUrl":"https://example.test/gh"},
 {"id":"linear","name":"Linear","url":"https://mcp.linear.app/mcp","headers":{"Authorization":"Bearer ${TOKEN}"},"docsUrl":""}]}`

// mcpBackend is a fake control plane for the credential MCP server routes,
// grants and the store-ticket flow. It holds one credential's server list.
type mcpBackend struct {
	srv *httptest.Server
	mu  sync.Mutex

	servers   string // JSON array served as {"servers": ...}
	putBodies []map[string]any
	puts      int
	putFails  int    // first N PUTs answer 401 REAUTH_REQUIRED
	putStatus int    // when set, every PUT answers this status ...
	putBody   string // ... with this body
	grants    []map[string]any
	stored    []string
}

func newMCPBackend(t *testing.T, ctxType string) *mcpBackend {
	t.Helper()
	b := &mcpBackend{servers: `[]`}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		p := r.URL.Path
		switch {
		case p == "/api/cli/auth/refresh":
			w.Write([]byte(`{"id_token":"idt","expires_in":3600}`))
		case r.Method == "GET" && p == "/api/config/mcp-templates":
			w.Write([]byte(tplJSON))
		case r.Method == "GET" && strings.HasSuffix(p, "/mcp-servers"):
			w.Write([]byte(`{"servers":` + b.servers + `}`))
		case r.Method == "PUT" && strings.HasSuffix(p, "/mcp-servers"):
			b.puts++
			b.putBodies = append(b.putBodies, body)
			if b.puts <= b.putFails {
				w.WriteHeader(401)
				w.Write([]byte(`{"detail":{"code":"REAUTH_REQUIRED","message":"sign in again"}}`))
				return
			}
			if b.putStatus != 0 {
				w.WriteHeader(b.putStatus)
				w.Write([]byte(b.putBody))
				return
			}
			out, _ := json.Marshal(body["servers"])
			b.servers = string(out)
			w.Write([]byte(`{"servers":` + b.servers + `}`))
		case r.Method == "GET" && p == "/api/agents":
			w.Write([]byte(existingAgent))
		case r.Method == "GET" && strings.HasPrefix(p, "/api/agents/"):
			w.Write([]byte(`{"id":"abcdefghij0123456789","name":"my-agent","mcpEnabled":true}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/grants"):
			b.grants = append(b.grants, body)
			w.Write([]byte(`{}`))
		case r.Method == "GET" && strings.HasPrefix(p, "/api/tokens/"):
			w.Write([]byte(`{"serviceName":"github","tokenType":"PlainText"}`))
		case r.Method == "POST" && p == "/api/vault/store-ticket":
			w.Write([]byte(`{"ticket":"tk","webhookUrl":"` + b.srv.URL + `/wh","expiresIn":60}`))
		case r.Method == "POST" && p == "/wh/v1/store":
			td, _ := body["tokenData"].(map[string]any)
			b.stored = append(b.stored, td["accessToken"].(string))
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, p)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(b.srv.Close)
	lastBackend = &agentBackend{srv: b.srv} // for fakeClaude's %URL%
	ctx := &config.Context{Type: ctxType, APIURL: b.srv.URL, Identity: "me"}
	if ctxType == "admin" {
		ctx.RefreshToken = "rt"
	} else {
		ctx.APIKey = "tvkey_k"
	}
	setupContext(t, ctx)
	return b
}

const existingServer = `[{"name":"docs","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${TOKEN}"}}]`

func putServers(t *testing.T, b *mcpBackend, i int) []map[string]any {
	t.Helper()
	if len(b.putBodies) <= i {
		t.Fatalf("only %d PUT(s) sent", len(b.putBodies))
	}
	raw, _ := b.putBodies[i]["servers"].([]any)
	out := make([]map[string]any, len(raw))
	for j, s := range raw {
		out[j] = s.(map[string]any)
	}
	return out
}

func TestMCPServers_Templates(t *testing.T) {
	newMCPBackend(t, "admin")
	stdout, _, err := run(t, "mcp-servers", "templates", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || len(got) != 2 || got[0]["id"] != "github" {
		t.Errorf("stdout = %q (%v)", stdout, err)
	}
	table, _, _ := run(t, "mcp", "templates", "--format", "table")
	if !strings.Contains(table, "linear") || !strings.Contains(table, "ID") {
		t.Errorf("table = %q", table)
	}
}

func TestMCPServers_ListJSONAndTable(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.servers = `[{"name":"github","url":"https://api.githubcopilot.com/mcp","headers":{"Authorization":"Bearer ${TOKEN}"},"template":"github"}]`
	stdout, _, err := run(t, "mcp-servers", "ls", "github", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || len(got) != 1 {
		t.Fatalf("stdout = %q (%v)", stdout, err)
	}
	if got[0]["endpoint"] != b.srv.URL+"/api/mcp/github/github" || got[0]["template"] != "github" {
		t.Errorf("row = %v", got[0])
	}
	table, _, _ := run(t, "mcp-servers", "list", "github", "--format", "wide")
	if !strings.Contains(table, "Authorization: Bearer ${TOKEN}") {
		t.Errorf("wide table = %q", table)
	}

	b.servers = `[{"name":"github","url":"https://api.githubcopilot.com/mcp","tools":{"count":41,"fetchedAt":"2026-10-31T20:00:00Z","stale":true}},
	 {"name":"docs","url":"https://docs.example.com/mcp","tools":{"count":0,"fetchedAt":null}}]`
	table, _, _ = run(t, "mcp-servers", "ls", "github", "--format", "table")
	if !strings.Contains(table, "41 (stale)") || !strings.Contains(table, "pending") {
		t.Errorf("tools column = %q", table)
	}
	// A write sends the list back without the read-only tool summary.
	if _, _, err := run(t, "mcp-servers", "add", "github", "--name", "x", "--url", "https://x.example.com/mcp",
		"--header", "Authorization: Bearer ${TOKEN}"); err != nil {
		t.Fatal(err)
	}
	for _, s := range putServers(t, b, 0) {
		if _, ok := s["tools"]; ok {
			t.Errorf("PUT sent tools: %v", s)
		}
	}

	b.servers = `[]`
	stdout, stderr, _ := run(t, "mcp-servers", "ls", "github", "--format", "table")
	if stdout != "" || !strings.Contains(stderr, "No MCP servers") {
		t.Errorf("empty: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestMCPServers_AddPresetIsFullReplaceWithLiteralPlaceholder(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.servers = existingServer
	stdout, stderr, err := run(t, "mcp-servers", "add", "github", "--preset", "github")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	servers := putServers(t, b, 0)
	if len(servers) != 2 || servers[0]["name"] != "docs" || servers[1]["name"] != "github" {
		t.Fatalf("PUT must carry the existing server plus the new one: %v", servers)
	}
	h := servers[1]["headers"].(map[string]any)
	if h["Authorization"] != "Bearer ${TOKEN}" || servers[1]["template"] != "github" ||
		servers[1]["url"] != "https://api.githubcopilot.com/mcp/" {
		t.Errorf("new server = %v", servers[1])
	}
	if _, ok := servers[0]["urlRedacted"]; ok {
		t.Errorf("read-only flag leaked into the PUT: %v", servers[0])
	}
	if !strings.Contains(stderr, "/api/mcp/github/github") || !strings.Contains(stderr, "github=tools:github") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestMCPServers_AddCustomAndOverrides(t *testing.T) {
	b := newMCPBackend(t, "admin")
	_, _, err := run(t, "mcp-servers", "add", "github", "--name", "docs", "--url", "https://mcp.example.com/mcp",
		"--header", "Authorization: Bearer ${TOKEN}", "--header", "Accept: application/json, text/event-stream")
	if err != nil {
		t.Fatal(err)
	}
	s := putServers(t, b, 0)[0]
	h := s["headers"].(map[string]any)
	if s["name"] != "docs" || h["Accept"] != "application/json, text/event-stream" || h["Authorization"] != "Bearer ${TOKEN}" {
		t.Errorf("server = %v", s)
	}
	if _, has := s["template"]; has {
		t.Errorf("custom server must not carry a template: %v", s)
	}

	// A preset with overridden name, url and a header replaced case-insensitively.
	b2 := newMCPBackend(t, "admin")
	_, _, err = run(t, "mcp-servers", "add", "github", "--preset", "github", "--name", "gh2",
		"--url", "https://ghe.example.com/mcp", "--header", "authorization: token ${TOKEN}")
	if err != nil {
		t.Fatal(err)
	}
	s = putServers(t, b2, 0)[0]
	h = s["headers"].(map[string]any)
	if s["name"] != "gh2" || s["url"] != "https://ghe.example.com/mcp" || s["template"] != "github" ||
		h["authorization"] != "token ${TOKEN}" || h["Authorization"] != nil {
		t.Errorf("server = %v", s)
	}
}

func TestMCPServers_AddSameNameReplaces(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.servers = existingServer
	_, _, err := run(t, "mcp-servers", "add", "github", "--name", "docs", "--url", "https://other.example.com/mcp",
		"--header", "Authorization: Bearer ${TOKEN}")
	if err != nil {
		t.Fatal(err)
	}
	servers := putServers(t, b, 0)
	if len(servers) != 1 || servers[0]["url"] != "https://other.example.com/mcp" {
		t.Errorf("servers = %v", servers)
	}
}

func TestMCPServers_AddRejectsLocallyWithoutPlaceholderOrFields(t *testing.T) {
	for name, args := range map[string][]string{
		"no placeholder":   {"--name", "docs", "--url", "https://x.example.com", "--header", "Authorization: Bearer "},
		"no name":          {"--url", "https://x.example.com", "--header", "A: ${TOKEN}"},
		"no url":           {"--name", "docs", "--header", "A: ${TOKEN}"},
		"malformed header": {"--name", "docs", "--url", "https://x.example.com", "--header", "oops"},
		"unknown preset":   {"--preset", "nope"},
	} {
		b := newMCPBackend(t, "admin")
		_, _, err := run(t, append([]string{"mcp-servers", "add", "github"}, args...)...)
		if err == nil || clierr.ExitCode(err) != userExit {
			t.Errorf("%s: err = %v, want a user error", name, err)
		}
		if b.puts != 0 {
			t.Errorf("%s: nothing should be sent", name)
		}
	}
	_, _, err := run(t, "mcp-servers", "add", "github", "--preset", "nope")
	if err == nil || !strings.Contains(err.Error(), "github, linear") {
		t.Errorf("unknown preset should list the known ones: %v", err)
	}
}

func TestMCPServers_AddReauthRetriesOnce(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.putFails = 1
	logins := withReauthStub(t, true, b.srv.URL)
	if _, _, err := run(t, "mcp-servers", "add", "github", "--preset", "linear"); err != nil {
		t.Fatal(err)
	}
	if *logins != 1 || b.puts != 2 {
		t.Errorf("logins=%d puts=%d, want 1 and 2", *logins, b.puts)
	}
	// Without a terminal the plain error (exit 2) stays.
	b2 := newMCPBackend(t, "admin")
	b2.putFails = 1
	withReauthStub(t, false, b2.srv.URL)
	_, _, err := run(t, "mcp-servers", "add", "github", "--preset", "linear")
	if !isReauthRequired(err) || clierr.ExitCode(err) != 2 {
		t.Errorf("err = %v", err)
	}
}

func TestMCPServers_ServerErrorsKeepTheirCode(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.putStatus = 422
	b.putBody = `{"detail":{"code":"MCP_SERVER_LITERAL_CREDENTIAL","message":"header Authorization may hold only ${TOKEN}"}}`
	_, _, err := run(t, "mcp-servers", "add", "github", "--preset", "github")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Code != "MCP_SERVER_LITERAL_CREDENTIAL" || clierr.ExitCode(err) != userExit {
		t.Fatalf("err = %v", err)
	}
	b.putStatus, b.putBody = 422, `{"detail":{"code":"SERVICE_NOT_HOSTABLE","message":"bad name"}}`
	_, _, err = run(t, "mcp-servers", "add", "github", "--preset", "github")
	if !errors.As(err, &ce) || ce.Code != "SERVICE_NOT_HOSTABLE" {
		t.Fatalf("err = %v", err)
	}
}

func TestMCPServers_Rm(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.servers = `[{"name":"docs","url":"https://a.example.com","headers":{"A":"${TOKEN}"}},{"name":"gh","url":"https://b.example.com","headers":{"A":"${TOKEN}"}}]`
	if _, _, err := run(t, "mcp-servers", "rm", "github", "docs", "--force"); err != nil {
		t.Fatal(err)
	}
	if s := putServers(t, b, 0); len(s) != 1 || s[0]["name"] != "gh" || s[0]["url"] != "https://b.example.com" {
		t.Errorf("remaining = %v", s)
	}
	// The last one goes: PUT carries [] (not null), clearing the list.
	if _, _, err := run(t, "mcp-servers", "rm", "github", "gh", "--force"); err != nil {
		t.Fatal(err)
	}
	if s, ok := b.putBodies[1]["servers"].([]any); !ok || len(s) != 0 {
		t.Errorf("clearing body = %v", b.putBodies[1])
	}
	// Unknown name: user error, no PUT.
	puts := b.puts
	_, _, err := run(t, "mcp-servers", "rm", "github", "nope", "--force")
	if err == nil || clierr.ExitCode(err) != userExit || b.puts != puts {
		t.Errorf("err=%v puts=%d->%d", err, puts, b.puts)
	}
	// Non-interactive without --force refuses before touching anything.
	_, _, err = run(t, "mcp-servers", "rm", "github", "gh")
	if err == nil || b.puts != puts {
		t.Errorf("err=%v puts=%d", err, b.puts)
	}
}

func TestMCPServers_KeyContextCannotOverwriteRedactedList(t *testing.T) {
	b := newMCPBackend(t, "key")
	b.servers = `[{"name":"docs","url":"https://mcp.example.com","urlRedacted":true}]`
	_, _, err := run(t, "mcp-servers", "add", "github", "--preset", "github")
	if clierr.ExitCode(err) != 9 || b.puts != 0 {
		t.Errorf("err=%v puts=%d, want exit 9 and no PUT", err, b.puts)
	}
	// From an empty list a key may add (the server enforces its own gates).
	b.servers = `[]`
	if _, _, err := run(t, "mcp-servers", "add", "github", "--preset", "github"); err != nil || b.puts != 1 {
		t.Errorf("err=%v puts=%d", err, b.puts)
	}
}

func TestMCPServers_DryRunSendsNoPut(t *testing.T) {
	b := newMCPBackend(t, "admin")
	// The dry-run request line goes to the process stderr (not captured here).
	_, stderr, err := run(t, "mcp-servers", "add", "github", "--preset", "github", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if b.puts != 0 || strings.Contains(stderr, "Attached") {
		t.Errorf("puts=%d stderr=%q", b.puts, stderr)
	}
}

// --- grant specs -----------------------------------------------------------

func TestParseGrantSpec(t *testing.T) {
	for _, c := range []struct {
		in      string
		svc     string
		uses    string
		servers string
		bad     bool
	}{
		{"github", "github", "", "", false},
		{"github=tools", "github", "tools", "", false},
		{"github=value,tools", "github", "value,tools", "", false},
		{"github=value,tools:github", "github", "value,tools", "github", false},
		{"github=tools:a,b", "github", "tools", "a,b", false},
		{"github=tools,tools", "github", "tools", "", false},
		{"github=value:a", "", "", "", true},
		{"github=admin", "", "", "", true},
		{"github=", "", "", "", true},
		{"github=tools:", "", "", "", true},
		{"=tools", "", "", "", true},
	} {
		got, err := parseGrantSpec(c.in, "grant")
		if c.bad {
			if err == nil || clierr.ExitCode(err) != userExit {
				t.Errorf("%q: err = %v, want a user error", c.in, err)
			}
			continue
		}
		if err != nil || got.Service != c.svc || strings.Join(got.Uses, ",") != c.uses || strings.Join(got.Servers, ",") != c.servers {
			t.Errorf("%q: got %+v, %v", c.in, got, err)
		}
	}
}

func TestGrant_SendsUsesAndServersOnlyWhenGiven(t *testing.T) {
	b := newMCPBackend(t, "admin")
	if _, _, err := run(t, "grant", "my-agent", "stripe", "github=value,tools:github", "linear=tools"); err != nil {
		t.Fatal(err)
	}
	if len(b.grants) != 3 {
		t.Fatalf("grants = %v", b.grants)
	}
	if _, has := b.grants[0]["uses"]; has || b.grants[0]["serviceName"] != "stripe" {
		t.Errorf("plain service must stay a plain value grant: %v", b.grants[0])
	}
	if u := b.grants[1]["uses"].([]any); len(u) != 2 || u[0] != "value" || u[1] != "tools" {
		t.Errorf("uses = %v", b.grants[1])
	}
	if s := b.grants[1]["servers"].([]any); len(s) != 1 || s[0] != "github" || b.grants[1]["serviceName"] != "github" {
		t.Errorf("servers = %v", b.grants[1])
	}
	if _, has := b.grants[2]["servers"]; has {
		t.Errorf("no servers named means all: %v", b.grants[2])
	}
}

func TestGrant_BadSpecSendsNothing(t *testing.T) {
	b := newMCPBackend(t, "admin")
	_, _, err := run(t, "grant", "my-agent", "stripe", "github=value:github")
	if err == nil || clierr.ExitCode(err) != userExit || len(b.grants) != 0 {
		t.Errorf("err=%v grants=%v", err, b.grants)
	}
}

func TestGrant_ServerErrorCodesSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/cli/auth/refresh":
			w.Write([]byte(`{"id_token":"idt","expires_in":3600}`))
		case r.URL.Path == "/api/agents":
			w.Write([]byte(existingAgent))
		default:
			w.WriteHeader(422)
			w.Write([]byte(`{"detail":{"code":"INVALID_GRANT_USES","message":"tools needs a credential with MCP servers"}}`))
		}
	}))
	defer srv.Close()
	setupContext(t, &config.Context{Type: "admin", APIURL: srv.URL, Identity: "me", RefreshToken: "rt"})
	_, _, err := run(t, "grant", "my-agent", "github=tools")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) && !strings.Contains(err.Error(), "tools needs") {
		t.Errorf("err = %v", err)
	}
}

func TestExplain_CoversMCPServerAndGrantCodes(t *testing.T) {
	for _, code := range []string{"MCP_SERVER_LITERAL_CREDENTIAL", "MCP_SERVER_HEADERS_REQUIRED", "SERVICE_NOT_HOSTABLE",
		"MCP_SERVERS_CAP", "INVALID_GRANT_USES", "INVALID_GRANT_SERVERS", "GRANT_USES_EXCEEDED",
		"GRANT_SERVERS_EXCEEDED", "GRANT_TOOLS_ONLY"} {
		out, _, err := run(t, "explain", strings.ToLower(code))
		if err != nil {
			t.Errorf("explain %s: %v", code, err)
		}
		if _, ok := errorExplanations[code]; !ok {
			t.Errorf("no explanation for %s (output %q)", code, out)
		}
	}
}

// --- tvault add --mcp / --for ----------------------------------------------

func TestAddMCP_StoresThenAttaches(t *testing.T) {
	b := newMCPBackend(t, "admin")
	withStdin(t, "s3cret\n", false, "")
	stdout, stderr, err := runCLI(t, "add", "github", "--mcp", "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.stored) != 1 || b.stored[0] != "s3cret" {
		t.Errorf("stored = %q", b.stored)
	}
	s := putServers(t, b, 0)
	if len(s) != 1 || s[0]["name"] != "github" || s[0]["template"] != "github" {
		t.Errorf("servers = %v", s)
	}
	// The secret is stored at the webhook only: never in a TV request body.
	for _, body := range b.putBodies {
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), "s3cret") {
			t.Errorf("credential value leaked into %s", raw)
		}
	}
	if stdout != "" || !strings.Contains(stderr, "Attached MCP server") {
		t.Errorf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestAddMCP_AttachFailureKeepsValueAndSaysHowToRetry(t *testing.T) {
	b := newMCPBackend(t, "admin")
	b.putStatus = 422
	b.putBody = `{"detail":{"code":"SERVICE_NOT_HOSTABLE","message":"bad credential name"}}`
	withStdin(t, "s3cret\n", false, "")
	_, _, err := runCLI(t, "add", "github", "--mcp", "github", "--for", "my-agent=tools")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if len(b.stored) != 1 {
		t.Errorf("the value must stay stored: %q", b.stored)
	}
	if ce.Code != "SERVICE_NOT_HOSTABLE" || !strings.Contains(ce.Message, "is stored") ||
		!strings.Contains(ce.Hint, "tvault mcp-servers add github --preset github") ||
		!strings.Contains(ce.Hint, "tvault grant my-agent github=tools") {
		t.Errorf("err = %+v", ce)
	}
	if len(b.grants) != 0 {
		t.Errorf("no grant after a failed attach: %v", b.grants)
	}
}

func TestAddMCP_UnknownPresetFailsBeforeStoring(t *testing.T) {
	b := newMCPBackend(t, "admin")
	withStdin(t, "s3cret\n", false, "")
	_, _, err := runCLI(t, "add", "github", "--mcp", "nope")
	if err == nil || clierr.ExitCode(err) != userExit || len(b.stored) != 0 {
		t.Errorf("err=%v stored=%q", err, b.stored)
	}
}

func TestAddFor_AcceptsUsesAndServers(t *testing.T) {
	b := newMCPBackend(t, "admin")
	withStdin(t, "s3cret\n", false, "")
	if _, _, err := runCLI(t, "add", "github", "--mcp", "github", "--for", "my-agent=value,tools:github"); err != nil {
		t.Fatal(err)
	}
	if len(b.grants) != 1 || b.grants[0]["serviceName"] != "github" {
		t.Fatalf("grants = %v", b.grants)
	}
	if u := b.grants[0]["uses"].([]any); len(u) != 2 {
		t.Errorf("uses = %v", b.grants[0])
	}
	if s := b.grants[0]["servers"].([]any); len(s) != 1 || s[0] != "github" {
		t.Errorf("servers = %v", b.grants[0])
	}
	// A bad --for spec stops before the value is asked for or stored.
	withStdin(t, "s3cret\n", false, "")
	before := len(b.stored)
	_, _, err := runCLI(t, "add", "github", "--for", "my-agent=bogus")
	if err == nil || clierr.ExitCode(err) != userExit || len(b.stored) != before {
		t.Errorf("err=%v stored=%q", err, b.stored)
	}
}

// --- tvault connect --server -----------------------------------------------

func TestConnectServer_AddsPerServerEntry(t *testing.T) {
	b := newMCPBackend(t, "admin")
	withStdin(t, "", false, "")
	ran := fakeClaude(t, true, "", errors.New("exit status 1"))
	stdout, stderr, err := runCLI(t, "connect", "my-agent", "github=tools:github", "--server", "github/github")
	if err != nil {
		t.Fatal(err)
	}
	want := "mcp add --transport http --scope user tv-github-github " + b.srv.URL + "/api/mcp/github/github"
	if len(*ran) != 2 || (*ran)[0] != "mcp get tv-github-github" || (*ran)[1] != want {
		t.Errorf("claude invocations = %q, want get then %q", *ran, want)
	}
	if !strings.Contains(stderr, "claude "+want) {
		t.Errorf("the command should be printed first: %q", stderr)
	}
	for _, a := range *ran {
		if strings.Contains(a, "mcp add --transport http --scope user tokenvault") {
			t.Errorf("must not register the general entry: %q", *ran)
		}
	}
	if len(b.grants) != 1 || strings.Contains(stderr, "needs a tools grant") || stdout != "" {
		t.Errorf("grants=%v stderr=%q stdout=%q", b.grants, stderr, stdout)
	}
}

func TestConnectServer_NameOverrideDryRunAndGrantNote(t *testing.T) {
	newMCPBackend(t, "admin")
	withStdin(t, "", false, "")
	ran := fakeClaude(t, true, "", errors.New("exit status 1"))
	_, stderr, err := runCLI(t, "connect", "my-agent", "--server", "github/docs", "--name", "gh-docs", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if len(*ran) != 0 {
		t.Errorf("--dry-run must run nothing: %q", *ran)
	}
	if !strings.Contains(stderr, "claude mcp add --transport http --scope user gh-docs ") ||
		!strings.Contains(stderr, "/api/mcp/github/docs") ||
		!strings.Contains(stderr, "tvault grant my-agent github=tools:docs") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestConnectServer_Validation(t *testing.T) {
	newMCPBackend(t, "admin")
	withStdin(t, "", false, "")
	for _, args := range [][]string{
		{"connect", "my-agent", "--server", "github"},
		{"connect", "my-agent", "--server", "/x"},
		{"connect", "my-agent", "--server", "a/b/c"},
		{"connect", "my-agent", "--name", "x"},
	} {
		if _, _, err := run(t, args...); err == nil || clierr.ExitCode(err) != userExit {
			t.Errorf("%v: err = %v, want a user error", args, err)
		}
	}
}

func TestConnectDefaultStillRegistersGeneralEntry(t *testing.T) {
	b := newMCPBackend(t, "admin")
	withStdin(t, "", false, "")
	ran := fakeClaude(t, true, "", errors.New("exit status 1"))
	if _, _, err := runCLI(t, "connect", "my-agent", "github"); err != nil {
		t.Fatal(err)
	}
	want := "mcp add --transport http --scope user tokenvault " + b.srv.URL + "/api/agents/mcp"
	if len(*ran) != 2 || (*ran)[0] != "mcp get tokenvault" || (*ran)[1] != want {
		t.Errorf("claude invocations = %q", *ran)
	}
}
