package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

func TestAddSignIn_CreatesAttachesGrants(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	withStdin(t, "", false, "")
	stdout, stderr, err := run(t, "add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--for", "my-agent=tools")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.signIns) != 1 || b.signIns[0] != "notes" {
		t.Errorf("signIns = %v", b.signIns)
	}
	s := putServers(t, b, 0)
	if len(s) != 1 || s[0]["name"] != "mcp" || s[0]["url"] != "https://mcp.example.com/mcp" {
		t.Fatalf("servers = %v", s)
	}
	if h := s[0]["headers"].(map[string]any); h["Authorization"] != "Bearer ${AGENT_SESSION}" {
		t.Errorf("headers = %v", h)
	}
	if len(b.grants) != 1 || b.grants[0]["serviceName"] != "notes" {
		t.Fatalf("grants = %v", b.grants)
	}
	if u := b.grants[0]["uses"].([]any); len(u) != 1 || u[0] != "tools" {
		t.Errorf("uses = %v", u)
	}
	if len(b.stored) != 0 {
		t.Errorf("a sign-in credential stores no value: %q", b.stored)
	}
	if stdout != "" || !strings.Contains(stderr, "Token Vault sign-in credential") || !strings.Contains(stderr, "/api/mcp/notes/mcp") {
		t.Errorf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestAddSignIn_PlainForMeansTools_CustomServerName(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	withStdin(t, "", false, "")
	if _, _, err := run(t, "add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--server", "docs", "--for", "my-agent"); err != nil {
		t.Fatal(err)
	}
	if s := putServers(t, b, 0); s[0]["name"] != "docs" {
		t.Errorf("servers = %v", s)
	}
	if u := b.grants[0]["uses"].([]any); len(u) != 1 || u[0] != "tools" {
		t.Errorf("uses = %v", u)
	}
}

func TestAddSignIn_RefusesValueUseBeforeCallingAnything(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	for _, args := range [][]string{
		{"add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--for", "my-agent=value"},
		{"add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--for", "my-agent=value,tools"},
		{"add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--value", "x"},
		{"add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--mcp", "github"},
		{"add", "notes", "--sign-in", "http://mcp.example.com/mcp"},
	} {
		withStdin(t, "", false, "")
		_, _, err := run(t, args...)
		if err == nil || clierr.ExitCode(err) != userExit {
			t.Errorf("%v: err = %v", args, err)
		}
	}
	if len(b.signIns) != 0 || b.puts != 0 || len(b.grants) != 0 {
		t.Errorf("nothing may be called: signIns=%v puts=%d grants=%v", b.signIns, b.puts, b.grants)
	}
}

func TestAddSignIn_NameTakenSurfacesCode(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	b.signInStatus = 409
	b.signInBody = `{"detail":{"code":"NAME_TAKEN","message":"that name is in use"}}`
	withStdin(t, "", false, "")
	_, _, err := run(t, "add", "notes", "--sign-in", "https://mcp.example.com/mcp")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Code != "NAME_TAKEN" || b.puts != 0 {
		t.Errorf("err=%v puts=%d", err, b.puts)
	}
}

func TestAddSignIn_AttachFailureSaysHowToRetry(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	b.putStatus = 422
	b.putBody = `{"detail":{"code":"SIGNIN_URL_ON_TOKEN_VAULT","message":"nope"}}`
	withStdin(t, "", false, "")
	_, _, err := run(t, "add", "notes", "--sign-in", "https://mcp.example.com/mcp", "--for", "my-agent=tools")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if ce.Code != "SIGNIN_URL_ON_TOKEN_VAULT" || !strings.Contains(ce.Message, "is created") ||
		!strings.Contains(ce.Hint, "tvault mcp-servers add notes --name mcp") ||
		!strings.Contains(ce.Hint, "tvault grant my-agent notes=tools") {
		t.Errorf("err = %+v", ce)
	}
	if len(b.grants) != 0 {
		t.Errorf("no grant after a failed attach: %v", b.grants)
	}
}

func TestMCPServersAdd_AcceptsAgentSessionPlaceholder(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	_, _, err := run(t, "mcp-servers", "add", "notes", "--name", "mcp", "--url", "https://mcp.example.com/mcp",
		"--header", "Authorization: Bearer ${AGENT_SESSION}")
	if err != nil {
		t.Fatal(err)
	}
	if s := putServers(t, b, 0); s[0]["headers"].(map[string]any)["Authorization"] != "Bearer ${AGENT_SESSION}" {
		t.Errorf("servers = %v", s)
	}
}

func TestBuildMCPServer_NeedsOnePlaceholder(t *testing.T) {
	if _, err := buildMCPServer(nil, "a", "https://x.test", []string{"X-Y: z"}, "t"); err == nil {
		t.Error("a header with neither placeholder must be refused")
	}
	for _, h := range []string{"Authorization: Bearer ${TOKEN}", "Authorization: Bearer ${AGENT_SESSION}"} {
		if _, err := buildMCPServer(nil, "a", "https://x.test", []string{h}, "t"); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

func TestListShowLabelSignInKind(t *testing.T) {
	newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	stdout, _, err := run(t, "ls")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Token Vault sign-in") || !strings.Contains(stdout, "PlainText") || strings.Contains(stdout, "TVSignIn") {
		t.Errorf("ls = %q", stdout)
	}
}

func TestShowLabelsSignIn(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	b.tokenKind = "tv_signin"
	stdout, _, err := run(t, "show", "notes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Token Vault sign-in") {
		t.Errorf("show = %q", stdout)
	}
}

func TestValueCommandsRefuseSignInPlainly(t *testing.T) {
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	b.tokenKind = "tv_signin"

	// get: exit 6 like an empty credential, nothing on stdout.
	stdout, _, err := run(t, "get", "notes")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Code != "SIGNIN_NO_VALUE" || clierr.ExitCode(err) != 6 || stdout != "" {
		t.Errorf("get: err=%v stdout=%q", err, stdout)
	}
	// get goes straight to the ticket route, which refuses a sign-in
	// credential; nothing reaches the webhook.
	if b.credReads != 1 {
		t.Errorf("get asked for %d credential tickets, want 1", b.credReads)
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Errorf("message = %q", err.Error())
	}

	// set: refused before the value is asked for or sent.
	withStdin(t, "s3cret\n", false, "")
	stdout, _, err = run(t, "set", "notes")
	if !errors.As(err, &ce) || ce.Code != "SIGNIN_NO_VALUE" || clierr.ExitCode(err) != 6 || stdout != "" || len(b.stored) != 0 {
		t.Errorf("set: err=%v stdout=%q stored=%q", err, stdout, b.stored)
	}
}

func TestServerSigninNoValueMapsToExit6(t *testing.T) {
	// A server that answers SIGNIN_NO_VALUE on the ticket route (e.g. a
	// context that cannot see the kind) is still shown plainly with exit 6.
	b := newMCPBackend(t, "admin")
	t.Cleanup(func() { resetFlags(t) })
	b.tokenKind = "" // the CLI cannot tell; the server decides
	stdout, _, err := run(t, "get", "github")
	var ce *clierr.CLIError
	if !errors.As(err, &ce) || ce.Code != "SIGNIN_NO_VALUE" || clierr.ExitCode(err) != 6 || stdout != "" {
		t.Errorf("err=%v stdout=%q", err, stdout)
	}
	if !strings.Contains(ce.Hint, "tvault explain SIGNIN_NO_VALUE") {
		t.Errorf("hint = %q", ce.Hint)
	}
}

func TestExplain_CoversGoal4Codes(t *testing.T) {
	for _, code := range []string{"SIGNIN_NO_VALUE", "SIGNIN_TOOLS_ONLY", "SIGNIN_URL_ON_TOKEN_VAULT", "USE_SIGNIN_ROUTE",
		"SIGNIN_SESSION_REFUSED", "SIGNIN_SESSION_UNAVAILABLE", "MCP_KEY_RETIRED", "PROXY_CREATE_REMOVED",
		"PROXY_FROZEN", "PROXY_GROUPS_REMOVED", "MCP_TOGGLE_REMOVED", "SCOPE_RETIRED"} {
		out, errOut, err := run(t, "explain", strings.ToLower(code))
		out += errOut // explain prints through cobra's default writer (stderr)
		if err != nil || !strings.Contains(out, "what:") || !strings.Contains(out, "fix :") {
			t.Errorf("explain %s: err=%v out=%q", code, err, out)
		}
	}
}
