package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

const (
	victimID  = "vVvVvVvVvVvVvVvVvVvV" // 20-char agent ID
	squatID   = "sSsSsSsSsSsSsSsSsSsS" // the squatter's own ID
	idShaped  = "abcdefghij0123456789" // a NAME that looks like an ID
	namedByID = "nNnNnNnNnNnNnNnNnNnN"
)

// An attacker names an agent after the victim's ID. Acting on that ID must be
// refused rather than guessed, for grants and for deletion alike.
func TestSquattedAgentName_IsRefusedAsAmbiguous(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/agents" {
			w.Write([]byte(`[{"id":"` + victimID + `","name":"prod-bot","status":"active"},{"id":"` + squatID + `","name":"` + victimID + `","status":"active"}]`))
			return
		}
		w.WriteHeader(500)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	for _, args := range [][]string{
		{"agents", "grants", "add", victimID, "github"},
		{"agents", "rm", victimID, "--force"},
		{"agents", "suspend", victimID},
		{"agents", "rotate-key", victimID},
	} {
		_, _, err := run(t, args...)
		if err == nil || clierr.ExitCode(err) != 1 || !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("%v: want an ambiguity refusal (exit 1), got %v", args, err)
			continue
		}
		if !strings.Contains(err.Error(), squatID) || !strings.Contains(err.Error(), "prod-bot") {
			t.Errorf("%v: error should show both principals: %v", args, err)
		}
	}
	for _, c := range rec.calls {
		if c != "GET /api/agents" {
			t.Errorf("a mutation was sent despite the ambiguity: %v", rec.calls)
		}
	}
}

func TestSquattedKeyName_IsRefusedAsAmbiguous(t *testing.T) {
	other := strings.Replace(keyJSON, `"id":"`+keyID+`","name":"ci"`, `"id":"zZzZzZzZzZzZzZzZzZzZ","name":"`+keyID+`"`, 1)
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`{"keys":[` + keyJSON + `,` + other + `]}`))
			return
		}
		w.WriteHeader(500)
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, _, err := run(t, "keys", "revoke", keyID, "--force")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("want ambiguity refusal, got %v", err)
	}
	if rec.has("DELETE /api/keys/" + keyID) {
		t.Errorf("revoke was sent: %v", rec.calls)
	}
}

// An ID-shaped ref that is no agent's ID but is one agent's name: read-only
// commands resolve it by name; mutating commands refuse and name the id.
func TestIDShapedName_ReadOnlyResolvesMutatingRefuses(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + namedByID + `","name":"` + idShaped + `","status":"active"}]`))
		case "GET /api/agents/" + namedByID:
			w.Write([]byte(`{"id":"` + namedByID + `","name":"` + idShaped + `","status":"active","grants":[]}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	stdout, _, err := run(t, "agents", "show", idShaped, "--format", "json")
	if err != nil || !strings.Contains(stdout, namedByID) {
		t.Fatalf("show should resolve by name: err=%v stdout=%q", err, stdout)
	}

	for _, args := range [][]string{
		{"agents", "rm", idShaped, "--force"},
		{"agents", "suspend", idShaped},
		{"agents", "resume", idShaped},
		{"agents", "rotate-key", idShaped},
		{"agents", "grants", "add", idShaped, "github"},
		{"agents", "grants", "rm", idShaped, "github", "--force"},
	} {
		_, _, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "NAMED "+idShaped) || !strings.Contains(err.Error(), namedByID) {
			t.Errorf("%v: want a 'use its id' refusal, got %v", args, err)
		}
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "DELETE") || strings.HasPrefix(c, "POST") || strings.HasPrefix(c, "PATCH") {
			t.Errorf("a mutation was sent: %v", rec.calls)
		}
	}
}

// A real ID resolves to that agent, and the destructive output names both the
// name and the id.
func TestRm_ShowsResolvedNameAndID(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + victimID + `","name":"prod-bot","status":"active"}]`))
		case "DELETE /api/agents/" + victimID:
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	_, stderr, err := run(t, "agents", "rm", "prod-bot", "--force")
	if err != nil || !strings.Contains(stderr, "prod-bot ("+victimID+")") {
		t.Errorf("err=%v stderr=%q", err, stderr)
	}
}

// Without agents:read the ID-shaped ref is taken as an ID (the server decides);
// a plain name still gets the "pass the id" error.
func TestListingDenied_IDShapedIsIDNameIsError(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(403)
			w.Write([]byte(`{"detail":{"code":"SCOPE_DENIED","message":"denied","missingScope":"agents:read"}}`))
			return
		}
		w.Write([]byte(`{}`))
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	if _, _, err := run(t, "agents", "rm", victimID, "--force"); err != nil {
		t.Fatalf("rm by id with listing denied: %v", err)
	}
	if !rec.has("DELETE /api/agents/" + victimID) {
		t.Errorf("calls = %v", rec.calls)
	}
	_, _, err := run(t, "agents", "rm", "prod-bot", "--force")
	if clierr.ExitCode(err) != 8 || !strings.Contains(err.Error(), "agent ID") {
		t.Errorf("name with listing denied: want exit 8 + 'agent ID', got %v", err)
	}
}

// Server-supplied names can't repaint a confirmation prompt: control, escape
// and bidi characters come out escaped and quoted.
func TestLabelEscapesUnsafeNames(t *testing.T) {
	cases := map[string]string{
		"build-worker":                            "build-worker (a1)",
		"x\x1b[2K\rpayments":                      `"x\x1b[2K\rpayments" (a1)`,
		"ok\nAbout to delete agent(s): y":         `"ok\nAbout to delete agent(s): y" (a1)`,
		"evil" + string(rune(0x202e)) + "gnp.exe": `"evil` + `\` + `u202egnp.exe" (a1)`,
	}
	for name, want := range cases {
		if got := (resolved{ID: "a1", Name: name}).label(); got != want {
			t.Errorf("label(%q) = %s, want %s", name, got, want)
		}
	}
}
