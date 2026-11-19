package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/config"
)

// The grants list shows each entry of a grant (the value, each MCP server) with its own end.
func TestGrantsListShowsOneRowPerEntry(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents":
			w.Write([]byte(`[{"id":"` + agentID + `","name":"busy","status":"active"}]`))
		case "GET /api/agents/" + agentID:
			w.Write([]byte(`{"id":"` + agentID + `","name":"busy","status":"active","grants":[
				{"serviceName":"github","entries":[{"key":"value","expiresAt":null},
				 {"key":"tools:main","expiresAt":"2026-11-20T10:00:00+00:00"}]},
				{"serviceName":"old","grantExpiresAt":"2026-12-01T00:00:00+00:00"}]}`))
		default:
			w.WriteHeader(500)
		}
	})
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	table, errOut, err := run(t, "agents", "grants", "ls", "busy", "--format", "table")
	if err != nil {
		t.Fatalf("ls errored: %v (%s)", err, errOut)
	}
	for _, want := range []string{"ENTRY", "EXPIRES", "value", "never", "tools:main", "2026-11-20T10:00:00+00:00",
		"old", "2026-12-01T00:00:00+00:00"} {
		if !strings.Contains(table, want) {
			t.Errorf("table missing %q:\n%s", want, table)
		}
	}
	if strings.Count(table, "github") != 2 {
		t.Errorf("want one github row per entry:\n%s", table)
	}
}
