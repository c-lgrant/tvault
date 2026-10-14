package cmd

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/config"
)

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"":                                 "never",
		"2026-10-14T11:59:30+00:00":        "just now",
		"2026-10-14T11:14:59.123456+00:00": "45m ago",
		"2026-10-13T09:00:00+00:00":        "27h ago",
		"2026-10-01T12:00:00+00:00":        "13d ago",
		"not-a-time":                       "not-a-time",
	}
	for in, want := range cases {
		if got := relativeTime(in, now); got != want {
			t.Errorf("relativeTime(%q) = %q, want %q", in, got, want)
		}
	}
}

func agentsServer(t *testing.T) *recorder {
	t.Helper()
	return newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/agents":
			w.Write([]byte(`[
				{"id":"` + agentID + `","name":"busy","status":"active","lastActiveAt":"2026-10-14T11:00:00+00:00","totalAccesses":42.0},
				{"id":"bbbbbbbbbbbbbbbbbbbb","name":"idle","status":"active","lastActiveAt":null,"totalAccesses":0}
			]`))
		default:
			w.WriteHeader(500)
		}
	})
}

// The list shows when each agent was last active, so an unused one stands
// out; wide adds the access count; JSON keeps the raw timestamp.
func TestAgentsListShowsActivity(t *testing.T) {
	rec := agentsServer(t)
	setupContext(t, &config.Context{Type: "key", APIURL: rec.srv.URL, Identity: "k", APIKey: "tvkey_k"})

	table, _, err := run(t, "agents", "ls", "--format", "table")
	if err != nil {
		t.Fatalf("ls errored: %v", err)
	}
	if !strings.Contains(table, "LAST_ACTIVE") || !strings.Contains(table, "never") || strings.Contains(table, "ACCESSES") {
		t.Errorf("table output = %q, want LAST_ACTIVE with never and no ACCESSES column", table)
	}

	wide, _, err := run(t, "agents", "ls", "--format", "wide")
	if err != nil {
		t.Fatalf("ls wide errored: %v", err)
	}
	if !strings.Contains(wide, "ACCESSES") || !strings.Contains(wide, "42") {
		t.Errorf("wide output = %q, want ACCESSES with 42", wide)
	}

	js, _, err := run(t, "agents", "ls", "--format", "json")
	if err != nil {
		t.Fatalf("ls json errored: %v", err)
	}
	if !strings.Contains(js, `"last_active": "2026-10-14T11:00:00+00:00"`) || !strings.Contains(js, `"accesses": "42"`) {
		t.Errorf("json output = %q, want raw last_active and accesses", js)
	}
}
