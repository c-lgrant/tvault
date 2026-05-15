package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveFormat(t *testing.T) {
	if got := ResolveFormat("json", false); got != FormatJSON {
		t.Errorf("explicit json → %v", got)
	}
	if got := ResolveFormat("", false); got != FormatJSON {
		t.Errorf("non-tty default → %v, want json", got)
	}
	if got := ResolveFormat("", true); got != FormatTable {
		t.Errorf("tty default → %v, want table", got)
	}
}

func TestRenderTable(t *testing.T) {
	buf := new(bytes.Buffer)
	rows := []map[string]string{
		{"service": "github", "type": "oauth", "status": "active"},
		{"service": "stripe", "type": "api_key", "status": "active"},
	}
	err := Render(buf, FormatTable, []string{"service", "type", "status"}, rows)
	if err != nil {
		t.Fatalf("Render errored: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "github") || !strings.Contains(out, "SERVICE") {
		t.Errorf("table output missing header or row:\n%s", out)
	}
}

func TestRenderName(t *testing.T) {
	buf := new(bytes.Buffer)
	rows := []map[string]string{{"service": "github"}, {"service": "stripe"}}
	if err := Render(buf, FormatName, []string{"service"}, rows); err != nil {
		t.Fatalf("Render errored: %v", err)
	}
	if buf.String() != "github\nstripe\n" {
		t.Errorf("name output = %q", buf.String())
	}
}

func TestRenderJSON(t *testing.T) {
	buf := new(bytes.Buffer)
	rows := []map[string]string{{"service": "github", "type": "oauth"}}
	if err := Render(buf, FormatJSON, []string{"service", "type"}, rows); err != nil {
		t.Fatalf("Render errored: %v", err)
	}
	if !strings.Contains(buf.String(), `"service": "github"`) {
		t.Errorf("json output = %s", buf.String())
	}
}
