package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestDryRunSkipsHTTPAndPrints(t *testing.T) {
	var sink bytes.Buffer
	client := &Client{BaseURL: "https://unused.example", DryRun: true, DryRunOut: &sink}
	_, err := client.doRequest("POST", "/api/tokens", map[string]string{"serviceName": "github"}, nil)
	if err != nil {
		t.Fatalf("dry-run should not error: %v", err)
	}
	out := sink.String()
	if !strings.Contains(out, "POST /api/tokens") || !strings.Contains(out, "github") {
		t.Errorf("dry-run output missing request details:\n%s", out)
	}
}

func TestDryRunOnlyAffectsWrites(t *testing.T) {
	client := &Client{BaseURL: "https://unused.example", DryRun: true}
	_, err := client.doRequest("GET", "/api/tokens", nil, nil)
	if err == nil {
		t.Error("GET in dry-run should still attempt the request (and fail to connect here)")
	}
}
