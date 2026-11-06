package cmd

import (
	"reflect"
	"strings"
	"testing"
)

// `mcp` is the name shown to people; the API still receives "tools".
func TestParseGrantSpecMCPAliasSendsTools(t *testing.T) {
	cases := []struct {
		arg     string
		uses    []string
		servers []string
	}{
		{"github=mcp", []string{"tools"}, nil},
		{"github=tools", []string{"tools"}, nil},
		{"github=value,mcp", []string{"value", "tools"}, nil},
		{"github=mcp:github,docs", []string{"tools"}, []string{"github", "docs"}},
		{"github=mcp,tools", []string{"tools"}, nil},
	}
	for _, c := range cases {
		spec, err := parseGrantSpec(c.arg, "grant")
		if err != nil {
			t.Fatalf("%s: %v", c.arg, err)
		}
		if !reflect.DeepEqual(spec.Uses, c.uses) || !reflect.DeepEqual(spec.Servers, c.servers) {
			t.Errorf("%s: uses=%v servers=%v", c.arg, spec.Uses, spec.Servers)
		}
	}
}

func TestParseGrantSpecErrorsNameMCP(t *testing.T) {
	_, err := parseGrantSpec("github=nope", "grant")
	if err == nil || !strings.Contains(err.Error(), `"mcp"`) {
		t.Fatalf("want an error naming mcp, got %v", err)
	}
	if _, err := parseGrantSpec("github=value:docs", "grant"); err == nil {
		t.Fatal("servers without mcp must be refused")
	}
}
