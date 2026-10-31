package cmd

import (
	"testing"

	"github.com/c-lgrant/tvault/internal/config"
)

func TestStoredAPIURL(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if got := storedAPIURL("dev"); got != "" {
		t.Fatalf("no config: storedAPIURL = %q, want empty", got)
	}
	cfg := &config.Config{Current: "default", Contexts: map[string]*config.Context{
		"default": {Type: "admin", APIURL: "https://api.tokenvault.uk"},
		"dev":     {Type: "admin", APIURL: "https://api.tokenvault.one"},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"dev":     "https://api.tokenvault.one",
		"":        "https://api.tokenvault.uk",
		"missing": "",
	} {
		if got := storedAPIURL(name); got != want {
			t.Errorf("storedAPIURL(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestDeriveFrontendURL(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"https://api.tokenvault.one", "https://tokenvault.one", true},
		{"https://api.tokenvault.uk/", "https://tokenvault.uk", true},
		{"http://api.localhost:8000", "http://localhost:8000", true},
		{"http://localhost:8000", "", false},
		{"not a url", "", false},
	}
	for _, c := range cases {
		got, ok := deriveFrontendURL(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("deriveFrontendURL(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
