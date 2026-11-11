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

func TestStoredFrontendURL(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{Current: "default", Contexts: map[string]*config.Context{
		// an old file: no frontend_url field
		"default": {Type: "admin", APIURL: "https://api.tokenvault.uk"},
		"custom":  {Type: "admin", APIURL: "https://api.example.test", FrontendURL: "https://console.example.test"},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, api, want string }{
		{"custom", "https://api.example.test", "https://console.example.test"},
		{"custom", "https://api.example.test/", "https://console.example.test"},
		{"custom", "https://api.other.test", ""}, // a different API: the saved site doesn't apply
		{"", "https://api.tokenvault.uk", ""},    // old context without the field
		{"missing", "https://api.example.test", ""},
	} {
		if got := storedFrontendURL(c.name, c.api); got != c.want {
			t.Errorf("storedFrontendURL(%q, %q) = %q, want %q", c.name, c.api, got, c.want)
		}
	}
	// and it survives a save/load round trip
	back, err := config.Load()
	if err != nil || back.Contexts["custom"].FrontendURL != "https://console.example.test" {
		t.Errorf("round trip: %+v, %v", back.Contexts["custom"], err)
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
