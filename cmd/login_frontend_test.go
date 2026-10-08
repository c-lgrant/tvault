package cmd

import "testing"

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
