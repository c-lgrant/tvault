package webhook

import "testing"

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"foo.ngrok-free.app":          "foo.ngrok-free.app",
		"https://foo.ngrok-free.app":  "foo.ngrok-free.app",
		"http://foo.ngrok-free.app":   "foo.ngrok-free.app",
		"HTTPS://Foo.Ngrok.App":       "Foo.Ngrok.App",
		"https://foo.ngrok-free.app/": "foo.ngrok-free.app",
		"  https://foo.example/  ":    "foo.example",
		"":                            "",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnsureHTTPS(t *testing.T) {
	cases := map[string]string{
		"foo.example":          "https://foo.example",
		"https://foo.example":  "https://foo.example",
		"http://foo.example":   "https://foo.example",
		"HTTP://Foo.Example":   "https://Foo.Example",
		"https://foo.example/": "https://foo.example",
		"  foo.example  ":      "https://foo.example",
		"":                     "",
	}
	for in, want := range cases {
		if got := ensureHTTPS(in); got != want {
			t.Errorf("ensureHTTPS(%q) = %q, want %q", in, got, want)
		}
	}
}
