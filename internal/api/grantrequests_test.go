package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server text is printed to the terminal: control characters come back quoted
// and a non-http(s) approval link is dropped.
func TestGrantRequestSanitize(t *testing.T) {
	cases := map[string]string{
		"https://tv.example/requests/r1": "https://tv.example/requests/r1",
		"javascript:alert(1)":            "",
		"https://tv.example/\x1b[2Jx":    "",
		"/requests/r1":                   "",
	}
	for in, want := range cases {
		r := GrantRequest{URL: in, Status: "pend\x1b[31ming", Granted: []string{"a\nb"},
			Skipped: []SkippedService{{Service: "x\x07", Reason: "ok"}}}
		r.sanitize()
		if r.URL != want {
			t.Errorf("URL %q -> %q, want %q", in, r.URL, want)
		}
		for _, s := range []string{r.Status, r.Granted[0], r.Skipped[0].Service} {
			if strings.ContainsAny(s, "\x1b\n\x07") {
				t.Errorf("unsanitised %q", s)
			}
		}
	}
}

func TestDropGrantsSanitizes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"dropped":["a\u001b[2J"],"notHeld":["b\n"]}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "tvkey_x"}
	res, err := c.DropGrants([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(res.Dropped[0]+res.NotHeld[0], "\x1b\n") {
		t.Errorf("unsanitised: %v", res)
	}
}
