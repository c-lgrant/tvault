package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCleanClientLabel(t *testing.T) {
	cases := map[string]string{
		"macmini":               "macmini",
		"nuc.lan":               "nuc.lan",
		"ci@runner-7:eu":        "ci@runner-7:eu",
		"My Mac mini":           "MyMacmini",
		"-lead":                 "lead",
		"<script>":              "script",
		"héllo":                 "hllo",
		"":                      "",
		"...":                   "",
		strings.Repeat("a", 90): strings.Repeat("a", clientLabelMax),
	}
	for in, want := range cases {
		if got := cleanClientLabel(in); got != want {
			t.Errorf("cleanClientLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientLabelFromEnvOrHostName(t *testing.T) {
	t.Setenv(ClientLabelEnv, "build box 3")
	if got := clientLabel(); got != "buildbox3" {
		t.Errorf("env label = %q", got)
	}
	t.Setenv(ClientLabelEnv, " - ")
	if got := clientLabel(); got != "" {
		t.Errorf("\"-\" must send no label, got %q", got)
	}
	// Unset (or empty): the short host name.
	os.Unsetenv(ClientLabelEnv)
	host, err := os.Hostname()
	if err != nil {
		t.Skip("no host name on this machine")
	}
	short, _, _ := strings.Cut(host, ".")
	if got := clientLabel(); got != cleanClientLabel(short) {
		t.Errorf("default label = %q, want the short host name %q", got, cleanClientLabel(short))
	}
	t.Setenv(ClientLabelEnv, "")
	if got := clientLabel(); got != cleanClientLabel(short) {
		t.Errorf("an empty value falls back to the host name, got %q", got)
	}
}

func TestClientLabelIsSentToTheControlPlane(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(clientLabelHeader))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	t.Setenv(ClientLabelEnv, "macmini")
	c := New(srv.URL, 0)
	if _, err := c.doRequest("GET", "/api/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ClientLabelEnv, "-")
	c = New(srv.URL, 0)
	if _, err := c.doRequest("GET", "/api/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "macmini" || got[1] != "" {
		t.Errorf("header values = %q, want [macmini, \"\"]", got)
	}
}

func TestClientLabelIsNotCarriedToAnotherHost(t *testing.T) {
	first, _ := http.NewRequest("GET", "https://api.example.com/a", nil)
	next, _ := http.NewRequest("GET", "https://webhook.example.net/b", nil)
	next.Header.Set(clientLabelHeader, "macmini")
	if err := refuseInsecureRedirect(next, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	if next.Header.Get(clientLabelHeader) != "" {
		t.Error("the label went to another host on a redirect")
	}
	same, _ := http.NewRequest("GET", "https://api.example.com/c", nil)
	same.Header.Set(clientLabelHeader, "macmini")
	if err := refuseInsecureRedirect(same, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	if same.Header.Get(clientLabelHeader) != "macmini" {
		t.Error("the label was dropped on a redirect to the same host")
	}
}
