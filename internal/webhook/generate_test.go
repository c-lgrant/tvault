package webhook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildComposeNgrok(t *testing.T) {
	m, _ := MethodByID("ngrok")
	out, err := buildCompose(m, "img:test")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"img:test", "ngrok/ngrok:latest", "webhook:8080",
		"NGROK_AUTHTOKEN", "tv-webhook-data", "gunicorn",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ngrok compose missing %q\n%s", want, s)
		}
	}
}

func TestBuildComposeCloudflare(t *testing.T) {
	m, _ := MethodByID("cloudflare")
	out, err := buildCompose(m, "img:test")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"cloudflare/cloudflared:latest", "CLOUDFLARE_TUNNEL_TOKEN", "img:test"} {
		if !strings.Contains(s, want) {
			t.Errorf("cloudflare compose missing %q\n%s", want, s)
		}
	}
}

func TestBuildComposeTailscale(t *testing.T) {
	m, _ := MethodByID("tailscale")
	out, err := buildCompose(m, "img:test")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"service:tailscale", "network_mode", "tailscale/tailscale:latest",
		"TS_AUTHKEY", "serve.json", "tailscale-state",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("tailscale compose missing %q\n%s", want, s)
		}
	}
}

func TestBuildComposeCustomNoTunnel(t *testing.T) {
	m, _ := MethodByID("custom")
	out, err := buildCompose(m, "img:test")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "tunnel:") || strings.Contains(s, "ngrok") {
		t.Errorf("custom compose should have no tunnel service:\n%s", s)
	}
	if !strings.Contains(s, "img:test") {
		t.Errorf("custom compose missing webhook image:\n%s", s)
	}
}

func TestExternalURLNgrokDerived(t *testing.T) {
	m, _ := MethodByID("ngrok")
	got := externalURL(m, map[string]string{"NGROK_URL": "foo.ngrok-free.app"})
	if got != "https://foo.ngrok-free.app" {
		t.Errorf("externalURL = %q, want https://foo.ngrok-free.app", got)
	}
}

func TestBuildComposeUnknownMethod(t *testing.T) {
	if _, err := buildCompose(Method{ID: "bogus"}, "img:test"); err == nil {
		t.Error("expected error for unknown method")
	}
}

func TestExternalURLPassthrough(t *testing.T) {
	m, _ := MethodByID("custom")
	got := externalURL(m, map[string]string{"WEBHOOK_EXTERNAL_URL": "https://wh.example.com"})
	if got != "https://wh.example.com" {
		t.Errorf("externalURL = %q, want https://wh.example.com", got)
	}
}

func TestBuildEnvDerivesExternalURL(t *testing.T) {
	m, _ := MethodByID("ngrok")
	out := string(buildEnv(m, map[string]string{
		"NGROK_AUTHTOKEN": "tok", "NGROK_URL": "foo.ngrok-free.app",
	}))
	if !strings.Contains(out, "WEBHOOK_EXTERNAL_URL=https://foo.ngrok-free.app") {
		t.Errorf("env missing derived URL:\n%s", out)
	}
	if !strings.Contains(out, "NGROK_AUTHTOKEN=tok") {
		t.Errorf("env missing authtoken:\n%s", out)
	}
}

func TestGenerateFileSetTailscale(t *testing.T) {
	m, _ := MethodByID("tailscale")
	files, err := Generate(m, map[string]string{
		"TS_AUTHKEY": "k", "TS_HOSTNAME": "h", "WEBHOOK_EXTERNAL_URL": "https://h.ts.net",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]uint32{}
	for _, f := range files {
		modes[f.Name] = uint32(f.Mode)
	}
	for _, want := range []string{"docker-compose.yml", ".env", "README.md", ".gitignore", "serve.json"} {
		if _, ok := modes[want]; !ok {
			t.Errorf("missing generated file %q", want)
		}
	}
	if modes[".env"] != 0o600 {
		t.Errorf(".env mode = %o, want 600", modes[".env"])
	}
	for _, f := range files {
		if f.Name == ".gitignore" && string(f.Data) != ".env\n" {
			t.Errorf(".gitignore content = %q, want \".env\\n\"", f.Data)
		}
	}
}

func TestGenerateCustomHasNoServeJSON(t *testing.T) {
	m, _ := MethodByID("custom")
	files, _ := Generate(m, map[string]string{"WEBHOOK_EXTERNAL_URL": "https://x"}, "")
	for _, f := range files {
		if f.Name == "serve.json" {
			t.Error("custom method should not generate serve.json")
		}
	}
}

func TestDefaultImageFor(t *testing.T) {
	cases := map[string]string{
		// CI-built preview binary (ldflags-injected version)
		"preview-9749169":                                 "ghcr.io/c-lgrant/tvault-webhook:preview",
		"preview-abcdef0":                                 "ghcr.io/c-lgrant/tvault-webhook:preview",
		// Real release tags
		"v0.5.0":                                          "ghcr.io/c-lgrant/tvault-webhook:0.5.0",
		"0.5.0":                                           "ghcr.io/c-lgrant/tvault-webhook:0.5.0",
		"v1.0.0":                                          "ghcr.io/c-lgrant/tvault-webhook:1.0.0",
		// Go pseudo-versions (go install ...@<branch>)
		"v0.4.10-0.20260515140135-f760cf955e71":           "ghcr.io/c-lgrant/tvault-webhook:preview",
		"v0.0.0-20260515140135-f760cf955e71":              "ghcr.io/c-lgrant/tvault-webhook:preview",
		"v0.5.0-pre.0.20260515140135-abcdef012345":        "ghcr.io/c-lgrant/tvault-webhook:preview",
		// Unknown / dev / empty — last-resort :latest
		"dev":                                             "ghcr.io/c-lgrant/tvault-webhook:latest",
		"(devel)":                                         "ghcr.io/c-lgrant/tvault-webhook:latest",
		"":                                                "ghcr.io/c-lgrant/tvault-webhook:latest",
		"unknown":                                         "ghcr.io/c-lgrant/tvault-webhook:latest",
		// Things that LOOK like semver but aren't (extra suffixes etc.)
		"v0.5.0-rc1":                                      "ghcr.io/c-lgrant/tvault-webhook:latest",
		"0.5":                                             "ghcr.io/c-lgrant/tvault-webhook:latest",
		"v0.5.0+build.1":                                  "ghcr.io/c-lgrant/tvault-webhook:latest",
		// Pseudo-version with wrong shapes — must NOT match
		"v0.5.0-0.2026051514013-f760cf955e71":             "ghcr.io/c-lgrant/tvault-webhook:latest", // 13-digit ts
		"v0.5.0-0.20260515140135-f760cf955e7":             "ghcr.io/c-lgrant/tvault-webhook:latest", // 11-char sha
		"v0.5.0-0.20260515140135-zzzzzzzzzzzz":            "ghcr.io/c-lgrant/tvault-webhook:latest", // non-hex sha
	}
	for in, want := range cases {
		if got := DefaultImageFor(in); got != want {
			t.Errorf("DefaultImageFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConflicts(t *testing.T) {
	dir := t.TempDir()
	files := []GeneratedFile{
		{Name: "docker-compose.yml", Data: []byte("x")},
		{Name: ".env", Data: []byte("y")},
		{Name: "README.md", Data: []byte("z")},
	}
	if got := Conflicts(dir, files); len(got) != 0 {
		t.Errorf("empty dir Conflicts = %v, want []", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Conflicts(dir, files)
	if len(got) != 2 {
		t.Fatalf("Conflicts = %v, want 2 entries", got)
	}
	// Order matches files slice — assert membership not position to keep
	// the test resilient to reordering.
	seen := map[string]bool{}
	for _, n := range got {
		seen[n] = true
	}
	if !seen["docker-compose.yml"] || !seen[".env"] {
		t.Errorf("Conflicts = %v, want both docker-compose.yml and .env", got)
	}
	if seen["README.md"] {
		t.Errorf("Conflicts incorrectly flagged README.md (does not exist on disk)")
	}
	// Missing dir is not an error — should return no conflicts.
	if got := Conflicts(filepath.Join(dir, "nonexistent"), files); len(got) != 0 {
		t.Errorf("missing-dir Conflicts = %v, want []", got)
	}
}

func TestWriteProjectRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	files := []GeneratedFile{
		{Name: "docker-compose.yml", Mode: 0o644, Data: []byte("x")},
		{Name: ".env", Mode: 0o600, Data: []byte("SECRET=x\n")},
	}
	if err := WriteProject(dir, files, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteProject(dir, files, false); err == nil {
		t.Error("second WriteProject without force should fail")
	}
	if err := WriteProject(dir, files, true); err != nil {
		t.Errorf("WriteProject with force should succeed: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("stat .env: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf(".env on-disk mode = %o, want 600", fi.Mode().Perm())
	}
}
