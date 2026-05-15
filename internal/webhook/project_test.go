package webhook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := "# comment\nWEBHOOK_EXTERNAL_URL=https://wh.example.com\nNGROK_URL=x\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProject(dir)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if p.ExternalURL != "https://wh.example.com" {
		t.Errorf("ExternalURL = %q", p.ExternalURL)
	}
}

func TestLoadProjectMissingCompose(t *testing.T) {
	if _, err := LoadProject(t.TempDir()); err == nil {
		t.Error("missing docker-compose.yml should error")
	}
}

func TestLoadProjectMissingURL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("NGROK_URL=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProject(dir); err == nil {
		t.Error("missing WEBHOOK_EXTERNAL_URL should error")
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# header comment\n\nKEY1=value1\nKEY2 = spaced value \nURL=https://foo.example?a=1&b=2\nbareline\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if env["KEY1"] != "value1" {
		t.Errorf("KEY1 = %q", env["KEY1"])
	}
	if env["KEY2"] != "spaced value" {
		t.Errorf("KEY2 = %q, want trimmed", env["KEY2"])
	}
	if env["URL"] != "https://foo.example?a=1&b=2" {
		t.Errorf("URL = %q, want value with = preserved", env["URL"])
	}
	if _, ok := env["bareline"]; ok {
		t.Error("bare no-'=' line should be skipped")
	}
	if len(env) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(env), env)
	}
}
